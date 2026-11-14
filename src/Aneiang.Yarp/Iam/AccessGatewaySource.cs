using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Aneiang.Yarp.Iam;

internal static class AccessJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web) { MaxDepth = 32 };

    public static T? Deserialize<T>(byte[] bytes)
    {
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
        IamBundleWireProtocol.RejectDuplicateProperties(document.RootElement);
        return document.RootElement.Deserialize<T>(Options);
    }
}

internal sealed class AccessRouteRefreshService(
    IHttpClientFactory clients, IOptions<AccessGatewayOptions> settings, IIamServiceTokenProvider tokens,
    AccessPolicyStore store, ILogger<AccessRouteRefreshService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var options = settings.Value;
                using var message = new HttpRequestMessage(HttpMethod.Get, options.RoutesEndpoint);
                message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await tokens.GetAsync(stoppingToken));
                using var response = await clients.CreateClient("Aneiang.Access").SendAsync(message,
                    HttpCompletionOption.ResponseHeadersRead, stoppingToken);
                if (!response.IsSuccessStatusCode) throw new IamContractException("access_routes_unavailable");
                var bytes = await IamHttpPayload.ReadAsync(response, 2 * 1024 * 1024, stoppingToken);
                var snapshot = AccessJson.Deserialize<AccessRouteSnapshot>(bytes)
                    ?? throw new IamContractException("access_routes_malformed");
                store.Accept(snapshot);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception) { logger.LogWarning("IAM access route refresh failed. Expired snapshots will fail closed."); }
            await Task.Delay(settings.Value.RefreshInterval, stoppingToken);
        }
    }
}

public sealed class AccessEntitlementCache(
    IHttpClientFactory clients, IOptions<AccessGatewayOptions> options,
    IIamServiceTokenProvider tokens, IMemoryCache cache, TimeProvider clock)
{
    private static string Key(AccessResolveRequest request, long revision)
    {
        // Token role changes must not reuse a snapshot created under different roles.
        var roles = string.Join("\n", request.RealmRoles.Order(StringComparer.Ordinal))
            + "\n" + string.Join("\n", request.ClientRoles.OrderBy(x => x.Key, StringComparer.Ordinal)
                .Select(x => x.Key + ":" + string.Join(",", x.Value.Order(StringComparer.Ordinal))));
        var raw = revision + "|" + request.ApplicationId + "|" + request.Issuer + "|" + request.Subject
            + "|" + request.ClientId + "|" + roles;
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
    }

    public async Task<AccessEntitlementSnapshot> GetAsync(AccessResolveRequest input, long revision, CancellationToken ct)
    {
        var key = Key(input, revision);
        if (cache.TryGetValue<AccessEntitlementSnapshot>(key, out var cached) &&
            cached is not null && cached.ExpiresAt > clock.GetUtcNow()) return cached;

        using var message = new HttpRequestMessage(HttpMethod.Post, options.Value.ResolveEndpoint)
        {
            Content = JsonContent.Create(input, options: AccessJson.Options)
        };
        message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await tokens.GetAsync(ct));
        using var response = await clients.CreateClient("Aneiang.Access").SendAsync(message,
            HttpCompletionOption.ResponseHeadersRead, ct);
        if (!response.IsSuccessStatusCode) throw new IamContractException("access_resolve_unavailable");
        var bytes = await IamHttpPayload.ReadAsync(response, 128 * 1024, ct);
        var result = AccessJson.Deserialize<AccessEntitlementSnapshot>(bytes)
            ?? throw new IamContractException("access_resolve_malformed");
        var now = clock.GetUtcNow();
        if (result.SchemaVersion != 1 || result.Revision != revision || result.ApplicationId != input.ApplicationId
            || !string.Equals(result.Issuer, input.Issuer, StringComparison.Ordinal)
            || !string.Equals(result.Subject, input.Subject, StringComparison.Ordinal)
            || result.AccessCodes is null || result.AccessCodes.Length > 1024
            || result.AccessCodes.Any(x => string.IsNullOrWhiteSpace(x) || x.Length > 120)
            || result.IssuedAt > now.AddSeconds(30) || result.ExpiresAt <= now
            || result.ExpiresAt > now.AddSeconds(120))
            throw new IamContractException("access_resolve_invalid");
        // Short-lived authorization decision; no stale-while-revalidate on security data.
        cache.Set(key, result, new MemoryCacheEntryOptions
        {
            AbsoluteExpiration = result.ExpiresAt < now.AddSeconds(30) ? result.ExpiresAt : now.AddSeconds(30),
            Size = 1
        });
        return result;
    }
}
