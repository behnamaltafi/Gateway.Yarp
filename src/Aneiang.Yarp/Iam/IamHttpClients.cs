using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Aneiang.Yarp.Iam;

public interface IIamServiceTokenProvider { Task<string> GetAsync(CancellationToken cancellationToken); }

public sealed class IamServiceTokenProvider(IHttpClientFactory clients, IOptions<IamGatewayOptions> options, TimeProvider clock)
    : IIamServiceTokenProvider, IDisposable
{
    private readonly SemaphoreSlim _lock = new(1);
    private string? _token;
    private DateTimeOffset _expiresAt;
    public async Task<string> GetAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;
        if (!string.IsNullOrWhiteSpace(settings.InternalApiToken)) return settings.InternalApiToken;
        await _lock.WaitAsync(cancellationToken);
        try
        {
            if (_token is not null && _expiresAt > clock.GetUtcNow()) return _token;
            if (settings.InternalTokenEndpoint?.Scheme != "https" || string.IsNullOrWhiteSpace(settings.InternalClientId)
                || string.IsNullOrWhiteSpace(settings.InternalClientSecret)) throw new IamContractException("internal_identity_unconfigured");
            using var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials", ["client_id"] = settings.InternalClientId, ["client_secret"] = settings.InternalClientSecret
            });
            using var response = await clients.CreateClient("Aneiang.Iam.ServiceAuth").PostAsync(settings.InternalTokenEndpoint, content, cancellationToken);
            if (!response.IsSuccessStatusCode) throw new IamContractException("internal_identity_unavailable");
            var bytes = await IamHttpPayload.ReadAsync(response, 64 * 1024, cancellationToken);
            using var json = JsonDocument.Parse(bytes);
            IamBundleWireProtocol.RejectDuplicateProperties(json.RootElement);
            var seconds = json.RootElement.GetProperty("expires_in").GetInt32();
            var token = json.RootElement.GetProperty("access_token").GetString();
            if (string.IsNullOrWhiteSpace(token) || seconds <= 0 || json.RootElement.GetProperty("token_type").GetString() != "Bearer")
                throw new IamContractException("internal_identity_malformed");
            _token = token; _expiresAt = clock.GetUtcNow().AddSeconds(Math.Max(1, seconds - 30));
            return token;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        { throw new IamContractException("internal_identity_malformed"); }
        finally { _lock.Release(); }
    }
    public void Dispose() { _token = null; _lock.Dispose(); }
}

public static class IamHttpPayload
{
    public static async Task<byte[]> ReadAsync(HttpResponseMessage response, int maximum, CancellationToken ct)
    {
        if (response.Content.Headers.ContentLength > maximum) throw new IamContractException("payload_oversized");
        if (response.Content.Headers.ContentType?.MediaType != "application/json") throw new IamContractException("payload_content_type");
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var output = new MemoryStream(); var buffer = new byte[8192]; int count;
        while ((count = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, maximum + 1 - (int)output.Length)), ct)) != 0)
        {
            output.Write(buffer, 0, count);
            if (output.Length > maximum) throw new IamContractException("payload_oversized");
        }
        return output.ToArray();
    }
}

public sealed class IamHttpEntitlementSource(HttpClient client, IOptions<IamGatewayOptions> options, IIamServiceTokenProvider tokens) : IIamEntitlementSource
{
    public async Task<IamEntitlementSnapshot> FetchAsync(string issuer, string subject, string applicationId, CancellationToken cancellationToken, string? clientId = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, options.Value.EntitlementEndpoint ?? throw new IamContractException("entitlement_endpoint"));
        request.Content = JsonContent.Create(new { schemaVersion = 1, applicationId, validatedIdentity = new { issuer, subject, clientId } });
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await tokens.GetAsync(cancellationToken));
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) throw new IamIdentityNotFoundException();
        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            var error = await IamHttpPayload.ReadAsync(response, 8192, cancellationToken);
            using var parsed = JsonDocument.Parse(error);
            if (parsed.RootElement.TryGetProperty("errorCode", out var code) && code.GetString() == "iam.identity_conflict")
                throw new IamIdentityConflictException();
        }
        if (!response.IsSuccessStatusCode) throw new IamContractException("entitlement_source_unavailable");
        var bytes = await IamHttpPayload.ReadAsync(response, options.Value.MaxEntitlementPayloadBytes, cancellationToken);
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
        IamBundleWireProtocol.RejectDuplicateProperties(document.RootElement);
        return document.RootElement.Deserialize<IamEntitlementSnapshot>(IamBundleWireProtocol.JsonOptions) ?? throw new IamContractException("entitlement_malformed");
    }
}

public sealed class IamPolicyBundleStore : IIamPolicyBundleProvider
{
    private IamPolicyBundle? _current;
    private readonly TimeProvider _clock;
    private readonly object _gate = new();
    public IamPolicyBundleStore(TimeProvider clock) => _clock = clock;
    public IamPolicyBundle? Current => Volatile.Read(ref _current);
    public bool IsReady => Current is { } value && value.ValidatedUntil > _clock.GetUtcNow();
    public void Publish(IamPolicyBundle bundle)
    {
        if (!IamPolicyBundleValidator.TryValidate(bundle, _clock.GetUtcNow(), out var reason)) throw new IamContractException(reason);
        lock (_gate)
        {
            var old = Current;
            if (old is not null && (bundle.Revision < old.Revision || bundle.Revision == old.Revision
                && (bundle.Hash != old.Hash || bundle.PolicyContentBase64 != old.PolicyContentBase64)))
                throw new IamContractException("bundle_stale_or_mutated");
            if (old is not null && bundle.Revision == old.Revision && bundle.ValidatedUntil <= old.ValidatedUntil) return;
            Volatile.Write(ref _current, bundle); // same immutable revision/hash may receive a freshly authenticated renewable lease
        }
    }
}

internal sealed class IamPolicyBundleRefreshService(IHttpClientFactory clients, IamPolicyBundleStore store,
    IOptions<IamGatewayOptions> options, IIamServiceTokenProvider tokens, TimeProvider clock, ILogger<IamPolicyBundleRefreshService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await RefreshAsync(stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception) { logger.LogWarning("IAM policy pull failed; retain only an unexpired previously validated bundle."); }
            await Task.Delay(options.Value.BundleRefreshInterval, stoppingToken);
        }
    }
    internal async Task RefreshAsync(CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, options.Value.PolicyBundleEndpoint ?? throw new IamContractException("bundle_endpoint"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await tokens.GetAsync(ct));
        using var response = await clients.CreateClient("Aneiang.Iam.Bundle").SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!response.IsSuccessStatusCode) throw new IamContractException("bundle_source_unavailable");
        var bytes = await IamHttpPayload.ReadAsync(response, options.Value.MaxBundlePayloadBytes, ct);
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
        IamBundleWireProtocol.RejectDuplicateProperties(document.RootElement);
        var envelope = document.RootElement.Deserialize<IamBundleEnvelope>(IamBundleWireProtocol.JsonOptions) ?? throw new IamContractException("bundle_malformed");
        store.Publish(IamBundleWireProtocol.Decode(envelope, clock.GetUtcNow()));
    }
}
