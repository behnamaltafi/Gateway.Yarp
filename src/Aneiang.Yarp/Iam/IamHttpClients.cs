using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Aneiang.Yarp.Iam;

public sealed class IamHttpEntitlementSource(HttpClient client, IOptions<IamGatewayOptions> options) : IIamEntitlementSource
{
    private readonly IamGatewayOptions _options = options.Value;

    public async Task<IamEntitlementSnapshot> FetchAsync(string issuer, string subject, string applicationId, CancellationToken cancellationToken)
    {
        var endpoint = _options.EntitlementEndpoint ?? throw new IamContractException("entitlement_endpoint");
        var uri = new UriBuilder(endpoint) { Query = $"issuer={Uri.EscapeDataString(issuer)}&subject={Uri.EscapeDataString(subject)}&applicationId={Uri.EscapeDataString(applicationId)}" }.Uri;
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        AddInternalAuth(request, _options.InternalApiToken);
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw new HttpRequestException("IAM entitlement endpoint was unavailable.", null, response.StatusCode);
        EnsureSize(response, _options.MaxEntitlementPayloadBytes);
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<IamEntitlementSnapshot>(stream, cancellationToken: cancellationToken).ConfigureAwait(false)
               ?? throw new IamContractException("entitlement_malformed");
    }

    internal static void AddInternalAuth(HttpRequestMessage request, string token)
    {
        if (!string.IsNullOrWhiteSpace(token)) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    internal static void EnsureSize(HttpResponseMessage response, int maximum)
    {
        if (response.Content.Headers.ContentLength > maximum) throw new IamContractException("payload_oversized");
    }
}

public sealed class IamPolicyBundleStore : IIamPolicyBundleProvider
{
    private IamPolicyBundle? _current;
    private readonly TimeProvider _clock;
    public IamPolicyBundleStore(TimeProvider clock) => _clock = clock;
    public IamPolicyBundle? Current => Volatile.Read(ref _current);
    public bool IsReady => IamPolicyBundleValidator.TryValidate(Current, _clock.GetUtcNow(), out _);
    public void Publish(IamPolicyBundle bundle)
    {
        if (!IamPolicyBundleValidator.TryValidate(bundle, _clock.GetUtcNow(), out var reason)) throw new IamContractException(reason);
        var observed = Current;
        if (observed is not null && bundle.Revision <= observed.Revision) throw new IamContractException("bundle_stale");
        Volatile.Write(ref _current, bundle);
    }
}

internal sealed class IamPolicyBundleRefreshService(
    IHttpClientFactory clients,
    IamPolicyBundleStore store,
    IOptions<IamGatewayOptions> options,
    ILogger<IamPolicyBundleRefreshService> logger) : BackgroundService
{
    private readonly IamGatewayOptions _options = options.Value;
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await RefreshAsync(stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) { logger.LogError(ex, "IAM policy bundle refresh failed; the gateway remains fail-closed or on the unexpired last-known-good bundle."); }
            await Task.Delay(_options.BundleRefreshInterval, stoppingToken).ConfigureAwait(false);
        }
    }

    internal async Task RefreshAsync(CancellationToken cancellationToken)
    {
        var endpoint = _options.PolicyBundleEndpoint ?? throw new IamContractException("bundle_endpoint");
        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        IamHttpEntitlementSource.AddInternalAuth(request, _options.InternalApiToken);
        using var response = await clients.CreateClient("Aneiang.Iam.Bundle").SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        IamHttpEntitlementSource.EnsureSize(response, _options.MaxBundlePayloadBytes);
        var bundle = await response.Content.ReadFromJsonAsync<IamPolicyBundle>(cancellationToken: cancellationToken).ConfigureAwait(false)
                     ?? throw new IamContractException("bundle_malformed");
        if (store.Current?.Revision == bundle.Revision) return;
        store.Publish(bundle);
    }
}
