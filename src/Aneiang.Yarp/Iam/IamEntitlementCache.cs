using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Aneiang.Yarp.Iam;

public interface IIamEntitlementCache
{
    Task<IamEntitlementSnapshot> GetAsync(string issuer, string subject, string applicationId, CancellationToken cancellationToken, string? clientId = null);
}

public sealed class IamEntitlementCache : IIamEntitlementCache, IDisposable
{
    private readonly IIamEntitlementSource _source;
    private readonly IamGatewayOptions _options;
    private readonly TimeProvider _clock;
    private readonly MemoryCache _cache;
    private readonly SemaphoreSlim _fetchSlots;
    private readonly SemaphoreSlim _pendingSlots;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly ConcurrentDictionary<string, Lazy<Task<IamEntitlementSnapshot>>> _flights = new(StringComparer.Ordinal);

    public IamEntitlementCache(IIamEntitlementSource source, IOptions<IamGatewayOptions> options, TimeProvider clock)
    {
        _source = source; _options = options.Value; _clock = clock;
        _cache = new(new MemoryCacheOptions { SizeLimit = _options.EntitlementCacheSize });
        _fetchSlots = new(_options.MaxConcurrentEntitlementFetches);
        _pendingSlots = new(_options.MaxPendingEntitlementFetches);
    }
    public async Task<IamEntitlementSnapshot> GetAsync(string issuer, string subject, string applicationId, CancellationToken cancellationToken, string? clientId = null)
    {
        if (issuer.Length > 300 || subject.Length > 200 || clientId?.Length > 200 || !Guid.TryParse(applicationId, out _))
            throw new IamContractException("identity_invalid");
        var identity = new[] { issuer, subject, applicationId, clientId ?? "" };
        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('|', identity.Select(s => $"{s.Length}:{s}")))));
        if (_cache.TryGetValue(key, out CacheEntry? cached) && cached is not null)
        {
            if (cached.ExpiresAt > _clock.GetUtcNow()) return cached.Value ?? throw new IamIdentityNotFoundException();
            _cache.Remove(key);
        }
        var lazy = _flights.GetOrAdd(key, _ => new(() => FetchAndCacheAsync(key, issuer, subject, applicationId, clientId), LazyThreadSafetyMode.ExecutionAndPublication));
        // A canceled waiter never cancels a shared fetch belonging to other valid requests.
        try { return await lazy.Value.WaitAsync(cancellationToken).ConfigureAwait(false); }
        finally { if (lazy.IsValueCreated && lazy.Value.IsCompleted) _flights.TryRemove(new KeyValuePair<string, Lazy<Task<IamEntitlementSnapshot>>>(key, lazy)); }
    }
    private async Task<IamEntitlementSnapshot> FetchAndCacheAsync(string key, string issuer, string subject, string app, string? client)
    {
        if (!_pendingSlots.Wait(0)) throw new IamContractException("entitlement_overload");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_shutdown.Token);
        timeout.CancelAfter(_options.IamTimeout);
        try
        {
            await _fetchSlots.WaitAsync(timeout.Token).ConfigureAwait(false);
            IamEntitlementSnapshot snapshot;
            try { snapshot = await _source.FetchAsync(issuer, subject, app, timeout.Token, client).ConfigureAwait(false); }
            finally { _fetchSlots.Release(); }
            var now = _clock.GetUtcNow();
            Validate(snapshot, issuer, subject, app, client, now);
            var maximum = !snapshot.IsActive || snapshot.Grants.IsEmpty ? _options.NegativeCacheMaxAge : _options.EntitlementMaxAge;
            var expires = snapshot.ExpiresAt < now + maximum ? snapshot.ExpiresAt : now + maximum;
            _cache.Set(key, new CacheEntry(snapshot, expires), new MemoryCacheEntryOptions { AbsoluteExpiration = expires, Size = 1 });
            return snapshot;
        }
        catch (IamIdentityNotFoundException)
        {
            var expiry = _clock.GetUtcNow() + _options.NegativeCacheMaxAge;
            _cache.Set(key, new CacheEntry(null, expiry), new MemoryCacheEntryOptions { AbsoluteExpiration = expiry, Size = 1 });
            throw;
        }
        finally { _pendingSlots.Release(); _flights.TryRemove(key, out _); }
    }
    private static void Validate(IamEntitlementSnapshot value, string issuer, string subject, string app, string? client, DateTimeOffset now)
    {
        if (value.SchemaVersion != 1 || !Guid.TryParse(value.PrincipalId, out var id) || id == Guid.Empty
            || value.Revision < 0 || value.IssuedAt > now || value.ExpiresAt <= now
            || value.ExpiresAt <= value.IssuedAt || value.ExpiresAt - value.IssuedAt > TimeSpan.FromSeconds(120))
            throw new IamContractException("entitlement_invalid");
        if (value.Issuer != issuer || value.Subject != subject || value.ApplicationId != app || !Enum.IsDefined(value.PrincipalKind)
            || value.PrincipalKind == IamPrincipalKind.Service && (string.IsNullOrWhiteSpace(client) || client != value.ClientId)
            || value.PrincipalKind == IamPrincipalKind.User && value.ClientId is not null)
            throw new IamContractException("entitlement_binding");
        if (value.Grants.IsDefault || value.Grants.Length > 4096 || !value.IsActive && value.Grants.Length != 0)
            throw new IamContractException("entitlement_grants");
        foreach (var grant in value.Grants)
            if (string.IsNullOrWhiteSpace(grant.PermissionCode) || grant.PermissionCode.Length > 120
                || !(grant.ScopeKind == IamScopeKind.Global && grant.ScopeId is null
                    || grant.ScopeKind == IamScopeKind.System && !string.IsNullOrWhiteSpace(grant.ScopeId) && grant.ScopeId.Length <= 100))
                throw new IamContractException("entitlement_scope");
    }
    public void Dispose() { _shutdown.Cancel(); _shutdown.Dispose(); _cache.Dispose(); /* pending tasks own semaphore releases */ }
    private sealed record CacheEntry(IamEntitlementSnapshot? Value, DateTimeOffset ExpiresAt);
}
public sealed class IamContractException(string reason) : Exception(reason) { public string Reason { get; } = reason; }
public sealed class IamIdentityNotFoundException : Exception;
public sealed class IamIdentityConflictException : Exception;
