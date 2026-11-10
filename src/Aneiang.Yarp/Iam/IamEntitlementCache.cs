using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Aneiang.Yarp.Iam;

public interface IIamEntitlementCache
{
    Task<IamEntitlementSnapshot> GetAsync(string issuer, string subject, string applicationId, CancellationToken cancellationToken);
}

public sealed class IamEntitlementCache : IIamEntitlementCache, IDisposable
{
    private readonly IIamEntitlementSource _source;
    private readonly IamGatewayOptions _options;
    private readonly TimeProvider _clock;
    private readonly MemoryCache _cache;
    private readonly SemaphoreSlim _fetchSlots;
    private readonly ConcurrentDictionary<string, Lazy<Task<IamEntitlementSnapshot>>> _flights = new(StringComparer.Ordinal);

    public IamEntitlementCache(IIamEntitlementSource source, IOptions<IamGatewayOptions> options, TimeProvider clock)
    {
        _source = source;
        _options = options.Value;
        _clock = clock;
        _cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = _options.EntitlementCacheSize });
        _fetchSlots = new SemaphoreSlim(_options.MaxConcurrentEntitlementFetches, _options.MaxConcurrentEntitlementFetches);
    }

    public async Task<IamEntitlementSnapshot> GetAsync(string issuer, string subject, string applicationId, CancellationToken cancellationToken)
    {
        var key = Key(issuer, subject, applicationId);
        if (_cache.TryGetValue(key, out CacheEntry? cached) && cached is not null)
        {
            if (cached.ExpiresAt > _clock.GetUtcNow()) return cached.Value;
            _cache.Remove(key);
        }

        var lazy = _flights.GetOrAdd(key, _ => new Lazy<Task<IamEntitlementSnapshot>>(
            () => FetchAndCacheAsync(key, issuer, subject, applicationId, cancellationToken),
            LazyThreadSafetyMode.ExecutionAndPublication));
        try { return await lazy.Value.WaitAsync(cancellationToken).ConfigureAwait(false); }
        finally { if (lazy.IsValueCreated && lazy.Value.IsCompleted) _flights.TryRemove(new KeyValuePair<string, Lazy<Task<IamEntitlementSnapshot>>>(key, lazy)); }
    }

    private async Task<IamEntitlementSnapshot> FetchAndCacheAsync(string key, string issuer, string subject, string applicationId, CancellationToken cancellationToken)
    {
        await _fetchSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
        IamEntitlementSnapshot snapshot;
        try { snapshot = await _source.FetchAsync(issuer, subject, applicationId, cancellationToken).ConfigureAwait(false); }
        finally { _fetchSlots.Release(); }
        var now = _clock.GetUtcNow();
        Validate(snapshot, issuer, subject, applicationId, now);
        var maxAge = snapshot.IsActive ? _options.EntitlementMaxAge : _options.NegativeCacheMaxAge;
        var expires = snapshot.ExpiresAt < now + maxAge ? snapshot.ExpiresAt : now + maxAge;
        if (expires <= now) throw new IamContractException("entitlement_expired");
        _cache.Set(key, new CacheEntry(snapshot, expires), new MemoryCacheEntryOptions { AbsoluteExpiration = expires, Size = 1 });
        return snapshot;
    }

    private static void Validate(IamEntitlementSnapshot value, string issuer, string subject, string applicationId, DateTimeOffset now)
    {
        if (!string.Equals(value.SchemaVersion, "1.0", StringComparison.Ordinal)) throw new IamContractException("entitlement_schema");
        if (!string.Equals(value.Issuer, issuer, StringComparison.Ordinal) || !string.Equals(value.Subject, subject, StringComparison.Ordinal)
            || !string.Equals(value.ApplicationId, applicationId, StringComparison.Ordinal)) throw new IamContractException("entitlement_binding");
        if (string.IsNullOrWhiteSpace(value.PrincipalId) || value.Revision <= 0 || value.IssuedAt > now.AddMinutes(1) || value.ExpiresAt <= now)
            throw new IamContractException("entitlement_invalid");
        if (value.Grants.IsDefault || value.Grants.Length > 10_000) throw new IamContractException("entitlement_grants");
    }

    private static string Key(string issuer, string subject, string app)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{issuer.Length}:{issuer}|{subject.Length}:{subject}|{app.Length}:{app}")));

    public void Dispose() { _cache.Dispose(); _fetchSlots.Dispose(); }

    private sealed record CacheEntry(IamEntitlementSnapshot Value, DateTimeOffset ExpiresAt);
}

public sealed class IamContractException(string reason) : Exception(reason)
{
    public string Reason { get; } = reason;
}
