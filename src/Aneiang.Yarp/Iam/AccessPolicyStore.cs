using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing.Template;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;

namespace Aneiang.Yarp.Iam;

public sealed class AccessGatewayOptions
{
    public const string SectionName = "Gateway:Access";
    public bool Enabled { get; set; }
    public Uri? RoutesEndpoint { get; set; }
    public Uri? ResolveEndpoint { get; set; }
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromSeconds(15);
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(3);
    public int MaxRoutes { get; set; } = 4096;
}

public sealed record AccessRouteRule(Guid ApplicationId, string GatewayRouteId,
    string Method, string PathTemplate, string[] AccessCodes);
public sealed record AccessRouteSnapshot(int SchemaVersion, long Revision, DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt, AccessRouteRule[] Routes);
public sealed record AccessResolveRequest(int SchemaVersion, Guid ApplicationId, string Issuer,
    string Subject, string? ClientId, string[] RealmRoles, Dictionary<string,string[]> ClientRoles);
public sealed record AccessEntitlementSnapshot(int SchemaVersion, long Revision, Guid ApplicationId,
    string Issuer, string Subject, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt,
    bool IsActive, string[] AccessCodes);

internal sealed record MatchedAccess(AccessRouteRule Rule, TemplateMatcher Matcher);

public sealed class AccessPolicyStore(TimeProvider clock)
{
    private sealed record State(AccessRouteSnapshot Snapshot, MatchedAccess[] Matchers, string Hash);
    private State? _state;
    public bool IsReady => Volatile.Read(ref _state) is { } state && state.Snapshot.ExpiresAt > clock.GetUtcNow();
    public long? CurrentRevision => IsReady ? Volatile.Read(ref _state)?.Snapshot.Revision : null;

    public void Accept(AccessRouteSnapshot snapshot)
    {
        var now = clock.GetUtcNow();
        if (snapshot is null || snapshot.SchemaVersion != 1 || snapshot.Revision < 0
            || snapshot.Routes is null || snapshot.Routes.Length > 4096
            || snapshot.IssuedAt > now.AddSeconds(30) || snapshot.ExpiresAt <= now
            || snapshot.ExpiresAt > now.AddSeconds(120) || snapshot.ExpiresAt <= snapshot.IssuedAt)
            throw new IamContractException("access_routes_invalid");
        var keys = new HashSet<string>(StringComparer.Ordinal);
        var matchers = new List<MatchedAccess>(snapshot.Routes.Length);
        foreach (var r in snapshot.Routes)
        {
            if (r.ApplicationId == Guid.Empty || string.IsNullOrWhiteSpace(r.GatewayRouteId)
                || r.GatewayRouteId.Length > 200 || r.GatewayRouteId.Any(char.IsControl)
                || r.Method is not ("GET" or "POST" or "PUT" or "PATCH" or "DELETE" or "HEAD" or "OPTIONS" or "TRACE")
                || r.PathTemplate is null || !r.PathTemplate.StartsWith('/') || r.PathTemplate.Length > 512
                || r.PathTemplate.StartsWith("//", StringComparison.Ordinal) || r.PathTemplate.Contains('%')
                || r.AccessCodes is null || r.AccessCodes.Length > 256
                || r.AccessCodes.Any(x => string.IsNullOrWhiteSpace(x) || x.Length > 120 || x.Any(char.IsWhiteSpace)))
                throw new IamContractException("access_route_invalid");
            if (!keys.Add(r.GatewayRouteId + "\n" + r.Method + "\n" + r.PathTemplate))
                throw new IamContractException("duplicate_access_route");
            try { matchers.Add(new(r, new TemplateMatcher(TemplateParser.Parse(r.PathTemplate), new RouteValueDictionary()))); }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            { throw new IamContractException("invalid_route_template"); }
        }
        var hash = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(snapshot.Routes)));
        lock (this)
        {
            var current = _state;
            if (current is not null && (snapshot.Revision < current.Snapshot.Revision
                || snapshot.Revision == current.Snapshot.Revision && hash != current.Hash))
                throw new IamContractException("access_routes_rollback");
            Volatile.Write(ref _state, new(snapshot, matchers.ToArray(), hash));
        }
    }

    // Must also match YARP's selected route ID; catch-all proxy routes cannot bypass operation-level access.
    public AccessRouteRule? Find(string yarpRouteId, string method, PathString requestPath, out bool ambiguous)
    {
        ambiguous = false;
        var state = Volatile.Read(ref _state);
        if (state is null || state.Snapshot.ExpiresAt <= clock.GetUtcNow()) return null;
        AccessRouteRule? found = null;
        foreach (var match in state.Matchers)
        {
            if (!string.Equals(match.Rule.GatewayRouteId, yarpRouteId, StringComparison.Ordinal)
                || !string.Equals(match.Rule.Method, method, StringComparison.Ordinal)) continue;
            if (!match.Matcher.TryMatch(requestPath, new RouteValueDictionary())) continue;
            if (found != null) { ambiguous = true; return null; }
            found = match.Rule;
        }
        return found;
    }
}
