using System.Security.Cryptography;
using System.Text.Json;
using Aneiang.Yarp.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Yarp.ReverseProxy.Configuration;

namespace Aneiang.Yarp.Iam;

public static class IamRouteManifestExporter
{
    public static byte[] Export(IProxyConfig config)
    {
        // Export the actual single provider snapshot, not a second routing source or a list inferred from IAM policy.
        var unsupported = config.Routes.Where(r => r.Match.Headers?.Count > 0 || r.Match.QueryParameters?.Count > 0
            || string.IsNullOrWhiteSpace(r.ClusterId) || string.IsNullOrWhiteSpace(r.Match.Path)).ToArray();
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1,
            unsupportedRouteIds = unsupported.Select(r => r.RouteId).Order(StringComparer.Ordinal).ToArray(),
            routes = config.Routes.Except(unsupported).OrderBy(r => r.RouteId, StringComparer.Ordinal).Select(r => new
            {
                routeId = r.RouteId, clusterId = r.ClusterId, path = r.Match.Path,
                methods = r.Match.Methods?.Select(m => m.ToUpperInvariant()).ToArray() ?? [], hosts = r.Match.Hosts?.ToArray() ?? [],
                order = r.Order ?? 0, transforms = r.Transforms?.ToArray() ?? [], fingerprint = IamRouteFingerprint.Compute(r)
            }).ToArray()
        }, IamBundleWireProtocol.JsonOptions);
        if (bytes.Length > 1024 * 1024) throw new IamContractException("manifest_oversized");
        return bytes;
    }
    public static IEndpointConventionBuilder MapAneiangIamManifestExport(this IEndpointRouteBuilder endpoints)
        => endpoints.MapGet("/internal/v1/iam/route-manifest", (HttpContext context, AneiangProxyConfigProvider provider) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            var bytes = Export(provider.GetConfig());
            context.Response.Headers.ETag = '"' + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() + '"';
            return Results.Bytes(bytes, "application/json");
        }).RequireAuthorization("IamManifestExport");
}
