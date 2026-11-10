using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Yarp.ReverseProxy.Configuration;

namespace Aneiang.Yarp.Iam;

public static class IamRouteFingerprint
{
    public static string Compute(RouteConfig route)
    {
        ArgumentNullException.ThrowIfNull(route);
        var canonical = new
        {
            route.RouteId,
            route.ClusterId,
            Match = new
            {
                route.Match.Path,
                Hosts = route.Match.Hosts?.Order(StringComparer.Ordinal).ToArray(),
                Methods = route.Match.Methods?.Select(x => x.ToUpperInvariant()).Order(StringComparer.Ordinal).ToArray(),
                Headers = route.Match.Headers?.OrderBy(x => x.Name, StringComparer.Ordinal).ThenBy(x => x.Mode).Select(x => new
                {
                    x.Name, x.Mode, Values = x.Values?.Order(StringComparer.Ordinal).ToArray(), x.IsCaseSensitive
                }).ToArray(),
                QueryParameters = route.Match.QueryParameters?.OrderBy(x => x.Name, StringComparer.Ordinal).ThenBy(x => x.Mode).Select(x => new
                {
                    x.Name, x.Mode, Values = x.Values?.Order(StringComparer.Ordinal).ToArray(), x.IsCaseSensitive
                }).ToArray()
            },
            Transforms = route.Transforms?.Select(t => t.OrderBy(x => x.Key, StringComparer.Ordinal).ToArray()).ToArray()
        };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(canonical);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }
}
