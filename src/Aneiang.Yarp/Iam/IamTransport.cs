using System.Net;
using Microsoft.AspNetCore.Http;

namespace Aneiang.Yarp.Iam;

public static class IamTransport
{
    public static bool Allows(Uri? uri, bool localHttp) =>
        uri is { IsAbsoluteUri: true } && (uri.Scheme == Uri.UriSchemeHttps
            || localHttp && uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback);

    public static bool Allows(HttpContext context, bool localHttp) =>
        context.Request.IsHttps || localHttp && context.Request.Scheme == "http"
            && context.Connection.RemoteIpAddress is { } remote && IPAddress.IsLoopback(remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote)
            && context.Connection.LocalIpAddress is { } local && IPAddress.IsLoopback(local.IsIPv4MappedToIPv6 ? local.MapToIPv4() : local)
            && Uri.TryCreate("http://" + context.Request.Host, UriKind.Absolute, out var host) && host.IsLoopback;
}
