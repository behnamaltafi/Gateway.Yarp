using System.Net;
using Microsoft.AspNetCore.Http;

namespace Aneiang.Yarp.OpenApi;

// MMLib v1 enumerates all clusters for merging. Prevent network requests for opted-out services.
internal sealed class DocumentationFetchHandler(IHttpContextAccessor accessor) : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var snapshot = accessor.HttpContext?.Items[AneiangOpenApiCatalog.RequestSnapshotKey] as CatalogSnapshot;
        var permitted = snapshot?.Clusters.Any(c =>
            snapshot.Options.Clusters.TryGetValue(c.ClusterId, out var settings) &&
            c.Destinations?.Values.Any(d =>
                Uri.TryCreate(d.Address.TrimEnd('/') + settings.OpenApiPath, UriKind.Absolute, out var uri) && uri == request.RequestUri) == true) == true;
        return permitted ? base.SendAsync(request, cancellationToken)
            : Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
