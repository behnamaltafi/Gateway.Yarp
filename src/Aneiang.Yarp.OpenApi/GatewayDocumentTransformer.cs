using Microsoft.OpenApi;
using MMLib.OpenApiForYarp.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Template;

namespace Aneiang.Yarp.OpenApi;

/// <summary>Applies gateway publication policy after MMLib's standard transformations.</summary>
internal sealed class GatewayDocumentTransformer(AneiangOpenApiCatalog catalog, IHttpContextAccessor accessor) : IOpenApiDocumentTransformer
{
    public Task TransformAsync(OpenApiDocument document, OpenApiDocumentTransformerContext context, CancellationToken cancellationToken)
    {
        if (!catalog.Current.Options.Clusters.ContainsKey(context.ClusterName))
        {
            // v1's merger enumerates every YARP cluster. An opted-out cluster contributes nothing,
            // including schemas and security definitions (not just an empty set of paths).
            document.Paths = [];
            document.Components = null;
            document.Security = null;
            document.Tags = null;
            document.Webhooks = null;
            document.Extensions = null;
        }
        // Root, path-item and operation servers can otherwise direct UI requests to the backend.
        document.Servers = [new OpenApiServer { Url = accessor.HttpContext?.Request.PathBase.Value is { Length: > 0 } pathBase ? pathBase : "/" }];
        foreach (var entry in document.Paths?.ToArray() ?? [])
        {
            var path = entry.Value;
            path.Servers?.Clear();
            foreach (var operation in path.Operations?.ToArray() ?? [])
            {
                // MMLib filters published paths; also honor the HTTP method restriction on routes.
                var published = context.Routes.Any(route =>
                    route.Match.Path != null && new TemplateMatcher(TemplateParser.Parse(route.Match.Path), new())
                        .TryMatch(entry.Key, new RouteValueDictionary()) &&
                    (route.Match.Methods == null || route.Match.Methods.Count == 0 ||
                     route.Match.Methods.Contains(operation.Key.Method, StringComparer.OrdinalIgnoreCase)));
                if (context.Options.AddOnlyPublishedPaths && !published) { path.Operations!.Remove(operation.Key); continue; }
                operation.Value.Security ??= document.Security;
                operation.Value.Servers?.Clear();
            }
            if (path.Operations?.Count == 0) document.Paths!.Remove(entry.Key);
        }
        if (document.Validate(ValidationRuleSet.GetDefaultRuleSet()).Any())
            throw new InvalidOperationException("Downstream OpenAPI document failed validation.");
        return Task.CompletedTask;
    }
}
