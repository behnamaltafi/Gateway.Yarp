using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using MMLib.OpenApiForYarp;
using MMLib.OpenApiForYarp.Configuration;
using Yarp.ReverseProxy.Configuration;

namespace Aneiang.Yarp.OpenApi;

/// <summary>The live opt-in documentation catalog. It never registers a proxy configuration provider.</summary>
public sealed class AneiangOpenApiCatalog(
    IEnumerable<IProxyConfigProvider> providers,
    IOptionsMonitor<YarpOpenApiOptions> options,
    IHttpContextAccessor accessor) : IClusterDocumentSource
{
    internal static readonly object RequestSnapshotKey = new();
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };

    internal CatalogSnapshot Capture()
    {
        var configs = providers.Select(p => p.GetConfig()).ToArray();
        var root = options.CurrentValue;
        var effective = new YarpOpenApiOptions
        {
            CacheDuration = root.CacheDuration,
            FetchTimeout = root.FetchTimeout,
            DocumentRoutePattern = root.DocumentRoutePattern,
            MergeDocuments = root.MergeDocuments,
            MergedDocument = root.MergedDocument
        };
        var clusters = configs.SelectMany(c => c.Clusters)
            .GroupBy(c => c.ClusterId, StringComparer.OrdinalIgnoreCase).Select(g => g.Last()).ToArray();
        foreach (var cluster in clusters)
        {
            var enabled = root.Clusters.ContainsKey(cluster.ClusterId);
            if (cluster.Metadata?.TryGetValue("OpenApi.Enabled", out var flag) == true)
                enabled = bool.TryParse(flag, out var value) && value;
            if (!enabled) continue;
            var settings = root.Clusters.TryGetValue(cluster.ClusterId, out var configured)
                ? configured : new YarpOpenApiClusterOptions();
            // One JSON value uses the upstream model and survives native cluster editing/storage/rollback.
            if (cluster.Metadata?.TryGetValue("OpenApi.Settings", out var json) == true)
                settings = JsonSerializer.Deserialize<YarpOpenApiClusterOptions>(json, Json)
                    ?? throw new InvalidOperationException("Invalid OpenApi.Settings metadata.");
            if (!settings.OpenApiPath.StartsWith('/') || settings.OpenApiPath.StartsWith("//") ||
                settings.OpenApiPath.IndexOfAny(['?', '#', '\\']) >= 0)
                throw new InvalidOperationException("OpenApiPath must be a local absolute path without credentials or query strings.");
            foreach (var destination in cluster.Destinations?.Values ?? [])
                if (!Uri.TryCreate(destination.Address, UriKind.Absolute, out var uri) ||
                    !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
                    throw new InvalidOperationException("Documentation destinations must not contain embedded credentials, queries or fragments.");
            effective.Clusters[cluster.ClusterId] = settings;
        }
        return new(configs, root, effective, clusters);
    }

    internal CatalogSnapshot Current => accessor.HttpContext?.Items[RequestSnapshotKey] as CatalogSnapshot ?? Capture();

    public IReadOnlyList<ClusterDocumentInfo> GetDocuments()
    {
        var snapshot = Current;
        return snapshot.Options.Clusters.OrderBy(c => c.Key, StringComparer.OrdinalIgnoreCase)
            .Select(c => new ClusterDocumentInfo(c.Key, c.Value.Title ?? c.Key,
                snapshot.Options.GetDocumentRoute(Uri.EscapeDataString(c.Key)))).ToArray();
    }
    public bool MergeEnabled => Current.Options.MergeDocuments;
    public ClusterDocumentInfo? MergedDocument => MergeEnabled
        ? new(Current.Options.MergedDocument.DocumentName, Current.Options.MergedDocument.Title,
            Current.Options.MergedDocument.RoutePattern) : null;
}

internal sealed record CatalogSnapshot(IProxyConfig[] Configs, YarpOpenApiOptions Root,
    YarpOpenApiOptions Options, ClusterConfig[] Clusters);

// MMLib resolves this facade on every build; options monitoring remains owned by ASP.NET Core.
internal sealed class LiveOpenApiOptions(AneiangOpenApiCatalog catalog) : IOptions<YarpOpenApiOptions>
{
    public YarpOpenApiOptions Value => catalog.Current.Options;
}
