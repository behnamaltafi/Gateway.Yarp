using Microsoft.AspNetCore.Http;

namespace Aneiang.Yarp.OpenApi;

/// <summary>Access and visibility settings, bound from Gateway:OpenApi.</summary>
public sealed class AneiangOpenApiOptions
{
    public bool Enabled { get; set; }
    public bool SwaggerEnabled { get; set; } = true;
    public bool ScalarEnabled { get; set; } = true;
    public bool JsonEnabled { get; set; } = true;
    public string SwaggerPath { get; set; } = "/swagger";
    public string ScalarPath { get; set; } = "/scalar";
    public string CatalogPath { get; set; } = "/openapi/catalog";
    /// <summary>Anonymous access is permitted only in Development.</summary>
    public bool AllowAnonymousInDevelopment { get; set; }
    public string? AuthorizationPolicy { get; set; }
    /// <summary>Optional adapter to the host's existing authentication system.</summary>
    public Func<HttpContext, Task<bool>>? AuthorizeRequest { get; set; }
    /// <summary>Optional listener/role restriction, evaluated before authentication.</summary>
    public Func<HttpContext, bool>? IsAvailableOnEndpoint { get; set; }
    public int MaxClusters { get; set; } = 128;
    public long MaxDocumentBytes { get; set; } = 4 * 1024 * 1024;
}
