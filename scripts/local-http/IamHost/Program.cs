using Microsoft.EntityFrameworkCore;
using System.Text.Json.Serialization;
using IAM.Api.Controllers;
using IAM.Application.Authorization;
using IAM.Infrastructure.Authorization;
using IAM.Infrastructure.DataBase;
using IAM.Infrastructure.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Net;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddJsonFile(Environment.GetEnvironmentVariable("IAM_LOCAL_SETTINGS")!, optional: false);
var localHttp = builder.Environment.IsDevelopment() && builder.Configuration.GetValue<bool>("LocalHttp");
if (localHttp && builder.Configuration.GetSection("Kestrel:Endpoints").GetChildren().Any(endpoint =>
    !Uri.TryCreate(endpoint["Url"], UriKind.Absolute, out var uri) || !uri.IsLoopback))
    throw new InvalidOperationException("Local HTTP requires loopback listeners.");
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped(_ => new EntityFrameworkExtensions(null, builder.Configuration, null));
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("ApplicationDbContext")));
builder.Services.AddIamAuthorizationCore(builder.Configuration);
builder.Services.AddAuthentication("Bearer").AddJwtBearer(options =>
{
    options.Authority = builder.Configuration["Authentication:Authority"];
    options.Audience = builder.Configuration["Authentication:Audience"];
    options.MapInboundClaims = false;
    options.RequireHttpsMetadata = !localHttp;
    options.IncludeErrorDetails = false;
});
if (localHttp)
{
    builder.Services.Configure<JwtBearerOptions>(AuthorizationRegistration.InternalScheme, options => options.RequireHttpsMetadata = false);
    var callers = builder.Configuration.GetSection("InternalAuthentication:Callers").Get<TrustedGatewayCaller[]>() ?? [];
    builder.Services.AddAuthorization(options => options.AddPolicy(AuthorizationRegistration.InternalPolicy, policy =>
    {
        policy.AddAuthenticationSchemes(AuthorizationRegistration.InternalScheme).RequireAuthenticatedUser().RequireAssertion(context =>
        {
            if (context.Resource is not HttpContext http || http.Connection.RemoteIpAddress is not { } remote
                || !IPAddress.IsLoopback(remote) || http.Connection.LocalIpAddress is not { } local || !IPAddress.IsLoopback(local)
                || !Uri.TryCreate("http://" + http.Request.Host, UriKind.Absolute, out var host) || !host.IsLoopback)
                return false;
            var user = context.User;
            if (new[] { "iss", "sub", "azp", "client_id" }.Any(name => user.FindAll(name).Skip(1).Any())) return false;
            var client = user.FindFirst("client_id")?.Value;
            var azp = user.FindFirst("azp")?.Value;
            return (client is null || azp is null || client == azp) && callers.Any(c =>
                c.Issuer == user.FindFirst("iss")?.Value && c.Subject == user.FindFirst("sub")?.Value && c.ClientId == (client ?? azp));
        });
    }));
}
builder.Services.AddControllers().AddApplicationPart(typeof(AuthorizationAdminController).Assembly)
    .ConfigureApplicationPartManager(parts => parts.FeatureProviders.Add(new LocalControllers()))
    .AddJsonOptions(options => options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter()));
var app = builder.Build();
app.UseExceptionHandler(handler => handler.Run(context =>
{
    var error = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>()?.Error;
    if (error is IamAdminException known)
    {
        var status = known.Status;
        context.Response.StatusCode = status;
    }
    else context.Response.StatusCode = 500;
    return context.Response.WriteAsJsonAsync(new { status = context.Response.StatusCode });
}));
app.UseAuthentication();
app.UseAuthorization();
app.UseRequestTimeouts();
app.MapControllers();
app.MapGet("/health/live", () => Results.Ok());
app.Run();

sealed class LocalControllers : IApplicationFeatureProvider<ControllerFeature>
{
    public void PopulateFeature(IEnumerable<ApplicationPart> parts, ControllerFeature feature)
    {
        var allowed = new HashSet<string> { "AuthorizationAdminController", "EntitlementsController",
            "OperationCatalogController", "PoliciesController", "NavigationController", "InternalPolicyBundlesController" };
        foreach (var type in feature.Controllers.Where(type => !allowed.Contains(type.Name)).ToArray())
            feature.Controllers.Remove(type);
    }
}
