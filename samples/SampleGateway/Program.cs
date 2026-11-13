using Aneiang.Yarp.Extensions;
using Aneiang.Yarp.Dashboard.Extensions;
using Aneiang.Yarp.Dashboard.Infrastructure.Deployment;
using Aneiang.Yarp.Storage.Sqlite;
using Microsoft.Extensions.Options;
using Serilog;
using Aneiang.Yarp.OpenApi;
using Aneiang.Yarp.Iam;
using System.Diagnostics;
using System.Text.Json;

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", Serilog.Events.LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.AspNetCore", Serilog.Events.LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.Hosting.Lifetime", Serilog.Events.LogEventLevel.Information)
    .MinimumLevel.Override("Microsoft.AspNetCore.Server.Kestrel", Serilog.Events.LogEventLevel.Information)
    .MinimumLevel.Override("Yarp.ReverseProxy", Serilog.Events.LogEventLevel.Information)
    .Enrich.FromLogContext()
    .WriteTo.Console(outputTemplate: "[Serilog] {Timestamp:HH:mm:ss} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
    .CreateLogger();

try
{
    Log.Information("Starting SampleGateway with Serilog...");
    
    var builder = WebApplication.CreateBuilder(args);
    var localSettings = Environment.GetEnvironmentVariable("IAM_LOCAL_SETTINGS");
    var visualStudioProfile = Environment.GetEnvironmentVariable("GATEWAY_VISUAL_STUDIO_LOCAL");
    var allowLocalHttp = builder.Environment.IsDevelopment() && visualStudioProfile is "http" or "http-direct";
    if (builder.Environment.IsDevelopment() && visualStudioProfile is "1" or "http")
    {
        var workspace = Path.GetFullPath(Path.Combine(builder.Environment.ContentRootPath, "..", ".."));
        var local = Path.Combine(workspace, ".gapcode", allowLocalHttp ? "sso-http" : "sso-local");
        localSettings = Path.Combine(local, "gateway.json");
        using var settings = JsonDocument.Parse(File.ReadAllText(Path.Combine(local, "settings.json")));
        Environment.SetEnvironmentVariable("GATEWAY_DASHBOARD_OIDC_CLIENT_SECRET",
            settings.RootElement.GetProperty("dashboardSecret").GetString());
        var dependencies = new ProcessStartInfo("pwsh") { UseShellExecute = false, CreateNoWindow = true };
        foreach (var argument in new[] { "-NoProfile", "-File", Path.Combine(workspace, "Start-LocalGateway.ps1"), "-DependenciesOnly" })
            dependencies.ArgumentList.Add(argument);
        if (allowLocalHttp) dependencies.ArgumentList.Add("-Http");
        using var startup = Process.Start(dependencies) ?? throw new InvalidOperationException("Could not start local IAM and Keycloak.");
        await startup.WaitForExitAsync();
        if (startup.ExitCode != 0)
            throw new InvalidOperationException("Local IAM or Keycloak did not start. Check the launcher output and Docker Desktop.");
    }
    if (!string.IsNullOrWhiteSpace(localSettings))
    {
        builder.Configuration.Sources.Clear();
        builder.Configuration.AddJsonFile(localSettings, optional: false, reloadOnChange: false).AddEnvironmentVariables().AddCommandLine(args);
    }
    if (!builder.Configuration.GetValue<bool>("Gateway:Dashboard:Sso:Enabled")
        || !builder.Configuration.GetValue<bool>("Gateway:Iam:Enabled"))
        throw new InvalidOperationException(
            "SampleGateway requires Keycloak SSO and IAM in every environment. Set Gateway:Dashboard:Sso:Enabled and Gateway:Iam:Enabled to true and configure both integrations. See docs/gateway-keycloak-sso-migration.md.");
    if (allowLocalHttp && builder.Configuration.GetSection("Kestrel:Endpoints").GetChildren().Any(endpoint =>
        !Uri.TryCreate(endpoint["Url"], UriKind.Absolute, out var address) || !address.IsLoopback))
        throw new InvalidOperationException("The local HTTP profile requires loopback listeners.");
    builder.Services.AddAneiangIamGateway(builder.Configuration, allowLocalHttp);
    builder.Services.AddAneiangDashboardSso(builder.Configuration, allowLocalHttp);

    // Replace default logger with Serilog
    builder.Host.UseSerilog();

    // Enable HTTP/2 on all endpoints (required for gRPC)
    // When Kestrel:Endpoints has 2+ entries, auto-injection of the +1 gRPC port is
    // skipped automatically, so role-based routing keeps working.
    if (string.IsNullOrWhiteSpace(localSettings)) builder.UseYarpKestrelAutoConfig();

    // Gateway: one-liner — auto-loads ReverseProxy routes/clusters + dynamic config
    builder.Services.AddAneiangYarp(proxy => proxy.AddAneiangOpenApi(), enableRegistration:false);

    // Storage backend: host app is responsible for choosing the storage implementation
    builder.Services.AddAneiangStorage();

    // Dashboard with Keycloak SSO and IAM management authorization.
    builder.Services.AddAneiangYarpDashboard();

    // Multi-port / split / proxy-only deployment support (optional, backward compatible)
    // Wires up deployment options, endpoint role resolver, validators, hot-reload, etc.
    builder.Services.AddAneiangYarpDeployment();
    builder.Services.AddAneiangOpenApiDashboard();

    // Optional: enable gRPC endpoint auth (shares Dashboard credentials by default)
    // builder.Services.AddGatewayApiAuth();

    var app = builder.Build();
    app.UseRouting();
    app.UseAneiangDashboardSsoCallbacks();
    app.UseAuthentication();
    app.UseCors();
    app.UseAuthorization();
    app.UseAneiangOpenApi();

    // Register Dashboard middleware + MapReverseProxy (mode-aware).
    // Deployment-aware routing and health-check middleware are mounted automatically when deployment services are registered.
    app.UseAneiangYarpDashboard(new DashboardApplicationBuilderExtensions.DashboardUseOptions
    {
        AutoUseAuthorization = false,
        AutoUseCors = false
    });

    app.MapControllers();
    app.MapAneiangIamManifestExport();
    app.MapAneiangYarpGrpc(); // gRPC GatewayRegistry service (HTTP/2)

    // Log startup summary
    var depOptions = app.Services.GetRequiredService<IOptions<DeploymentOptions>>().Value;
    var grpcEndpoint = depOptions.ResolvedEndpoints.FirstOrDefault(e =>
        e.EndpointName.Contains("grpc", StringComparison.OrdinalIgnoreCase));
    Console.WriteLine("======================================================");
    Console.WriteLine("  Internal gateway is running");
    Console.WriteLine($"  Mode:               {depOptions.Mode}");
    foreach (var ep in depOptions.ResolvedEndpoints)
        Console.WriteLine($"  Endpoint:           {ep.EndpointName} → {ep.IpAddress}:{ep.Port} ({ep.Role})");
    Console.WriteLine("  Dashboard:          /aneiang");
    Console.WriteLine("  Login:              Keycloak SSO");
    Console.WriteLine("  Credentials:        configured outside source control");
    Console.WriteLine("  Health:             /health, /ready, /live");
    Console.WriteLine("  API documentation:  /swagger, /scalar (Dashboard authentication)");
    Console.WriteLine("  Logger:             Serilog");
    Console.WriteLine(grpcEndpoint != null
        ? $"  gRPC:               HTTP/2 listening on {grpcEndpoint.IpAddress}:{grpcEndpoint.Port}"
        : "  gRPC:               HTTP/2 enabled");
    Console.WriteLine("======================================================");

    // Auto-launch browser in Development (only when not already opened by IDE).
    // Wait for ApplicationStarted so Kestrel has actually bound the ports.
    if (app.Environment.IsDevelopment()
        && Environment.GetEnvironmentVariable("ASPNETCORE_AUTO_BROWSER") != "0")
    {
        var dashboardEndpoint = depOptions.ResolvedEndpoints
            .FirstOrDefault(e => string.Equals(e.Role, "Dashboard", StringComparison.OrdinalIgnoreCase))
            ?? depOptions.ResolvedEndpoints.FirstOrDefault();
        if (dashboardEndpoint != null
            && Uri.TryCreate(builder.Configuration[$"Kestrel:Endpoints:{dashboardEndpoint.EndpointName}:Url"], UriKind.Absolute, out var endpointUrl)
            && endpointUrl.Scheme == Uri.UriSchemeHttps)
        {
            var host = dashboardEndpoint.IsPubliclyBound ? "localhost" : endpointUrl.Host;
            var prefix = app.Services.GetRequiredService<IOptions<Aneiang.Yarp.Dashboard.Infrastructure.DashboardOptions>>().Value.RoutePrefix.Trim('/');
            var dashUrl = new UriBuilder(Uri.UriSchemeHttps, host, endpointUrl.Port, "/" + prefix).Uri.AbsoluteUri;
            var lifetime = app.Services.GetRequiredService<Microsoft.Extensions.Hosting.IHostApplicationLifetime>();
            lifetime.ApplicationStarted.Register(() =>
            {
                try
                {
                    Log.Information("Opening browser at {Url}", dashUrl);
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = dashUrl,
                        UseShellExecute = true
                    });
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "Failed to auto-open browser at {Url}", dashUrl);
                }
            });
            Console.WriteLine($"  Browser:            will open {dashUrl} after Kestrel ready ...");
        }
    }

    Log.Information("Gateway started successfully (waiting for Kestrel to bind ports...)");
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Gateway terminated unexpectedly");
    Environment.ExitCode = 1;
}
finally
{
    Log.CloseAndFlush();
}
