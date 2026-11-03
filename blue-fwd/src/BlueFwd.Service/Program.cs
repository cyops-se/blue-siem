using System.Threading.Channels;
using BlueFwd.Service.Configuration;
using BlueFwd.Service.Monitoring;
using BlueFwd.Service.Pipeline;
using BlueFwd.Service.Web;
using Microsoft.Extensions.Hosting.WindowsServices;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    // Services start in System32; resolve appsettings.json and wwwroot next to the executable.
    ContentRootPath = WindowsServiceHelpers.IsWindowsService() ? AppContext.BaseDirectory : default,
});

builder.Services.AddWindowsService(o => o.ServiceName = "BlueFwd");

var serviceOptions = builder.Configuration.GetSection(ServiceOptions.SectionName).Get<ServiceOptions>() ?? new ServiceOptions();
builder.Services.Configure<ServiceOptions>(builder.Configuration.GetSection(ServiceOptions.SectionName));

builder.Services.ConfigureHttpJsonOptions(o => JsonDefaults.Configure(o.SerializerOptions));

builder.Services.AddSingleton<ConfigStore>();
builder.Services.AddSingleton<PositionStore>();
builder.Services.AddSingleton<StatsRegistry>();
builder.Services.AddSingleton(Channel.CreateBounded<OutgoingEvent>(new BoundedChannelOptions(Math.Max(100, serviceOptions.QueueCapacity))
{
    SingleReader = true,
    FullMode = BoundedChannelFullMode.Wait,
}));

builder.Services.AddHostedService<SyslogSender>();
builder.Services.AddHostedService<PipelineManager>();

var app = builder.Build();

app.UseApiKey(serviceOptions.ApiKey);
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapApi();

app.Logger.LogInformation("BlueFwd data directory: {Path}", serviceOptions.ResolvedDataDirectory);
app.Run();
