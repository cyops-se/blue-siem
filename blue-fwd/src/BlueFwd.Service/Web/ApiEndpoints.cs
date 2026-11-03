using System.Diagnostics.Eventing.Reader;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using BlueFwd.Service.Configuration;
using BlueFwd.Service.Monitoring;
using BlueFwd.Service.Pipeline;
using Microsoft.Extensions.Options;

namespace BlueFwd.Service.Web;

public static class ApiEndpoints
{
    public sealed record TestMessageRequest(string? Message);

    public static void MapApi(this WebApplication app)
    {
        var api = app.MapGroup("/api");

        api.MapGet("/status", (ConfigStore config, StatsRegistry stats, PositionStore positions,
            Channel<OutgoingEvent> queue, IOptions<ServiceOptions> options) =>
        {
            var current = config.Current;
            var subscriptions = stats.Subscriptions(current).Select(s => new
            {
                s.Id,
                s.Name,
                s.Channel,
                State = s.State.ToString(),
                s.Received,
                s.Queued,
                s.Forwarded,
                s.Dropped,
                s.Errors,
                s.LastEventUtc,
                s.StartedUtc,
                s.LastError,
                s.LastErrorUtc,
                StoredPosition = positions.Get(s.Id),
            });

            return Results.Ok(new
            {
                Version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3),
                Machine = Environment.MachineName,
                stats.StartedUtc,
                UptimeSeconds = (long)(DateTimeOffset.UtcNow - stats.StartedUtc).TotalSeconds,
                DataDirectory = options.Value.ResolvedDataDirectory,
                Target = $"{current.Syslog.Host}:{current.Syslog.Port}",
                Queue = new { Length = queue.Reader.Count, Capacity = options.Value.QueueCapacity },
                Sender = stats.Sender,
                Subscriptions = subscriptions,
            });
        });

        api.MapGet("/config", (ConfigStore config) => Results.Ok(config.Current));

        api.MapPut("/config", (ForwarderConfig body, ConfigStore config) =>
        {
            var errors = config.TryUpdate(body);
            if (errors.Count > 0)
                return Results.BadRequest(new { Errors = errors });

            var warnings = body.Subscriptions
                .Where(s => s.Enabled)
                .Select(ConfigStore.ProbeSubscription)
                .OfType<string>()
                .ToList();
            return Results.Ok(new { Warnings = warnings });
        });

        api.MapPost("/subscriptions/probe", (SubscriptionConfig sub) =>
        {
            var problem = ConfigStore.ProbeSubscription(sub);
            return Results.Ok(new { Ok = problem is null, Message = problem ?? "Channel and query OK." });
        });

        api.MapGet("/channels", () =>
        {
            using var session = new EventLogSession();
            var names = session.GetLogNames().Order(StringComparer.OrdinalIgnoreCase).ToList();
            return Results.Ok(names);
        });

        api.MapGet("/recent", (StatsRegistry stats) => Results.Ok(stats.Recent()));

        api.MapPost("/test", (TestMessageRequest? body, Channel<OutgoingEvent> queue) =>
        {
            var text = string.IsNullOrWhiteSpace(body?.Message)
                ? $"blue-fwd test message from {Environment.MachineName} at {DateTimeOffset.Now:O}"
                : body.Message;
            var ev = new OutgoingEvent(null, null, DateTimeOffset.UtcNow, 6, Environment.MachineName, "TEST", text, []);
            return queue.Writer.TryWrite(ev)
                ? Results.Ok(new { Queued = true })
                : Results.Problem("The queue is full.", statusCode: 503);
        });
    }

    /// <summary>Requires the X-Api-Key header on /api when an API key is configured.</summary>
    public static void UseApiKey(this WebApplication app, string? apiKey)
    {
        if (string.IsNullOrEmpty(apiKey))
            return;

        var expected = Encoding.UTF8.GetBytes(apiKey);
        app.Use(async (context, next) =>
        {
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                var provided = Encoding.UTF8.GetBytes(context.Request.Headers["X-Api-Key"].ToString());
                if (!CryptographicOperations.FixedTimeEquals(provided, expected))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return;
                }
            }
            await next();
        });
    }
}
