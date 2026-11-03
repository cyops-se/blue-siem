using System.Text.Json;
using System.Threading.Channels;
using BlueFwd.Service.Configuration;
using BlueFwd.Service.Monitoring;

namespace BlueFwd.Service.Pipeline;

/// <summary>
/// Owns the <see cref="SubscriptionWatcher"/>s: starts them from the config, restarts only those that changed
/// when the config is edited, and retries watchers that failed (e.g. a channel that does not exist yet).
/// </summary>
public sealed class PipelineManager(
    ConfigStore configStore,
    Channel<OutgoingEvent> queue,
    PositionStore positions,
    StatsRegistry stats,
    ILogger<PipelineManager> logger) : BackgroundService
{
    private static readonly TimeSpan RetryInterval = TimeSpan.FromSeconds(30);

    private readonly Dictionary<string, SubscriptionWatcher> _watchers = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        configStore.Changed += Apply;
        try
        {
            Apply(configStore.Current);

            using var timer = new PeriodicTimer(RetryInterval);
            while (await timer.WaitForNextTickAsync(stoppingToken))
                RetryFailed();
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            configStore.Changed -= Apply;
            StopAll();
            positions.Flush();
        }
    }

    private void Apply(ForwarderConfig config)
    {
        lock (_lock)
        {
            stats.Sync(config);
            var wanted = config.Subscriptions.ToDictionary(s => s.Id, StringComparer.OrdinalIgnoreCase);

            foreach (var (id, watcher) in _watchers.ToList())
            {
                if (wanted.TryGetValue(id, out var sub) && sub.Enabled && SameSettings(sub, watcher.Config))
                    continue;

                watcher.Dispose();
                _watchers.Remove(id);

                if (sub is null)
                {
                    positions.Remove(id);
                }
                else if (!string.Equals(sub.Channel, watcher.Config.Channel, StringComparison.OrdinalIgnoreCase))
                {
                    // Record ids belong to a channel; a stored position is meaningless for another one.
                    positions.Remove(id);
                    stats.For(sub).ResetQueuedPosition();
                }
            }

            foreach (var sub in config.Subscriptions)
            {
                var subStats = stats.For(sub);
                if (!sub.Enabled)
                {
                    subStats.State = WatcherState.Disabled;
                    continue;
                }
                if (!_watchers.ContainsKey(sub.Id))
                    StartWatcher(sub, subStats);
            }
        }
    }

    private void StartWatcher(SubscriptionConfig sub, SubscriptionStats subStats)
    {
        long? resumeAfter = null;
        if (sub.ResumeFromLastPosition)
        {
            // Prefer what was already queued in this process (avoids duplicates when a watcher is restarted
            // while events are still waiting in the queue), otherwise what the sender confirmed last run.
            var queued = subStats.LastQueuedRecordId;
            resumeAfter = queued >= 0 ? queued : positions.Get(sub.Id);
        }

        var watcher = new SubscriptionWatcher(sub, queue.Writer, subStats, stats, logger);
        watcher.Start(resumeAfter);
        _watchers[sub.Id] = watcher;
    }

    private void RetryFailed()
    {
        lock (_lock)
        {
            foreach (var (id, watcher) in _watchers.ToList())
            {
                var subStats = stats.Find(id);
                if (subStats?.State != WatcherState.Error)
                    continue;

                logger.LogInformation("Retrying subscription {Name}", watcher.Config.Name);
                watcher.Dispose();
                _watchers.Remove(id);
                StartWatcher(watcher.Config, subStats);
            }
        }
    }

    private void StopAll()
    {
        lock (_lock)
        {
            foreach (var watcher in _watchers.Values)
                watcher.Dispose();
            _watchers.Clear();
        }
    }

    private static bool SameSettings(SubscriptionConfig a, SubscriptionConfig b) =>
        JsonSerializer.Serialize(a, JsonDefaults.Options) == JsonSerializer.Serialize(b, JsonDefaults.Options);
}
