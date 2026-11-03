using System.Diagnostics.Eventing.Reader;
using System.Threading.Channels;
using BlueFwd.Service.Configuration;
using BlueFwd.Service.Monitoring;

namespace BlueFwd.Service.Pipeline;

/// <summary>Push subscription on one event log channel that formats events and puts them on the send queue.</summary>
public sealed class SubscriptionWatcher : IDisposable
{
    private const int PreviewLength = 400;

    private readonly SubscriptionConfig _config;
    private readonly ChannelWriter<OutgoingEvent> _queue;
    private readonly SubscriptionStats _stats;
    private readonly StatsRegistry _registry;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _cts = new();
    private EventLogWatcher? _watcher;

    // Used when resuming without a bookmark: skip records that were already forwarded.
    private long _skipUpTo = -1;

    public SubscriptionWatcher(SubscriptionConfig config, ChannelWriter<OutgoingEvent> queue,
        SubscriptionStats stats, StatsRegistry registry, ILogger logger)
    {
        _config = config;
        _queue = queue;
        _stats = stats;
        _registry = registry;
        _logger = logger;
    }

    public SubscriptionConfig Config => _config;

    /// <param name="resumeAfterRecordId">Start after this record, or null to use <see cref="SubscriptionConfig.ReadExistingOnFirstStart"/>.</param>
    public void Start(long? resumeAfterRecordId)
    {
        _stats.State = WatcherState.Starting;
        try
        {
            // EventLogWatcher does not throw for a missing channel; it only reports it later via the callback.
            if (ConfigStore.ProbeSubscription(_config) is { } problem)
                throw new InvalidOperationException(problem);

            var query = new EventLogQuery(_config.Channel, PathType.LogName, ConfigStore.EffectiveQuery(_config));
            EventBookmark? bookmark = null;
            var readExisting = false;

            if (resumeAfterRecordId is long last)
            {
                bookmark = TryCreateBookmark(_config.Channel, last);
                if (bookmark is null)
                {
                    // Record not found (log rolled over or cleared): read what is there and filter.
                    readExisting = true;
                    _skipUpTo = last;
                }
                _logger.LogInformation("Subscription {Name}: resuming after record {RecordId} ({Mode})",
                    _config.Name, last, bookmark is null ? "scan" : "bookmark");
            }
            else
            {
                readExisting = _config.ReadExistingOnFirstStart;
            }

            _watcher = new EventLogWatcher(query, bookmark, readExisting);
            _watcher.EventRecordWritten += OnEventRecordWritten;
            _watcher.Enabled = true;

            _stats.State = WatcherState.Running;
            _stats.StartedUtc = DateTimeOffset.UtcNow;
            _stats.LastError = null;
            _logger.LogInformation("Subscription {Name} started on {Channel} (query: {Query})",
                _config.Name, _config.Channel, _config.Query);
        }
        catch (Exception ex)
        {
            _stats.State = WatcherState.Error;
            _stats.OnError(ex.Message);
            _logger.LogWarning("Subscription {Name} could not start on {Channel}: {Error}", _config.Name, _config.Channel, ex.Message);
            DisposeWatcher();
        }
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventException is not null)
        {
            // The subscription is usually unusable after this; Error makes PipelineManager restart it
            // from the last queued record.
            _stats.State = WatcherState.Error;
            _stats.OnError(e.EventException.Message);
            _logger.LogWarning(e.EventException, "Subscription {Name}: event log error", _config.Name);
            return;
        }

        using var record = e.EventRecord;
        if (record is null || _cts.IsCancellationRequested)
            return;

        if (_skipUpTo >= 0 && record.RecordId is long rid && rid <= _skipUpTo)
            return;

        _stats.OnReceived();

        OutgoingEvent ev;
        try
        {
            ev = EventFormatter.Format(record, _config);
        }
        catch (Exception ex)
        {
            _stats.OnError($"Format error: {ex.Message}");
            _logger.LogWarning(ex, "Subscription {Name}: could not format record {RecordId}", _config.Name, record.RecordId);
            return;
        }

        try
        {
            // Block (back-pressure) when the queue is full rather than dropping: unread events stay in the
            // event log, and the position store only advances once the syslog server has accepted them.
            if (!_queue.TryWrite(ev))
                _queue.WriteAsync(ev, _cts.Token).AsTask().GetAwaiter().GetResult();
            _stats.OnQueued(ev.RecordId);
        }
        catch (Exception ex) when (ex is OperationCanceledException or ChannelClosedException)
        {
            _stats.OnDropped();
            return;
        }

        _registry.AddRecent(new RecentEvent(DateTimeOffset.UtcNow, _config.Name, ev.MsgId,
            ev.Payload.Length > PreviewLength ? ev.Payload[..PreviewLength] + "…" : ev.Payload));
    }

    private static EventBookmark? TryCreateBookmark(string channel, long recordId)
    {
        // EventBookmark has no public constructor; obtain one by reading the bookmarked record itself.
        try
        {
            var query = new EventLogQuery(channel, PathType.LogName, $"*[System[EventRecordID={recordId}]]");
            using var reader = new EventLogReader(query);
            using var record = reader.ReadEvent();
            return record?.Bookmark;
        }
        catch (EventLogException)
        {
            return null;
        }
    }

    private void DisposeWatcher()
    {
        if (_watcher is null) return;
        try
        {
            _watcher.Enabled = false;
            _watcher.EventRecordWritten -= OnEventRecordWritten;
            _watcher.Dispose();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error while stopping watcher {Name}", _config.Name);
        }
        _watcher = null;
    }

    public void Dispose()
    {
        _cts.Cancel();
        DisposeWatcher();
        if (_stats.State != WatcherState.Error)
            _stats.State = WatcherState.Stopped;
        _cts.Dispose();
    }
}
