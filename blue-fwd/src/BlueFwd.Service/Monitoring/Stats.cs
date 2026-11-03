using System.Collections.Concurrent;
using BlueFwd.Service.Configuration;

namespace BlueFwd.Service.Monitoring;

public enum WatcherState { Stopped, Starting, Running, Error, Disabled }

/// <summary>Counters for one subscription. Updated concurrently from event log callbacks and the sender.</summary>
public sealed class SubscriptionStats(string id)
{
    private long _received, _queued, _forwarded, _dropped, _errors;
    private long _lastQueuedRecordId = -1;

    public string Id { get; } = id;
    public string Name { get; set; } = "";
    public string Channel { get; set; } = "";
    public WatcherState State { get; set; } = WatcherState.Stopped;
    public string? LastError { get; set; }
    public DateTimeOffset? LastErrorUtc { get; set; }
    public DateTimeOffset? LastEventUtc { get; set; }
    public DateTimeOffset? StartedUtc { get; set; }

    public long Received => Interlocked.Read(ref _received);
    public long Queued => Interlocked.Read(ref _queued);
    public long Forwarded => Interlocked.Read(ref _forwarded);
    public long Dropped => Interlocked.Read(ref _dropped);
    public long Errors => Interlocked.Read(ref _errors);

    /// <summary>Record id of the newest event handed to the queue (-1 = none since start).</summary>
    public long LastQueuedRecordId => Interlocked.Read(ref _lastQueuedRecordId);

    public void OnReceived() { Interlocked.Increment(ref _received); LastEventUtc = DateTimeOffset.UtcNow; }
    public void OnQueued(long? recordId)
    {
        Interlocked.Increment(ref _queued);
        if (recordId is long id) Interlocked.Exchange(ref _lastQueuedRecordId, id);
    }
    public void OnForwarded() => Interlocked.Increment(ref _forwarded);
    public void OnDropped() => Interlocked.Increment(ref _dropped);
    public void OnError(string message)
    {
        Interlocked.Increment(ref _errors);
        LastError = message;
        LastErrorUtc = DateTimeOffset.UtcNow;
    }
    public void ResetQueuedPosition() => Interlocked.Exchange(ref _lastQueuedRecordId, -1);
}

public sealed class SenderStats
{
    private long _sent, _bytes, _errors, _connects;

    public bool Connected { get; set; }
    public string? Endpoint { get; set; }
    public DateTimeOffset? ConnectedSinceUtc { get; set; }
    public DateTimeOffset? LastSendUtc { get; set; }
    public string? LastError { get; set; }
    public DateTimeOffset? LastErrorUtc { get; set; }

    public long Sent => Interlocked.Read(ref _sent);
    public long BytesSent => Interlocked.Read(ref _bytes);
    public long Errors => Interlocked.Read(ref _errors);
    public long Connects => Interlocked.Read(ref _connects);

    public void OnSent(int count, long bytes)
    {
        Interlocked.Add(ref _sent, count);
        Interlocked.Add(ref _bytes, bytes);
        LastSendUtc = DateTimeOffset.UtcNow;
    }
    public void OnConnected(string endpoint)
    {
        Interlocked.Increment(ref _connects);
        Connected = true;
        Endpoint = endpoint;
        ConnectedSinceUtc = DateTimeOffset.UtcNow;
    }
    public void OnError(string message)
    {
        Interlocked.Increment(ref _errors);
        Connected = false;
        LastError = message;
        LastErrorUtc = DateTimeOffset.UtcNow;
    }
}

public sealed record RecentEvent(DateTimeOffset ReceivedUtc, string Subscription, string EventId, string Preview);

/// <summary>Central place for all runtime statistics shown in the web UI.</summary>
public sealed class StatsRegistry
{
    private const int RecentCapacity = 100;
    private readonly ConcurrentDictionary<string, SubscriptionStats> _subscriptions = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<RecentEvent> _recent = new();

    public DateTimeOffset StartedUtc { get; } = DateTimeOffset.UtcNow;
    public SenderStats Sender { get; } = new();

    public SubscriptionStats? Find(string id) => _subscriptions.GetValueOrDefault(id);

    public SubscriptionStats For(SubscriptionConfig sub)
    {
        var stats = _subscriptions.GetOrAdd(sub.Id, id => new SubscriptionStats(id));
        stats.Name = sub.Name;
        stats.Channel = sub.Channel;
        return stats;
    }

    /// <summary>Drops statistics for subscriptions that no longer exist and returns the rest in config order.</summary>
    public IReadOnlyList<SubscriptionStats> Sync(ForwarderConfig config)
    {
        var keep = config.Subscriptions.Select(s => s.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var id in _subscriptions.Keys.Where(k => !keep.Contains(k)))
            _subscriptions.TryRemove(id, out _);
        return config.Subscriptions.Select(For).ToList();
    }

    public IReadOnlyList<SubscriptionStats> Subscriptions(ForwarderConfig config) =>
        config.Subscriptions.Select(s => _subscriptions.GetValueOrDefault(s.Id)).OfType<SubscriptionStats>().ToList();

    public void AddRecent(RecentEvent ev)
    {
        _recent.Enqueue(ev);
        while (_recent.Count > RecentCapacity && _recent.TryDequeue(out _)) { }
    }

    public IReadOnlyList<RecentEvent> Recent() => _recent.Reverse().ToList();
}
