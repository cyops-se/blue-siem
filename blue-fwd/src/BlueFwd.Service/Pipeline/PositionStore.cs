using System.Collections.Concurrent;
using System.Text.Json;
using BlueFwd.Service.Configuration;
using Microsoft.Extensions.Options;

namespace BlueFwd.Service.Pipeline;

/// <summary>
/// Remembers the record id of the last event that was successfully written to the syslog server,
/// per subscription, so forwarding can resume after a restart. Flushed to disk periodically.
/// </summary>
public sealed class PositionStore : IDisposable
{
    private readonly string _path;
    private readonly ILogger<PositionStore> _logger;
    private readonly ConcurrentDictionary<string, long> _positions;
    private readonly Timer _timer;
    private readonly Lock _saveLock = new();
    private int _dirty;

    public PositionStore(IOptions<ServiceOptions> options, ILogger<PositionStore> logger)
    {
        _path = options.Value.PositionsFile;
        _logger = logger;
        _positions = Load();
        _timer = new Timer(_ => Flush(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
    }

    public long? Get(string subscriptionId) =>
        _positions.TryGetValue(subscriptionId, out var id) ? id : null;

    public void Set(string subscriptionId, long recordId)
    {
        _positions[subscriptionId] = recordId;
        Volatile.Write(ref _dirty, 1);
    }

    public void Remove(string subscriptionId)
    {
        if (_positions.TryRemove(subscriptionId, out _))
            Volatile.Write(ref _dirty, 1);
    }

    public void Flush()
    {
        if (Interlocked.Exchange(ref _dirty, 0) == 0)
            return;

        lock (_saveLock)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                var tmp = _path + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(new Dictionary<string, long>(_positions), JsonDefaults.Options));
                File.Move(tmp, _path, overwrite: true);
            }
            catch (Exception ex)
            {
                Volatile.Write(ref _dirty, 1);
                _logger.LogWarning(ex, "Could not save positions to {Path}", _path);
            }
        }
    }

    public void Dispose()
    {
        _timer.Dispose();
        Flush();
    }

    private ConcurrentDictionary<string, long> Load()
    {
        try
        {
            if (File.Exists(_path))
            {
                var data = JsonSerializer.Deserialize<Dictionary<string, long>>(File.ReadAllText(_path), JsonDefaults.Options);
                if (data is not null)
                    return new ConcurrentDictionary<string, long>(data, StringComparer.OrdinalIgnoreCase);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read positions from {Path}; starting without stored positions", _path);
        }
        return new ConcurrentDictionary<string, long>(StringComparer.OrdinalIgnoreCase);
    }
}
