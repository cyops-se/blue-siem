using System.Diagnostics.Eventing.Reader;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace BlueFwd.Service.Configuration;

/// <summary>Loads, validates, persists and publishes the runtime <see cref="ForwarderConfig"/>.</summary>
public sealed class ConfigStore
{
    private readonly string _path;
    private readonly ILogger<ConfigStore> _logger;
    private readonly Lock _lock = new();
    private ForwarderConfig _current;

    public event Action<ForwarderConfig>? Changed;

    public ConfigStore(IOptions<ServiceOptions> options, ILogger<ConfigStore> logger)
    {
        _path = options.Value.ConfigFile;
        _logger = logger;
        _current = LoadOrCreate();
    }

    public string FilePath => _path;

    public ForwarderConfig Current
    {
        get { lock (_lock) return _current; }
    }

    /// <summary>Validates, saves and publishes a new configuration.</summary>
    /// <returns>Validation errors; empty when the config was applied.</returns>
    public IReadOnlyList<string> TryUpdate(ForwarderConfig config)
    {
        Normalize(config);
        var errors = Validate(config);
        if (errors.Count > 0)
            return errors;

        lock (_lock)
        {
            Save(config);
            _current = config;
        }

        _logger.LogInformation("Configuration updated ({Count} subscriptions)", config.Subscriptions.Count);
        Changed?.Invoke(config);
        return errors;
    }

    public static List<string> Validate(ForwarderConfig config)
    {
        var errors = new List<string>();
        var s = config.Syslog;

        if (string.IsNullOrWhiteSpace(s.Host)) errors.Add("Syslog host is required.");
        if (s.Port is < 1 or > 65535) errors.Add("Syslog port must be 1-65535.");
        if (s.Facility is < 0 or > 23) errors.Add("Facility must be 0-23.");
        if (s.ReconnectDelaySeconds is < 1 or > 3600) errors.Add("Reconnect delay must be 1-3600 seconds.");
        if (s.MaxMessageBytes is < 480 or > 1_048_576) errors.Add("Max message size must be 480-1048576 bytes.");

        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var sub in config.Subscriptions)
        {
            var label = string.IsNullOrWhiteSpace(sub.Name) ? sub.Channel : sub.Name;
            if (string.IsNullOrWhiteSpace(sub.Name)) errors.Add("Every subscription needs a name.");
            if (string.IsNullOrWhiteSpace(sub.Channel)) errors.Add($"Subscription '{label}': channel is required.");
            if (!ids.Add(sub.Id)) errors.Add($"Subscription '{label}': duplicate id.");
        }

        return errors;
    }

    /// <summary>
    /// Checks that a channel exists and the query is accepted by the event log service.
    /// Returns null when OK, otherwise a human readable problem (used as a warning, not an error,
    /// because e.g. Sysmon may be installed after the forwarder).
    /// </summary>
    public static string? ProbeSubscription(SubscriptionConfig sub)
    {
        try
        {
            var query = new EventLogQuery(sub.Channel, PathType.LogName, EffectiveQuery(sub)) { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            using var _ = reader.ReadEvent(TimeSpan.FromSeconds(2));
            return null;
        }
        catch (EventLogNotFoundException)
        {
            return $"Channel '{sub.Channel}' was not found on this machine.";
        }
        catch (UnauthorizedAccessException)
        {
            return $"Access denied to channel '{sub.Channel}' (the service account needs read access).";
        }
        catch (EventLogException ex)
        {
            return $"Query for '{sub.Channel}' was rejected: {ex.Message}";
        }
    }

    public static string EffectiveQuery(SubscriptionConfig sub) =>
        string.IsNullOrWhiteSpace(sub.Query) ? "*" : sub.Query.Trim();

    private static void Normalize(ForwarderConfig config)
    {
        config.Syslog ??= new SyslogTargetConfig();
        config.Subscriptions ??= [];
        config.Syslog.Host = config.Syslog.Host?.Trim() ?? "";
        config.Syslog.Hostname = string.IsNullOrWhiteSpace(config.Syslog.Hostname) ? null : config.Syslog.Hostname.Trim();
        foreach (var sub in config.Subscriptions)
        {
            if (string.IsNullOrWhiteSpace(sub.Id)) sub.Id = Guid.NewGuid().ToString("N");
            sub.Name = sub.Name?.Trim() ?? "";
            sub.Channel = sub.Channel?.Trim() ?? "";
            sub.Query = EffectiveQuery(sub);
        }
    }

    private ForwarderConfig LoadOrCreate()
    {
        if (File.Exists(_path))
        {
            try
            {
                var loaded = JsonSerializer.Deserialize<ForwarderConfig>(File.ReadAllText(_path), JsonDefaults.Options)
                             ?? ForwarderConfig.CreateDefault();
                Normalize(loaded);
                foreach (var error in Validate(loaded))
                    _logger.LogWarning("Configuration problem in {Path}: {Error}", _path, error);
                return loaded;
            }
            catch (Exception ex)
            {
                // Keep the broken file for inspection and fall back to defaults so the UI stays reachable.
                var backup = _path + $".invalid-{DateTime.Now:yyyyMMddHHmmss}";
                _logger.LogError(ex, "Could not read {Path}; moved to {Backup} and using defaults", _path, backup);
                File.Move(_path, backup, overwrite: true);
            }
        }

        var config = ForwarderConfig.CreateDefault();
        Save(config);
        _logger.LogInformation("Created default configuration at {Path}", _path);
        return config;
    }

    private void Save(ForwarderConfig config)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(config, JsonDefaults.Options));
        File.Move(tmp, _path, overwrite: true);
    }
}
