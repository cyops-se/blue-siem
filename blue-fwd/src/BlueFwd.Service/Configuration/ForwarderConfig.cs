namespace BlueFwd.Service.Configuration;

public enum SyslogFormat { Rfc5424, Rfc3164 }

/// <summary>RFC 6587 framing used on the TCP stream.</summary>
public enum SyslogFraming { OctetCounting, NewLine }

/// <summary>How the event itself is rendered into the syslog MSG part.</summary>
public enum PayloadFormat { Json, Xml, Message }

/// <summary>
/// Runtime configuration that can be edited from the web UI. Persisted as JSON in the data directory.
/// Instances are treated as immutable once published by <see cref="ConfigStore"/>.
/// </summary>
public sealed class ForwarderConfig
{
    public SyslogTargetConfig Syslog { get; set; } = new();
    public List<SubscriptionConfig> Subscriptions { get; set; } = [];

    public static ForwarderConfig CreateDefault() => new()
    {
        Subscriptions =
        [
            new SubscriptionConfig
            {
                Name = "Sysmon",
                Channel = "Microsoft-Windows-Sysmon/Operational",
                Query = "*",
            },
        ],
    };
}

public sealed class SyslogTargetConfig
{
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 514;
    public bool UseTls { get; set; }
    public bool AllowUntrustedCertificate { get; set; }
    public SyslogFormat Format { get; set; } = SyslogFormat.Rfc5424;
    public SyslogFraming Framing { get; set; } = SyslogFraming.OctetCounting;

    /// <summary>Syslog facility 0-23. 16 = local0.</summary>
    public int Facility { get; set; } = 16;

    public string AppName { get; set; } = "blue-fwd";

    /// <summary>Overrides the HOSTNAME field. Empty = the Computer field of the event.</summary>
    public string? Hostname { get; set; }

    public bool IncludeStructuredData { get; set; } = true;
    public int ReconnectDelaySeconds { get; set; } = 5;
    public int MaxMessageBytes { get; set; } = 65536;
}

public sealed class SubscriptionConfig
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "";
    public bool Enabled { get; set; } = true;

    /// <summary>Event log channel, e.g. "Security" or "Microsoft-Windows-Sysmon/Operational".</summary>
    public string Channel { get; set; } = "";

    /// <summary>XPath filter ("*" = everything), or a full &lt;QueryList&gt; XML query.</summary>
    public string Query { get; set; } = "*";

    public PayloadFormat PayloadFormat { get; set; } = PayloadFormat.Json;

    /// <summary>Adds the provider-rendered message text to JSON payloads (costs CPU per event).</summary>
    public bool IncludeRenderedMessage { get; set; }

    /// <summary>Continue after the last forwarded record when the service restarts.</summary>
    public bool ResumeFromLastPosition { get; set; } = true;

    /// <summary>When no position is stored, forward events already in the log instead of only new ones.</summary>
    public bool ReadExistingOnFirstStart { get; set; }
}
