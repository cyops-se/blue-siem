namespace BlueFwd.Service.Configuration;

/// <summary>Static settings from appsettings.json (section "BlueFwd"). Changing these requires a restart.</summary>
public sealed class ServiceOptions
{
    public const string SectionName = "BlueFwd";

    public string DataDirectory { get; set; } = @"%ProgramData%\BlueFwd";

    /// <summary>Max number of events buffered between the event log watchers and the syslog sender.</summary>
    public int QueueCapacity { get; set; } = 20000;

    /// <summary>When set, all /api calls require the header "X-Api-Key" with this value.</summary>
    public string? ApiKey { get; set; }

    public string ResolvedDataDirectory => Path.GetFullPath(Environment.ExpandEnvironmentVariables(DataDirectory));
    public string ConfigFile => Path.Combine(ResolvedDataDirectory, "config.json");
    public string PositionsFile => Path.Combine(ResolvedDataDirectory, "positions.json");
}
