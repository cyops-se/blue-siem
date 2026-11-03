using System.Diagnostics.Eventing.Reader;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using BlueFwd.Service.Configuration;

namespace BlueFwd.Service.Pipeline;

/// <summary>Turns an <see cref="EventRecord"/> into an <see cref="OutgoingEvent"/>.</summary>
public static class EventFormatter
{
    private static readonly XNamespace EventNs = "http://schemas.microsoft.com/win/2004/08/events/event";
    // Syslog payloads are not HTML; keep non-ASCII text (å, ä, ö...) readable instead of \uXXXX escapes.
    private static readonly JsonSerializerOptions CompactJson = new()
    {
        WriteIndented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static OutgoingEvent Format(EventRecord record, SubscriptionConfig sub)
    {
        var xml = record.ToXml();
        var payload = sub.PayloadFormat switch
        {
            PayloadFormat.Xml => xml,
            PayloadFormat.Message => TryFormatDescription(record) ?? xml,
            _ => BuildJson(record, xml, sub.IncludeRenderedMessage),
        };

        var timestamp = record.TimeCreated is DateTime t
            ? new DateTimeOffset(t.ToUniversalTime(), TimeSpan.Zero)
            : DateTimeOffset.UtcNow;

        var structured = new List<KeyValuePair<string, string>>
        {
            new("channel", record.LogName ?? sub.Channel),
            new("provider", record.ProviderName ?? ""),
            new("eventId", record.Id.ToString()),
            new("recordId", record.RecordId?.ToString() ?? ""),
            new("subscription", sub.Name),
        };

        return new OutgoingEvent(
            sub.Id,
            record.RecordId,
            timestamp,
            MapSeverity(record),
            record.MachineName ?? Environment.MachineName,
            record.Id.ToString(),
            payload,
            structured);
    }

    private static string BuildJson(EventRecord record, string xml, bool includeMessage)
    {
        var obj = new JsonObject
        {
            ["TimeCreated"] = record.TimeCreated?.ToUniversalTime().ToString("o"),
            ["Computer"] = record.MachineName,
            ["Channel"] = record.LogName,
            ["Provider"] = record.ProviderName,
            ["EventID"] = record.Id,
            ["RecordID"] = record.RecordId,
            ["Level"] = LevelName(record.Level),
            ["Task"] = record.Task,
            ["Opcode"] = record.Opcode,
            ["Keywords"] = record.Keywords is long k ? $"0x{k:X}" : null,
            ["ProcessID"] = record.ProcessId,
            ["ThreadID"] = record.ThreadId,
            ["UserID"] = record.UserId?.Value,
        };

        var doc = XDocument.Parse(xml);
        var root = doc.Root;
        var eventData = root?.Element(EventNs + "EventData");
        if (eventData is not null)
            obj["EventData"] = ReadEventData(eventData);

        var userData = root?.Element(EventNs + "UserData")?.Elements().FirstOrDefault();
        if (userData is not null)
            obj["UserData"] = Flatten(userData);

        if (includeMessage && TryFormatDescription(record) is { } message)
            obj["Message"] = message;

        return obj.ToJsonString(CompactJson);
    }

    private static JsonObject ReadEventData(XElement eventData)
    {
        var result = new JsonObject();
        var index = 0;
        foreach (var data in eventData.Elements())
        {
            var name = data.Attribute("Name")?.Value;
            if (string.IsNullOrEmpty(name))
                name = data.Name.LocalName == "Data" ? $"Data{index}" : data.Name.LocalName;
            index++;

            // Keep the first value when a provider repeats a name.
            if (!result.ContainsKey(name))
                result[name] = data.Value;
        }
        return result;
    }

    private static JsonNode Flatten(XElement element)
    {
        if (!element.HasElements)
            return JsonValue.Create(element.Value)!;

        var obj = new JsonObject();
        foreach (var child in element.Elements())
        {
            var name = child.Name.LocalName;
            if (!obj.ContainsKey(name))
                obj[name] = Flatten(child);
        }
        return obj;
    }

    private static string? TryFormatDescription(EventRecord record)
    {
        try
        {
            return record.FormatDescription();
        }
        catch (EventLogException)
        {
            // Provider metadata missing (e.g. uninstalled provider); fall back to the raw data.
            return null;
        }
    }

    private static string? LevelName(byte? level) => level switch
    {
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        0 or 4 => "Information",
        5 => "Verbose",
        null => null,
        _ => level.ToString(),
    };

    /// <summary>Maps the Windows event level to a syslog severity.</summary>
    private static int MapSeverity(EventRecord record)
    {
        // Security log: audit failures are interesting even though their level is "Information".
        const long auditFailure = 0x0010000000000000;
        if (record.Keywords is long k && (k & auditFailure) != 0)
            return 5; // notice

        return record.Level switch
        {
            1 => 2, // critical
            2 => 3, // error
            3 => 4, // warning
            5 => 7, // debug
            _ => 6, // informational
        };
    }
}
