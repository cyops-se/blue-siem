namespace BlueFwd.Service.Pipeline;

/// <summary>
/// A formatted event waiting to be sent. The syslog header is built by the sender so that
/// target settings (format, facility, hostname...) changed in the UI apply to queued events too.
/// </summary>
/// <param name="SubscriptionId">Owning subscription, or null for messages that don't track a position (test messages).</param>
/// <param name="RecordId">Event log record id, used to persist the read position after a successful send.</param>
/// <param name="Severity">Syslog severity 0-7.</param>
/// <param name="Hostname">Computer that logged the event.</param>
/// <param name="MsgId">Syslog MSGID (the event id).</param>
/// <param name="StructuredData">Key/values for the RFC 5424 structured data element.</param>
public sealed record OutgoingEvent(
    string? SubscriptionId,
    long? RecordId,
    DateTimeOffset Timestamp,
    int Severity,
    string Hostname,
    string MsgId,
    string Payload,
    IReadOnlyList<KeyValuePair<string, string>> StructuredData);
