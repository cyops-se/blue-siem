using System.Globalization;
using System.Text;
using BlueFwd.Service.Configuration;

namespace BlueFwd.Service.Pipeline;

/// <summary>Builds framed syslog messages (RFC 5424 / RFC 3164 over RFC 6587 TCP framing).</summary>
public static class SyslogEncoder
{
    // 32473 is the example Private Enterprise Number reserved for documentation (RFC 5612).
    private const string SdId = "win@32473";

    public static byte[] Encode(OutgoingEvent ev, SyslogTargetConfig target)
    {
        var pri = target.Facility * 8 + Math.Clamp(ev.Severity, 0, 7);
        var hostname = string.IsNullOrWhiteSpace(target.Hostname) ? ev.Hostname : target.Hostname;

        var header = target.Format == SyslogFormat.Rfc3164
            ? Rfc3164Header(pri, ev, hostname, target)
            : Rfc5424Header(pri, ev, hostname, target);

        var payload = ev.Payload;
        if (target.Framing == SyslogFraming.NewLine)
            payload = payload.Replace("\r\n", " ").Replace('\n', ' ').Replace('\r', ' ');

        var headerBytes = Encoding.UTF8.GetBytes(header);
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        var payloadLength = Math.Min(payloadBytes.Length, Math.Max(0, target.MaxMessageBytes - headerBytes.Length));
        payloadLength = Utf8SafeLength(payloadBytes, payloadLength);

        var messageLength = headerBytes.Length + payloadLength;
        var prefix = target.Framing == SyslogFraming.OctetCounting
            ? Encoding.ASCII.GetBytes(messageLength.ToString(CultureInfo.InvariantCulture) + " ")
            : [];
        var suffixLength = target.Framing == SyslogFraming.NewLine ? 1 : 0;

        var buffer = new byte[prefix.Length + messageLength + suffixLength];
        prefix.CopyTo(buffer, 0);
        headerBytes.CopyTo(buffer, prefix.Length);
        Array.Copy(payloadBytes, 0, buffer, prefix.Length + headerBytes.Length, payloadLength);
        if (suffixLength == 1)
            buffer[^1] = (byte)'\n';
        return buffer;
    }

    private static string Rfc5424Header(int pri, OutgoingEvent ev, string hostname, SyslogTargetConfig target)
    {
        var sb = new StringBuilder(256);
        sb.Append('<').Append(pri).Append(">1 ");
        sb.Append(ev.Timestamp.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture)).Append(' ');
        sb.Append(HeaderField(hostname, 255)).Append(' ');
        sb.Append(HeaderField(target.AppName, 48)).Append(' ');
        sb.Append("- ");
        sb.Append(HeaderField(ev.MsgId, 32)).Append(' ');

        if (target.IncludeStructuredData && ev.StructuredData.Count > 0)
        {
            sb.Append('[').Append(SdId);
            foreach (var (key, value) in ev.StructuredData)
            {
                if (string.IsNullOrEmpty(value)) continue;
                sb.Append(' ').Append(SdName(key)).Append("=\"").Append(EscapeSdValue(value)).Append('"');
            }
            sb.Append(']');
        }
        else
        {
            sb.Append('-');
        }

        sb.Append(' ');
        return sb.ToString();
    }

    private static string Rfc3164Header(int pri, OutgoingEvent ev, string hostname, SyslogTargetConfig target)
    {
        var local = ev.Timestamp.ToLocalTime();
        var month = local.ToString("MMM", CultureInfo.InvariantCulture);
        var day = local.Day.ToString(CultureInfo.InvariantCulture).PadLeft(2);
        var time = local.ToString("HH:mm:ss", CultureInfo.InvariantCulture);

        var tag = new string(target.AppName.Where(char.IsAsciiLetterOrDigit).Take(32).ToArray());
        if (tag.Length == 0) tag = "blue-fwd";

        return $"<{pri}>{month} {day} {time} {HeaderField(hostname, 255)} {tag}: ";
    }

    /// <summary>RFC 5424 header fields are PRINTUSASCII without spaces; "-" means nil.</summary>
    private static string HeaderField(string? value, int maxLength)
    {
        if (string.IsNullOrEmpty(value)) return "-";
        var chars = value.Select(c => c is > (char)32 and < (char)127 ? c : '_').Take(maxLength).ToArray();
        return new string(chars);
    }

    private static string SdName(string name) =>
        new(name.Where(c => c is > (char)32 and < (char)127 and not '=' and not ']' and not '"' and not ' ').Take(32).ToArray());

    private static string EscapeSdValue(string value) =>
        value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("]", "\\]");

    /// <summary>Backs off so a truncated buffer does not end in the middle of a UTF-8 sequence.</summary>
    private static int Utf8SafeLength(byte[] bytes, int length)
    {
        if (length >= bytes.Length) return bytes.Length;
        while (length > 0 && (bytes[length] & 0xC0) == 0x80)
            length--;
        return length;
    }
}
