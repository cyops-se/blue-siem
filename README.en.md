# Blue SIEM

**English** · [Svenska](README.md)

A simple SIEM that receives syslog, decodes messages with configurable regex rules,
sets criticality through pattern matching and raises alarms that must be acknowledged.

- **Backend:** Go, chi (REST), GORM + SQLite (pure Go, no CGO)
- **Frontend:** Vue 3 + Vuetify 3 + Tailwind, embedded in the Go binary with `go:embed`
- **Live:** Server-Sent Events (`/api/stream`) for new events and alarms
- **Language:** the UI is available in Swedish and English (chosen in the toolbar or under Settings
  and stored in the browser; the default follows the browser's language). The translations live in
  `frontend/src/i18n.js`. All messages from the backend (errors, logs) are in English, as are the
  default decoders and rules created in a new database.

## Building and running

```powershell
./build.ps1            # or: make build
./blue-siem.exe        # web UI on http://localhost:8080, syslog on UDP/TCP 5514
```

| Flag    | Environment variable | Default   | Description                  |
|---------|----------------------|-----------|------------------------------|
| `-http` | `SIEM_HTTP`          | `:8080`   | Web UI and REST API          |
| `-udp`  | `SIEM_SYSLOG_UDP`    | `:5514`   | Syslog UDP (empty = off)     |
| `-tcp`  | `SIEM_SYSLOG_TCP`    | `:5514`   | Syslog TCP (empty = off)     |
| `-db`   | `SIEM_DB`            | `siem.db` | SQLite file                  |

Development with hot reload: run the backend (`cd backend && go run .`) and `npm run dev` in `frontend/`.
Vite proxies `/api` to `:8080`.

Send logs from rsyslog: `*.* @siem-host:5514` (UDP) or `*.* @@siem-host:5514` (TCP).

## Pipeline

```
syslog (UDP/TCP) ─▶ parser (RFC3164/5424) ─▶ decoders ─▶ severity rules ─▶ storage
                                                                     └─▶ alarm if ≥ threshold
```

1. **Parser:** PRI, timestamp, host, program and pid. TCP supports both octet counting and newline framing.
2. **Decoders** are tried in priority order, and the first one that matches wins.
   - `regex`: Go/RE2 pattern with named groups, e.g. `(?P<user>\S+)`. Each group becomes a field.
     An optional program filter is matched against `app_name`. Tags are added on a match.
   - `iptables`: built-in parser for netfilter LOG lines. Fields are normalised to `src_ip`,
     `dst_ip`, `src_port`, `dst_port`, `proto`, `in_iface`, `out_iface` etc., plus `prefix`,
     `action` (DROP/ACCEPT/…), `direction`, `flags` and `class`.
   - `bluefwd`: built-in parser for Windows events from [blue-fwd](../blue-fwd) (app name `blue-fwd`,
     or `bluefwd` with RFC 3164). The structured data `[win@32473 …]` gives `channel`, `provider`,
     `event_id`, `record_id` and `subscription`. The JSON or XML payload gives the system fields (`computer`,
     `level`, `keywords`, `user_sid` …) and all `EventData`/`UserData` values under their own names (e.g.
     `Image`, `TargetUserName`). Common fields are also copied to the names other decoders use: `src_ip`,
     `dst_ip`, `src_port`, `dst_port`, `proto`, `user`, `image` and `command`. Tags: `windows`, `bluefwd`, the
     channel (`sysmon`, `security`, `powershell`, `system`, `application`) and `audit_failure`/`audit_success`.
     Messages without blue-fwd data are left to the next decoder. The decoder is also added to existing
     databases, once.
3. **Classification of iptables traffic** (the tag `WHITE`, `BLACK` or `GREY`). WHITE is trusted traffic
   that is allowed, BLACK is known threats that are blocked and GREY is unknown traffic that is
   **allowed but logged and raises alarms** for review. The class is decided as follows:
   1. the word WHITE/BLACK/GREY in the log prefix (`--log-prefix "BLACK DROP: "`),
   2. `BLACK` if the source or destination address is on the blacklist,
   3. `WHITE` if the source address is on the whitelist,
   4. otherwise `GREY`.
4. **Severity rules** (0–10): all conditions (`field ~ regex`, can be negated) must match.
   The event gets the highest criticality of the matching rules. A rule with *Stop* ends the
   evaluation (used e.g. so that WHITE traffic never raises an alarm).
   Fields: `message`, `raw`, `tags` (each tag separately), `decoder`, `hostname`, `app_name`,
   `source_ip`, `syslog_severity`, `facility` and all decoded fields.
5. **Flows:** all classified iptables traffic is counted in a flow table per hour, log source (`hostname`,
   the host that sent the log), class, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto` and action. The
   *Flows* view sums the counters. Which fields to group by can be chosen, e.g. without `src_port` so that
   random source ports merge into one flow. Log sources are listed with their number of flows and events,
   and a click shows only that source's flows. For grey (and white) flows, iptables rules are suggested
   for copying; they are inserted at the top of the chain, before the LOG rule for grey traffic. White
   traffic is never logged; black and grey always are:
   - *White – allow:* `-j ACCEPT` without logging.
   - *White – block:* `-j DROP` without logging, for known noise.
   - *Black:* `-j LOG --log-prefix "BLACK DROP: "` followed by `-j DROP` (positions 1 and 2), so the
     traffic is classified as BLACK and raises an alarm.

   Black flows get no suggestions, since they must always be logged. Fields that vary within the flow are
   not matched, and the source port is only included on request. The values come from received logs and
   are strictly validated (IP, port, protocol) before they end up in the command.
   **Learning mode** (toggle in *Flows* and *Settings*): classified iptables traffic is only counted as
   flows, and no events or alarms are created. The criticality is still computed and shown as “Max crit.”.
   Other messages (ssh, sudo …) are handled as usual. Flows are removed according to the retention time.
6. **Alarms:** criticality ≥ the alarm threshold (default 7) raises an alarm that remains until it is
   acknowledged with a name and a comment.
7. **Forwarding** (under *Settings*): events with a criticality ≥ a separate threshold (default 7) are
   sent to another syslog server over UDP or TCP (octet counting). Two modes:
   - *Original message:* the received line is sent unchanged, except that the severity in its PRI is
     replaced by the chosen one (default 2, `crit`). Facility, timestamp, host and text are kept.
   - *Alarm only:* a new RFC 5424 message that only states the alarm type (the rule that set the
     criticality), criticality, class and the instance name (default the computer's name), e.g.
     `<34>1 2026-11-02T10:00:00Z siem01 blue-siem - alarm - Blue SIEM alarm: rule="Blacklisted traffic (BLACK)" criticality=9 class=BLACK`.
     No sources, addresses, ports or host names are included.

   Sending happens on its own queue, so a slow or unreachable receiver does not affect ingestion;
   the number of sent, failed and dropped messages is shown in the settings. Traffic that is only
   counted as flows in learning mode is not forwarded. The instance's own syslog port on the local
   machine is refused as a receiver, since that would create a loop.

Example firewall rules where GREY is allowed but logged (new connections only, so that not every
packet becomes an alarm):

```sh
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m set --match-set blacklist src -j LOG --log-prefix "BLACK DROP: "
iptables -A INPUT -m set --match-set blacklist src -j DROP
iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate NEW -j LOG --log-prefix "GREY ACCEPT: "
iptables -A INPUT -j ACCEPT
```

Default rules created on first start: BLACK → 9, GREY → 7 (alarm), GREY to sensitive ports → 8,
WHITE → 1 (stop), failed SSH login → 5, unknown user → 6, root login → 7,
sudo with incorrect password → 7, syslog emerg/alert/crit → 8.

Rules for Windows events from blue-fwd (also added to existing databases, once):

| Event | Criticality |
|---|---|
| Failed logon (4625) | 5 |
| Account locked out (4740) | 7 (alarm) |
| Event log cleared (1102 Security, 104 System) | 8 (alarm) |
| User account created (4720) | 7 (alarm) |
| Member added to security group (4728/4732/4756) | 7 (alarm) |
| Service installed (7045/4697) | 6 |
| Scheduled task created (4698) | 6 |
| Event with a blacklisted address (`ip_list` = BLACK) | 9 (alarm) |
| Sysmon: outgoing connection to an unusual port (3, `Initiated` = true) | 4 |

Windows events are not classified as WHITE/GREY/BLACK, since the computer's own outgoing connections
would otherwise all be GREY and raise alarms. Instead the decoder checks `src_ip`/`dst_ip` against the
blacklist and sets `ip_list=BLACK` (and `ip_list_match`) on a match.

## REST API

| Method | Path | |
|---|---|---|
| GET | `/api/events?q=&tag=&decoder=&min_crit=&hours=&f.<field>=&limit=&offset=` | Search events (`f.src_ip=1.2.3.4` matches a decoded field exactly) |
| GET | `/api/events/{id}` | One event |
| GET | `/api/flows?group=&class=&hostname=&q=&hours=&sort=&order=&limit=&offset=` | iptables flows per class and field combination |
| DELETE | `/api/flows` | Clear all flows |
| DELETE | `/api/events` | Delete all events and alarms |
| GET | `/api/alarms?status=open\|acked\|all` | Alarms |
| POST | `/api/alarms/{id}/ack` · `/api/alarms/ack` | Acknowledge (`{user, comment}` and `{ids \| all, user, comment}` respectively) |
| GET/POST/PUT/DELETE | `/api/decoders`, `/api/rules`, `/api/iplists` | Configuration |
| POST | `/api/decoders/test` | Test an unsaved decoder (`{decoder, raw}`) |
| POST | `/api/test` | Analyse messages without storing them (`{raw, source_ip}`) |
| POST | `/api/ingest` | Store messages as if they had arrived over syslog |
| GET/PUT | `/api/settings` | Alarm threshold, retention, learning mode and forwarding (`forward`); PUT only changes the given fields |
| POST | `/api/forward/test` | Send a test message to the receiver (unsaved values in the body, empty = saved) |
| GET | `/api/stats?hours=24` | Statistics for the overview |
| GET | `/api/stream` | SSE stream (`event`, `alarm`, `ack`, `cleared`, `flow`, `flows_cleared`, `settings`) |

## Tests

```
cd backend && go test ./...
```
