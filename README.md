# Blue SIEM

[English](README.en.md) · **Svenska**

En enkel SIEM som tar emot syslog, avkodar meddelanden med konfigurerbara regex-regler,
sätter kritikalitet via mönstermatchning och skapar larm som måste kvitteras.

- **Backend:** Go, chi (REST), GORM + SQLite (ren Go, ingen CGO)
- **Frontend:** Vue 3 + Vuetify 3 + Tailwind, byggs in i Go-binären med `go:embed`
- **Live:** Server-Sent Events (`/api/stream`) för nya händelser och larm
- **Språk:** gränssnittet finns på svenska och engelska (väljs i verktygsfältet eller under Inställningar
  och sparas i webbläsaren; standard följer webbläsarens språk). Översättningarna ligger i
  `frontend/src/i18n.js`. Alla meddelanden från backend (fel, loggar) är på engelska, liksom
  standardavkodare och standardregler som skapas i en ny databas.

## Bygga och köra

```powershell
./build.ps1            # eller: make build
./blue-siem.exe        # webb-UI på http://localhost:8080, syslog på UDP/TCP 5514
```

| Flagga  | Miljövariabel     | Standard  | Beskrivning                     |
|---------|-------------------|-----------|---------------------------------|
| `-http` | `SIEM_HTTP`       | `:8080`   | Webbgränssnitt och REST-API     |
| `-udp`  | `SIEM_SYSLOG_UDP` | `:5514`   | Syslog UDP (tomt = av)          |
| `-tcp`  | `SIEM_SYSLOG_TCP` | `:5514`   | Syslog TCP (tomt = av)          |
| `-db`   | `SIEM_DB`         | `siem.db` | SQLite-fil                      |

Utveckling med hot reload: kör backend (`cd backend && go run .`) och `npm run dev` i `frontend/`.
Vite skickar `/api` vidare till `:8080`.

Skicka loggar från rsyslog: `*.* @siem-host:5514` (UDP) eller `*.* @@siem-host:5514` (TCP).

## Flöde

```
syslog (UDP/TCP) ─▶ parser (RFC3164/5424) ─▶ avkodare ─▶ kritikalitetsregler ─▶ lagring
                                                                         └─▶ larm om ≥ gräns
```

1. **Parser:** PRI, tidsstämpel, värd, program och pid. TCP stöder både octet-counting och radbrytning.
2. **Avkodare** provas i prioritetsordning, och den första som matchar vinner.
   - `regex`: Go/RE2-mönster med namngivna grupper, t.ex. `(?P<user>\S+)`. Varje grupp blir ett fält.
     Ett valfritt programfilter matchas mot `app_name`. Taggar läggs på vid träff.
   - `iptables`: inbyggd tolkning av netfilter LOG-rader. Fälten normaliseras till `src_ip`,
     `dst_ip`, `src_port`, `dst_port`, `proto`, `in_iface`, `out_iface` osv., plus `prefix`,
     `action` (DROP/ACCEPT/…), `direction`, `flags` och `class`.
3. **Klassning av iptables-trafik** (taggen `WHITE`, `BLACK` eller `GREY`). WHITE är betrodd trafik
   som tillåts, BLACK är kända hot som blockeras och GREY är okänd trafik som **tillåts men loggas och
   larmar** för granskning. Klassen avgörs så här:
   1. ordet WHITE/BLACK/GREY i log-prefixet (`--log-prefix "BLACK DROP: "`),
   2. `BLACK` om käll- eller måladressen finns på svartlistan,
   3. `WHITE` om källadressen finns på vitlistan,
   4. annars `GREY`.
4. **Kritikalitetsregler** (0–10): alla villkor (`fält ~ regex`, kan negeras) måste matcha.
   Händelsen får den högsta kritikaliteten bland matchande regler. En regel med *Stoppa* avbryter
   utvärderingen (används t.ex. för att WHITE-trafik aldrig ska larma).
   Fält: `message`, `raw`, `tags` (varje tagg för sig), `decoder`, `hostname`, `app_name`,
   `source_ip`, `syslog_severity`, `facility` och alla avkodade fält.
5. **Flöden:** all klassad iptables-trafik räknas i en flödestabell per timme, loggkälla (`hostname`, den
   värd som skickat loggen), klass, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto` och åtgärd. Vyn
   *Flöden* summerar räknarna. Vilka fält som grupperas går att välja, t.ex. utan `src_port` så att slumpade
   källportar slås ihop till ett flöde. Loggkällorna listas med antal flöden och händelser, och ett klick
   visar bara den källans flöden. Varje flöde kan ge en iptables-regel att kopiera, som sätts in överst
   och ger flödet samma verdikt (ACCEPT/DROP/REJECT) innan LOG-regeln nås, så att det inte längre loggas.
   Fält som varierar i flödet matchas inte, och källporten tas bara med om man väljer det. Värdena kommer
   från mottagna loggar och valideras strikt (IP, port, protokoll) innan de hamnar i kommandot.
   **Inlärningsläge** (växel i *Flöden* och *Inställningar*): klassad iptables-trafik räknas bara som
   flöden, och inga händelser eller larm skapas. Kritikaliteten beräknas ändå och visas som ”Max krit.”.
   Övriga meddelanden (ssh, sudo …) behandlas som vanligt. Flöden rensas enligt lagringstiden.
6. **Larm:** kritikalitet ≥ larmgränsen (standard 7) skapar ett larm som ligger kvar tills det
   kvitteras med namn och kommentar.

Exempel på brandväggsregler där GREY tillåts men loggas (bara nya anslutningar, så att inte varje
paket blir ett larm):

```sh
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m set --match-set blacklist src -j LOG --log-prefix "BLACK DROP: "
iptables -A INPUT -m set --match-set blacklist src -j DROP
iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate NEW -j LOG --log-prefix "GREY ACCEPT: "
iptables -A INPUT -j ACCEPT
```

Standardregler som skapas vid första start: BLACK → 9, GREY → 7 (larm), GREY mot känsliga portar → 8,
WHITE → 1 (stopp), misslyckad SSH-inloggning → 5, okänd användare → 6, root-inloggning → 7,
sudo med fel lösenord → 7, syslog emerg/alert/crit → 8.

## REST-API

| Metod | Sökväg | |
|---|---|---|
| GET | `/api/events?q=&tag=&decoder=&min_crit=&hours=&f.<fält>=&limit=&offset=` | Sök händelser (`f.src_ip=1.2.3.4` matchar ett avkodat fält exakt) |
| GET | `/api/events/{id}` | En händelse |
| GET | `/api/flows?group=&class=&hostname=&q=&hours=&sort=&order=&limit=&offset=` | iptables-flöden per klass och fältkombination |
| DELETE | `/api/flows` | Rensa alla flöden |
| DELETE | `/api/events` | Radera alla händelser och larm |
| GET | `/api/alarms?status=open\|acked\|all` | Larm |
| POST | `/api/alarms/{id}/ack` · `/api/alarms/ack` | Kvittera (`{user, comment}` resp. `{ids \| all, user, comment}`) |
| GET/POST/PUT/DELETE | `/api/decoders`, `/api/rules`, `/api/iplists` | Konfiguration |
| POST | `/api/decoders/test` | Testa en osparad avkodare (`{decoder, raw}`) |
| POST | `/api/test` | Analysera meddelanden utan att spara (`{raw, source_ip}`) |
| POST | `/api/ingest` | Lagra meddelanden som om de kommit via syslog |
| GET/PUT | `/api/settings` | Larmgräns, lagringstid och inlärningsläge (PUT ändrar bara angivna fält) |
| GET | `/api/stats?hours=24` | Statistik till översikten |
| GET | `/api/stream` | SSE-ström (`event`, `alarm`, `ack`, `cleared`, `flow`, `flows_cleared`, `settings`) |

## Tester

```
cd backend && go test ./...
```
