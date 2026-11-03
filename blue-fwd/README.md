# BlueFwd – Windows Event → Syslog (TCP)

En Windows-tjänst (.NET 9) som prenumererar på konfigurerbara Windows-händelseloggar (t.ex. Sysmon,
Security, PowerShell) och skickar händelserna vidare som syslog över TCP (valfritt TLS) till en
konfigurerbar syslogserver. Tjänsten har ett inbyggt webbgränssnitt för konfiguration, status och statistik.

## Funktioner

- **Prenumerationer per kanal** med XPath-filter (eller en hel `<QueryList>`), t.ex.
  `*[System[(EventID=1 or EventID=3)]]` för Sysmon-processer och nätverksanslutningar.
- **Syslog över TCP**: RFC 5424 eller RFC 3164, framing med octet-counting (RFC 6587) eller radbrytning,
  valfri facility, appnamn och hostname, valfri TLS (även med osignerade certifikat).
- **Payload**: JSON (systemfält och `EventData`/`UserData` som nyckel/värde), rå händelse-XML
  eller den renderade meddelandetexten. I RFC 5424 läggs kanal, provider, eventId och recordId
  också i structured data (`[win@32473 …]`).
- **Leverans minst en gång (at-least-once)**: positionen (EventRecordID) sparas per prenumeration först
  när syslogservern har tagit emot händelsen. Efter en omstart fortsätter tjänsten där den slutade.
  När servern är nere stoppas läsningen i stället för att händelser kastas, och de oskickade händelserna
  ligger kvar i Windows-loggen.
- **Ändringar slår igenom direkt**: när konfigurationen sparas i webbgränssnittet startas bara de
  prenumerationer som ändrats om, och sändaren ansluter på nytt.
- **Automatiska nya försök**: en prenumeration som inte kan starta (t.ex. för att Sysmon inte är
  installerat än) provas igen var 30:e sekund.

## Webbgränssnitt

Standardadressen är `http://127.0.0.1:5080`, och gränssnittet nås bara från den lokala maskinen.

- **Overview**: anslutningsstatus, händelser/s, köns fyllnadsgrad, fel och en tabell per prenumeration
  (mottagna, vidarebefordrade, tappade, fel, senaste händelse och sparad position).
- **Configuration**: syslogservern samt prenumerationerna, med färdiga mallar för Sysmon,
  Security-inloggningar och PowerShell. Här finns också kanalförslag, knappen "Test channel"
  och knappen "Send test message".
- **Live events**: de senaste 100 händelserna, som kan fällas ut.

Vill du nå gränssnittet från andra maskiner ändrar du `Urls` i `appsettings.json`, t.ex. till
`http://0.0.0.0:5080`. Sätt i så fall också `BlueFwd:ApiKey`. Då kräver API:et headern `X-Api-Key`,
och webbgränssnittet frågar efter nyckeln.

## Bygga och installera

```powershell
# Bygg (kräver .NET 9 SDK)
.\scripts\publish.ps1                    # kräver ASP.NET Core 9-runtime på målmaskinen
.\scripts\publish.ps1 -SelfContained     # fristående exe, ingen runtime krävs

# Installera som tjänst (som administratör)
.\scripts\install.ps1

# Avinstallera
.\scripts\uninstall.ps1 [-RemoveFiles] [-RemoveData]
```

Tjänsten heter `BlueFwd`, körs som LocalSystem (som behövs för att läsa Security-loggen), startar
automatiskt och startas om om processen dör.

## Filer

| Fil | Innehåll |
| --- | --- |
| `%ProgramFiles%\BlueFwd\appsettings.json` | Statiska inställningar: `Urls`, `BlueFwd:DataDirectory`, `BlueFwd:QueueCapacity`, `BlueFwd:ApiKey`, loggnivåer. Ändringar kräver omstart. |
| `%ProgramData%\BlueFwd\config.json` | Syslogserver och prenumerationer, som redigeras i webbgränssnittet. |
| `%ProgramData%\BlueFwd\positions.json` | Senast skickade EventRecordID per prenumeration. |

Tjänstens egna loggar skrivs till Application-loggen med källan `BlueFwd`.

## Köra lokalt (utveckling)

```powershell
cd src\BlueFwd.Service
dotnet run
```

I Development-läge sparas data i `src\BlueFwd.Service\data`.

## Exempel på meddelande (RFC 5424, octet-counting)

```
1234 <134>1 2026-10-29T12:13:41.484071Z WS01 blue-fwd - 1 [win@32473 channel="Microsoft-Windows-Sysmon/Operational" provider="Microsoft-Windows-Sysmon" eventId="1" recordId="5512" subscription="Sysmon"] {"TimeCreated":"…","Computer":"WS01","Channel":"Microsoft-Windows-Sysmon/Operational","EventID":1,…,"EventData":{"Image":"C:\\Windows\\System32\\cmd.exe","CommandLine":"…",…}}
```

Syslog severity sätts utifrån händelsens nivå: Critical→2, Error→3, Warning→4, Information→6, Verbose→7.
Misslyckade granskningshändelser (audit failure) får severity 5.

## Att tänka på

- Prenumererar du på Application-loggen kommer även BlueFwds egna logghändelser med
  (källan `BlueFwd`, som registreras av `install.ps1`). Filtrera bort dem med en query vid behov:
  `*[System[Provider[@Name!='BlueFwd']]]`.
- Rotation av Windows-loggen styr hur länge tjänsten klarar sig utan syslogserver. Öka maxstorleken
  för t.ex. Sysmon-loggen om avbrotten kan bli långa.
