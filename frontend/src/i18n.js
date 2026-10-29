import { reactive } from 'vue'
import vuetify from './plugins/vuetify'

// Minimal i18n: t() reads the reactive locale, so templates and computed
// values that call it update when the language changes. Messages may contain
// {name} placeholders. Strings containing markup are only ever rendered with
// v-html when they and their parameters are static (never log data).

const messages = {
  sv: {
    common: {
      cancel: 'Avbryt', save: 'Spara', close: 'Stäng', copy: 'Kopiera', delete: 'Ta bort', edit: 'Redigera',
      refresh: 'Uppdatera', live: 'Live', clear: 'Rensa', add: 'Lägg till', enabled: 'Aktiv', prio: 'Prio',
      priority: 'Prioritet', name: 'Namn', description: 'Beskrivning', tags: 'Taggar', type: 'Typ', time: 'Tid',
      criticality: 'Kritikalitet', timeWindow: 'Tidsfönster', class: 'Klass', required: 'Krävs', language: 'Språk',
      show: 'Visa',
    },
    hours: { all: 'Allt', h1: 'Senaste timmen', h24: 'Senaste 24 h', h168: 'Senaste 7 dygn' },
    nav: {
      dashboard: 'Översikt', events: 'Händelser', flows: 'Flöden', alarms: 'Larm', decoders: 'Avkodare',
      rules: 'Kritikalitetsregler', iplists: 'IP-listor', test: 'Testa', testTitle: 'Testa meddelanden', settings: 'Inställningar',
    },
    app: {
      connected: 'Live', disconnected: 'Frånkopplad', openAlarms: '{n} okvitterade larm', toggleTheme: 'Byt tema',
      learning: 'Inlärningsläge', learningTitle: 'iptables-trafik räknas bara som flöden – inga händelser eller larm',
      newAlarm: 'Nytt larm ({crit} – {label}): {title}',
    },
    crit: { critical: 'Kritisk', high: 'Hög', medium: 'Medel', low: 'Låg', info: 'Info', none: 'Ingen' },
    fields: {
      message: 'meddelandetext', raw: 'hela råmeddelandet', tags: 'en tagg (t.ex. ^BLACK$)', decoder: 'avkodarens namn',
      app_name: 'program/tagg', source_ip: 'syslog-avsändare', prefix: 'iptables log-prefix',
    },
    samples: { sshFailed: 'SSH misslyckad', sshRoot: 'SSH root-inloggning', sudoBad: 'sudo fel lösenord' },
    event: {
      syslog: 'Syslog', received: 'Mottagen', timestamp: 'Tidsstämpel', sender: 'Avsändare', host: 'Värd', program: 'Program',
      format: 'Format', decoder: 'Avkodare', decodedFields: 'Avkodade fält', noFields: 'Inga fält avkodades.',
      classification: 'Klassning', alarm: 'Larm #{id}', matchedRules: 'Matchade regler', raw: 'Råmeddelande',
    },
    dashboard: {
      events24: 'Händelser 24 h', openAlarms: 'Okvitterade larm', alarms24: 'Larm 24 h', stored: 'Lagrade händelser',
      perHour: 'Händelser per timme, senaste 24 h', perHourAria: 'Händelser per timme, totalt {n}', events: 'händelser',
      highest: 'Högsta kritikalitet: {n} ({label})', now: 'nu', classes: 'iptables-klassning, 24 h', crit: 'Kritikalitet, 24 h',
      noEvents: 'Inga händelser.', topSources: 'Flest källadresser (src_ip), 24 h', address: 'Adress', count: 'Antal',
      max: 'Högsta', noData: 'Inga data.', byDecoder: 'Per avkodare, 24 h', noDecoder: '(ingen avkodare)',
    },
    events: {
      search: 'Sök (meddelande, värd, fält)', tag: 'Tagg', decoder: 'Avkodare', minCrit: 'Min. kritikalitet',
      deleteAll: 'Radera alla händelser och larm', fields: 'Fält', empty: '(tomt)', confirmTitle: 'Radera alla händelser?',
      confirmText: 'Alla lagrade händelser och larm tas bort permanent. Avkodare, regler, IP-listor och flöden påverkas inte.',
      deleteBtn: 'Radera', deleted: 'Alla händelser raderade', crit: 'Krit.', host: 'Värd', program: 'Program',
      message: 'Meddelande', noDecoder: '(ingen avkodare)', minCritItem: '≥ {min} ({label})',
    },
    alarms: {
      open: 'Okvitterade', acked: 'Kvitterade', all: 'Alla', ackSelected: 'Kvittera valda ({n})', ackAll: 'Kvittera alla',
      none: 'Inga larm 🎉', ack: 'Kvittera', rules: 'Regler: {rules}', eventGone: 'Händelsen har rensats bort.',
      ackAllTitle: 'Kvittera alla öppna larm', ackNTitle: 'Kvittera {n} larm', ackedBy: 'Kvitteras av',
      comment: 'Kommentar (åtgärd, orsak …)', acknowledged: '{n} larm kvitterade', alarm: 'Larm', status: 'Status',
    },
    decoders: {
      info: 'Avkodare provas i prioritetsordning (lägst först); den första som matchar tolkar meddelandet. Regex-avkodare använder Go/RE2-syntax med namngivna grupper, t.ex. <code>(?P&lt;user&gt;\\S+)</code>, och varje grupp blir ett fält. Avkodaren <b>iptables</b> är inbyggd: den tolkar netfilter-loggar och taggar dem <b>WHITE</b>, <b>BLACK</b> eller <b>GREY</b>.',
      title: 'Avkodare', new: 'Ny avkodare', allApps: 'alla', builtin: '(inbyggd tolkning)', editTitle: 'Redigera {name}',
      appFilter: 'Programfilter (regex mot app_name, valfritt)', appFilterCol: 'Programfilter', tagsOnMatch: 'Taggar som sätts vid träff',
      prefilter: 'Förfilter (regex mot meddelandet, valfritt)', pattern: 'Mönster (regex med namngivna grupper)', patternCol: 'Mönster',
      testTitle: 'Testa avkodaren (osparad)', samples: 'Exempelmeddelanden, ett per rad', test: 'Testa', noMatch: 'Ingen träff',
      messageWord: 'meddelande', typeRegex: 'regex – namngivna grupper', typeIptables: 'iptables – inbyggd',
      saved: 'Avkodaren sparad', confirmDelete: 'Ta bort avkodaren "{name}"?',
    },
    rules: {
      info: 'Reglerna utvärderas i prioritetsordning. En regel matchar när <b>alla</b> villkor matchar (regex mot fältet; ”negera” vänder villkoret). Händelsen får den <b>högsta</b> kritikaliteten bland matchande regler. ”Stoppa” avbryter utvärderingen när regeln matchar. Kritikalitet <b>≥ {threshold}</b> ger ett larm som måste kvitteras (ändras under Inställningar).',
      title: 'Kritikalitetsregler', new: 'Ny regel', conditions: 'Villkor', raisesAlarm: 'Ger larm', stops: 'Stoppar utvärderingen',
      stop: 'Stopp', copySuffix: ' (kopia)', editTitle: 'Redigera regel', conditionsTitle: 'Villkor (alla måste matcha)', field: 'Fält',
      regex: 'Regex', negate: 'Negera', addCondition: 'Lägg till villkor', alarmAt: 'Ger larm (gränsen är {n}).',
      belowAlarm: 'Under larmgränsen ({n}).', stopLabel: 'Stoppa vidare utvärdering vid träff', saved: 'Regeln sparad',
      confirmDelete: 'Ta bort regeln "{name}"?',
    },
    iplists: {
      info: '<b>WHITE</b> är betrodd trafik som tillåts, <b>BLACK</b> är kända hot som blockeras och <b>GREY</b> är okänd trafik som tillåts men loggas och larmar för granskning.<br />iptables-händelser klassas i denna ordning:<ol class="ml-5 list-decimal"><li>ett av orden <b>WHITE</b>, <b>BLACK</b> eller <b>GREY</b> i log-prefixet (<code>--log-prefix "BLACK DROP: "</code>),</li><li><b>BLACK</b> om käll- eller måladressen finns på svarta listan,</li><li><b>WHITE</b> om källadressen finns på vita listan,</li><li>annars <b>GREY</b>.</li></ol>Ändringar gäller nya händelser direkt.',
      black: 'Svartlista – kända hot', white: 'Vitlista – betrodda källor', count: '{n} st', cidr: 'IP eller nät (CIDR)',
      comment: 'Kommentar', empty: 'Listan är tom.',
    },
    test: {
      intro: 'Klistra in ett eller flera syslog-meddelanden (ett per rad). <b>Analysera</b> visar resultatet utan att spara. <b>Skicka in</b> lagrar meddelandena som om de tagits emot via syslog, så larm skapas på riktigt.',
      allSamples: 'Alla exempel', raw: 'Råa syslog-meddelanden', sourceIp: 'Avsändar-IP (valfri)', analyze: 'Analysera',
      ingest: 'Skicka in', flowOnly: 'Inlärningsläge: bara flöde', alarm: 'Larm (≥ {n})', noAlarm: 'Inget larm (gräns {n})',
      noDecoder: 'ingen avkodare', rules: 'Regler: {rules}', noRule: 'Ingen regel matchade',
      ingested: '{events} händelser lagrade, {alarms} larm skapade', ingestedFlows: ', {n} bara som flöden (inlärningsläge)',
    },
    settings: {
      alarms: 'Larm och lagring', threshold: 'Larmgräns',
      thresholdHelp: 'Händelser med kritikalitet på eller över gränsen skapar ett larm som måste kvitteras.',
      retention: 'Lagringstid (dygn, 0 = för alltid)',
      retentionHint: 'Kvitterade larm, händelser och flöden äldre än detta rensas varje timme. Händelser med öppna larm behålls.',
      learningHelp: 'Klassad iptables-trafik räknas bara som flöden (se Flöden) – inga händelser lagras och inga larm skapas. Övriga meddelanden behandlas som vanligt.',
      saved: 'Inställningarna sparade', receiving: 'Mottagning', syslogUdp: 'Syslog UDP', syslogTcp: 'Syslog TCP',
      disabled: 'avstängd', version: 'Version', interface: 'Gränssnitt',
      languageHelp: 'Språket sparas i den här webbläsaren. Meddelanden från servern är alltid på engelska.',
      iptablesTitle: 'iptables-loggning med klassning i prefixet',
      iptablesExample: 'iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n# BLACK – kända hot: logga och blockera\niptables -A INPUT -m set --match-set blacklist src -j LOG --log-prefix "BLACK DROP: "\niptables -A INPUT -m set --match-set blacklist src -j DROP\n# WHITE – betrodda: tillåt\niptables -A INPUT -s 192.168.1.0/24 -j LOG --log-prefix "WHITE ACCEPT: "\niptables -A INPUT -s 192.168.1.0/24 -j ACCEPT\n# GREY – okända: logga (ger larm) men tillåt\niptables -A INPUT -m conntrack --ctstate NEW -j LOG --log-prefix "GREY ACCEPT: "\niptables -A INPUT -j ACCEPT',
      iptablesNote: 'GREY loggas bara för nya anslutningar (<code>--ctstate NEW</code>), så att varje paket inte blir ett larm. Saknas klassning i prefixet används IP-listorna, annars blir trafiken GREY.',
    },
    learning: {
      on: 'Inlärningsläge på: iptables-trafik räknas bara som flöden',
      off: 'Inlärningsläge av: händelser och larm skapas igen',
    },
    flows: {
      learningOn: '<b class="text-warning">På.</b> Klassad iptables-trafik räknas bara som flöden – inga händelser lagras och inga larm skapas. ”Max krit.” visar vad trafiken skulle ha fått.',
      learningOff: 'Av. Trafiken räknas som flöden och ger dessutom händelser och larm enligt reglerna.',
      clear: 'Rensa flöden', showAllClasses: 'Visa alla klasser', showOnly: 'Visa bara {name}', flows: 'flöden', events: 'händelser',
      sources: 'Loggkällor', sourcesHelp: 'värdar som skickat brandväggsloggarna – klicka för att visa bara den källans flöden',
      noFlows: 'Inga flöden.', unknownSourceTitle: 'Flöden från före loggkällan registrerades', unknown: '(okänd)',
      sourceSummary: '{flows} flöden · {events} händelser', search: 'Sök (loggkälla, IP, port, protokoll)', groupBy: 'Gruppera på',
      distinct: '{n} olika', onlySource: 'Visa bara den här källan', ruleBtn: 'iptables-regel som slutar logga flödet',
      showEvents: 'Visa händelserna', allSuffix: ' (alla)', action: 'Åtgärd', count: 'Antal', maxCrit: 'Max krit.',
      firstSeen: 'Först sedd', lastSeen: 'Senast sedd',
      col: { hostname: 'Loggkälla', src_ip: 'Käll-IP', dst_ip: 'Mål-IP', src_port: 'Källport', dst_port: 'Målport', proto: 'Protokoll' },
      desc: { WHITE: 'betrodd', GREY: 'okänd, granskas', BLACK: 'känt hot' },
      ruleTitle: 'iptables-regel utan loggning',
      ruleIntro: 'Regeln sätts in överst i kedjan och ger flödet samma verdikt som förut, men innan LOG-regeln nås, så att flödet inte längre loggas. Fält som varierar i flödet matchas inte.',
      actionList: 'åtgärd {list}', runsOn: 'Körs på', manySources: 'flera loggkällor – {list}', chain: 'Kedja', target: 'Mål',
      matchSrcPort: 'Matcha källport', srcPortHint: 'Oftast en slumpad port – då matchar regeln bara en anslutning.',
      copied: 'Regeln kopierad', copyFailed: 'Kunde inte kopiera – markera texten och kopiera manuellt',
      clearTitle: 'Rensa alla flöden?', clearText: 'Alla flödesräknare tas bort, t.ex. för att börja om inlärningen. Händelser och larm påverkas inte.',
      cleared: 'Alla flöden rensade',
    },
    iptables: {
      unknownChain: 'Okänd kedja: {v}', unknownTarget: 'Okänt mål: {v}', srcIp: 'Käll-IP', dstIp: 'Mål-IP',
      invalidIp: '{label} är ingen giltig IP-adress: {v}', mixedIp: 'Käll- och mål-IP är olika IP-versioner.',
      invalidProto: 'Ogiltigt protokoll: {v}', srcPort: 'Källport', dstPort: 'Målport', invalidPort: '{label} är ingen giltig port: {v}',
      portsNeedProto: 'Portar kräver ett enda protokoll (tcp/udp). Gruppera på proto eller filtrera fram ett protokoll.',
      matchesAll: 'Regeln skulle matcha all trafik. Gruppera på minst en IP-adress eller protokoll.',
      varies: '{field} varierar i flödet ({n} olika) och matchas därför inte – regeln gäller alla värden.',
      blackAccept: 'Svartlistad trafik släpps in med ACCEPT.',
      acceptTop: 'Regeln sätts överst och accepterar innan senare regler (t.ex. svartlistan) prövas.',
    },
  },
  en: {
    common: {
      cancel: 'Cancel', save: 'Save', close: 'Close', copy: 'Copy', delete: 'Delete', edit: 'Edit',
      refresh: 'Refresh', live: 'Live', clear: 'Clear', add: 'Add', enabled: 'Enabled', prio: 'Prio',
      priority: 'Priority', name: 'Name', description: 'Description', tags: 'Tags', type: 'Type', time: 'Time',
      criticality: 'Criticality', timeWindow: 'Time window', class: 'Class', required: 'Required', language: 'Language',
      show: 'Show',
    },
    hours: { all: 'All', h1: 'Last hour', h24: 'Last 24 h', h168: 'Last 7 days' },
    nav: {
      dashboard: 'Overview', events: 'Events', flows: 'Flows', alarms: 'Alarms', decoders: 'Decoders',
      rules: 'Severity rules', iplists: 'IP lists', test: 'Test', testTitle: 'Test messages', settings: 'Settings',
    },
    app: {
      connected: 'Live', disconnected: 'Disconnected', openAlarms: '{n} unacknowledged alarms', toggleTheme: 'Toggle theme',
      learning: 'Learning mode', learningTitle: 'iptables traffic is only counted as flows – no events or alarms',
      newAlarm: 'New alarm ({crit} – {label}): {title}',
    },
    crit: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info', none: 'None' },
    fields: {
      message: 'message text', raw: 'the whole raw message', tags: 'a tag (e.g. ^BLACK$)', decoder: 'decoder name',
      app_name: 'program/tag', source_ip: 'syslog sender', prefix: 'iptables log prefix',
    },
    samples: { sshFailed: 'SSH failed', sshRoot: 'SSH root login', sudoBad: 'sudo wrong password' },
    event: {
      syslog: 'Syslog', received: 'Received', timestamp: 'Timestamp', sender: 'Sender', host: 'Host', program: 'Program',
      format: 'Format', decoder: 'Decoder', decodedFields: 'Decoded fields', noFields: 'No fields were decoded.',
      classification: 'Classification', alarm: 'Alarm #{id}', matchedRules: 'Matched rules', raw: 'Raw message',
    },
    dashboard: {
      events24: 'Events 24 h', openAlarms: 'Unacknowledged alarms', alarms24: 'Alarms 24 h', stored: 'Stored events',
      perHour: 'Events per hour, last 24 h', perHourAria: 'Events per hour, {n} in total', events: 'events',
      highest: 'Highest criticality: {n} ({label})', now: 'now', classes: 'iptables classification, 24 h', crit: 'Criticality, 24 h',
      noEvents: 'No events.', topSources: 'Top source addresses (src_ip), 24 h', address: 'Address', count: 'Count',
      max: 'Highest', noData: 'No data.', byDecoder: 'By decoder, 24 h', noDecoder: '(no decoder)',
    },
    events: {
      search: 'Search (message, host, fields)', tag: 'Tag', decoder: 'Decoder', minCrit: 'Min. criticality',
      deleteAll: 'Delete all events and alarms', fields: 'Fields', empty: '(empty)', confirmTitle: 'Delete all events?',
      confirmText: 'All stored events and alarms are permanently deleted. Decoders, rules, IP lists and flows are not affected.',
      deleteBtn: 'Delete', deleted: 'All events deleted', crit: 'Crit.', host: 'Host', program: 'Program',
      message: 'Message', noDecoder: '(no decoder)', minCritItem: '≥ {min} ({label})',
    },
    alarms: {
      open: 'Unacknowledged', acked: 'Acknowledged', all: 'All', ackSelected: 'Acknowledge selected ({n})', ackAll: 'Acknowledge all',
      none: 'No alarms 🎉', ack: 'Acknowledge', rules: 'Rules: {rules}', eventGone: 'The event has been removed.',
      ackAllTitle: 'Acknowledge all open alarms', ackNTitle: 'Acknowledge {n} alarms', ackedBy: 'Acknowledged by',
      comment: 'Comment (action, cause …)', acknowledged: '{n} alarms acknowledged', alarm: 'Alarm', status: 'Status',
    },
    decoders: {
      info: 'Decoders are tried in priority order (lowest first); the first one that matches parses the message. Regex decoders use Go/RE2 syntax with named groups, e.g. <code>(?P&lt;user&gt;\\S+)</code>, and each group becomes a field. The <b>iptables</b> decoder is built in: it parses netfilter logs and tags them <b>WHITE</b>, <b>BLACK</b> or <b>GREY</b>.',
      title: 'Decoders', new: 'New decoder', allApps: 'all', builtin: '(built-in parser)', editTitle: 'Edit {name}',
      appFilter: 'Program filter (regex on app_name, optional)', appFilterCol: 'Program filter', tagsOnMatch: 'Tags set on match',
      prefilter: 'Pre-filter (regex on the message, optional)', pattern: 'Pattern (regex with named groups)', patternCol: 'Pattern',
      testTitle: 'Test the decoder (unsaved)', samples: 'Sample messages, one per line', test: 'Test', noMatch: 'No match',
      messageWord: 'message', typeRegex: 'regex – named groups', typeIptables: 'iptables – built in',
      saved: 'Decoder saved', confirmDelete: 'Delete the decoder "{name}"?',
    },
    rules: {
      info: 'Rules are evaluated in priority order. A rule matches when <b>all</b> conditions match (regex on the field; “negate” inverts the condition). The event gets the <b>highest</b> criticality of the matching rules. “Stop” ends the evaluation when the rule matches. Criticality <b>≥ {threshold}</b> raises an alarm that must be acknowledged (change it under Settings).',
      title: 'Severity rules', new: 'New rule', conditions: 'Conditions', raisesAlarm: 'Raises an alarm', stops: 'Stops the evaluation',
      stop: 'Stop', copySuffix: ' (copy)', editTitle: 'Edit rule', conditionsTitle: 'Conditions (all must match)', field: 'Field',
      regex: 'Regex', negate: 'Negate', addCondition: 'Add condition', alarmAt: 'Raises an alarm (the threshold is {n}).',
      belowAlarm: 'Below the alarm threshold ({n}).', stopLabel: 'Stop further evaluation on match', saved: 'Rule saved',
      confirmDelete: 'Delete the rule "{name}"?',
    },
    iplists: {
      info: '<b>WHITE</b> is trusted traffic that is allowed, <b>BLACK</b> is known threats that are blocked and <b>GREY</b> is unknown traffic that is allowed but logged and raises alarms for review.<br />iptables events are classified in this order:<ol class="ml-5 list-decimal"><li>one of the words <b>WHITE</b>, <b>BLACK</b> or <b>GREY</b> in the log prefix (<code>--log-prefix "BLACK DROP: "</code>),</li><li><b>BLACK</b> if the source or destination address is on the black list,</li><li><b>WHITE</b> if the source address is on the white list,</li><li>otherwise <b>GREY</b>.</li></ol>Changes apply to new events immediately.',
      black: 'Blacklist – known threats', white: 'Whitelist – trusted sources', count: '{n} entries', cidr: 'IP or network (CIDR)',
      comment: 'Comment', empty: 'The list is empty.',
    },
    test: {
      intro: 'Paste one or more syslog messages (one per line). <b>Analyze</b> shows the result without storing anything. <b>Ingest</b> stores the messages as if they had been received over syslog, so alarms are raised for real.',
      allSamples: 'All samples', raw: 'Raw syslog messages', sourceIp: 'Sender IP (optional)', analyze: 'Analyze',
      ingest: 'Ingest', flowOnly: 'Learning mode: flow only', alarm: 'Alarm (≥ {n})', noAlarm: 'No alarm (threshold {n})',
      noDecoder: 'no decoder', rules: 'Rules: {rules}', noRule: 'No rule matched',
      ingested: '{events} events stored, {alarms} alarms raised', ingestedFlows: ', {n} only as flows (learning mode)',
    },
    settings: {
      alarms: 'Alarms and retention', threshold: 'Alarm threshold',
      thresholdHelp: 'Events with a criticality at or above the threshold raise an alarm that must be acknowledged.',
      retention: 'Retention (days, 0 = forever)',
      retentionHint: 'Acknowledged alarms, events and flows older than this are removed every hour. Events with open alarms are kept.',
      learningHelp: 'Classified iptables traffic is only counted as flows (see Flows) – no events are stored and no alarms are raised. Other messages are handled as usual.',
      saved: 'Settings saved', receiving: 'Receiving', syslogUdp: 'Syslog UDP', syslogTcp: 'Syslog TCP',
      disabled: 'disabled', version: 'Version', interface: 'Interface',
      languageHelp: 'The language is stored in this browser. Messages from the server are always in English.',
      iptablesTitle: 'iptables logging with classification in the prefix',
      iptablesExample: 'iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n# BLACK – known threats: log and block\niptables -A INPUT -m set --match-set blacklist src -j LOG --log-prefix "BLACK DROP: "\niptables -A INPUT -m set --match-set blacklist src -j DROP\n# WHITE – trusted: allow\niptables -A INPUT -s 192.168.1.0/24 -j LOG --log-prefix "WHITE ACCEPT: "\niptables -A INPUT -s 192.168.1.0/24 -j ACCEPT\n# GREY – unknown: log (raises an alarm) but allow\niptables -A INPUT -m conntrack --ctstate NEW -j LOG --log-prefix "GREY ACCEPT: "\niptables -A INPUT -j ACCEPT',
      iptablesNote: 'GREY is only logged for new connections (<code>--ctstate NEW</code>), so that not every packet becomes an alarm. Without a class in the prefix the IP lists are used, otherwise the traffic is GREY.',
    },
    learning: {
      on: 'Learning mode on: iptables traffic is only counted as flows',
      off: 'Learning mode off: events and alarms are raised again',
    },
    flows: {
      learningOn: '<b class="text-warning">On.</b> Classified iptables traffic is only counted as flows – no events are stored and no alarms are raised. “Max crit.” shows what the traffic would have got.',
      learningOff: 'Off. Traffic is counted as flows and also gives events and alarms according to the rules.',
      clear: 'Clear flows', showAllClasses: 'Show all classes', showOnly: 'Show only {name}', flows: 'flows', events: 'events',
      sources: 'Log sources', sourcesHelp: 'hosts that sent the firewall logs – click to show only that source’s flows',
      noFlows: 'No flows.', unknownSourceTitle: 'Flows from before the log source was recorded', unknown: '(unknown)',
      sourceSummary: '{flows} flows · {events} events', search: 'Search (log source, IP, port, protocol)', groupBy: 'Group by',
      distinct: '{n} distinct', onlySource: 'Show only this source', ruleBtn: 'iptables rule that stops logging the flow',
      showEvents: 'Show the events', allSuffix: ' (all)', action: 'Action', count: 'Count', maxCrit: 'Max crit.',
      firstSeen: 'First seen', lastSeen: 'Last seen',
      col: { hostname: 'Log source', src_ip: 'Source IP', dst_ip: 'Destination IP', src_port: 'Source port', dst_port: 'Destination port', proto: 'Protocol' },
      desc: { WHITE: 'trusted', GREY: 'unknown, review', BLACK: 'known threat' },
      ruleTitle: 'iptables rule without logging',
      ruleIntro: 'The rule is inserted at the top of the chain and gives the flow the same verdict as before, but before the LOG rule is reached, so the flow is no longer logged. Fields that vary within the flow are not matched.',
      actionList: 'action {list}', runsOn: 'Run on', manySources: 'several log sources – {list}', chain: 'Chain', target: 'Target',
      matchSrcPort: 'Match source port', srcPortHint: 'Usually a random port – the rule then only matches one connection.',
      copied: 'Rule copied', copyFailed: 'Could not copy – select the text and copy it manually',
      clearTitle: 'Clear all flows?', clearText: 'All flow counters are removed, e.g. to restart learning. Events and alarms are not affected.',
      cleared: 'All flows cleared',
    },
    iptables: {
      unknownChain: 'Unknown chain: {v}', unknownTarget: 'Unknown target: {v}', srcIp: 'Source IP', dstIp: 'Destination IP',
      invalidIp: '{label} is not a valid IP address: {v}', mixedIp: 'Source and destination IP are different IP versions.',
      invalidProto: 'Invalid protocol: {v}', srcPort: 'Source port', dstPort: 'Destination port', invalidPort: '{label} is not a valid port: {v}',
      portsNeedProto: 'Ports require a single protocol (tcp/udp). Group by proto or filter down to one protocol.',
      matchesAll: 'The rule would match all traffic. Group by at least one IP address or protocol.',
      varies: '{field} varies within the flow ({n} distinct) and is therefore not matched – the rule applies to all values.',
      blackAccept: 'Blacklisted traffic is let in with ACCEPT.',
      acceptTop: 'The rule is inserted at the top and accepts before later rules (e.g. the blacklist) are tried.',
    },
  },
}

export const locales = [
  { value: 'sv', title: 'Svenska' },
  { value: 'en', title: 'English' },
]

function initialLocale() {
  try {
    const stored = localStorage.getItem('locale')
    if (messages[stored]) return stored
  } catch {
    // storage unavailable
  }
  return (navigator.language || '').toLowerCase().startsWith('sv') ? 'sv' : 'en'
}

export const i18n = reactive({ locale: initialLocale() })

function lookup(dict, key) {
  return key.split('.').reduce((o, k) => (o == null ? undefined : o[k]), dict)
}

export function t(key, params) {
  const msg = lookup(messages[i18n.locale], key) ?? lookup(messages.en, key) ?? key
  if (!params) return msg
  return msg.replace(/\{(\w+)\}/g, (m, k) => (params[k] !== undefined ? String(params[k]) : m))
}

function applyLocale() {
  document.documentElement.lang = i18n.locale
  vuetify.locale.current.value = i18n.locale
}

export function setLocale(locale) {
  if (!messages[locale]) return
  i18n.locale = locale
  try {
    localStorage.setItem('locale', locale)
  } catch {
    // storage unavailable
  }
  applyLocale()
}

// numberLocale is the BCP 47 tag used for numbers and dates.
export function numberLocale() {
  return i18n.locale === 'sv' ? 'sv-SE' : 'en-GB'
}

export function fmtNum(n) {
  return Number(n || 0).toLocaleString(numberLocale())
}

applyLocale()
