import { numberLocale, t } from './i18n'

// label is a getter so that it follows the selected language.
const level = (min, key, color, icon) => ({ min, color, icon, get label() { return t('crit.' + key) } })

export const critLevels = [
  level(9, 'critical', 'red-darken-1', 'mdi-alert-octagon'),
  level(7, 'high', 'deep-orange-darken-1', 'mdi-alert'),
  level(5, 'medium', 'amber-darken-3', 'mdi-alert-circle-outline'),
  level(3, 'low', 'blue-darken-1', 'mdi-information-outline'),
  level(1, 'info', 'blue-grey', 'mdi-information-variant'),
  level(0, 'none', 'grey-darken-1', 'mdi-circle-small'),
]

export function critInfo(n) {
  return critLevels.find((l) => n >= l.min) || critLevels[critLevels.length - 1]
}

export const syslogSeverities = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']

export const facilities = [
  'kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv',
  'ftp', 'ntp', 'audit', 'alert', 'clock', 'local0', 'local1', 'local2', 'local3', 'local4',
  'local5', 'local6', 'local7',
]

export const classes = ['WHITE', 'GREY', 'BLACK']

// hourOptions are the time windows offered by the event and flow views.
export function hourOptions() {
  return [
    { title: t('hours.all'), value: 0 },
    { title: t('hours.h1'), value: 1 },
    { title: t('hours.h24'), value: 24 },
    { title: t('hours.h168'), value: 168 },
  ]
}

export function fmtTime(s) {
  if (!s) return ''
  const d = new Date(s)
  if (isNaN(d)) return s
  return d.toLocaleString(numberLocale())
}

const translatedFields = ['message', 'raw', 'tags', 'decoder', 'app_name', 'source_ip', 'prefix']
const fieldHints = {
  syslog_severity: '0–7', facility: '0–23', class: 'WHITE/GREY/BLACK', action: 'DROP/ACCEPT/…',
  direction: 'inbound/outbound/forward',
}

// ruleFields returns the field suggestions for rule conditions in the
// current language.
export function ruleFields() {
  return ['message', 'raw', 'tags', 'decoder', 'hostname', 'app_name', 'source_ip', 'syslog_severity', 'facility', 'class',
    'action', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto', 'direction', 'in_iface', 'prefix', 'user'].map((value) => {
    const hint = translatedFields.includes(value) ? t('fields.' + value) : fieldHints[value]
    return { title: hint ? `${value} – ${hint}` : value, value }
  })
}

export const samples = [
  {
    label: 'iptables BLACK',
    raw: '<4>Oct 29 10:15:01 fw01 kernel: [86512.123456] BLACK DROP: IN=eth0 OUT= MAC=00:16:3e:aa:bb:cc:00:16:3e:11:22:33:08:00 SRC=185.220.101.4 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=4321 DF PROTO=TCP SPT=51234 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0',
  },
  {
    label: 'iptables GREY',
    raw: '<4>Oct 29 10:15:02 fw01 kernel: [86513.000001] GREY ACCEPT: IN=eth0 OUT= SRC=203.0.113.50 DST=192.168.1.10 LEN=44 TOS=0x00 PREC=0x00 TTL=240 ID=54321 PROTO=TCP SPT=44321 DPT=443 WINDOW=1024 RES=0x00 SYN URGP=0',
  },
  {
    label: 'iptables WHITE',
    raw: '<6>Oct 29 10:15:03 fw01 kernel: [86514.5] WHITE ACCEPT: IN=eth1 OUT=eth0 SRC=192.168.1.20 DST=1.1.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=1 DF PROTO=UDP SPT=53000 DPT=53 LEN=40',
  },
  {
    get label() { return t('samples.sshFailed') },
    raw: '<38>Oct 29 10:16:00 web01 sshd[2211]: Failed password for invalid user admin from 45.13.22.9 port 40022 ssh2',
  },
  {
    get label() { return t('samples.sshRoot') },
    raw: '<38>Oct 29 10:17:00 web01 sshd[2212]: Accepted publickey for root from 10.10.0.5 port 50122 ssh2',
  },
  {
    get label() { return t('samples.sudoBad') },
    raw: '<85>Oct 29 10:18:00 web01 sudo:     erik : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/erik ; USER=root ; COMMAND=/bin/bash',
  },
  {
    label: 'RFC 5424 crit',
    raw: '<130>1 2026-10-29T10:19:00.000Z db01 postgres 812 - - FATAL: could not write to file "pg_wal/xlogtemp.812": No space left on device',
  },
]
