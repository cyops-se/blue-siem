// Suggests iptables rules for a GREY (or WHITE) flow: WHITE allow or WHITE
// block, which are not logged, or BLACK, which is always logged. The rules
// are inserted at the top of the chain, before the LOG rule that logs GREY
// traffic, so WHITE traffic stops being logged while BLACK gets its own LOG.
//
// Every value comes from received log lines, which anyone can spoof over
// syslog, and the commands are meant to be pasted into a root shell. Values
// are therefore only used when they are strictly valid; anything else is an
// error rather than being escaped.

import { t } from './i18n'

export const chains = ['INPUT', 'OUTPUT', 'FORWARD']
export const choices = ['white-allow', 'white-block', 'black']

// Must match the BLACK class word the decoder looks for in the prefix.
const blackPrefix = 'BLACK DROP: '

const portProtos = ['tcp', 'udp', 'udplite', 'sctp', 'dccp']

// single returns the field's value when the whole flow has the same one.
function single(flow, f) {
  const n = flow['n_' + f]
  return n === undefined || n === 1 ? flow[f] || '' : ''
}

function ipVersion(ip) {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (m) return m.slice(1).every((o) => Number(o) <= 255) ? 4 : 0
  return /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':') && ip.length <= 39 ? 6 : 0
}

function validPort(p) {
  return /^\d{1,5}$/.test(p) && Number(p) <= 65535
}

// canSuggest reports whether rules can be suggested for the flow: BLACK
// traffic must always be logged, so it gets none.
export function canSuggest(flow) {
  return flow.class !== 'BLACK'
}

// flowRule returns { command, errors, warnings }. command holds one rule
// per line and is empty when there are errors. The source port is only
// matched on request since it is usually ephemeral, which would make the
// rule match a single connection.
export function flowRule(flow, { chain = 'INPUT', choice = 'white-allow', srcPort = false } = {}) {
  const errors = []
  const warnings = []
  const match = []

  if (!canSuggest(flow)) errors.push(t('iptables.blackLogged'))
  if (!chains.includes(chain)) errors.push(t('iptables.unknownChain', { v: chain }))
  if (!choices.includes(choice)) errors.push(t('iptables.unknownChoice', { v: choice }))

  const src = single(flow, 'src_ip')
  const dst = single(flow, 'dst_ip')
  const versions = new Set()
  for (const [opt, ip, label] of [['-s', src, t('iptables.srcIp')], ['-d', dst, t('iptables.dstIp')]]) {
    if (!ip) continue
    const v = ipVersion(ip)
    if (!v) {
      errors.push(t('iptables.invalidIp', { label, v: ip }))
      continue
    }
    versions.add(v)
    match.push(opt, ip)
  }
  if (versions.size > 1) errors.push(t('iptables.mixedIp'))

  const proto = single(flow, 'proto').toLowerCase()
  if (proto) {
    if (/^[a-z0-9-]{1,16}$/.test(proto)) match.push('-p', proto)
    else errors.push(t('iptables.invalidProto', { v: proto }))
  }

  const ports = [
    ['--sport', srcPort ? single(flow, 'src_port') : '', t('iptables.srcPort')],
    ['--dport', single(flow, 'dst_port'), t('iptables.dstPort')],
  ].filter(([, p]) => p)
  if (ports.length) {
    // Dropping the ports would widen the rule, so it is refused instead.
    if (!portProtos.includes(proto)) {
      errors.push(t('iptables.portsNeedProto'))
    }
    for (const [opt, p, label] of ports) {
      if (validPort(p)) match.push(opt, p)
      else errors.push(t('iptables.invalidPort', { label, v: p }))
    }
  }

  if (!src && !dst && !proto) errors.push(t('iptables.matchesAll'))
  for (const f of ['src_ip', 'dst_ip', ...(srcPort ? ['src_port'] : []), 'dst_port', 'proto']) {
    if (flow['n_' + f] > 1) warnings.push(t('iptables.varies', { field: f, n: flow['n_' + f] }))
  }
  if (choice === 'white-allow') warnings.push(t('iptables.acceptTop'))
  if (errors.length) return { command: '', errors, warnings }

  // Comments end up on the firewall, so they are not translated.
  const cmd = versions.has(6) ? 'ip6tables' : 'iptables'
  const m = match.join(' ')
  const comment = (text) => `-m comment --comment "blue-siem: ${text}"`
  let lines
  switch (choice) {
    case 'white-allow':
      lines = [`${cmd} -I ${chain} ${m} ${comment('WHITE allow')} -j ACCEPT`]
      break
    case 'white-block':
      lines = [`${cmd} -I ${chain} ${m} ${comment('WHITE block')} -j DROP`]
      break
    default:
      // Fixed positions so LOG always comes right before DROP.
      lines = [
        `${cmd} -I ${chain} 1 ${m} ${comment('BLACK')} -j LOG --log-prefix "${blackPrefix}"`,
        `${cmd} -I ${chain} 2 ${m} ${comment('BLACK')} -j DROP`,
      ]
  }
  return { command: lines.join('\n'), errors, warnings }
}

// copyText copies to the clipboard, falling back to execCommand where the
// Clipboard API is unavailable (plain http to anything but localhost).
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    ta.remove()
    return ok
  }
}
