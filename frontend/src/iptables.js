// Builds an iptables rule that matches a flow and gives it the same verdict
// before the LOG rule is reached, so the flow is no longer logged.
//
// Every value comes from received log lines, which anyone can spoof over
// syslog, and the command is meant to be pasted into a root shell. Values are
// therefore only used when they are strictly valid; anything else is an
// error rather than being escaped.

import { t } from './i18n'

export const chains = ['INPUT', 'OUTPUT', 'FORWARD']
export const targets = ['ACCEPT', 'DROP', 'REJECT']

const portProtos = ['tcp', 'udp', 'udplite', 'sctp', 'dccp']
const targetFor = { ACCEPT: 'ACCEPT', ALLOW: 'ACCEPT', DROP: 'DROP', DENY: 'DROP', BLOCK: 'DROP', REJECT: 'REJECT' }

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

// defaultTarget keeps the verdict the flow already got. BLACK traffic is
// never accepted by default.
export function defaultTarget(flow) {
  const acts = (flow.actions || '').split(',').filter(Boolean)
  if (acts.length === 1 && targetFor[acts[0]]) return targetFor[acts[0]]
  return flow.class === 'BLACK' ? 'DROP' : 'ACCEPT'
}

// flowRule returns { command, errors, warnings }. command is empty when
// there are errors. The source port is only matched on request since it is
// usually ephemeral, which would make the rule match a single connection.
export function flowRule(flow, { chain = 'INPUT', target = defaultTarget(flow), srcPort = false } = {}) {
  const errors = []
  const warnings = []
  const args = []

  if (!chains.includes(chain)) errors.push(t('iptables.unknownChain', { v: chain }))
  if (!targets.includes(target)) errors.push(t('iptables.unknownTarget', { v: target }))

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
    args.push(opt, ip)
  }
  if (versions.size > 1) errors.push(t('iptables.mixedIp'))

  const proto = single(flow, 'proto').toLowerCase()
  if (proto) {
    if (/^[a-z0-9-]{1,16}$/.test(proto)) args.push('-p', proto)
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
      if (validPort(p)) args.push(opt, p)
      else errors.push(t('iptables.invalidPort', { label, v: p }))
    }
  }

  if (!src && !dst && !proto) errors.push(t('iptables.matchesAll'))
  for (const f of ['src_ip', 'dst_ip', ...(srcPort ? ['src_port'] : []), 'dst_port', 'proto']) {
    if (flow['n_' + f] > 1) warnings.push(t('iptables.varies', { field: f, n: flow['n_' + f] }))
  }
  if (target === 'ACCEPT' && flow.class === 'BLACK') warnings.push(t('iptables.blackAccept'))
  if (target === 'ACCEPT') warnings.push(t('iptables.acceptTop'))

  // The comment ends up on the firewall, so it is not translated.
  const cls = /^(WHITE|GREY|BLACK)$/.test(flow.class) ? flow.class : 'flow'
  args.push('-m', 'comment', '--comment', `"blue-siem: ${cls} not logged"`, '-j', target)

  const cmd = versions.has(6) ? 'ip6tables' : 'iptables'
  return { command: errors.length ? '' : `${cmd} -I ${chain} ${args.join(' ')}`, errors, warnings }
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
