import { reactive } from 'vue'
import { api } from './api'
import { t } from './i18n'

// Shared live state fed by the backend's Server-Sent Events stream.
export const live = reactive({
  connected: false,
  openAlarms: 0,
  // Learning mode: iptables traffic is only counted as flows.
  learning: false,
  snackbar: { show: false, text: '', color: 'info' },
})

const listeners = new Set()
let source = null

export function notify(text, color = 'info') {
  live.snackbar = { show: true, text, color }
}

export async function refreshAlarmCount() {
  try {
    const res = await api.get('/alarms?status=open&limit=1')
    live.openAlarms = res.total
  } catch {
    // shown as disconnected anyway
  }
}

export async function refreshSettings() {
  try {
    live.learning = (await api.get('/settings')).learning_mode
  } catch {
    // shown as disconnected anyway
  }
}

// setLearning toggles learning mode; other clients follow via the stream.
export async function setLearning(on) {
  try {
    live.learning = (await api.put('/settings', { learning_mode: on })).learning_mode
    notify(t(on ? 'learning.on' : 'learning.off'), 'success')
  } catch (e) {
    notify(e.message, 'error')
  }
}

export function startLive() {
  if (source) return
  source = new EventSource('/api/stream')
  source.onopen = () => {
    live.connected = true
    refreshAlarmCount()
    refreshSettings()
  }
  // EventSource reconnects by itself.
  source.onerror = () => {
    live.connected = false
  }
  source.onmessage = (e) => {
    let msg
    try {
      msg = JSON.parse(e.data)
    } catch {
      return
    }
    if (msg.type === 'alarm') live.openAlarms++
    if (msg.type === 'ack' || msg.type === 'cleared') refreshAlarmCount()
    if (msg.type === 'settings') live.learning = msg.data.learning_mode
    listeners.forEach((fn) => fn(msg))
  }
}

// onLive registers a listener and returns a function that removes it.
export function onLive(fn) {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

export function debounce(fn, ms) {
  let t
  return (...args) => {
    clearTimeout(t)
    t = setTimeout(() => fn(...args), ms)
  }
}
