<template>
  <div class="grid gap-4 lg:grid-cols-2">
    <div class="flex flex-col gap-4">
      <v-card variant="flat" border :title="t('settings.alarms')">
        <v-card-text>
          <div class="text-subtitle-2">{{ t('settings.threshold') }}</div>
          <div class="text-caption text-medium-emphasis mb-2">{{ t('settings.thresholdHelp') }}</div>
          <div class="flex items-center gap-4 mb-6">
            <v-slider v-model="form.alarm_threshold" :min="1" :max="10" :step="1" show-ticks="always" tick-size="3" :color="critInfo(form.alarm_threshold).color" hide-details class="flex-1" />
            <CritChip :value="form.alarm_threshold" size="default" />
          </div>
          <v-text-field v-model.number="form.retention_days" type="number" min="0" :label="t('settings.retention')" :hint="t('settings.retentionHint')" persistent-hint class="mb-4" />
          <v-switch v-model="form.learning_mode" :label="t('app.learning')" color="warning" inset hide-details />
          <div class="text-caption text-medium-emphasis">{{ t('settings.learningHelp') }}</div>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn color="primary" variant="flat" :loading="saving" @click="save">{{ t('common.save') }}</v-btn>
        </v-card-actions>
      </v-card>

      <v-card variant="flat" border :title="t('forward.title')">
        <v-card-text v-if="form.forward">
          <div class="text-caption text-medium-emphasis mb-2">{{ t('forward.help') }}</div>
          <v-switch v-model="form.forward.enabled" :label="t('forward.enabled')" color="success" inset hide-details class="mb-2" />
          <div class="flex flex-wrap gap-x-4">
            <v-text-field v-model="form.forward.address" :label="t('forward.address')" placeholder="siem2.example.com:514" class="mono flex-1 min-w-[220px]" />
            <v-select v-model="form.forward.protocol" :items="['udp', 'tcp']" :label="t('forward.protocol')" class="w-32 flex-none" />
          </div>
          <div class="text-subtitle-2">{{ t('forward.minCrit') }}</div>
          <div class="flex items-center gap-4 mb-4">
            <v-slider v-model="form.forward.min_crit" :min="1" :max="10" :step="1" show-ticks="always" tick-size="3" :color="critInfo(form.forward.min_crit).color" hide-details class="flex-1" />
            <CritChip :value="form.forward.min_crit" size="default" />
          </div>
          <v-select v-model="form.forward.severity" :items="severityItems" :label="t('forward.severity')" />
          <div class="text-subtitle-2 mb-1">{{ t('forward.mode') }}</div>
          <v-radio-group v-model="form.forward.mode" hide-details class="mb-2">
            <v-radio value="original">
              <template #label>
                <div>
                  <div>{{ t('forward.modeOriginal') }}</div>
                  <div class="text-caption text-medium-emphasis">{{ t('forward.modeOriginalHelp') }}</div>
                </div>
              </template>
            </v-radio>
            <v-radio value="alarm">
              <template #label>
                <div>
                  <div>{{ t('forward.modeAlarm') }}</div>
                  <div class="text-caption text-medium-emphasis">{{ t('forward.modeAlarmHelp') }}</div>
                </div>
              </template>
            </v-radio>
          </v-radio-group>
          <v-text-field
            v-model="form.forward.instance"
            :label="t('forward.instance')"
            :placeholder="form.forward.instance_default"
            :hint="t('forward.instanceHint', { name: form.forward.instance_default })"
            persistent-hint
            class="mono mb-2"
          />
          <div class="text-caption text-medium-emphasis mb-1">{{ t('forward.example') }}</div>
          <pre class="raw mono mb-2 whitespace-pre-wrap break-all">{{ example }}</pre>
          <div class="text-caption text-medium-emphasis">{{ t('forward.learningNote') }}</div>
          <div class="text-caption mt-2">{{ t('forward.status', { sent: fmtNum(form.forward.status.sent), failed: fmtNum(form.forward.status.failed), dropped: fmtNum(form.forward.status.dropped) }) }}</div>
          <div v-if="form.forward.status.last_error" class="text-caption text-error">
            {{ t('forward.lastError', { time: fmtTime(form.forward.status.last_error_at), error: form.forward.status.last_error }) }}
          </div>
        </v-card-text>
        <v-card-actions>
          <v-btn variant="tonal" prepend-icon="mdi-send" :disabled="!form.forward?.address" :loading="testing" @click="testForward">{{ t('forward.test') }}</v-btn>
          <v-spacer />
          <v-btn color="primary" variant="flat" :loading="saving" @click="save">{{ t('common.save') }}</v-btn>
        </v-card-actions>
      </v-card>

      <v-card variant="flat" border :title="t('settings.interface')">
        <v-card-text>
          <v-btn-toggle :model-value="i18n.locale" mandatory density="comfortable" variant="outlined" divided @update:model-value="setLocale">
            <v-btn v-for="l in locales" :key="l.value" :value="l.value" prepend-icon="mdi-translate">{{ l.title }}</v-btn>
          </v-btn-toggle>
          <div class="text-caption text-medium-emphasis mt-2">{{ t('settings.languageHelp') }}</div>
        </v-card-text>
      </v-card>
    </div>

    <v-card variant="flat" border :title="t('settings.receiving')">
      <v-card-text>
        <v-table density="compact" class="mb-4">
          <tbody>
            <tr><td>{{ t('settings.syslogUdp') }}</td><td class="mono">{{ form.syslog_udp || t('settings.disabled') }}</td></tr>
            <tr><td>{{ t('settings.syslogTcp') }}</td><td class="mono">{{ form.syslog_tcp || t('settings.disabled') }}</td></tr>
            <tr><td>{{ t('settings.version') }}</td><td class="mono">{{ form.version }}</td></tr>
          </tbody>
        </v-table>
        <div class="text-subtitle-2 mb-1">rsyslog (/etc/rsyslog.d/90-siem.conf)</div>
        <pre class="raw mono mb-4">*.* @siem-host{{ port(form.syslog_udp) }}      # UDP
# *.* @@siem-host{{ port(form.syslog_tcp) }}  # TCP</pre>
        <div class="text-subtitle-2 mb-1">{{ t('settings.iptablesTitle') }}</div>
        <pre class="raw mono">{{ t('settings.iptablesExample') }}</pre>
        <!-- Static, translated text only. -->
        <div class="text-caption text-medium-emphasis mt-2" v-html="t('settings.iptablesNote')" />
      </v-card-text>
    </v-card>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api'
import { live, notify } from '../live'
import { critInfo, fmtTime, syslogSeverities } from '../util'
import { fmtNum, i18n, locales, setLocale, t } from '../i18n'
import CritChip from '../components/CritChip.vue'

const form = ref({ alarm_threshold: 7, retention_days: 30 })
const saving = ref(false)
const testing = ref(false)

const severityItems = syslogSeverities.map((name, value) => ({ title: `${value} – ${name}`, value }))

// Mirrors what the backend sends, for illustration only.
const example = computed(() => {
  const f = form.value.forward
  if (!f) return ''
  if (f.mode === 'alarm') {
    const name = f.instance || f.instance_default
    return `<${4 * 8 + f.severity}>1 2026-11-02T10:00:00Z ${name} blue-siem - alarm - Blue SIEM alarm: rule="Blacklisted traffic (BLACK)" criticality=9 class=BLACK`
  }
  return `<${f.severity}>Nov  2 10:00:00 fw01 kernel: BLACK DROP: IN=eth0 OUT= SRC=185.220.101.4 DST=192.168.1.10 PROTO=TCP SPT=51234 DPT=22`
})

// forwardBody is the editable part of the forwarding settings.
function forwardBody() {
  const { enabled, address, protocol, min_crit, severity, mode, instance } = form.value.forward
  return { enabled, address, protocol, min_crit, severity, mode, instance }
}

async function testForward() {
  testing.value = true
  try {
    await api.post('/forward/test', forwardBody())
    notify(t('forward.testSent'), 'success')
  } catch (e) {
    notify(e.message, 'error')
  } finally {
    testing.value = false
  }
}

const port = (addr) => {
  const p = (addr || '').split(':').pop()
  return p ? ':' + p : ''
}

async function save() {
  saving.value = true
  try {
    const { alarm_threshold, retention_days, learning_mode } = form.value
    form.value = await api.put('/settings', { alarm_threshold, retention_days, learning_mode, forward: forwardBody() })
    live.learning = form.value.learning_mode
    notify(t('settings.saved'), 'success')
  } catch (e) {
    notify(e.message, 'error')
  } finally {
    saving.value = false
  }
}

onMounted(async () => {
  form.value = await api.get('/settings')
})
</script>
