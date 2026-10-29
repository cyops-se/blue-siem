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
import { onMounted, ref } from 'vue'
import { api } from '../api'
import { live, notify } from '../live'
import { critInfo } from '../util'
import { i18n, locales, setLocale, t } from '../i18n'
import CritChip from '../components/CritChip.vue'

const form = ref({ alarm_threshold: 7, retention_days: 30 })
const saving = ref(false)

const port = (addr) => {
  const p = (addr || '').split(':').pop()
  return p ? ':' + p : ''
}

async function save() {
  saving.value = true
  try {
    form.value = await api.put('/settings', form.value)
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
