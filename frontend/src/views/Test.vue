<template>
  <v-card variant="flat" border>
    <v-card-text>
      <!-- Static, translated text only; never log data. -->
      <div class="text-body-2 text-medium-emphasis mb-3" v-html="t('test.intro')" />
      <div class="flex flex-wrap gap-2 mb-3">
        <v-chip v-for="s in samples" :key="s.raw" size="small" variant="outlined" prepend-icon="mdi-plus" @click="addSample(s.raw)">{{ s.label }}</v-chip>
        <v-chip size="small" variant="outlined" prepend-icon="mdi-playlist-plus" @click="raw = samples.map((s) => s.raw).join('\n')">{{ t('test.allSamples') }}</v-chip>
      </div>
      <v-textarea v-model="raw" :label="t('test.raw')" rows="5" auto-grow class="mono" />
      <div class="flex flex-wrap items-center gap-3">
        <v-text-field v-model="sourceIp" :label="t('test.sourceIp')" class="max-w-[220px] mono" hide-details density="compact" />
        <v-btn color="primary" variant="flat" prepend-icon="mdi-magnify-scan" :loading="busy" :disabled="!raw.trim()" @click="analyze">{{ t('test.analyze') }}</v-btn>
        <v-btn variant="tonal" prepend-icon="mdi-send" :loading="busy" :disabled="!raw.trim()" @click="ingest">{{ t('test.ingest') }}</v-btn>
        <v-btn variant="text" @click="(raw = ''), (results = [])">{{ t('common.clear') }}</v-btn>
      </div>
    </v-card-text>
  </v-card>

  <v-card v-for="(r, i) in results" :key="i" variant="flat" border class="mt-4">
    <v-card-title class="d-flex flex-wrap align-center ga-2">
      <CritChip :value="r.event.criticality" size="default" />
      <v-chip v-if="r.flow_only" color="warning" variant="flat" prepend-icon="mdi-school-outline">{{ t('test.flowOnly') }}</v-chip>
      <v-chip v-else-if="r.alarm" color="error" variant="flat" prepend-icon="mdi-bell-ring">{{ t('test.alarm', { n: r.threshold }) }}</v-chip>
      <v-chip v-else variant="tonal" prepend-icon="mdi-bell-off-outline">{{ t('test.noAlarm', { n: r.threshold }) }}</v-chip>
      <v-chip variant="tonal" color="teal" label>{{ r.event.decoder || t('test.noDecoder') }}</v-chip>
      <span class="text-body-2 text-medium-emphasis">{{ r.matched_rules.length ? t('test.rules', { rules: r.matched_rules.join(', ') }) : t('test.noRule') }}</span>
    </v-card-title>
    <v-card-text><EventDetail :event="r.event" /></v-card-text>
  </v-card>
</template>

<script setup>
import { ref } from 'vue'
import { api } from '../api'
import { notify } from '../live'
import { samples } from '../util'
import { t } from '../i18n'
import CritChip from '../components/CritChip.vue'
import EventDetail from '../components/EventDetail.vue'

const raw = ref('')
const sourceIp = ref('')
const results = ref([])
const busy = ref(false)

function addSample(s) {
  raw.value = raw.value.trim() ? raw.value.trimEnd() + '\n' + s : s
}

async function analyze() {
  busy.value = true
  try {
    results.value = await api.post('/test', { raw: raw.value, source_ip: sourceIp.value })
  } catch (e) {
    notify(e.message, 'error')
  } finally {
    busy.value = false
  }
}

async function ingest() {
  busy.value = true
  try {
    const res = await api.post('/ingest', { raw: raw.value, source_ip: sourceIp.value })
    const learned = res.flow_only ? t('test.ingestedFlows', { n: res.flow_only }) : ''
    notify(t('test.ingested', { events: res.events, alarms: res.alarms }) + learned, 'success')
  } catch (e) {
    notify(e.message, 'error')
  } finally {
    busy.value = false
  }
}
</script>
