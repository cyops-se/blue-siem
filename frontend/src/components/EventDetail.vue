<template>
  <div class="grid gap-4 lg:grid-cols-3 py-3">
    <div>
      <div class="text-overline">{{ t('event.syslog') }}</div>
      <v-table density="compact" class="bg-transparent">
        <tbody>
          <tr><td class="text-medium-emphasis">{{ t('event.received') }}</td><td>{{ fmtTime(event.received_at) }}</td></tr>
          <tr><td class="text-medium-emphasis">{{ t('event.timestamp') }}</td><td>{{ fmtTime(event.timestamp) }}</td></tr>
          <tr><td class="text-medium-emphasis">{{ t('event.sender') }}</td><td class="mono">{{ event.source_ip }}</td></tr>
          <tr><td class="text-medium-emphasis">{{ t('event.host') }}</td><td>{{ event.hostname }}</td></tr>
          <tr><td class="text-medium-emphasis">{{ t('event.program') }}</td><td>{{ event.app_name }}<span v-if="event.proc_id">[{{ event.proc_id }}]</span></td></tr>
          <tr>
            <td class="text-medium-emphasis">Facility / severity</td>
            <td>{{ facilities[event.facility] ?? event.facility }} / {{ syslogSeverities[event.severity] ?? event.severity }} ({{ event.severity }})</td>
          </tr>
          <tr><td class="text-medium-emphasis">{{ t('event.format') }}</td><td>{{ event.format }}</td></tr>
          <tr><td class="text-medium-emphasis">{{ t('event.decoder') }}</td><td>{{ event.decoder || '–' }}</td></tr>
        </tbody>
      </v-table>
    </div>
    <div>
      <div class="text-overline">{{ t('event.decodedFields') }}</div>
      <v-table v-if="fieldList.length" density="compact" class="bg-transparent">
        <tbody>
          <tr v-for="[k, v] in fieldList" :key="k">
            <td class="mono text-medium-emphasis">{{ k }}</td>
            <td class="mono">{{ v }}</td>
          </tr>
        </tbody>
      </v-table>
      <div v-else class="text-medium-emphasis text-body-2">{{ t('event.noFields') }}</div>
    </div>
    <div>
      <div class="text-overline">{{ t('event.classification') }}</div>
      <div class="flex items-center gap-2 mb-2">
        <CritChip :value="event.criticality" />
        <v-chip v-if="event.alarm_id" size="small" color="error" variant="tonal" prepend-icon="mdi-bell" to="/alarms">{{ t('event.alarm', { id: event.alarm_id }) }}</v-chip>
      </div>
      <TagChips :tags="event.tags" class="mb-3" />
      <div class="text-caption text-medium-emphasis">{{ t('event.matchedRules') }}</div>
      <div class="text-body-2 mb-3">{{ event.matched_rules || '–' }}</div>
      <div class="text-caption text-medium-emphasis">{{ t('event.raw') }}</div>
      <pre class="raw mono">{{ event.raw }}</pre>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import CritChip from './CritChip.vue'
import TagChips from './TagChips.vue'
import { facilities, fmtTime, syslogSeverities } from '../util'
import { t } from '../i18n'

const props = defineProps({ event: { type: Object, required: true } })
const fieldList = computed(() => Object.entries(props.event.fields || {}).sort(([a], [b]) => a.localeCompare(b)))
</script>
