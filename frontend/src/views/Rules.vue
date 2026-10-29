<template>
  <!-- Static, translated text only; never log data. -->
  <v-alert type="info" variant="tonal" density="compact" class="mb-4"><span v-html="t('rules.info', { threshold: Number(threshold) })" /></v-alert>

  <v-card variant="flat" border>
    <v-card-title class="d-flex align-center">
      <span class="text-subtitle-1">{{ t('rules.title') }}</span>
      <v-spacer />
      <v-btn color="primary" variant="flat" prepend-icon="mdi-plus" @click="edit()">{{ t('rules.new') }}</v-btn>
    </v-card-title>
    <v-data-table :headers="headers" :items="items" :loading="loading" density="comfortable" :items-per-page="-1" hide-default-footer>
      <template #item.enabled="{ item }">
        <v-switch :model-value="item.enabled" color="success" hide-details density="compact" @update:model-value="(v) => toggle(item, v)" />
      </template>
      <template #item.name="{ item }">
        <div class="font-weight-medium">{{ item.name }}</div>
        <div class="text-caption text-medium-emphasis">{{ item.description }}</div>
      </template>
      <template #item.conditions="{ item }">
        <div class="flex flex-col gap-1 py-1">
          <span v-for="(c, i) in item.conditions" :key="i" class="mono text-caption">
            <b>{{ c.field }}</b> {{ c.negate ? '!~' : '~' }} /{{ c.pattern }}/
          </span>
        </div>
      </template>
      <template #item.criticality="{ item }">
        <div class="flex items-center gap-1">
          <CritChip :value="item.criticality" />
          <v-icon v-if="item.criticality >= threshold" color="error" size="18" :title="t('rules.raisesAlarm')">mdi-bell-ring</v-icon>
        </div>
      </template>
      <template #item.stop="{ item }"><v-icon v-if="item.stop" :title="t('rules.stops')">mdi-octagon-outline</v-icon></template>
      <template #item.actions="{ item }">
        <div class="flex">
          <v-btn icon="mdi-pencil" size="small" variant="text" :title="t('common.edit')" @click="edit(item)" />
          <v-btn icon="mdi-content-copy" size="small" variant="text" :title="t('common.copy')" @click="edit({ ...item, id: undefined, name: item.name + t('rules.copySuffix') })" />
          <v-btn icon="mdi-delete-outline" size="small" variant="text" color="error" :title="t('common.delete')" @click="remove(item)" />
        </div>
      </template>
    </v-data-table>
  </v-card>

  <v-dialog v-model="dialog" max-width="900" scrollable>
    <v-card :title="form.id ? t('rules.editTitle') : t('rules.new')">
      <v-card-text>
        <div class="grid gap-x-4 md:grid-cols-6">
          <v-text-field v-model="form.name" :label="t('common.name')" class="md:col-span-5" />
          <v-text-field v-model.number="form.priority" type="number" :label="t('common.priority')" class="md:col-span-1" />
          <v-text-field v-model="form.description" :label="t('common.description')" class="md:col-span-6" />
        </div>

        <div class="text-subtitle-2 mb-2">{{ t('rules.conditionsTitle') }}</div>
        <div v-for="(c, i) in form.conditions" :key="i" class="flex flex-wrap md:flex-nowrap items-start gap-2">
          <v-combobox
            v-model="c.field"
            :items="fieldItems"
            :return-object="false"
            :label="t('rules.field')"
            class="w-full md:w-72 md:flex-none mono"
          />
          <v-text-field v-model="c.pattern" :label="t('rules.regex')" placeholder="^BLACK$" class="flex-1 mono" />
          <v-checkbox v-model="c.negate" :label="t('rules.negate')" hide-details density="compact" class="flex-none" />
          <v-btn icon="mdi-close" variant="text" class="mt-1" :disabled="form.conditions.length === 1" @click="form.conditions.splice(i, 1)" />
        </div>
        <v-btn variant="tonal" size="small" prepend-icon="mdi-plus" class="mb-4" @click="form.conditions.push({ field: 'message', pattern: '', negate: false })">
          {{ t('rules.addCondition') }}
        </v-btn>

        <div class="text-subtitle-2">{{ t('common.criticality') }}</div>
        <div class="flex items-center gap-4">
          <v-slider v-model="form.criticality" :min="0" :max="10" :step="1" show-ticks="always" tick-size="3" :color="critInfo(form.criticality).color" hide-details class="flex-1" />
          <CritChip :value="form.criticality" size="default" />
        </div>
        <div class="text-caption mb-2" :class="form.criticality >= threshold ? 'text-error' : 'text-medium-emphasis'">
          {{ form.criticality >= threshold ? t('rules.alarmAt', { n: threshold }) : t('rules.belowAlarm', { n: threshold }) }}
        </div>

        <div class="flex gap-6">
          <v-switch v-model="form.enabled" :label="t('common.enabled')" color="success" inset hide-details />
          <v-switch v-model="form.stop" :label="t('rules.stopLabel')" inset hide-details />
        </div>
      </v-card-text>
      <v-card-actions>
        <span v-if="error" class="text-error text-body-2 px-2">{{ error }}</span>
        <v-spacer />
        <v-btn @click="dialog = false">{{ t('common.cancel') }}</v-btn>
        <v-btn color="primary" variant="flat" :loading="saving" @click="submit">{{ t('common.save') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api'
import { notify } from '../live'
import { critInfo, ruleFields } from '../util'
import { t } from '../i18n'
import CritChip from '../components/CritChip.vue'

const items = ref([])
const loading = ref(false)
const threshold = ref(7)
const dialog = ref(false)
const form = ref({})
const saving = ref(false)
const error = ref('')
const fieldItems = computed(() => ruleFields())

const headers = computed(() => [
  { title: t('common.enabled'), key: 'enabled', width: 70, sortable: false },
  { title: t('common.prio'), key: 'priority', width: 70 },
  { title: t('common.name'), key: 'name' },
  { title: t('rules.conditions'), key: 'conditions', sortable: false },
  { title: t('common.criticality'), key: 'criticality', width: 160 },
  { title: t('rules.stop'), key: 'stop', width: 70 },
  { title: '', key: 'actions', sortable: false, width: 140 },
])

async function load() {
  loading.value = true
  try {
    const [rules, settings] = await Promise.all([api.get('/rules'), api.get('/settings')])
    items.value = rules
    threshold.value = settings.alarm_threshold
  } finally {
    loading.value = false
  }
}

function edit(item) {
  error.value = ''
  form.value = item
    ? JSON.parse(JSON.stringify(item))
    : { name: '', description: '', enabled: true, priority: 100, criticality: 5, stop: false, conditions: [{ field: 'message', pattern: '', negate: false }] }
  if (!form.value.conditions?.length) form.value.conditions = [{ field: 'message', pattern: '', negate: false }]
  dialog.value = true
}

function save(item) {
  return item.id ? api.put(`/rules/${item.id}`, item) : api.post('/rules', item)
}

async function toggle(item, enabled) {
  try {
    await save({ ...item, enabled })
  } catch (e) {
    notify(e.message, 'error')
  }
  load()
}

async function submit() {
  saving.value = true
  error.value = ''
  try {
    await save(form.value)
    dialog.value = false
    notify(t('rules.saved'), 'success')
    load()
  } catch (e) {
    error.value = e.message
  } finally {
    saving.value = false
  }
}

async function remove(item) {
  if (!confirm(t('rules.confirmDelete', { name: item.name }))) return
  await api.del(`/rules/${item.id}`)
  load()
}

onMounted(load)
</script>
