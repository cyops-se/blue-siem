<template>
  <!-- Static, translated text only; never log data. -->
  <v-alert type="info" variant="tonal" density="compact" class="mb-4"><span v-html="t('decoders.info')" /></v-alert>

  <v-card variant="flat" border>
    <v-card-title class="d-flex align-center">
      <span class="text-subtitle-1">{{ t('decoders.title') }}</span>
      <v-spacer />
      <v-btn color="primary" variant="flat" prepend-icon="mdi-plus" @click="edit()">{{ t('decoders.new') }}</v-btn>
    </v-card-title>
    <v-data-table :headers="headers" :items="items" :loading="loading" density="comfortable" :items-per-page="-1" hide-default-footer>
      <template #item.enabled="{ item }">
        <v-switch :model-value="item.enabled" color="success" hide-details density="compact" @update:model-value="(v) => toggle(item, v)" />
      </template>
      <template #item.name="{ item }">
        <div class="font-weight-medium">{{ item.name }}</div>
        <div class="text-caption text-medium-emphasis">{{ item.description }}</div>
      </template>
      <template #item.type="{ item }">
        <v-chip size="small" :color="item.type === 'iptables' ? 'deep-purple' : 'teal'" variant="tonal" label>{{ item.type }}</v-chip>
      </template>
      <template #item.app_filter="{ item }"><code v-if="item.app_filter">{{ item.app_filter }}</code><span v-else class="text-medium-emphasis">{{ t('decoders.allApps') }}</span></template>
      <template #item.pattern="{ item }">
        <div class="msg-cell mono max-w-[420px]" :title="item.pattern">{{ item.pattern || (item.type === 'iptables' ? t('decoders.builtin') : '') }}</div>
      </template>
      <template #item.tags="{ item }"><TagChips :tags="item.tags" /></template>
      <template #item.actions="{ item }">
        <div class="flex">
          <v-btn icon="mdi-pencil" size="small" variant="text" :title="t('common.edit')" @click="edit(item)" />
          <v-btn icon="mdi-delete-outline" size="small" variant="text" color="error" :title="t('common.delete')" @click="remove(item)" />
        </div>
      </template>
    </v-data-table>
  </v-card>

  <v-dialog v-model="dialog" max-width="980" scrollable>
    <v-card :title="form.id ? t('decoders.editTitle', { name: form.name }) : t('decoders.new')">
      <v-card-text>
        <div class="grid gap-x-4 md:grid-cols-6">
          <v-text-field v-model="form.name" :label="t('common.name')" class="md:col-span-3" />
          <v-select v-model="form.type" :items="types" :label="t('common.type')" class="md:col-span-2" />
          <v-text-field v-model.number="form.priority" type="number" :label="t('common.priority')" class="md:col-span-1" />
          <v-text-field v-model="form.description" :label="t('common.description')" class="md:col-span-6" />
          <v-text-field
            v-model="form.app_filter"
            :label="t('decoders.appFilter')"
            placeholder="^sshd$"
            class="md:col-span-3 mono"
          />
          <v-combobox v-model="form.tags" :label="t('decoders.tagsOnMatch')" multiple chips closable-chips class="md:col-span-3" />
          <v-textarea
            v-model="form.pattern"
            :label="form.type === 'iptables' ? t('decoders.prefilter') : t('decoders.pattern')"
            rows="2"
            auto-grow
            class="md:col-span-6 mono"
          />
          <v-switch v-model="form.enabled" :label="t('common.enabled')" color="success" inset class="md:col-span-6" />
        </div>

        <v-divider class="my-2" />
        <div class="text-subtitle-2 mb-2">{{ t('decoders.testTitle') }}</div>
        <v-textarea v-model="sample" :label="t('decoders.samples')" rows="3" auto-grow class="mono" />
        <v-btn variant="tonal" prepend-icon="mdi-play" :loading="testing" @click="test">{{ t('decoders.test') }}</v-btn>
        <div v-for="(r, i) in testResults" :key="i" class="mt-3">
          <v-alert :type="r.matched ? 'success' : 'warning'" variant="tonal" density="compact">
            <div class="mono text-caption mb-1">{{ r.event.raw }}</div>
            <template v-if="r.matched">
              <TagChips :tags="r.event.tags" class="mb-1" />
              <div class="flex flex-wrap gap-x-4 gap-y-1">
                <span v-for="(v, k) in r.event.fields" :key="k" class="mono text-caption"><b>{{ k }}</b>={{ v }}</span>
              </div>
            </template>
            <span v-else>{{ t('decoders.noMatch') }} (app_name: <code>{{ r.event.app_name || '–' }}</code>, {{ t('decoders.messageWord') }}: <code>{{ r.event.message }}</code>)</span>
          </v-alert>
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
import { t } from '../i18n'
import TagChips from '../components/TagChips.vue'

const items = ref([])
const loading = ref(false)
const dialog = ref(false)
const form = ref({})
const saving = ref(false)
const error = ref('')
const sample = ref('')
const testing = ref(false)
const testResults = ref([])

const types = computed(() => [
  { title: t('decoders.typeRegex'), value: 'regex' },
  { title: t('decoders.typeIptables'), value: 'iptables' },
])
const headers = computed(() => [
  { title: t('common.enabled'), key: 'enabled', width: 70, sortable: false },
  { title: t('common.prio'), key: 'priority', width: 70 },
  { title: t('common.name'), key: 'name' },
  { title: t('common.type'), key: 'type' },
  { title: t('decoders.appFilterCol'), key: 'app_filter', sortable: false },
  { title: t('decoders.patternCol'), key: 'pattern', sortable: false },
  { title: t('common.tags'), key: 'tags', sortable: false },
  { title: '', key: 'actions', sortable: false, width: 100 },
])

async function load() {
  loading.value = true
  try {
    items.value = await api.get('/decoders')
  } finally {
    loading.value = false
  }
}

function edit(item) {
  error.value = ''
  testResults.value = []
  form.value = item
    ? JSON.parse(JSON.stringify(item))
    : { name: '', description: '', type: 'regex', enabled: true, priority: 100, app_filter: '', pattern: '', tags: [] }
  dialog.value = true
}

async function save(item) {
  if (item.id) return api.put(`/decoders/${item.id}`, item)
  return api.post('/decoders', item)
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
    notify(t('decoders.saved'), 'success')
    load()
  } catch (e) {
    error.value = e.message
  } finally {
    saving.value = false
  }
}

async function test() {
  testing.value = true
  error.value = ''
  try {
    testResults.value = await api.post('/decoders/test', { decoder: form.value, raw: sample.value })
  } catch (e) {
    error.value = e.message
  } finally {
    testing.value = false
  }
}

async function remove(item) {
  if (!confirm(t('decoders.confirmDelete', { name: item.name }))) return
  await api.del(`/decoders/${item.id}`)
  load()
}

onMounted(load)
</script>
