<template>
  <!-- Static, translated text only; never log data. -->
  <v-alert type="info" variant="tonal" density="compact" class="mb-4"><div v-html="t('iplists.info')" /></v-alert>

  <div class="grid gap-4 lg:grid-cols-2">
    <v-card v-for="l in lists" :key="l.name" variant="flat" border>
      <v-card-title class="d-flex align-center ga-2">
        <TagChips :tags="[l.name]" />
        <span class="text-subtitle-1">{{ t(l.title) }}</span>
        <v-spacer />
        <span class="text-caption text-medium-emphasis">{{ t('iplists.count', { n: entries(l.name).length }) }}</span>
      </v-card-title>
      <v-card-text>
        <div class="flex flex-wrap md:flex-nowrap gap-2">
          <v-text-field v-model="drafts[l.name].cidr" :label="t('iplists.cidr')" placeholder="203.0.113.0/24" class="mono md:w-56 md:flex-none" hide-details @keyup.enter="add(l.name)" />
          <v-text-field v-model="drafts[l.name].comment" :label="t('iplists.comment')" class="flex-1" hide-details @keyup.enter="add(l.name)" />
          <v-btn color="primary" variant="flat" height="48" icon="mdi-plus" :title="t('common.add')" @click="add(l.name)" />
        </div>
      </v-card-text>
      <v-table density="compact">
        <tbody>
          <tr v-for="e in entries(l.name)" :key="e.id">
            <td class="mono">{{ e.cidr }}</td>
            <td class="text-medium-emphasis">{{ e.comment }}</td>
            <td class="text-right" style="width: 50px">
              <v-btn icon="mdi-delete-outline" size="small" variant="text" color="error" :title="t('common.delete')" @click="remove(e)" />
            </td>
          </tr>
          <tr v-if="!entries(l.name).length"><td class="text-medium-emphasis">{{ t('iplists.empty') }}</td></tr>
        </tbody>
      </v-table>
    </v-card>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { api } from '../api'
import { notify } from '../live'
import { t } from '../i18n'
import TagChips from '../components/TagChips.vue'

const lists = [
  { name: 'BLACK', title: 'iplists.black' },
  { name: 'WHITE', title: 'iplists.white' },
]
const items = ref([])
const drafts = reactive({ WHITE: { cidr: '', comment: '' }, BLACK: { cidr: '', comment: '' } })

const entries = (list) => items.value.filter((e) => e.list === list)

async function load() {
  items.value = await api.get('/iplists')
}

async function add(list) {
  const d = drafts[list]
  if (!d.cidr.trim()) return
  try {
    await api.post('/iplists', { list, cidr: d.cidr.trim(), comment: d.comment })
    drafts[list] = { cidr: '', comment: '' }
    load()
  } catch (e) {
    notify(e.message, 'error')
  }
}

async function remove(e) {
  await api.del(`/iplists/${e.id}`)
  load()
}

onMounted(load)
</script>
