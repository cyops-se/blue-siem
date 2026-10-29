<template>
  <v-card variant="flat" border>
    <v-card-text class="flex flex-wrap items-center gap-3">
      <v-text-field
        v-model="filters.q"
        :label="t('events.search')"
        prepend-inner-icon="mdi-magnify"
        clearable
        hide-details
        class="min-w-[240px] flex-1"
        @update:model-value="debouncedApply"
      />
      <v-combobox v-model="filters.tag" :items="tagSuggestions" :label="t('events.tag')" clearable hide-details class="w-44 flex-none" @update:model-value="apply" />
      <v-select v-model="filters.decoder" :items="decoderItems" :label="t('events.decoder')" clearable hide-details class="w-48 flex-none" @update:model-value="apply" />
      <v-select v-model="filters.min_crit" :items="critItems" :label="t('events.minCrit')" clearable hide-details class="w-48 flex-none" @update:model-value="apply" />
      <v-select v-model="filters.hours" :items="hourItems" :label="t('common.timeWindow')" hide-details class="w-40 flex-none" @update:model-value="apply" />
      <v-switch v-model="liveMode" :label="t('common.live')" color="success" hide-details inset density="compact" class="flex-none" />
      <v-btn icon="mdi-refresh" variant="text" :title="t('common.refresh')" @click="load" />
      <v-btn icon="mdi-delete-sweep-outline" variant="text" color="error" :title="t('events.deleteAll')" @click="confirmClear = true" />
      <div v-if="filters.hostname || Object.keys(fieldFilters).length" class="flex flex-wrap items-center gap-2 w-full">
        <span class="text-body-2 text-medium-emphasis">{{ t('events.fields') }}</span>
        <v-chip v-if="filters.hostname" size="small" closable class="mono" prepend-icon="mdi-server-network" @click:close="(filters.hostname = null), apply()">
          hostname = {{ filters.hostname }}
        </v-chip>
        <v-chip v-for="(v, k) in fieldFilters" :key="k" size="small" closable class="mono" @click:close="removeField(k)">
          {{ k }} = {{ v || t('events.empty') }}
        </v-chip>
      </div>
    </v-card-text>

    <v-data-table-server
      v-model:items-per-page="itemsPerPage"
      v-model:page="page"
      v-model:expanded="expanded"
      :headers="headers"
      :items="items"
      :items-length="total"
      :loading="loading"
      :items-per-page-options="[25, 50, 100, 250]"
      item-value="id"
      show-expand
      density="compact"
      hover
      @update:options="load"
      @click:row="(_, { item }) => toggle(item.id)"
    >
      <template #item.received_at="{ item }"><span class="whitespace-nowrap">{{ fmtTime(item.received_at) }}</span></template>
      <template #item.criticality="{ item }"><CritChip :value="item.criticality" short /></template>
      <template #item.tags="{ item }"><TagChips :tags="item.tags" class="min-w-[200px] py-1" @select="setTag" /></template>
      <template #item.decoder="{ item }"><span class="text-medium-emphasis whitespace-nowrap">{{ item.decoder || '–' }}</span></template>
      <template #item.message="{ item }">
        <div class="msg-cell mono" :title="item.message">
          <v-icon v-if="item.alarm_id" color="error" size="14" class="mr-1">mdi-bell</v-icon>{{ item.message }}
        </div>
      </template>
      <template #expanded-row="{ columns, item }">
        <tr>
          <td :colspan="columns.length"><EventDetail :event="item" /></td>
        </tr>
      </template>
    </v-data-table-server>
  </v-card>

  <v-dialog v-model="confirmClear" max-width="440">
    <v-card :title="t('events.confirmTitle')">
      <v-card-text>{{ t('events.confirmText') }}</v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn @click="confirmClear = false">{{ t('common.cancel') }}</v-btn>
        <v-btn color="error" variant="flat" @click="clearAll">{{ t('events.deleteBtn') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, query } from '../api'
import { debounce, notify, onLive } from '../live'
import { critLevels, fmtTime, hourOptions } from '../util'
import { t } from '../i18n'
import CritChip from '../components/CritChip.vue'
import TagChips from '../components/TagChips.vue'
import EventDetail from '../components/EventDetail.vue'

const route = useRoute()
const router = useRouter()

const filters = reactive({
  q: route.query.q || '',
  tag: route.query.tag || null,
  decoder: route.query.decoder || null,
  min_crit: route.query.min_crit ? Number(route.query.min_crit) : null,
  hours: route.query.hours ? Number(route.query.hours) : 0,
  hostname: route.query.hostname || null,
})
// Exact matches on decoded fields, passed as f.<name>=value (e.g. from Flows).
const fieldFilters = reactive(
  Object.fromEntries(Object.entries(route.query).filter(([k]) => k.startsWith('f.')).map(([k, v]) => [k.slice(2), String(v ?? '')])),
)
const items = ref([])
const total = ref(0)
const loading = ref(false)
const page = ref(1)
const itemsPerPage = ref(50)
const expanded = ref([])
const liveMode = ref(true)
const confirmClear = ref(false)
const decoderNames = ref([])
const decoderItems = computed(() => [...decoderNames.value, { title: t('events.noDecoder'), value: '-' }])

const headers = computed(() => [
  { title: t('common.time'), key: 'received_at', sortable: false, width: 170 },
  { title: t('events.crit'), key: 'criticality', sortable: false, width: 80 },
  { title: t('events.host'), key: 'hostname', sortable: false },
  { title: t('events.program'), key: 'app_name', sortable: false },
  { title: t('events.decoder'), key: 'decoder', sortable: false },
  { title: t('common.tags'), key: 'tags', sortable: false },
  { title: t('events.message'), key: 'message', sortable: false },
  { title: '', key: 'data-table-expand', width: 40 },
])
const tagSuggestions = ['BLACK', 'GREY', 'WHITE', 'iptables', 'DROP', 'ACCEPT', 'auth', 'auth_failure', 'auth_success', 'invalid_user', 'ssh', 'sudo']
const critItems = computed(() => critLevels.filter((l) => l.min > 0).map((l) => ({ title: t('events.minCritItem', { min: l.min, label: l.label }), value: l.min })))
const hourItems = computed(() => hourOptions())

async function load() {
  loading.value = true
  try {
    const res = await api.get('/events' + query({
      ...filters,
      limit: itemsPerPage.value,
      offset: (page.value - 1) * itemsPerPage.value,
    }) + fieldQuery('&'))
    items.value = res.items
    total.value = res.total
  } catch (e) {
    notify(e.message, 'error')
  } finally {
    loading.value = false
  }
}

// fieldQuery serialises the field filters. Empty values are kept since they
// match events where the field is missing (e.g. ports for ICMP).
function fieldQuery(sep) {
  const q = new URLSearchParams(Object.entries(fieldFilters).map(([k, v]) => ['f.' + k, v])).toString()
  return q ? sep + q : ''
}

function apply() {
  page.value = 1
  const q = Object.fromEntries(new URLSearchParams(query(filters)))
  for (const [k, v] of Object.entries(fieldFilters)) q['f.' + k] = v
  router.replace({ query: q })
  load()
}

function removeField(k) {
  delete fieldFilters[k]
  apply()
}
const debouncedApply = debounce(apply, 350)

function setTag(t) {
  filters.tag = t
  apply()
}

function toggle(id) {
  expanded.value = expanded.value.includes(id) ? expanded.value.filter((x) => x !== id) : [...expanded.value, id]
}

async function clearAll() {
  confirmClear.value = false
  await api.del('/events')
  notify(t('events.deleted'), 'success')
  load()
}

// Only refresh when the user is looking at the newest page and has nothing
// expanded, so rows don't jump around while reading.
const liveReload = debounce(() => {
  if (liveMode.value && page.value === 1 && expanded.value.length === 0) load()
}, 700)

let off
onMounted(async () => {
  off = onLive((msg) => {
    if (msg.type === 'event' || msg.type === 'cleared') liveReload()
  })
  const ds = await api.get('/decoders')
  decoderNames.value = ds.map((d) => d.name)
})
onUnmounted(() => off?.())
</script>
