<template>
  <div class="flex flex-col gap-4">
    <v-card variant="flat" border>
      <v-card-text class="flex flex-wrap items-center gap-4">
        <v-switch
          :model-value="live.learning"
          :label="t('app.learning')"
          color="warning"
          inset
          hide-details
          class="flex-none"
          @update:model-value="setLearning"
        />
        <div class="flex-1 min-w-[240px] text-body-2 text-medium-emphasis">
          <!-- Static, translated text only. -->
          <span v-if="live.learning" v-html="t('flows.learningOn')" />
          <template v-else>{{ t('flows.learningOff') }}</template>
        </div>
        <v-btn variant="text" color="error" prepend-icon="mdi-delete-sweep-outline" @click="confirmClear = true">{{ t('flows.clear') }}</v-btn>
      </v-card-text>
    </v-card>

    <div class="grid gap-4 md:grid-cols-3">
      <v-card
        v-for="c in classCards"
        :key="c.name"
        variant="flat"
        border
        :class="filters.class === c.name ? 'border-primary border-opacity-100' : ''"
        @click="toggleClass(c.name)"
      >
        <!-- v-card renders a title prop as heading, so the tooltip goes here. -->
        <v-card-text :title="filters.class === c.name ? t('flows.showAllClasses') : t('flows.showOnly', { name: c.name })">
          <div class="flex items-center justify-between">
            <TagChips :tags="[c.name]" />
            <span class="text-caption text-medium-emphasis">{{ t('flows.desc.' + c.name) }}</span>
          </div>
          <div class="flex items-baseline gap-2 mt-2">
            <span class="text-h4 font-weight-bold">{{ fmtNum(c.flows) }}</span>
            <span class="text-body-2 text-medium-emphasis">{{ t('flows.flows') }}</span>
          </div>
          <div class="text-body-2 text-medium-emphasis">{{ fmtNum(c.events) }} {{ t('flows.events') }}</div>
        </v-card-text>
      </v-card>
    </div>

    <v-card variant="flat" border>
      <v-card-title class="d-flex align-center text-subtitle-1">
        {{ t('flows.sources') }}
        <span class="text-caption text-medium-emphasis ml-2">{{ t('flows.sourcesHelp') }}</span>
      </v-card-title>
      <v-card-text>
        <div v-if="!sources.length" class="text-medium-emphasis">{{ t('flows.noFlows') }}</div>
        <div class="flex flex-wrap gap-2">
          <v-chip
            v-for="src in sources"
            :key="src.hostname"
            :color="filters.hostname === src.hostname ? 'primary' : undefined"
            :variant="filters.hostname === src.hostname ? 'flat' : 'outlined'"
            :disabled="!src.hostname"
            :title="src.hostname ? '' : t('flows.unknownSourceTitle')"
            prepend-icon="mdi-server-network"
            label
            @click="toggleSource(src.hostname)"
          >
            <span class="mono font-weight-medium">{{ src.hostname || t('flows.unknown') }}</span>
            <span class="ml-2 text-caption">{{ t('flows.sourceSummary', { flows: fmtNum(src.flows), events: fmtNum(src.events) }) }}</span>
          </v-chip>
        </div>
      </v-card-text>
    </v-card>

    <v-card variant="flat" border>
      <v-card-text class="flex flex-col gap-3">
        <div class="flex flex-wrap items-center gap-3">
          <v-text-field
            v-model="filters.q"
            :label="t('flows.search')"
            prepend-inner-icon="mdi-magnify"
            clearable
            hide-details
            class="min-w-[240px] flex-1"
            @update:model-value="debouncedApply"
          />
          <v-select
            v-model="filters.hostname"
            :items="sourceItems"
            :label="t('flows.col.hostname')"
            clearable
            hide-details
            class="w-48 flex-none"
            @update:model-value="apply"
          />
          <v-select v-model="filters.class" :items="classes" :label="t('common.class')" clearable hide-details class="w-36 flex-none" @update:model-value="apply" />
          <v-select v-model="filters.hours" :items="hourItems" :label="t('common.timeWindow')" hide-details class="w-40 flex-none" @update:model-value="apply" />
          <v-switch v-model="liveMode" :label="t('common.live')" color="success" hide-details inset density="compact" class="flex-none" />
          <v-btn icon="mdi-refresh" variant="text" :title="t('common.refresh')" @click="load" />
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <span class="text-body-2 text-medium-emphasis">{{ t('flows.groupBy') }}</span>
          <v-chip-group v-model="filters.group" multiple filter selected-class="text-primary" @update:model-value="apply">
            <v-chip v-for="f in flowFields" :key="f" :value="f" size="small" variant="outlined" class="mono">{{ f }}</v-chip>
          </v-chip-group>
        </div>
      </v-card-text>

      <v-data-table-server
        v-model:items-per-page="itemsPerPage"
        v-model:page="page"
        v-model:sort-by="sortBy"
        :headers="headers"
        :items="items"
        :items-length="total"
        :loading="loading"
        :items-per-page-options="[25, 50, 100, 250]"
        :must-sort="true"
        density="compact"
        hover
        @update:options="load"
      >
        <template #item.class="{ item }"><TagChips :tags="[item.class]" @select="toggleClass" /></template>
        <template v-for="f in flowFields" #[`item.${f}`]="{ item }" :key="f">
          <v-tooltip v-if="item['n_' + f] > 1" location="top" max-width="420">
            <template #activator="{ props }">
              <v-chip v-bind="props" size="x-small" variant="tonal" label class="cursor-default">{{ t('flows.distinct', { n: fmtNum(item['n_' + f]) }) }}</v-chip>
            </template>
            <div class="mono text-caption">{{ samples(item['s_' + f], item['n_' + f]) }}</div>
          </v-tooltip>
          <a
            v-else-if="f === 'hostname' && item.hostname"
            href="#"
            class="mono whitespace-nowrap"
            :title="t('flows.onlySource')"
            @click.prevent="toggleSource(item.hostname)"
          >{{ item.hostname }}</a>
          <span v-else class="mono whitespace-nowrap">{{ item[f] || '–' }}</span>
        </template>
        <template #item.actions="{ item }">
          <span class="text-caption whitespace-nowrap">{{ item.actions.split(',').join(', ') || '–' }}</span>
        </template>
        <template #item.count="{ item }"><span class="font-weight-bold">{{ fmtNum(item.count) }}</span></template>
        <template #item.max_crit="{ item }"><CritChip :value="item.max_crit" short /></template>
        <template #item.first_seen="{ item }"><span class="whitespace-nowrap">{{ fmtTime(item.first_seen) }}</span></template>
        <template #item.last_seen="{ item }"><span class="whitespace-nowrap">{{ fmtTime(item.last_seen) }}</span></template>
        <template #item.open="{ item }">
          <div class="flex">
            <v-btn icon="mdi-wall-fire" size="small" variant="text" :title="t('flows.ruleBtn')" @click="openRule(item)" />
            <v-btn icon="mdi-format-list-bulleted" size="small" variant="text" :title="t('flows.showEvents')" :to="eventsLink(item)" />
          </div>
        </template>
      </v-data-table-server>
    </v-card>
  </div>

  <v-dialog v-model="ruleDialog" max-width="760" scrollable>
    <v-card v-if="ruleFlow" :title="t('flows.ruleTitle')">
      <v-card-text>
        <div class="text-body-2 mb-3">{{ t('flows.ruleIntro') }}</div>
        <div class="flex flex-wrap items-center gap-2 mb-3 text-body-2">
          <TagChips :tags="[ruleFlow.class]" />
          <span v-if="ruleFlow.actions" class="text-medium-emphasis">{{ t('flows.actionList', { list: ruleFlow.actions.split(',').join(', ') }) }}</span>
          <v-spacer />
          <v-icon size="18">mdi-server-network</v-icon>
          <span>{{ t('flows.runsOn') }}
            <b v-if="ruleHost" class="mono">{{ ruleHost }}</b>
            <span v-else class="text-warning">{{ t('flows.manySources', { list: samples(ruleFlow.s_hostname, ruleFlow.n_hostname) }) }}</span>
          </span>
        </div>
        <div class="flex flex-wrap items-center gap-x-4">
          <v-select v-model="ruleOpts.chain" :items="chains" :label="t('flows.chain')" hide-details density="compact" class="w-36 flex-none" />
          <v-select v-model="ruleOpts.target" :items="targets" :label="t('flows.target')" hide-details density="compact" class="w-36 flex-none" />
          <v-checkbox
            v-model="ruleOpts.srcPort"
            :disabled="!ruleFlow.src_port || ruleFlow.n_src_port > 1"
            :label="t('flows.matchSrcPort')"
            :hint="t('flows.srcPortHint')"
            persistent-hint
            density="compact"
            class="flex-none"
          />
        </div>
        <v-alert v-for="e in rule.errors" :key="e" type="error" variant="tonal" density="compact" class="mt-3">{{ e }}</v-alert>
        <template v-if="rule.command">
          <pre class="raw mono mt-3 whitespace-pre-wrap break-all">{{ rule.command }}</pre>
          <v-alert v-for="w in rule.warnings" :key="w" type="warning" variant="tonal" density="compact" class="mt-2">{{ w }}</v-alert>
        </template>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn @click="ruleDialog = false">{{ t('common.close') }}</v-btn>
        <v-btn color="primary" variant="flat" prepend-icon="mdi-content-copy" :disabled="!rule.command" @click="copyRule">{{ t('common.copy') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <v-dialog v-model="confirmClear" max-width="440">
    <v-card :title="t('flows.clearTitle')">
      <v-card-text>{{ t('flows.clearText') }}</v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn @click="confirmClear = false">{{ t('common.cancel') }}</v-btn>
        <v-btn color="error" variant="flat" @click="clearFlows">{{ t('common.clear') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, query } from '../api'
import { debounce, live, notify, onLive, setLearning } from '../live'
import { classes, fmtTime, hourOptions } from '../util'
import { fmtNum, t } from '../i18n'
import { chains, copyText, defaultTarget, flowRule, targets } from '../iptables'
import CritChip from '../components/CritChip.vue'
import TagChips from '../components/TagChips.vue'

const flowFields = ['hostname', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto']

const route = useRoute()
const router = useRouter()

const filters = reactive({
  q: route.query.q || '',
  class: route.query.class || null,
  hostname: route.query.hostname || null,
  hours: route.query.hours ? Number(route.query.hours) : 24,
  group: route.query.group !== undefined ? String(route.query.group).split(',').filter((f) => flowFields.includes(f)) : [...flowFields],
})
const items = ref([])
const total = ref(0)
const summary = ref([])
const sources = ref([])
const loading = ref(false)
const page = ref(1)
const itemsPerPage = ref(50)
const sortBy = ref([{ key: 'count', order: 'desc' }])
const liveMode = ref(true)
const confirmClear = ref(false)
const ruleDialog = ref(false)
const ruleFlow = ref(null)
const ruleOpts = reactive({ chain: 'INPUT', target: 'ACCEPT', srcPort: false })
const rule = computed(() => (ruleFlow.value ? flowRule(ruleFlow.value, ruleOpts) : { command: '', errors: [], warnings: [] }))
// The log source the rule belongs on, when the flow has a single one.
const ruleHost = computed(() => {
  const f = ruleFlow.value
  if (!f) return ''
  return f.n_hostname > 1 ? '' : f.hostname || filters.hostname || ''
})

const hourItems = computed(() => hourOptions())

const headers = computed(() => [
  { title: t('common.class'), key: 'class', width: 110 },
  // Fields that are not grouped stay visible: they show the value when it is
  // the same for the whole flow, otherwise how many distinct values it has.
  ...flowFields.map((f) =>
    filters.group.includes(f)
      ? { title: t('flows.col.' + f), key: f }
      : { title: t('flows.col.' + f) + t('flows.allSuffix'), key: f, headerProps: { class: 'font-italic text-medium-emphasis' } },
  ),
  { title: t('flows.action'), key: 'actions', sortable: false },
  { title: t('flows.count'), key: 'count', align: 'end', width: 100 },
  { title: t('flows.maxCrit'), key: 'max_crit', width: 100 },
  { title: t('flows.firstSeen'), key: 'first_seen', width: 170 },
  { title: t('flows.lastSeen'), key: 'last_seen', width: 170 },
  { title: '', key: 'open', sortable: false, width: 90 },
])

// The selected source stays selectable even when it has no flows in the
// current window.
const sourceItems = computed(() => {
  const names = sources.value.map((s) => s.hostname).filter(Boolean)
  if (filters.hostname && !names.includes(filters.hostname)) names.unshift(filters.hostname)
  return names
})

const classCards = computed(() =>
  classes.map((name) => {
    const s = summary.value.find((c) => c.class === name)
    return { name, flows: s?.flows || 0, events: s?.events || 0 }
  }),
)

function params() {
  const { group, ...rest } = filters
  // "-" means no grouped fields; an empty value would fall back to all.
  return { ...rest, group: group.join(',') || '-' }
}

async function load() {
  loading.value = true
  const sort = sortBy.value[0] || { key: 'count', order: 'desc' }
  try {
    const res = await api.get('/flows' + query({
      ...params(),
      sort: sort.key,
      order: sort.order,
      limit: itemsPerPage.value,
      offset: (page.value - 1) * itemsPerPage.value,
    }))
    items.value = res.items
    total.value = res.total
    summary.value = res.classes
    sources.value = res.sources
  } catch (e) {
    notify(e.message, 'error')
  } finally {
    loading.value = false
  }
}

function apply() {
  page.value = 1
  const p = params()
  if (p.group === flowFields.join(',')) delete p.group
  router.replace({ query: Object.fromEntries(new URLSearchParams(query(p))) })
  load()
}
const debouncedApply = debounce(apply, 350)

function toggleClass(name) {
  filters.class = filters.class === name ? null : name
  apply()
}

// samples formats the server's truncated, comma separated list of distinct
// values; a value cut off by the truncation is dropped.
function samples(list, n) {
  let vals = list ? list.split(',') : []
  if (list.length >= 300) vals = vals.slice(0, -1)
  const more = n - vals.length
  return vals.map((v) => v || '–').join(', ') + (more > 0 ? ` … (+${fmtNum(more)})` : '')
}

function openRule(flow) {
  ruleFlow.value = flow
  Object.assign(ruleOpts, { chain: 'INPUT', target: defaultTarget(flow), srcPort: false })
  ruleDialog.value = true
}

async function copyRule() {
  if (await copyText(rule.value.command)) notify(t('flows.copied'), 'success')
  else notify(t('flows.copyFailed'), 'error')
}

function toggleSource(name) {
  filters.hostname = filters.hostname === name ? null : name
  apply()
}

function eventsLink(flow) {
  const q = { 'f.class': flow.class }
  for (const f of filters.group) {
    if (f !== 'hostname') q['f.' + f] = flow[f]
  }
  const host = filters.group.includes('hostname') ? flow.hostname : filters.hostname
  if (host) q.hostname = host
  if (filters.hours) q.hours = filters.hours
  return { path: '/events', query: q }
}

async function clearFlows() {
  confirmClear.value = false
  try {
    await api.del('/flows')
    notify(t('flows.cleared'), 'success')
    load()
  } catch (e) {
    notify(e.message, 'error')
  }
}

const liveReload = debounce(() => {
  if (liveMode.value && page.value === 1) load()
}, 1000)

let off
onMounted(() => {
  off = onLive((msg) => {
    if (msg.type === 'flow' || msg.type === 'flows_cleared') liveReload()
  })
})
onUnmounted(() => off?.())
</script>
