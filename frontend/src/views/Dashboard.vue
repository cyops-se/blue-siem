<template>
  <div class="flex flex-col gap-4">
    <div class="grid gap-4 grid-cols-2 lg:grid-cols-4">
      <v-card v-for="tile in tiles" :key="tile.label" :to="tile.to" variant="flat" border>
        <v-card-text>
          <div class="flex items-center justify-between">
            <span class="text-body-2 text-medium-emphasis">{{ tile.label }}</span>
            <v-icon :color="tile.alert ? 'error' : 'medium-emphasis'">{{ tile.icon }}</v-icon>
          </div>
          <div class="text-h4 font-weight-bold mt-1" :class="tile.alert ? 'text-error' : ''">{{ fmtNum(tile.value) }}</div>
        </v-card-text>
      </v-card>
    </div>

    <div class="grid gap-4 lg:grid-cols-3">
      <v-card variant="flat" border class="lg:col-span-2">
        <v-card-title class="text-subtitle-1">{{ t('dashboard.perHour') }}</v-card-title>
        <v-card-text>
          <div class="flex items-end gap-[2px] h-40 border-b" role="img" :aria-label="t('dashboard.perHourAria', { n: stats.events_recent })">
            <v-tooltip v-for="b in timeline" :key="b.key" location="top">
              <template #activator="{ props }">
                <div v-bind="props" class="flex-1 h-full flex items-end cursor-default group">
                  <div
                    class="w-full rounded-t bg-[rgb(var(--v-theme-primary))] group-hover:opacity-80"
                    :style="{ height: b.count ? Math.max(2, (b.count / maxBucket) * 100) + '%' : '0' }"
                  />
                </div>
              </template>
              <div>{{ b.label }}</div>
              <div><b>{{ fmtNum(b.count) }}</b> {{ t('dashboard.events') }}</div>
              <div v-if="b.count">{{ t('dashboard.highest', { n: b.max, label: critInfo(b.max).label }) }}</div>
            </v-tooltip>
          </div>
          <div class="flex justify-between text-caption text-medium-emphasis mt-1">
            <span>{{ timeline[0]?.hour }}:00</span>
            <span>{{ timeline[12]?.hour }}:00</span>
            <span>{{ t('dashboard.now') }}</span>
          </div>
        </v-card-text>
      </v-card>

      <v-card variant="flat" border>
        <v-card-title class="text-subtitle-1">{{ t('dashboard.classes') }}</v-card-title>
        <v-card-text class="flex flex-col gap-3">
          <router-link
            v-for="c in classRows"
            :key="c.name"
            :to="{ path: '/events', query: { tag: c.name } }"
            class="no-underline text-inherit"
            style="color: inherit; text-decoration: none"
          >
            <div class="flex items-center justify-between mb-1">
              <TagChips :tags="[c.name]" />
              <span class="font-weight-bold">{{ fmtNum(c.count) }}</span>
            </div>
            <v-progress-linear :model-value="c.pct" :color="c.bar" height="6" rounded bg-color="grey" bg-opacity="0.15" />
          </router-link>
        </v-card-text>
      </v-card>
    </div>

    <div class="grid gap-4 lg:grid-cols-3">
      <v-card variant="flat" border>
        <v-card-title class="text-subtitle-1">{{ t('dashboard.crit') }}</v-card-title>
        <v-card-text>
          <div v-if="!critRows.length" class="text-medium-emphasis">{{ t('dashboard.noEvents') }}</div>
          <router-link
            v-for="r in critRows"
            :key="r.level"
            :to="{ path: '/events', query: { min_crit: r.level } }"
            class="flex items-center gap-3 mb-2"
            style="color: inherit; text-decoration: none"
          >
            <CritChip :value="r.level" class="w-28 justify-center" />
            <v-progress-linear :model-value="r.pct" :color="critInfo(r.level).color" height="6" rounded class="flex-1" />
            <span class="w-12 text-right text-body-2">{{ fmtNum(r.count) }}</span>
          </router-link>
        </v-card-text>
      </v-card>

      <v-card variant="flat" border>
        <v-card-title class="text-subtitle-1">{{ t('dashboard.topSources') }}</v-card-title>
        <v-table density="compact">
          <thead>
            <tr><th>{{ t('dashboard.address') }}</th><th class="text-right">{{ t('dashboard.count') }}</th><th>{{ t('dashboard.max') }}</th></tr>
          </thead>
          <tbody>
            <tr v-for="s in stats.top_sources" :key="s.key">
              <td class="mono"><router-link :to="{ path: '/events', query: { q: s.key } }">{{ s.key }}</router-link></td>
              <td class="text-right">{{ fmtNum(s.count) }}</td>
              <td><CritChip :value="s.max" short size="x-small" /></td>
            </tr>
            <tr v-if="!stats.top_sources?.length"><td colspan="3" class="text-medium-emphasis">{{ t('dashboard.noData') }}</td></tr>
          </tbody>
        </v-table>
      </v-card>

      <v-card variant="flat" border>
        <v-card-title class="text-subtitle-1">{{ t('dashboard.byDecoder') }}</v-card-title>
        <v-table density="compact">
          <tbody>
            <tr v-for="d in stats.by_decoder" :key="d.key">
              <td>
                <router-link :to="{ path: '/events', query: { decoder: d.key } }">{{ d.key === '-' ? t('dashboard.noDecoder') : d.key }}</router-link>
              </td>
              <td class="text-right">{{ fmtNum(d.count) }}</td>
            </tr>
            <tr v-if="!stats.by_decoder?.length"><td class="text-medium-emphasis">{{ t('dashboard.noData') }}</td></tr>
          </tbody>
        </v-table>
      </v-card>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { api } from '../api'
import { debounce, onLive } from '../live'
import { critInfo } from '../util'
import { fmtNum, numberLocale, t } from '../i18n'
import CritChip from '../components/CritChip.vue'
import TagChips from '../components/TagChips.vue'

const stats = ref({
  events_total: 0, events_recent: 0, alarms_open: 0, alarms_recent: 0,
  classes: { WHITE: 0, GREY: 0, BLACK: 0 }, by_criticality: [], by_decoder: [], top_sources: [], timeline: [],
})

async function load() {
  stats.value = await api.get('/stats?hours=24')
}

const tiles = computed(() => [
  { label: t('dashboard.events24'), value: stats.value.events_recent, icon: 'mdi-pulse', to: '/events' },
  { label: t('dashboard.openAlarms'), value: stats.value.alarms_open, icon: 'mdi-bell-alert', to: '/alarms', alert: stats.value.alarms_open > 0 },
  { label: t('dashboard.alarms24'), value: stats.value.alarms_recent, icon: 'mdi-bell-outline', to: '/alarms' },
  { label: t('dashboard.stored'), value: stats.value.events_total, icon: 'mdi-database-outline', to: '/events' },
])

const classRows = computed(() => {
  const c = stats.value.classes || {}
  const total = (c.WHITE || 0) + (c.GREY || 0) + (c.BLACK || 0) || 1
  return [
    { name: 'BLACK', count: c.BLACK || 0, bar: 'red-darken-1' },
    { name: 'GREY', count: c.GREY || 0, bar: 'grey' },
    { name: 'WHITE', count: c.WHITE || 0, bar: 'blue-grey-lighten-2' },
  ].map((r) => ({ ...r, pct: (r.count / total) * 100 }))
})

const critRows = computed(() => {
  const rows = (stats.value.by_criticality || []).map((r) => ({ level: Number(r.key), count: r.count }))
  const max = Math.max(1, ...rows.map((r) => r.count))
  return rows.sort((a, b) => b.level - a.level).map((r) => ({ ...r, pct: (r.count / max) * 100 }))
})

// Backend buckets are UTC "YYYY-MM-DD HH"; fill in empty hours.
const timeline = computed(() => {
  const byKey = Object.fromEntries((stats.value.timeline || []).map((r) => [r.key, r]))
  const now = new Date()
  const out = []
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 3600_000)
    const key = d.toISOString().slice(0, 13).replace('T', ' ')
    const hour = String(d.getHours()).padStart(2, '0')
    const r = byKey[key]
    out.push({ key, hour, label: `${d.toLocaleDateString(numberLocale())} ${hour}:00–${hour}:59`, count: r?.count || 0, max: r?.max || 0 })
  }
  return out
})
const maxBucket = computed(() => Math.max(1, ...timeline.value.map((b) => b.count)))

const reload = debounce(load, 1500)
let off
onMounted(() => {
  load()
  off = onLive(reload)
})
onUnmounted(() => off?.())
</script>
