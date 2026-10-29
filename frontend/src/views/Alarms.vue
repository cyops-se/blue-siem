<template>
  <v-card variant="flat" border>
    <div class="flex flex-wrap items-center gap-3 px-4 pt-3">
      <v-btn-toggle v-model="status" mandatory density="comfortable" variant="outlined" divided @update:model-value="load">
        <v-btn value="open" prepend-icon="mdi-bell-ring-outline">{{ t('alarms.open') }}</v-btn>
        <v-btn value="acked" prepend-icon="mdi-check-all">{{ t('alarms.acked') }}</v-btn>
        <v-btn value="all">{{ t('alarms.all') }}</v-btn>
      </v-btn-toggle>
      <v-spacer />
      <v-btn
        v-if="status !== 'acked'"
        :disabled="!selected.length"
        color="primary"
        variant="flat"
        prepend-icon="mdi-check"
        @click="openAck(selected)"
      >
        {{ t('alarms.ackSelected', { n: selected.length }) }}
      </v-btn>
      <v-btn
        v-if="status !== 'acked'"
        :disabled="!live.openAlarms"
        variant="outlined"
        prepend-icon="mdi-check-all"
        @click="openAck('all')"
      >
        {{ t('alarms.ackAll') }}
      </v-btn>
    </div>

    <v-data-table
      v-model="selected"
      v-model:expanded="expanded"
      :headers="headers"
      :items="items"
      :loading="loading"
      :show-select="status !== 'acked'"
      item-value="id"
      :item-selectable="(a) => !a.acknowledged"
      show-expand
      density="comfortable"
      :items-per-page="50"
      class="mt-2"
      :no-data-text="t('alarms.none')"
    >
      <template #item.created_at="{ item }"><span class="whitespace-nowrap">{{ fmtTime(item.created_at) }}</span></template>
      <template #item.criticality="{ item }"><CritChip :value="item.criticality" /></template>
      <template #item.title="{ item }">
        <div class="font-weight-medium">{{ item.title }}</div>
        <div class="text-caption text-medium-emphasis msg-cell mono max-w-[340px]" :title="item.summary">{{ item.summary }}</div>
      </template>
      <template #item.tags="{ item }"><TagChips :tags="item.event?.tags || []" class="max-w-[220px]" /></template>
      <template #item.status="{ item }">
        <div v-if="item.acknowledged" class="text-body-2">
          <v-icon color="success" size="16">mdi-check-circle</v-icon>
          {{ item.acked_by }}
          <div class="text-caption text-medium-emphasis">{{ fmtTime(item.acked_at) }}</div>
          <div v-if="item.ack_comment" class="text-caption">”{{ item.ack_comment }}”</div>
        </div>
        <v-btn v-else size="small" color="primary" variant="tonal" prepend-icon="mdi-check" @click.stop="openAck([item.id])">{{ t('alarms.ack') }}</v-btn>
      </template>
      <template #expanded-row="{ columns, item }">
        <tr>
          <td :colspan="columns.length">
            <div class="text-caption text-medium-emphasis pt-2">{{ t('alarms.rules', { rules: item.rules }) }}</div>
            <EventDetail v-if="item.event" :event="item.event" />
            <div v-else class="py-3 text-medium-emphasis">{{ t('alarms.eventGone') }}</div>
          </td>
        </tr>
      </template>
    </v-data-table>
  </v-card>

  <v-dialog v-model="ackDialog" max-width="480">
    <v-card :title="ackTarget === 'all' ? t('alarms.ackAllTitle') : t('alarms.ackNTitle', { n: ackTarget.length })">
      <v-card-text class="flex flex-col gap-3">
        <v-text-field v-model="ackUser" :label="t('alarms.ackedBy')" prepend-inner-icon="mdi-account" autofocus :rules="[(v) => !!v?.trim() || t('common.required')]" />
        <v-textarea v-model="ackComment" :label="t('alarms.comment')" rows="3" auto-grow />
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn @click="ackDialog = false">{{ t('common.cancel') }}</v-btn>
        <v-btn color="primary" variant="flat" :disabled="!ackUser?.trim()" :loading="acking" @click="doAck">{{ t('alarms.ack') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { api } from '../api'
import { debounce, live, notify, onLive } from '../live'
import { fmtTime } from '../util'
import { t } from '../i18n'
import CritChip from '../components/CritChip.vue'
import TagChips from '../components/TagChips.vue'
import EventDetail from '../components/EventDetail.vue'

const status = ref('open')
const items = ref([])
const loading = ref(false)
const selected = ref([])
const expanded = ref([])

const ackDialog = ref(false)
const ackTarget = ref([])
const ackUser = ref(readUser())
const ackComment = ref('')
const acking = ref(false)

const headers = computed(() => [
  { title: t('common.time'), key: 'created_at', width: 170 },
  { title: t('common.criticality'), key: 'criticality', width: 130 },
  { title: t('alarms.alarm'), key: 'title', sortable: false },
  { title: t('common.tags'), key: 'tags', sortable: false },
  { title: t('alarms.status'), key: 'status', sortable: false, width: 200 },
  { title: '', key: 'data-table-expand', width: 40 },
])

function readUser() {
  try {
    return localStorage.getItem('ackUser') || ''
  } catch {
    return ''
  }
}

async function load() {
  loading.value = true
  try {
    const res = await api.get(`/alarms?status=${status.value}&limit=1000`)
    items.value = res.items
    const ids = new Set(res.items.filter((a) => !a.acknowledged).map((a) => a.id))
    selected.value = selected.value.filter((id) => ids.has(id))
  } catch (e) {
    notify(e.message, 'error')
  } finally {
    loading.value = false
  }
}

function openAck(target) {
  ackTarget.value = target
  ackComment.value = ''
  ackDialog.value = true
}

async function doAck() {
  acking.value = true
  try {
    const body = { user: ackUser.value.trim(), comment: ackComment.value }
    const res = ackTarget.value === 'all'
      ? await api.post('/alarms/ack', { ...body, all: true })
      : await api.post('/alarms/ack', { ...body, ids: ackTarget.value })
    try {
      localStorage.setItem('ackUser', body.user)
    } catch {
      // storage unavailable
    }
    notify(t('alarms.acknowledged', { n: res.acknowledged }), 'success')
    ackDialog.value = false
    selected.value = []
    load()
  } catch (e) {
    notify(e.message, 'error')
  } finally {
    acking.value = false
  }
}

const reload = debounce(load, 500)
let off
onMounted(() => {
  load()
  off = onLive((msg) => {
    if (['alarm', 'ack', 'cleared'].includes(msg.type)) reload()
  })
})
onUnmounted(() => off?.())
</script>
