<template>
  <v-app>
    <v-navigation-drawer v-model="drawer" :rail="rail" :permanent="mdAndUp" :temporary="!mdAndUp">
      <div class="flex items-center gap-2 px-4 py-4">
        <v-icon color="primary" size="28">mdi-shield-half-full</v-icon>
        <span v-if="!rail || !mdAndUp" class="text-h6 font-weight-bold">Blue SIEM</span>
      </div>
      <v-divider />
      <v-list nav density="comfortable">
        <v-list-item v-for="item in nav" :key="item.to" :to="item.to" :prepend-icon="item.icon" :title="t(item.title)" exact>
          <template v-if="item.to === '/alarms' && live.openAlarms > 0" #append>
            <v-badge :content="live.openAlarms" color="error" inline />
          </template>
        </v-list-item>
      </v-list>
    </v-navigation-drawer>

    <v-app-bar flat border="b" density="comfortable">
      <v-app-bar-nav-icon @click="mdAndUp ? (rail = !rail) : (drawer = !drawer)" />
      <v-app-bar-title>{{ route.meta.title ? t(route.meta.title) : '' }}</v-app-bar-title>
      <v-chip
        v-if="live.learning"
        color="warning"
        variant="flat"
        size="small"
        class="mr-2"
        prepend-icon="mdi-school-outline"
        to="/flows"
        :title="t('app.learningTitle')"
      >
        {{ t('app.learning') }}
      </v-chip>
      <v-chip
        :color="live.connected ? 'success' : 'grey'"
        variant="tonal"
        size="small"
        class="mr-2"
        :prepend-icon="live.connected ? 'mdi-access-point' : 'mdi-access-point-off'"
      >
        {{ live.connected ? t('app.connected') : t('app.disconnected') }}
      </v-chip>
      <v-btn icon to="/alarms" :title="t('app.openAlarms', { n: live.openAlarms })">
        <v-badge :model-value="live.openAlarms > 0" :content="live.openAlarms" color="error">
          <v-icon>{{ live.openAlarms > 0 ? 'mdi-bell-ring' : 'mdi-bell-outline' }}</v-icon>
        </v-badge>
      </v-btn>
      <v-menu>
        <template #activator="{ props }">
          <v-btn v-bind="props" icon :title="t('common.language')">
            <v-icon>mdi-translate</v-icon>
          </v-btn>
        </template>
        <v-list density="compact">
          <v-list-item
            v-for="l in locales"
            :key="l.value"
            :title="l.title"
            :active="i18n.locale === l.value"
            @click="setLocale(l.value)"
          />
        </v-list>
      </v-menu>
      <v-btn icon :title="t('app.toggleTheme')" @click="toggleTheme">
        <v-icon>{{ theme.global.current.value.dark ? 'mdi-weather-sunny' : 'mdi-weather-night' }}</v-icon>
      </v-btn>
    </v-app-bar>

    <v-main>
      <div class="p-4 md:p-6 max-w-[1600px] mx-auto">
        <router-view />
      </div>
    </v-main>

    <v-snackbar v-model="live.snackbar.show" :color="live.snackbar.color" timeout="5000" location="bottom right">
      {{ live.snackbar.text }}
      <template #actions>
        <v-btn v-if="live.snackbar.color !== 'success'" variant="text" to="/alarms" @click="live.snackbar.show = false">{{ t('common.show') }}</v-btn>
        <v-btn variant="text" icon="mdi-close" @click="live.snackbar.show = false" />
      </template>
    </v-snackbar>
  </v-app>
</template>

<script setup>
import { onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useDisplay, useTheme } from 'vuetify'
import { live, notify, onLive, startLive } from './live'
import { critInfo } from './util'
import { i18n, locales, setLocale, t } from './i18n'
import { pageTitle } from './router'

const route = useRoute()
const theme = useTheme()
const { mdAndUp } = useDisplay()
const drawer = ref(true)
const rail = ref(false)

const nav = [
  { to: '/', title: 'nav.dashboard', icon: 'mdi-view-dashboard-outline' },
  { to: '/events', title: 'nav.events', icon: 'mdi-format-list-bulleted' },
  { to: '/flows', title: 'nav.flows', icon: 'mdi-transit-connection-variant' },
  { to: '/alarms', title: 'nav.alarms', icon: 'mdi-bell-alert-outline' },
  { to: '/decoders', title: 'nav.decoders', icon: 'mdi-code-braces' },
  { to: '/rules', title: 'nav.rules', icon: 'mdi-scale-balance' },
  { to: '/iplists', title: 'nav.iplists', icon: 'mdi-ip-network-outline' },
  { to: '/test', title: 'nav.test', icon: 'mdi-flask-outline' },
  { to: '/settings', title: 'nav.settings', icon: 'mdi-cog-outline' },
]

watch(() => i18n.locale, () => {
  document.title = pageTitle(route)
})

function toggleTheme() {
  const next = theme.global.current.value.dark ? 'light' : 'dark'
  theme.global.name.value = next
  try {
    localStorage.setItem('theme', next)
  } catch {
    // storage unavailable
  }
}

let off
onMounted(() => {
  startLive()
  off = onLive((msg) => {
    if (msg.type === 'alarm') {
      const c = critInfo(msg.data.criticality)
      notify(t('app.newAlarm', { crit: msg.data.criticality, label: c.label, title: msg.data.title }), c.color)
    }
  })
})
onUnmounted(() => off?.())
</script>
