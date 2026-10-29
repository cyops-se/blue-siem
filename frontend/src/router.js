import { createRouter, createWebHistory } from 'vue-router'
import { t } from './i18n'

const routes = [
  { path: '/', name: 'dashboard', component: () => import('./views/Dashboard.vue'), meta: { title: 'nav.dashboard' } },
  { path: '/events', name: 'events', component: () => import('./views/Events.vue'), meta: { title: 'nav.events' } },
  { path: '/flows', name: 'flows', component: () => import('./views/Flows.vue'), meta: { title: 'nav.flows' } },
  { path: '/alarms', name: 'alarms', component: () => import('./views/Alarms.vue'), meta: { title: 'nav.alarms' } },
  { path: '/decoders', name: 'decoders', component: () => import('./views/Decoders.vue'), meta: { title: 'nav.decoders' } },
  { path: '/rules', name: 'rules', component: () => import('./views/Rules.vue'), meta: { title: 'nav.rules' } },
  { path: '/iplists', name: 'iplists', component: () => import('./views/IpLists.vue'), meta: { title: 'nav.iplists' } },
  { path: '/test', name: 'test', component: () => import('./views/Test.vue'), meta: { title: 'nav.testTitle' } },
  { path: '/settings', name: 'settings', component: () => import('./views/Settings.vue'), meta: { title: 'nav.settings' } },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

const router = createRouter({ history: createWebHistory(), routes })

// meta.title is a message key; App.vue also updates the title when the
// language changes.
export function pageTitle(route) {
  return route.meta.title ? `${t(route.meta.title)} · Blue SIEM` : 'Blue SIEM'
}

router.afterEach((to) => {
  document.title = pageTitle(to)
})

export default router
