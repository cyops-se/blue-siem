<template>
  <v-chip :color="info.color" :size="size" variant="flat" label class="font-weight-bold" :prepend-icon="info.icon">
    {{ value }}<span v-if="!short" class="ml-1 font-weight-regular">{{ info.label }}</span>
  </v-chip>
</template>

<script setup>
import { computed } from 'vue'
import { critInfo } from '../util'

const props = defineProps({
  value: { type: Number, default: 0 },
  size: { type: String, default: 'small' },
  short: Boolean,
})
const info = computed(() => critInfo(props.value))
</script>
