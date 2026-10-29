<template>
  <div class="flex flex-wrap gap-1">
    <v-chip
      v-for="t in tags"
      :key="t"
      size="x-small"
      :variant="style(t).variant"
      :color="style(t).color"
      :class="style(t).cls"
      label
      @click.stop="$emit('select', t)"
    >
      <v-icon v-if="style(t).icon" start size="12">{{ style(t).icon }}</v-icon>{{ t }}
    </v-chip>
  </div>
</template>

<script setup>
defineProps({ tags: { type: Array, default: () => [] } })
defineEmits(['select'])

// WHITE/GREY/BLACK carry an icon as well as a colour so they are never
// distinguished by colour alone.
const special = {
  WHITE: { color: 'grey-lighten-4', variant: 'flat', cls: 'text-black font-weight-bold', icon: 'mdi-shield-check' },
  GREY: { color: 'grey', variant: 'flat', cls: 'font-weight-bold', icon: 'mdi-help-circle-outline' },
  BLACK: { color: 'black', variant: 'flat', cls: 'text-white font-weight-bold border-error', icon: 'mdi-skull-outline' },
}

function style(t) {
  return special[t] || { color: 'primary', variant: 'tonal', cls: '' }
}
</script>
