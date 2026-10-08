<!-- Copyright 2026 Cisco Systems, Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<script setup lang="ts">
import { ref } from "vue";
import { withBase } from "vitepress";

const props = defineProps<{
  src: string;
  alt: string;
  caption: string;
  label?: string;
}>();

const open = ref(false);
</script>

<template>
  <figure class="app-shot">
    <button
      class="app-shot__button"
      type="button"
      :aria-label="`Enlarge: ${alt}`"
      @click="open = true"
    >
      <img :src="withBase(src)" :alt="alt" loading="lazy" decoding="async" />
      <span class="app-shot__zoom" aria-hidden="true">Enlarge ↗</span>
    </button>
    <figcaption>
      <span v-if="label">{{ label }}</span
      >{{ caption }}
    </figcaption>
  </figure>
  <Teleport to="body">
    <div
      v-if="open"
      class="shot-lightbox"
      role="dialog"
      aria-modal="true"
      :aria-label="alt"
      @click.self="open = false"
      @keydown.esc="open = false"
    >
      <button type="button" aria-label="Close image" @click="open = false">
        Close ×
      </button>
      <img :src="withBase(src)" :alt="alt" />
    </div>
  </Teleport>
</template>
