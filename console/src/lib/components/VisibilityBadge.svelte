<script lang="ts">
  import type { VisibilityDto } from '../types';
  import {
    CLASS_LABEL,
    CLASS_DESCRIPTION,
    LEVEL_LABEL,
    LEVEL_DESCRIPTION,
    mustNotPresentAsVerified,
    isVerifiablyBlind,
  } from '../visibility';

  let { visibility, size = 'lg' }: { visibility: VisibilityDto; size?: 'lg' | 'sm' } = $props();

  let warn = $derived(mustNotPresentAsVerified(visibility));
  let verifiablyBlind = $derived(isVerifiablyBlind(visibility));
</script>

<div class="badge" class:sm={size === 'sm'} class:warn>
  <div class="glyph" aria-hidden="true">
    {#if visibility.class === 'terminating'}
      <svg viewBox="0 0 24 24" fill="none"><path d="M6 12h12M14 6l6 6-6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
    {:else if verifiablyBlind}
      <svg viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3.5v5c0 4.5-3 8.2-7 9.5-4-1.3-7-5-7-9.5v-5L12 3z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
    {:else}
      <svg viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3.5v5c0 4.5-3 8.2-7 9.5-4-1.3-7-5-7-9.5v-5L12 3z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M12 8v5M12 16.5h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
    {/if}
  </div>
  <div class="text">
    <div class="class-row">
      <span class="class-label">{CLASS_LABEL[visibility.class]}</span>
      <span class="sep">/</span>
      <span class="level-label">{LEVEL_LABEL[visibility.level]}</span>
    </div>
    <p class="desc">{CLASS_DESCRIPTION[visibility.class]}</p>
    {#if warn}
      <div class="assurance-note warn-text">
        <svg class="caveat-icon" aria-hidden="true" viewBox="0 0 24 24" fill="none">
          <path
            d="M12 4.2 21 19.5H3L12 4.2z"
            stroke="currentColor"
            stroke-width="1.8"
            stroke-linejoin="round"
          /><path d="M12 10.4v4.1M12 17.3h.01" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
        </svg>
        <p><strong>Declared, not verified.</strong> {LEVEL_DESCRIPTION[visibility.level]} A relying party cannot check this claim independently (CONTRACT §3.4) — never present it as verified.</p>
      </div>
    {:else if verifiablyBlind}
      <p class="assurance-note ok-text">
        <strong>{LEVEL_LABEL[visibility.level]} — verifiable.</strong> {LEVEL_DESCRIPTION[visibility.level]}
      </p>
    {:else}
      <p class="assurance-note">
        <strong>Disclosed trust boundary.</strong> {LEVEL_DESCRIPTION[visibility.level]}
      </p>
    {/if}
  </div>
</div>

<style>
  .badge {
    display: flex;
    gap: 1rem;
    align-items: flex-start;
    padding: 1.1rem 1.3rem;
    border-radius: var(--radius-lg);
    border: 1.5px solid var(--accent);
    background: var(--accent-soft);
    transition: border-color var(--dur) var(--ease), background-color var(--dur) var(--ease);
  }

  .badge.warn {
    border-color: var(--status-warning);
    background: var(--status-warning-soft);
  }

  .badge.sm {
    padding: 0.7rem 0.9rem;
    border-radius: var(--radius-md);
  }

  .glyph {
    width: 2.4rem;
    height: 2.4rem;
    flex-shrink: 0;
    color: var(--accent);
    border-radius: 50%;
    background: var(--bg-elevated);
    display: flex;
    align-items: center;
    justify-content: center;
    border: 1px solid var(--border-default);
  }

  .badge.warn .glyph {
    color: var(--status-warning);
  }

  .glyph svg {
    width: 1.3rem;
    height: 1.3rem;
  }

  .sm .glyph {
    width: 1.9rem;
    height: 1.9rem;
  }
  .sm .glyph svg {
    width: 1.05rem;
    height: 1.05rem;
  }

  .text {
    min-width: 0;
  }

  .class-row {
    font-family: var(--font-mono);
    font-weight: 700;
    font-size: 1.5rem;
    letter-spacing: -0.01em;
    display: flex;
    align-items: baseline;
    gap: 0.4rem;
    flex-wrap: wrap;
  }

  .sm .class-row {
    font-size: 1.05rem;
  }

  .sep {
    color: var(--text-tertiary);
    font-weight: 400;
  }

  .level-label {
    font-family: var(--font-mono);
    font-size: 0.95rem;
    color: var(--text-secondary);
    font-weight: 500;
  }
  .sm .level-label {
    font-size: 0.8rem;
  }

  .desc {
    margin: 0.3rem 0 0;
    font-size: 0.82rem;
    color: var(--text-secondary);
    max-width: 52ch;
  }
  .sm .desc {
    display: none;
  }

  .assurance-note {
    margin: 0.7rem 0 0;
    font-size: 0.78rem;
    line-height: 1.5;
    color: var(--text-secondary);
    max-width: 54ch;
  }

  .assurance-note p {
    margin: 0;
  }

  .sm .assurance-note {
    font-size: 0.72rem;
    margin-top: 0.45rem;
  }

  /* The "declared, not verified" caveat is a callout, not a stray sentence:
     a left rule + its own icon give it shape independent of colour, so the
     caveat still reads as a caveat if colour is stripped entirely. */
  .warn-text {
    display: flex;
    align-items: flex-start;
    gap: 0.5rem;
    padding: 0.55rem 0.7rem;
    border-radius: var(--radius-sm);
    background: color-mix(in srgb, var(--status-warning) 10%, transparent);
    box-shadow: inset 2px 0 0 var(--status-warning);
  }

  .caveat-icon {
    width: 1.05rem;
    height: 1.05rem;
    flex-shrink: 0;
    margin-top: 0.1rem;
    color: var(--status-warning);
  }

  .sm .caveat-icon {
    width: 0.9rem;
    height: 0.9rem;
  }

  .warn-text strong {
    color: var(--status-warning);
  }
  .ok-text strong {
    color: var(--accent);
  }
</style>
