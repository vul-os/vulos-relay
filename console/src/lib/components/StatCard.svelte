<script lang="ts">
  let {
    label,
    value,
    unit = '',
    hint = '',
    accent = 'ink',
  }: {
    label: string;
    value: string;
    unit?: string;
    hint?: string;
    accent?: 'ink' | 'teal' | 'bronze';
  } = $props();

  // Long values (hashes, ids, verbose amounts) must stay legible rather than
  // being silently ellipsised into meaninglessness — step the type size down
  // and let it wrap instead of truncating. The full string is still available
  // as a native tooltip via title.
  let long = $derived(value.length > 13);
</script>

<div class="stat panel">
  <span class="label">{label}</span>
  <div class="value-row">
    <span
      class="value"
      class:long
      class:teal={accent === 'teal'}
      class:bronze={accent === 'bronze'}
      title={long ? value : undefined}>{value}</span
    >
    {#if unit}<span class="unit">{unit}</span>{/if}
  </div>
  {#if hint}<span class="hint">{hint}</span>{/if}
</div>

<style>
  .stat {
    padding: 1.15rem 1.3rem 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    min-width: 0;
  }

  /* Label recedes — small, muted, wide-set, the same register as a table
     column header rather than a heading: it exists to be scanned once, then
     get out of the value's way. */
  .label {
    font-family: var(--font-mono);
    font-size: 0.66rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-muted);
  }

  .value-row {
    display: flex;
    align-items: baseline;
    gap: 0.45rem;
    min-width: 0;
  }

  /* The value is the one thing on this card that must dominate: largest,
     heaviest, tightest tracking, full-strength text colour. Tabular figures
     keep a column of these lining up when several stat cards sit in a row. */
  .value {
    font-family: var(--font-mono);
    font-size: 1.85rem;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    color: var(--text-primary);
    line-height: 1.05;
    letter-spacing: -0.02em;
    min-width: 0;
    /* Wrap rather than truncate — a clipped hash or id reads as broken, not
       tidy. overflow-wrap lets a long unbroken token (a hex digest, an id)
       break as a last resort while normal words still wrap on whitespace. */
    white-space: normal;
    overflow-wrap: break-word;
  }

  /* Long values step down in size (still bold, still dominant relative to
     label/unit/hint) so a verbose id doesn't blow out the card's rhythm or
     force an ellipsis. */
  .value.long {
    font-size: 1.15rem;
    line-height: 1.25;
    letter-spacing: -0.01em;
  }

  .value.teal,
  .value.bronze {
    color: var(--accent);
  }

  .unit {
    font-size: 0.78rem;
    font-weight: 500;
    color: var(--text-faint);
    font-family: var(--font-mono);
    flex-shrink: 0;
  }

  /* Hint sits below, quieter than the label so it never competes with it —
     a footnote to the value, not a second label. */
  .hint {
    font-size: 0.74rem;
    color: var(--text-tertiary);
    line-height: 1.4;
  }
</style>
