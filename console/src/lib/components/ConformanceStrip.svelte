<script module lang="ts">
  // Exported so other views (e.g. the Overview summary card) can reuse the same clause titles
  // instead of re-declaring them — the single source of truth for what COORD-1..8 stand for.
  export const CLAUSE_TITLE: Record<string, string> = {
    'COORD-1': 'Signed, discovery-only descriptor',
    'COORD-2': 'Zero lock-in',
    'COORD-3': 'Self-host backstop',
    'COORD-4': 'Declared content-visibility',
    'COORD-5': 'No silent downgrade',
    'COORD-6': 'Authorize, never classify',
    'COORD-7': 'Signed receipts if metered',
    'COORD-8': 'No token; existing-asset settlement',
  };

  const OUTCOME_WORD: Record<string, string> = {
    pass: 'Pass',
    behavioral: 'Behavioral',
    violation: 'Violation',
  };
</script>

<script lang="ts">
  import type { ReportDto } from '../types';

  let { report }: { report: ReportDto } = $props();
</script>

<div class="strip" role="list" aria-label="COORD-1..8 conformance status">
  {#each report.findings as f (f.id)}
    <div class="light" role="listitem" class:pass={f.outcome === 'pass'} class:behavioral={f.outcome === 'behavioral'} class:violation={f.outcome === 'violation'}>
      <button
        type="button"
        class="light-btn"
        aria-describedby={`coord-tip-${f.id}`}
        aria-label={`${f.id}, ${CLAUSE_TITLE[f.id] ?? f.clause} — ${OUTCOME_WORD[f.outcome] ?? f.outcome}`}
      >
        <!-- The mark's SHAPE carries the outcome (check / bar / cross), never
             colour alone — a reader with no colour perception, or a printed
             greyscale screenshot, still reads pass vs behavioral vs violation. -->
        <span class="mark" aria-hidden="true">
          {#if f.outcome === 'pass'}
            <svg viewBox="0 0 16 16" fill="none"><path d="M3.2 8.6l3.1 3 6.5-6.8" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg>
          {:else if f.outcome === 'behavioral'}
            <svg viewBox="0 0 16 16" fill="none"><path d="M8 3.4v6.1M8 12.6h.01" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/></svg>
          {:else}
            <svg viewBox="0 0 16 16" fill="none"><path d="M4.2 4.2l7.6 7.6M11.8 4.2l-7.6 7.6" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/></svg>
          {/if}
        </span>
        <span class="label">
          <span class="id">{f.id}</span>
          <span class="clause">{f.clause}</span>
        </span>
      </button>
      <div class="tooltip" id={`coord-tip-${f.id}`} role="tooltip">
        <strong>{CLAUSE_TITLE[f.id] ?? f.id}</strong>
        <span class="outcome-word">{OUTCOME_WORD[f.outcome] ?? f.outcome}</span>
        {#if f.detail}<p>{f.detail}</p>{/if}
      </div>
    </div>
  {/each}
</div>

<style>
  .strip {
    display: grid;
    grid-template-columns: repeat(8, minmax(0, 1fr));
    gap: 0.5rem;
  }

  @media (max-width: 760px) {
    .strip {
      grid-template-columns: repeat(4, minmax(0, 1fr));
    }
  }

  @media (max-width: 420px) {
    .strip {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }

  .light {
    position: relative;
    border-radius: var(--radius-md);
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    transition: border-color var(--dur) var(--ease), transform var(--dur-fast) var(--ease);
  }

  .light.pass {
    color: var(--status-success);
  }
  .light.behavioral {
    color: var(--status-warning);
  }
  .light.violation {
    color: var(--status-danger);
  }

  .light:hover {
    border-color: color-mix(in srgb, currentColor 45%, var(--border-default));
  }

  /* The button IS the light — full-bleed, transparent, reset of native button
     chrome — so the whole tile is a single keyboard-focusable hit target that
     both reveals the tooltip and carries a full accessible name. */
  .light-btn {
    all: unset;
    box-sizing: border-box;
    width: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.4rem;
    padding: 0.7rem 0.4rem;
    border-radius: inherit;
    cursor: default;
    color: inherit;
    transition: transform var(--dur-fast) var(--ease);
  }

  .light-btn:active {
    transform: scale(0.97);
  }

  .mark {
    width: 1.3rem;
    height: 1.3rem;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    color: currentColor;
    background: color-mix(in srgb, currentColor 14%, transparent);
    box-shadow: 0 0 0 1px color-mix(in srgb, currentColor 30%, transparent);
    flex-shrink: 0;
  }

  .mark svg {
    width: 0.85rem;
    height: 0.85rem;
  }

  .label {
    display: flex;
    flex-direction: column;
    align-items: center;
    line-height: 1.2;
  }

  .id {
    font-family: var(--font-mono);
    font-size: 0.68rem;
    font-weight: 700;
    color: var(--text-primary);
  }

  .clause {
    font-family: var(--font-mono);
    font-size: 0.62rem;
    color: var(--text-tertiary);
  }

  .tooltip {
    position: absolute;
    bottom: calc(100% + 0.5rem);
    left: 50%;
    transform: translateX(-50%) translateY(4px);
    width: 15rem;
    max-width: 70vw;
    background: var(--text-primary);
    color: var(--bg-base);
    border-radius: var(--radius-sm);
    padding: 0.6rem 0.75rem;
    font-size: 0.72rem;
    line-height: 1.4;
    opacity: 0;
    pointer-events: none;
    transition: opacity var(--dur) var(--ease), transform var(--dur) var(--ease);
    z-index: 20;
    box-shadow: var(--shadow-lg);
  }

  .tooltip strong {
    display: block;
    color: var(--bg-base);
    font-family: var(--font-mono);
  }

  .tooltip .outcome-word {
    display: inline-block;
    text-transform: uppercase;
    font-family: var(--font-mono);
    font-size: 0.62rem;
    letter-spacing: 0.08em;
    opacity: 0.75;
    margin-top: 0.15rem;
  }

  /* Left un-set: the detail sentence is running prose, so it inherits the
     global p → --font-sans rule, same split as everywhere else in the app —
     mono chrome (strong / outcome-word above), sans prose. */
  .tooltip p {
    margin: 0.35rem 0 0;
    opacity: 0.9;
  }

  .light:hover .tooltip,
  .light:focus-within .tooltip {
    opacity: 1;
    transform: translateX(-50%) translateY(0);
  }

  /* Focus lands on the inner button; the ring should read against the tile,
     not vanish under the reset button styles. */
  .light-btn:focus-visible {
    box-shadow: var(--focus-ring);
    border-radius: var(--radius-md);
  }
</style>
