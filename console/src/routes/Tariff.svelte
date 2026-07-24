<script lang="ts">
  import { client, ApiError } from '../lib/api';
  import type { TariffDto, ResourceKind } from '../lib/types';
  import { RESOURCE_KINDS } from '../lib/types';
  import { kindLabel, kindRecommendedPrice, kindNaturalUnitLabel, shortHex } from '../lib/format';

  let tariff = $state<TariffDto | null>(null);
  let loading = $state(true);

  let currency = $state('USD');
  let prices = $state<Record<ResourceKind, number>>({
    bytes_forwarded: 0,
    connections: 0,
    messages: 0,
    compute_seconds: 0,
  });
  let freeAllowance = $state<Record<ResourceKind, number>>({
    bytes_forwarded: 0,
    connections: 0,
    messages: 0,
    compute_seconds: 0,
  });
  let periodDays = $state(30);

  let saving = $state(false);
  let errorMsg = $state<string | null>(null);
  let published = $state(false);

  const RECOMMENDED: Record<ResourceKind, { microUsd: number; basis: string }> = {
    bytes_forwarded: { microUsd: 5, basis: 'Hetzner Cloud egress overage (~$1.2/TB) + margin' },
    connections: { microUsd: 35, basis: 'Vultr LB connection overhead, cost-plus ~3×' },
    messages: { microUsd: 12, basis: 'Amortized broker CPU + storage per message' },
    compute_seconds: { microUsd: 13, basis: 'Vultr/Hetzner shared-vCPU core-hour, cost-plus' },
  };

  $effect(() => {
    (async () => {
      const t = await client.getTariff();
      tariff = t;
      if (t) {
        currency = t.schedule.currency;
        for (const k of RESOURCE_KINDS) {
          prices[k] = t.schedule.prices[k] ?? 0;
          freeAllowance[k] = t.schedule.free_allowance[k] ?? 0;
        }
        periodDays = t.schedule.period_seconds ? Math.round(t.schedule.period_seconds / 86400) : 30;
      }
      loading = false;
    })();
  });

  function applyRecommended() {
    for (const k of RESOURCE_KINDS) prices[k] = RECOMMENDED[k].microUsd;
  }

  async function publish() {
    errorMsg = null;
    saving = true;
    published = false;
    try {
      const res = await client.putTariff({
        currency,
        prices: { ...prices },
        free_allowance: { ...freeAllowance },
        period_seconds: periodDays * 86400,
      });
      tariff = res;
      published = true;
    } catch (e) {
      errorMsg = e instanceof ApiError ? e.message : 'Could not publish the tariff.';
    } finally {
      saving = false;
    }
  }

  /* ---------- draft-vs-live diff cue (presentation only) ----------
     No pricing maths lives here — just an equality check against what's
     already loaded, so the editor can show the operator which rows (and
     which top-level fields) have drifted from the schedule actually signed
     and in force. Nothing here feeds `publish()` or the recommended-price
     helpers; it only decides what gets a "changed" mark on screen. */
  let rowDirty = $derived.by(() => {
    const d: Partial<Record<ResourceKind, boolean>> = {};
    const live = tariff?.schedule;
    for (const k of RESOURCE_KINDS) {
      d[k] = live
        ? (prices[k] ?? 0) !== (live.prices[k] ?? 0) || (freeAllowance[k] ?? 0) !== (live.free_allowance[k] ?? 0)
        : false;
    }
    return d;
  });

  let isDirty = $derived.by(() => {
    const live = tariff?.schedule;
    if (!live) return true; // nothing signed yet — the draft is inherently pending
    const livePeriodDays = live.period_seconds ? Math.round(live.period_seconds / 86400) : 30;
    return currency !== live.currency || periodDays !== livePeriodDays || RESOURCE_KINDS.some((k) => rowDirty[k]);
  });
</script>

<div class="page">
  <header class="page-head reveal">
    <span class="panel-kicker">Pricing</span>
    <h1>Tariff schedule</h1>
    <p class="lede">Priced in an existing currency, never a protocol token (DIRECTION §5) — this UI has no field for one, on purpose.</p>
  </header>

  {#if loading}
    <div class="loading-state reveal" role="status" aria-live="polite">
      <p class="loading-line">
        <span class="loading-dot" aria-hidden="true"></span>
        Reading the current tariff…
      </p>

      <div class="panel skeleton-panel" aria-hidden="true">
        <div class="skeleton-head">
          <span class="skeleton skeleton-kicker"></span>
          <span class="skeleton skeleton-title"></span>
        </div>
        <div class="skeleton-body">
          <span class="skeleton skeleton-line" style="width: 92%"></span>
          <span class="skeleton skeleton-line" style="width: 76%"></span>
          <span class="skeleton skeleton-line" style="width: 84%"></span>
        </div>
      </div>

      <div class="layout" aria-hidden="true">
        <div class="panel skeleton-panel">
          <div class="skeleton-head">
            <span class="skeleton skeleton-kicker"></span>
            <span class="skeleton skeleton-title"></span>
          </div>
          <div class="skeleton-body">
            <span class="skeleton skeleton-field"></span>
            <span class="skeleton skeleton-field" style="width: 60%"></span>
            <div class="skeleton-grid">
              {#each Array.from({ length: 4 }) as _, i (i)}
                <span class="skeleton skeleton-row"></span>
              {/each}
            </div>
          </div>
        </div>
        <div class="panel skeleton-panel">
          <div class="skeleton-head">
            <span class="skeleton skeleton-kicker"></span>
            <span class="skeleton skeleton-title"></span>
          </div>
          <div class="skeleton-body">
            <span class="skeleton skeleton-badge"></span>
            <span class="skeleton skeleton-field" style="width: 70%"></span>
            <span class="skeleton skeleton-field" style="width: 50%"></span>
          </div>
        </div>
      </div>
    </div>
  {:else}
    <section class="panel recommend-panel reveal reveal-1">
      <div class="panel-header">
        <div>
          <span class="panel-kicker">Reference only</span>
          <h2>Recommended USD pricing</h2>
        </div>
        <button type="button" class="btn btn-ghost" onclick={applyRecommended}>Apply to draft below →</button>
      </div>
      <div class="panel-body">
        <p class="disclaimer">
          <strong>These are recommendations, not a default you're bound to.</strong> Cost-plus estimates over
          common self-host targets (Hetzner, Vultr) at a modest margin — set your own numbers below; nothing
          in the protocol ranks or steers on price (CONTRACT §2.1, no price-rank field exists).
        </p>
        <div class="scroll-x">
          <table class="ledger">
            <thead>
              <tr>
                <th>Resource kind</th>
                <th>Recommended</th>
                <th>Basis</th>
              </tr>
            </thead>
            <tbody>
              {#each RESOURCE_KINDS as k (k)}
                <tr>
                  <td>{kindLabel(k)}</td>
                  <td class="mono price-cell">{kindRecommendedPrice(k, RECOMMENDED[k].microUsd)} / {kindNaturalUnitLabel(k)}</td>
                  <td class="basis">{RECOMMENDED[k].basis}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <div class="layout">
      <section class="panel draft-panel reveal reveal-2">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Draft · editable</span>
            <h2>Your tariff</h2>
          </div>
          <span class="pill" class:pill-behavioral={isDirty} class:pill-pass={!isDirty}>
            <span class="light-dot" aria-hidden="true"></span>
            {isDirty ? 'Unsigned changes' : 'Matches live'}
          </span>
        </div>
        <div class="panel-body">
          <div class="field-row">
            <div class="field field-currency">
              <label for="currency">Currency / asset</label>
              <input id="currency" type="text" bind:value={currency} placeholder="USD" />
              <p class="field-hint">Any existing currency or asset string — USD, USDC, EUR. Never a Ephor-minted token.</p>
            </div>
            <div class="field field-period">
              <label for="period">Billing period</label>
              <div class="unit-input">
                <input id="period" type="number" min="1" bind:value={periodDays} />
                <span class="unit-suffix" aria-hidden="true">days</span>
              </div>
            </div>
          </div>

          <div class="grid-caption">
            <span class="panel-kicker">Per-resource pricing</span>
            <span class="grid-caption-hint">≈ Per unit is derived from the price — read-only.</span>
          </div>

          <div class="scroll-x">
            <table class="ledger price-table">
              <thead>
                <tr>
                  <th class="col-kind"><span class="col-title">Resource kind</span></th>
                  <th class="col-price">
                    <span class="col-title">Price</span>
                    <span class="col-sub">µ{currency || 'USD'} / unit</span>
                  </th>
                  <th class="col-computed">
                    <span class="col-title">≈ Per unit</span>
                    <span class="col-sub">derived</span>
                  </th>
                  <th class="col-allowance">
                    <span class="col-title">Free allowance</span>
                    <span class="col-sub">units / period</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {#each RESOURCE_KINDS as k (k)}
                  <tr class:row-dirty={rowDirty[k]}>
                    <td class="cell-kind">
                      {#if rowDirty[k]}<span class="light-dot dirty-dot" aria-hidden="true" title="Differs from the live tariff"></span>{/if}
                      <span>{kindLabel(k)}</span>
                    </td>
                    <td class="cell-price" data-label="Price">
                      <input
                        type="number"
                        min="0"
                        bind:value={prices[k]}
                        aria-label={`Price for ${kindLabel(k)}, in micro-${currency || 'USD'} per unit`}
                      />
                    </td>
                    <td class="cell-computed" data-label="≈ Per unit">
                      <span
                        class="computed-chip"
                        aria-label={`Computed, read-only: ${kindRecommendedPrice(k, prices[k])} per ${kindNaturalUnitLabel(k)}`}
                      >
                        <span class="computed-value">{kindRecommendedPrice(k, prices[k])}</span>
                        <span class="computed-unit">/ {kindNaturalUnitLabel(k)}</span>
                      </span>
                    </td>
                    <td class="cell-allowance" data-label="Free allowance">
                      <input
                        type="number"
                        min="0"
                        bind:value={freeAllowance[k]}
                        aria-label={`Free allowance for ${kindLabel(k)}`}
                      />
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>

          {#if errorMsg}
            <div class="note note-danger" role="alert">
              <span aria-hidden="true">✕</span>
              <span>{errorMsg}</span>
            </div>
          {/if}

          <div class="sign-bar">
            <button
              type="button"
              class="btn btn-primary btn-sign"
              disabled={saving}
              aria-busy={saving}
              onclick={publish}
            >
              {#if saving}
                <span class="spinner" aria-hidden="true"></span>
              {:else}
                <span aria-hidden="true">✒</span>
              {/if}
              {saving ? 'Signing…' : 'Sign & publish tariff'}
            </button>
            <p class="sign-hint">
              Signs with the coordinator's operator key and replaces the live schedule immediately — every payer
              is billed at these rates from that moment on.
            </p>
            {#if published}
              <div class="note publish-success" role="status">
                <span class="glyph" aria-hidden="true">✓</span>
                <span>Published — attached to the signed descriptor.</span>
              </div>
            {/if}
          </div>
        </div>
      </section>

      <section class="panel live-panel reveal reveal-3">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Live · signed</span>
            <h2>Currently signed</h2>
          </div>
        </div>
        <div class="panel-body">
          {#if tariff}
            <div class="cert-block">
              <div class="stamp stamp-signed" aria-hidden="true">Signed<br />&amp; live</div>
              <dl class="cert-facts">
                <dt>Currency</dt><dd>{tariff.schedule.currency}</dd>
                <dt>Signer</dt><dd class="hex">{shortHex(tariff.identity_hex)}</dd>
                <dt>Signature</dt><dd class="hex">{shortHex(tariff.sig_hex)}</dd>
                <dt>Period</dt><dd>{tariff.schedule.period_seconds ? `${Math.round(tariff.schedule.period_seconds / 86400)} days` : 'unset'}</dd>
              </dl>
            </div>
            <div class="scroll-x">
              <table class="ledger">
                <thead><tr><th>Kind</th><th>Price</th><th>Free allowance</th></tr></thead>
                <tbody>
                  {#each RESOURCE_KINDS as k (k)}
                    <tr>
                      <td>{kindLabel(k)}</td>
                      <td class="mono">{kindRecommendedPrice(k, tariff.schedule.prices[k] ?? 0)} / {kindNaturalUnitLabel(k)}</td>
                      <td class="mono">{tariff.schedule.free_allowance[k] ?? 0}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {:else}
            <div class="cert-block cert-block-empty">
              <div class="stamp stamp-empty" aria-hidden="true">Not<br />signed</div>
              <div class="empty-copy">
                <p class="empty-title">No tariff signed yet</p>
                <p class="empty-hint">
                  Not metered — compose a draft on the left, then sign &amp; publish. It becomes the live schedule
                  the instant it's signed.
                </p>
              </div>
            </div>
          {/if}
        </div>
      </section>
    </div>

    <div class="note reveal reveal-4">
      <span aria-hidden="true">◈</span>
      <span><strong>No token, ever.</strong> KOTVA mints none (CONTRACT §6, DIRECTION §5). A field to configure one doesn't exist in this form — the admin API rejects an attempt on the wire, too.</span>
    </div>
  {/if}
</div>

<style>
  .page {
    display: flex;
    flex-direction: column;
    gap: var(--space-6);
  }

  .page-head {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    padding-bottom: var(--space-5);
    border-bottom: 1px solid var(--border-subtle);
    position: relative;
  }

  /* A short bronze segment riding the header's own rule — the same "ruled
     masthead" idiom used on .panel-header::after, scaled up for the page head. */
  .page-head::after {
    content: '';
    position: absolute;
    left: 0;
    right: 58%;
    bottom: -1px;
    height: 1px;
    background: linear-gradient(90deg, var(--accent), transparent 90%);
    opacity: 0.6;
  }

  h1 {
    font-size: 1.7rem;
    margin: var(--space-1) 0 var(--space-2);
  }

  .lede {
    color: var(--text-secondary);
    margin: 0;
    max-width: 62ch;
  }

  /* ---------- loading state ----------
     A composed skeleton of the real layout (reference table, then the two-up
     draft/live grid) rather than a bare status line, so the shape of the page
     is legible before the numbers land. */
  .loading-state {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }

  .loading-line {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin: 0;
    color: var(--text-tertiary);
    font-family: var(--font-mono);
    font-size: 0.85rem;
  }

  .loading-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 25%, transparent);
    flex-shrink: 0;
    animation: loading-pulse calc(var(--dur-slow) * 4) var(--ease) infinite;
  }

  @keyframes loading-pulse {
    0%,
    100% {
      opacity: 0.35;
      transform: scale(0.85);
    }
    50% {
      opacity: 1;
      transform: scale(1);
    }
  }

  .skeleton {
    display: block;
    border-radius: var(--radius-xs);
    background: color-mix(in srgb, var(--bg-elevated) 65%, var(--bg-hover) 35%);
    animation: skeleton-pulse calc(var(--dur-slow) * 4) var(--ease) infinite;
  }

  @keyframes skeleton-pulse {
    0%,
    100% {
      opacity: 0.5;
    }
    50% {
      opacity: 1;
    }
  }

  .skeleton-head {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    padding: var(--space-4) var(--space-5) var(--space-3);
    border-bottom: 1px solid var(--border-subtle);
  }

  .skeleton-kicker {
    width: 5rem;
    height: 0.6rem;
  }

  .skeleton-title {
    width: 55%;
    height: 1.05rem;
  }

  .skeleton-body {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-5);
  }

  .skeleton-field {
    width: 100%;
    height: 2.2rem;
    border-radius: var(--radius-sm);
  }

  .skeleton-badge {
    height: 5.6rem;
    border-radius: var(--radius-md);
  }

  .skeleton-grid {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin-top: var(--space-1);
  }

  .skeleton-row {
    width: 100%;
    height: 2.4rem;
    border-radius: var(--radius-sm);
  }

  /* ---------- recommended-pricing panel ---------- */
  .disclaimer {
    font-size: 0.84rem;
    color: var(--text-secondary);
    margin: 0 0 1rem;
    max-width: 72ch;
  }

  .price-cell {
    color: var(--accent);
    font-weight: 600;
  }

  .basis {
    color: var(--text-tertiary);
    font-size: 0.78rem;
  }

  /* ---------- two-up layout ---------- */
  .layout {
    display: grid;
    grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr);
    gap: var(--space-5);
    align-items: start;
  }

  @media (max-width: 980px) {
    .layout {
      grid-template-columns: 1fr;
    }
  }

  /* Draft reads as work-in-progress: a dashed outline over the shared .panel
     base (border-STYLE only — the colour stays --border-strong, no new hue),
     the same idiom carried through to the empty "not signed" stamp below. */
  .draft-panel {
    border-style: dashed;
  }

  /* Live sits opposite as the settled artifact: solid border, a touch more
     shadow so it reads as the heavier, "already decided" side of the pair. */
  .live-panel {
    box-shadow: var(--shadow-sm);
  }

  /* ---------- draft form ---------- */
  .field-row {
    display: grid;
    grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr);
    gap: var(--space-4);
    align-items: start;
  }

  @media (max-width: 560px) {
    .field-row {
      grid-template-columns: 1fr;
    }
  }

  .unit-input {
    position: relative;
  }

  .unit-input input {
    padding-right: 3.2rem;
  }

  .unit-suffix {
    position: absolute;
    right: 0.7rem;
    top: 50%;
    transform: translateY(-50%);
    font-size: 0.72rem;
    color: var(--text-faint);
    letter-spacing: 0.03em;
    pointer-events: none;
  }

  .grid-caption {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: var(--space-2);
    flex-wrap: wrap;
    margin: var(--space-2) 0 var(--space-2);
  }

  .grid-caption-hint {
    font-size: 0.72rem;
    color: var(--text-faint);
  }

  /* ---------- the price grid ----------
     Fixed column widths so PRICE / ≈ PER UNIT / FREE-ALLOWANCE line up down
     the table instead of drifting with each row's content, and a two-line
     header (title + unit caption) instead of letting the browser wrap the
     phrase mid-word. */
  .price-table {
    table-layout: fixed;
  }

  .col-kind {
    width: 32%;
  }

  .col-price,
  .col-allowance {
    width: 22%;
  }

  .col-computed {
    width: 24%;
  }

  .col-title {
    display: block;
  }

  .col-sub {
    display: block;
    margin-top: 0.15rem;
    font-size: 0.62rem;
    font-weight: 400;
    letter-spacing: 0.02em;
    text-transform: none;
    color: var(--text-faint);
  }

  .price-table td {
    vertical-align: middle;
  }

  .cell-kind {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-weight: 500;
  }

  .price-table input {
    min-width: 0;
    text-align: right;
    font-variant-numeric: tabular-nums;
    font-feature-settings: 'tnum' 1;
  }

  /* The changed-row tint reuses the same warning token the "Unsigned changes"
     pill uses — the row and the header pill are one visual statement, not
     two unrelated cues. */
  tr.row-dirty {
    background: var(--status-warning-soft);
  }

  tr.row-dirty:hover {
    background: color-mix(in srgb, var(--status-warning) 10%, transparent);
  }

  .dirty-dot {
    color: var(--status-warning);
  }

  /* A recessed, dashed slot for a value that is computed, never typed — the
     same depth language as .note (a --bg-base recess reads as "not a raised,
     editable surface"), with a dashed rather than solid edge to echo the
     draft panel's own "not yet final" outline. */
  .computed-chip {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    justify-content: center;
    gap: 0.1rem;
    width: 100%;
    min-height: 2.15rem;
    padding: 0.4rem 0.7rem;
    background: var(--bg-base);
    border: 1px dashed var(--border-strong);
    border-radius: var(--radius-sm);
    box-sizing: border-box;
  }

  .computed-value {
    font-family: var(--font-mono);
    font-size: 0.82rem;
    font-weight: 600;
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
    font-feature-settings: 'tnum' 1;
    white-space: nowrap;
  }

  .computed-unit {
    font-size: 0.66rem;
    color: var(--text-faint);
    white-space: nowrap;
  }

  /* ---------- phone: reflow the price grid into stacked, labelled cards —
     a sideways-scrolling data-entry table is unusable for numeric input, so
     below ~700px the table drops its header and each row becomes a small
     card: the kind as a title, price/allowance side by side, the computed
     readout spanning underneath. `order` re-sequences the fixed DOM order
     (kind, price, computed, allowance) into that card shape without any
     duplicate markup. ---------- */
  @media (max-width: 700px) {
    .price-table,
    .price-table tbody,
    .price-table tr,
    .price-table td {
      display: block;
      width: 100%;
    }

    .price-table thead {
      display: none;
    }

    .price-table tbody tr {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.5rem 0.75rem;
      padding: var(--space-3) 0;
      border-bottom: 1px solid var(--border-subtle);
    }

    .price-table tbody tr:last-child {
      border-bottom: none;
    }

    .price-table td {
      padding: 0;
      border-bottom: none;
    }

    .cell-kind {
      order: 1;
      grid-column: 1 / -1;
      font-size: 0.92rem;
    }

    .cell-price {
      order: 2;
    }

    .cell-allowance {
      order: 3;
    }

    .cell-computed {
      order: 4;
      grid-column: 1 / -1;
    }

    .cell-computed .computed-chip {
      align-items: flex-start;
    }

    .price-table td[data-label]::before {
      content: attr(data-label);
      display: block;
      font-size: 0.62rem;
      font-weight: 500;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      color: var(--text-tertiary);
      margin-bottom: 0.3rem;
    }

    .price-table input {
      text-align: left;
    }
  }

  /* ---------- sign bar ---------- */
  .sign-bar {
    margin-top: var(--space-4);
    padding-top: var(--space-4);
    border-top: 1px solid var(--border-default);
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }

  .btn-sign {
    align-self: flex-start;
    padding: 0.7rem 1.3rem;
    font-size: 0.88rem;
  }

  @media (max-width: 560px) {
    .btn-sign {
      align-self: stretch;
      justify-content: center;
    }
  }

  .spinner {
    width: 0.75rem;
    height: 0.75rem;
    border-radius: 50%;
    border: 2px solid color-mix(in srgb, var(--accent-fill-contrast) 35%, transparent);
    border-top-color: var(--accent-fill-contrast);
    animation: spin 700ms linear infinite;
    flex-shrink: 0;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .sign-hint {
    margin: 0;
    max-width: 52ch;
    font-size: 0.76rem;
    color: var(--text-tertiary);
  }

  .publish-success .glyph {
    color: var(--status-success);
  }

  /* ---------- live panel: the certificate block ----------
     The stamp anchors this as a certificate letterhead rather than sitting
     alone in the header — signer/signature/period read as the fine print
     underneath the seal. */
  .cert-block {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    padding-bottom: var(--space-4);
    margin-bottom: var(--space-4);
    border-bottom: 1px solid var(--border-default);
  }

  @media (max-width: 460px) {
    .cert-block {
      flex-direction: column;
      align-items: flex-start;
      text-align: left;
    }
  }

  .cert-facts {
    flex: 1;
    min-width: 0;
    display: grid;
    grid-template-columns: 6.5rem 1fr;
    row-gap: 0.55rem;
    column-gap: 0.6rem;
    margin: 0;
    font-size: 0.84rem;
  }

  .cert-facts dt {
    font-family: var(--font-mono);
    font-size: 0.66rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-tertiary);
    align-self: center;
  }

  .cert-facts dd {
    margin: 0;
    min-width: 0;
    word-break: break-all;
  }

  /* The "not yet signed" stamp: same ring, a dashed edge and the faint token
     instead of bronze — an absence of ink, not a new colour. */
  .stamp-empty {
    color: var(--text-faint);
    border-style: dashed;
  }

  .cert-block-empty {
    align-items: center;
  }

  .empty-copy {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    min-width: 0;
  }

  .empty-title {
    margin: 0;
    font-family: var(--font-mono);
    font-weight: 700;
    font-size: 0.92rem;
    color: var(--text-primary);
  }

  .empty-hint {
    margin: 0;
    color: var(--text-secondary);
    max-width: 40ch;
  }
</style>
