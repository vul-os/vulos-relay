<script lang="ts">
  import { client, ApiError } from '../lib/api';
  import type { PrepaidAccount, ReceiptDto, TopUp, UsageDto, ResourceKind } from '../lib/types';
  import { RESOURCE_KINDS } from '../lib/types';
  import { ledgerMoney, kindLabel, kindQuantity, shortHex, formatDate, money } from '../lib/format';

  let accounts = $state<PrepaidAccount[]>([]);
  let selectedPayer = $state<string>('');
  let usage = $state<UsageDto | null>(null);
  let receipts = $state<ReceiptDto[]>([]);
  let auditCaveat = $state('');
  let topups = $state<TopUp[]>([]);
  let loading = $state(true);

  let topUpOpen = $state(false);
  let topUpAmount = $state(50);
  let topUpRail = $state<'stablecoin' | 'card'>('stablecoin');
  let topUpBusy = $state(false);

  let runningBilling = $state(false);
  let runError = $state<string | null>(null);

  let selectedAccount = $derived(accounts.find((a) => a.payer_hex === selectedPayer) ?? null);

  /* Same low-balance test the template used twice inline — named once so the
     "money moment" (figure + flag) and the top-up nudge always agree. */
  let isLow = $derived(
    selectedAccount ? selectedAccount.balance_minor < selectedAccount.low_balance_threshold_minor : false
  );

  $effect(() => {
    (async () => {
      const a = await client.getPrepaidAccounts();
      accounts = a;
      selectedPayer = a[0]?.payer_hex ?? '';
      loading = false;
    })();
  });

  async function loadPayerData(payerHex: string) {
    if (!payerHex) return;
    const [u, r, t] = await Promise.all([
      client.getUsage(payerHex),
      client.getReceiptsForPayer(payerHex),
      client.getTopUps(payerHex),
    ]);
    usage = u;
    receipts = r.receipts;
    auditCaveat = r.one_directional_audit_caveat;
    topups = t;
  }

  $effect(() => {
    if (selectedPayer) loadPayerData(selectedPayer);
  });

  async function doTopUp() {
    if (!selectedAccount || topUpBusy) return;
    topUpBusy = true;
    try {
      await client.topUp(selectedAccount.payer_hex, Math.round(topUpAmount * 1_000_000), topUpRail);
      accounts = await client.getPrepaidAccounts();
      topups = await client.getTopUps(selectedAccount.payer_hex);
      topUpOpen = false;
    } finally {
      topUpBusy = false;
    }
  }

  async function runBilling() {
    if (!selectedAccount) return;
    runError = null;
    runningBilling = true;
    try {
      await client.runBilling(selectedAccount.payer_hex);
      await loadPayerData(selectedAccount.payer_hex);
    } catch (e) {
      runError = e instanceof ApiError ? e.message : 'Could not run the billing period.';
    } finally {
      runningBilling = false;
    }
  }

  async function toggleMonthlyCard() {
    if (!selectedAccount) return;
    const next = !selectedAccount.monthly_card_enabled;
    await client.setMonthlyCard(next);
    accounts = await client.getPrepaidAccounts();
  }

  let hasUsage = $derived(usage ? RESOURCE_KINDS.some((k) => (usage!.usage[k] ?? 0) > 0) : false);
</script>

<div class="page">
  <div class="page-head">
    <span class="kicker">Billing</span>
    <h1>Prepaid ledger</h1>
    <p class="lede">Payers fund a balance up front; usage debits it. No invoicing float, no credit risk to the operator by default.</p>
  </div>

  {#if loading}
    <div class="grid-top skeleton-grid" aria-hidden="true">
      <div class="panel skeleton-panel reveal">
        <div class="panel-header">
          <div class="skeleton-stack">
            <span class="skel-bar skel-kicker"></span>
            <span class="skel-bar skel-title"></span>
          </div>
        </div>
        <div class="panel-body skeleton-stack">
          <span class="skel-bar skel-figure"></span>
          <span class="skel-bar skel-line"></span>
          <span class="skel-bar skel-btn"></span>
        </div>
      </div>
      <div class="panel skeleton-panel reveal reveal-1">
        <div class="panel-header">
          <div class="skeleton-stack">
            <span class="skel-bar skel-kicker"></span>
            <span class="skel-bar skel-title"></span>
          </div>
        </div>
        <div class="panel-body skeleton-stack">
          <span class="skel-bar skel-row"></span>
          <span class="skel-bar skel-row"></span>
          <span class="skel-bar skel-row"></span>
        </div>
      </div>
    </div>
    <p class="visually-hidden" role="status">Loading billing data…</p>
  {:else}
    <div class="payer-row reveal">
      <label for="payer" class="payer-label">Payer</label>
      <select id="payer" bind:value={selectedPayer} class="payer-select">
        {#each accounts as a (a.payer_hex)}
          <option value={a.payer_hex}>{a.payer_label} — {shortHex(a.payer_hex, 6, 4)}</option>
        {/each}
      </select>
    </div>

    {#if selectedAccount}
      <div class="grid-top">
        <section class="panel balance-panel reveal reveal-1">
          <div class="panel-header">
            <div>
              <span class="panel-kicker">Prepaid — patala rails</span>
              <h2>Credit balance</h2>
            </div>
          </div>
          <div class="panel-body balance-body">
            <div class="balance-figure">
              <span class="balance-value" class:low={isLow}>
                {ledgerMoney(selectedAccount.balance_minor, selectedAccount.currency)}
              </span>
              <span class="balance-currency">{selectedAccount.currency}</span>
            </div>

            {#if isLow}
              <div class="balance-flag" role="status">
                <span class="flag-icon" aria-hidden="true">▲</span>
                <span>
                  <strong>Low balance.</strong> Below the {ledgerMoney(selectedAccount.low_balance_threshold_minor, selectedAccount.currency)} top-up
                  threshold — fund soon to avoid a metering gap.
                </span>
              </div>
            {/if}

            <button
              type="button"
              class="btn topup-toggle"
              class:btn-primary={!topUpOpen}
              class:btn-ghost={topUpOpen}
              disabled={topUpBusy}
              onclick={() => (topUpOpen = !topUpOpen)}
            >
              {topUpOpen ? 'Cancel' : 'Top up →'}
            </button>

            {#if topUpOpen}
              <form
                class="topup-form"
                aria-busy={topUpBusy}
                onsubmit={(e) => {
                  e.preventDefault();
                  doTopUp();
                }}
              >
                <div class="field">
                  <label for="amount">Amount ({selectedAccount.currency})</label>
                  <input id="amount" type="number" min="1" step="1" bind:value={topUpAmount} disabled={topUpBusy} />
                </div>

                <fieldset class="field rail-field" disabled={topUpBusy}>
                  <legend class="rail-label">Rail</legend>
                  <div class="rail-choice">
                    <label class="rail-opt" class:active={topUpRail === 'stablecoin'}>
                      <input type="radio" name="rail" value="stablecoin" bind:group={topUpRail} />
                      <span class="rail-opt-text">
                        <span class="rail-opt-title">Stablecoin</span>
                        <span class="rail-opt-sub">USDC</span>
                      </span>
                    </label>
                    <label class="rail-opt" class:active={topUpRail === 'card'}>
                      <input type="radio" name="rail" value="card" bind:group={topUpRail} />
                      <span class="rail-opt-text">
                        <span class="rail-opt-title">Card</span>
                        <span class="rail-opt-sub">patala-hyperswitch</span>
                      </span>
                    </label>
                  </div>
                </fieldset>

                <button type="submit" class="btn btn-primary topup-confirm" disabled={topUpBusy} aria-busy={topUpBusy}>
                  {#if topUpBusy}<span class="spinner" aria-hidden="true"></span>{/if}
                  {topUpBusy ? 'Processing…' : 'Confirm top-up'}
                </button>
              </form>
            {/if}

            <div class="topup-history">
              <span class="panel-kicker">Recent top-ups</span>
              {#if topups.length}
                <ul>
                  {#each topups.slice(0, 4) as t (t.id)}
                    <li>
                      <span class="mono topup-amount">+{money(t.amount_minor, t.currency)}</span>
                      <span class="topup-detail">{t.detail}</span>
                      <span class="topup-date">{formatDate(t.at)}</span>
                    </li>
                  {/each}
                </ul>
              {:else}
                <p class="empty-inline">No top-ups recorded yet for this payer.</p>
              {/if}
            </div>
          </div>
        </section>

        <section class="panel usage-panel reveal reveal-2">
          <div class="panel-header">
            <div>
              <span class="panel-kicker">Current period</span>
              <h2>Metered usage</h2>
            </div>
            <button type="button" class="btn btn-ghost" disabled={runningBilling || !hasUsage} onclick={runBilling}>
              {runningBilling ? 'Billing…' : 'Run billing period →'}
            </button>
          </div>
          <div class="panel-body">
            {#if runError}
              <div class="note note-danger" role="alert"><span aria-hidden="true">✕</span><span>{runError}</span></div>
            {/if}
            {#if usage && hasUsage}
              <div class="scroll-x">
                <table class="ledger">
                  <thead><tr><th>Resource</th><th class="num">Metered</th></tr></thead>
                  <tbody>
                    {#each RESOURCE_KINDS as k (k)}
                      {#if (usage.usage[k] ?? 0) > 0}
                        <tr><td>{kindLabel(k)}</td><td class="mono num">{kindQuantity(k, usage.usage[k] ?? 0)}</td></tr>
                      {/if}
                    {/each}
                  </tbody>
                </table>
              </div>
            {:else}
              <div class="empty-state">
                <span class="empty-icon" aria-hidden="true">∅</span>
                <p class="empty-title">No usage yet this period</p>
                <p class="empty-hint">Meter reset — nothing has accrued for {selectedAccount.payer_label} since the period started.</p>
              </div>
            {/if}

            <div class="settings-block">
              <div class="settings-row">
                <button
                  type="button"
                  id="monthly-card-switch"
                  class="switch"
                  class:on={selectedAccount.monthly_card_enabled}
                  onclick={toggleMonthlyCard}
                  role="switch"
                  aria-checked={selectedAccount.monthly_card_enabled}
                  aria-labelledby="monthly-card-label"
                >
                  <span class="knob"></span>
                </button>
                <label for="monthly-card-switch" id="monthly-card-label" class="settings-title">Monthly card (postpaid)</label>
              </div>
              <p class="settings-desc">Optional fallback via patala-hyperswitch — bills a card at period close instead of debiting prepaid balance. Secondary to prepaid; off unless the operator opts a payer in.</p>
            </div>
          </div>
        </section>
      </div>

      <section class="panel receipts-panel reveal reveal-3">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Signed usage receipts</span>
            <h2>Receipts for {selectedAccount.payer_label}</h2>
          </div>
        </div>
        <div class="panel-body">
          <div class="note note-caution audit-note">
            <span aria-hidden="true">⚑</span>
            <span><strong>One-directional audit.</strong> {auditCaveat}</span>
          </div>
          {#if receipts.length}
            <div class="scroll-x">
              <table class="ledger receipts-table">
                <thead>
                  <tr><th>#</th><th>Kind</th><th class="num">Metered</th><th class="num">Billed</th><th class="num">Amount</th><th>Verifies</th><th>Signer</th></tr>
                </thead>
                <tbody>
                  {#each receipts as r (r.sequence + r.kind)}
                    <tr>
                      <td class="mono">{r.sequence}</td>
                      <td>{kindLabel(r.kind)}</td>
                      <td class="mono num">{kindQuantity(r.kind, r.metered_units)}</td>
                      <td class="mono num">{kindQuantity(r.kind, r.billed_units)}</td>
                      <td class="mono num">{money(r.amount, r.currency)}</td>
                      <td>
                        <span class="pill" class:pill-pass={r.verifies} class:pill-violation={!r.verifies}>
                          <span aria-hidden="true">{r.verifies ? '✓' : '✕'}</span>
                          {r.verifies ? 'signature ok' : 'invalid'}
                        </span>
                      </td>
                      <td class="hex">{shortHex(r.identity_hex, 6, 4)}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {:else}
            <div class="empty-state">
              <span class="empty-icon" aria-hidden="true">∅</span>
              <p class="empty-title">No receipts yet</p>
              <p class="empty-hint">No signed usage receipts have been issued for {selectedAccount.payer_label}.</p>
            </div>
          {/if}
        </div>
      </section>
    {/if}
  {/if}
</div>

<style>
  .page {
    display: flex;
    flex-direction: column;
    gap: 1.4rem;
  }
  .kicker {
    font-family: var(--font-mono);
    font-size: 0.72rem;
    font-weight: 500;
    letter-spacing: 0.02em;
    color: var(--text-muted);
  }
  h1 {
    font-size: 1.9rem;
    margin: 0.2rem 0 0.35rem;
  }
  .lede {
    color: var(--text-secondary);
    margin: 0;
    max-width: 68ch;
  }

  /* ---------- loading skeleton ---------- */
  .skeleton-panel {
    padding: 0;
  }
  .skeleton-stack {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .skel-bar {
    display: block;
    border-radius: var(--radius-sm);
    background: var(--bg-hover);
    animation: skel-pulse 1.6s var(--ease) infinite;
  }
  .skel-kicker {
    width: 7rem;
    height: 0.65rem;
  }
  .skel-title {
    width: 9.5rem;
    height: 1.05rem;
  }
  .skel-figure {
    width: 10rem;
    height: 2rem;
    margin-top: 0.3rem;
  }
  .skel-line {
    width: 14rem;
    height: 0.8rem;
  }
  .skel-btn {
    width: 8rem;
    height: 2.2rem;
    margin-top: 0.4rem;
    border-radius: var(--radius-sm);
  }
  .skel-row {
    width: 100%;
    height: 1.7rem;
  }
  @keyframes skel-pulse {
    0%,
    100% {
      opacity: 0.5;
    }
    50% {
      opacity: 1;
    }
  }

  /* ---------- composed empty states ---------- */
  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: 0.3rem;
    padding: 1.9rem 1.2rem;
    border: 1px dashed var(--border-strong);
    border-radius: var(--radius-md);
    background: color-mix(in srgb, var(--bg-base) 55%, transparent);
  }
  .empty-icon {
    font-size: 1.3rem;
    line-height: 1;
    color: var(--text-faint);
    margin-bottom: 0.15rem;
  }
  .empty-title {
    margin: 0;
    font-weight: 600;
    font-size: 0.85rem;
    color: var(--text-secondary);
  }
  .empty-hint {
    margin: 0;
    font-size: 0.78rem;
    color: var(--text-tertiary);
    max-width: 40ch;
  }
  .empty-inline {
    margin: 0.5rem 0 0;
    font-size: 0.76rem;
    color: var(--text-tertiary);
  }

  .payer-row {
    display: flex;
    align-items: center;
    gap: 0.7rem;
  }
  .payer-label {
    margin: 0;
    flex-shrink: 0;
  }
  .payer-select {
    max-width: 24rem;
  }
  .grid-top {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1.3fr);
    gap: 1.1rem;
    align-items: start;
  }
  @media (max-width: 980px) {
    .grid-top {
      grid-template-columns: 1fr;
    }
  }

  /* ---------- the money moment ---------- */
  .balance-body {
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
  }
  .balance-figure {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .balance-value {
    font-family: var(--font-mono);
    font-size: 2.35rem;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.015em;
    font-variant-numeric: tabular-nums;
    line-height: 1;
  }
  .balance-value.low {
    color: var(--status-danger);
  }
  .balance-currency {
    font-family: var(--font-mono);
    font-size: 0.82rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    color: var(--text-tertiary);
  }
  /* Non-colour-only low-balance tell: a bordered flag with its own glyph and
     bold lead-in, not just a red number — reads the same on a colour-blind
     pass or a printed screenshot. */
  .balance-flag {
    display: flex;
    align-items: flex-start;
    gap: 0.5rem;
    font-size: 0.78rem;
    line-height: 1.45;
    color: var(--text-primary);
    background: var(--status-danger-soft);
    border: 1px solid color-mix(in srgb, var(--status-danger) 45%, var(--border-strong));
    border-radius: var(--radius-sm);
    padding: 0.55rem 0.7rem;
  }
  .flag-icon {
    color: var(--status-danger);
    flex-shrink: 0;
    line-height: 1.5;
  }

  .topup-toggle {
    align-self: flex-start;
  }

  .topup-form {
    border-top: 1px solid var(--border-default);
    padding-top: 0.9rem;
    margin-top: 0.3rem;
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
  }
  .rail-field {
    border: 0;
    margin: 0;
    padding: 0;
    min-width: 0;
  }
  .rail-label {
    font-size: 0.78rem;
    font-weight: 600;
    color: var(--text-secondary);
    display: block;
    margin: 0 0 0.35rem;
    padding: 0;
  }
  .rail-choice {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }
  .rail-opt {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    border: 1px solid var(--border-strong);
    border-radius: 7px;
    padding: 0.55rem 0.7rem;
    color: var(--text-secondary);
    cursor: pointer;
    transition: border-color var(--dur-fast) var(--ease), background-color var(--dur-fast) var(--ease);
  }
  .rail-opt:hover {
    border-color: var(--border-emphasis);
  }
  .rail-opt:focus-within {
    box-shadow: var(--focus-ring);
    border-radius: var(--radius-sm);
  }
  .rail-opt.active {
    border-color: var(--accent);
    color: var(--text-primary);
    background: var(--accent-soft);
  }
  .rail-opt input {
    width: auto;
    flex-shrink: 0;
    accent-color: var(--accent);
  }
  .rail-opt-text {
    display: flex;
    flex-direction: column;
    line-height: 1.3;
  }
  .rail-opt-title {
    font-size: 0.84rem;
    font-weight: 600;
  }
  .rail-opt-sub {
    font-size: 0.72rem;
    color: var(--text-tertiary);
  }
  .rail-opt.active .rail-opt-sub {
    color: var(--text-secondary);
  }

  .topup-confirm {
    justify-content: center;
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

  .topup-history {
    border-top: 1px solid var(--border-default);
    padding-top: 0.8rem;
    margin-top: 0.2rem;
  }
  .topup-history ul {
    list-style: none;
    margin: 0.5rem 0 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .topup-history li {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 0.5rem;
    font-size: 0.78rem;
  }
  .topup-amount {
    color: var(--status-success);
    font-weight: 600;
  }
  .topup-detail {
    color: var(--text-secondary);
  }
  .topup-date {
    color: var(--text-tertiary);
    margin-left: auto;
  }

  /* ---------- postpaid toggle row ---------- */
  .settings-block {
    border-top: 1px solid var(--border-default);
    margin-top: 1.1rem;
    padding-top: 1rem;
  }
  /* Switch and its label are one tight unit — no space-between drift, so the
     control and the word describing it never separate, on any width. The
     longer description sits on its own full-width line below. */
  .settings-row {
    display: flex;
    align-items: center;
    gap: 0.65rem;
    flex-wrap: wrap;
  }
  .settings-title {
    font-weight: 600;
    font-size: 0.86rem;
    margin: 0;
    cursor: pointer;
  }
  .settings-desc {
    margin: 0.4rem 0 0;
    font-size: 0.76rem;
    color: var(--text-tertiary);
    max-width: 46ch;
  }
  .switch {
    position: relative;
    flex-shrink: 0;
    width: 2.6rem;
    height: 1.5rem;
    border-radius: 999px;
    background: var(--bg-base);
    border: 1px solid var(--border-strong);
    padding: 0.15rem;
    display: flex;
    align-items: center;
    cursor: pointer;
    transition: background-color var(--dur) var(--ease), border-color var(--dur) var(--ease);
  }
  .switch.on {
    background: color-mix(in srgb, var(--accent) 45%, var(--bg-base));
    border-color: color-mix(in srgb, var(--accent) 55%, var(--border-strong));
  }
  .knob {
    display: block;
    width: 1.1rem;
    height: 1.1rem;
    border-radius: 50%;
    background: var(--bg-elevated);
    box-shadow: var(--shadow-sm);
    transform: translateX(0);
    transition: transform var(--dur) var(--ease);
  }
  .switch.on .knob {
    transform: translateX(1.1rem);
  }

  /* ---------- receipts table ---------- */
  .receipts-table td,
  .receipts-table th {
    padding-top: 0.72rem;
    padding-bottom: 0.72rem;
  }
  .receipts-table .pill span[aria-hidden] {
    margin-right: 0.15rem;
  }
  .audit-note {
    margin-bottom: 1rem;
  }

  @media (max-width: 600px) {
    .balance-value {
      font-size: 1.9rem;
    }
  }
</style>
