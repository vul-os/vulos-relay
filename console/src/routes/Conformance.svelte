<script lang="ts">
  import { client } from '../lib/api';
  import type { ReportDto, FindingDto, Outcome } from '../lib/types';

  let report = $state<ReportDto | null>(null);
  let loading = $state(true);

  $effect(() => {
    (async () => {
      report = await client.getConformance();
      loading = false;
    })();
  });

  const ROWS: { id: string; title: string; summary: string }[] = [
    { id: 'COORD-1', title: 'Signed, discovery-only descriptor', summary: 'No global score, no price rank, no stake field — structurally, by the type.' },
    { id: 'COORD-2', title: 'Zero lock-in', summary: 'Switching operator is a config change: no data migration, no identity change.' },
    { id: 'COORD-3', title: 'Self-host backstop', summary: 'Anyone meeting the kind\'s requirement can run it themselves — or the one disclosed scarce-reachability exception.' },
    { id: 'COORD-4', title: 'Declared content-visibility', summary: 'Exactly one class + level declared; a declared-level blind claim must be shown unverified, never verified.' },
    { id: 'COORD-5', title: 'No silent downgrade', summary: 'Declaring terminating is the disclosure required; claiming blind while operating terminating is the violation.' },
    { id: 'COORD-6', title: 'Authorize, never classify', summary: 'Gates delivery-path traffic on sender identity + rate only, or sits on no delivery path at all.' },
    { id: 'COORD-7', title: 'Signed receipts if metered', summary: 'Metering without payer-facing signed receipts is a violation.' },
    { id: 'COORD-8', title: 'No token; existing-asset settlement', summary: 'Stakes/settles only in existing assets — minting a protocol token is forbidden.' },
  ];

  // Every outcome pairs a word with a distinct glyph — pass/behavioral/violation must never
  // ride on colour alone (an honesty requirement: amber "behavioral" reads as genuinely
  // different from red "violation", not just a lighter shade of the same warning).
  const OUTCOME_ICON: Record<Outcome, string> = {
    pass: '✓',
    behavioral: '◐',
    violation: '✕',
  };

  function findingFor(id: string, r: ReportDto | null): FindingDto | undefined {
    return r?.findings.find((f) => f.id === id);
  }

  function revealClass(i: number): string {
    return `reveal-${Math.min(i + 1, 6)}`;
  }
</script>

<div class="page">
  <div class="page-head reveal">
    <span class="kicker">Conformance</span>
    <h1>COORD-1..8 checklist</h1>
    <p class="lede">Every coordinator kind inherits the same eight clauses (CONTRACT §7). Some are decidable from the descriptor; others are marked <strong>behavioral</strong> — honestly deferred to a runtime test, never falsely passed.</p>
  </div>

  {#if loading}
    <div class="summary-bar panel skel-bar reveal reveal-1" aria-busy="true">
      <span class="visually-hidden" role="status">Running the self-check…</span>
      <div class="skel skel-pill" aria-hidden="true"></div>
      <div class="skel skel-counts" aria-hidden="true"></div>
    </div>
    <div class="rows">
      {#each ROWS as row, i (row.id)}
        <div class="panel skel-finding reveal {revealClass(i)}" aria-hidden="true"></div>
      {/each}
    </div>
  {:else if !report}
    <div class="empty-state panel">
      <span class="empty-icon" aria-hidden="true">◈</span>
      <p class="empty-title">Conformance report unavailable</p>
      <p class="empty-copy">The self-check did not return a report for this coordinator. Try reloading the console.</p>
    </div>
  {:else}
    <div class="summary-bar panel reveal reveal-1">
      <div class="summary-top">
        <div class="summary-left">
          <span class="pill" class:pill-pass={report.is_conformant} class:pill-violation={!report.is_conformant}>
            <span aria-hidden="true">{report.is_conformant ? '✓' : '✕'}</span>
            {report.is_conformant ? 'Conformant — no violations' : 'Non-conformant'}
          </span>
          <span class="summary-kind">kind: {report.kind}</span>
        </div>
        <div class="counts">
          <span><span class="light-dot pass-dot" aria-hidden="true"></span> {report.findings.filter((f) => f.outcome === 'pass').length} pass</span>
          <span><span class="light-dot behavioral-dot" aria-hidden="true"></span> {report.findings.filter((f) => f.outcome === 'behavioral').length} behavioral</span>
          <span><span class="light-dot violation-dot" aria-hidden="true"></span> {report.findings.filter((f) => f.outcome === 'violation').length} violation</span>
        </div>
      </div>
      <p class="summary-caveat">
        <strong>Behavioral</strong> means decidable only against real traffic — it is a deferred check, never a violation.
      </p>
    </div>

    <div class="rows">
      {#each ROWS as row, i (row.id)}
        {@const f = findingFor(row.id, report)}
        <article
          class="finding panel reveal {revealClass(i)}"
          class:pass={f?.outcome === 'pass'}
          class:behavioral={f?.outcome === 'behavioral'}
          class:violation={f?.outcome === 'violation'}
        >
          <div class="finding-badge">
            <span class="light-dot" aria-hidden="true"></span>
            <span class="fid">{row.id}</span>
            <span class="fclause">{f?.clause}</span>
          </div>
          {#if f}
            <span class="outcome-pill pill" class:pill-pass={f.outcome === 'pass'} class:pill-behavioral={f.outcome === 'behavioral'} class:pill-violation={f.outcome === 'violation'}>
              <span class="outcome-icon" aria-hidden="true">{OUTCOME_ICON[f.outcome]}</span>
              {f.outcome}
            </span>
          {:else}
            <span class="outcome-pill pill outcome-unknown">
              <span class="outcome-icon" aria-hidden="true">?</span>
              no finding
            </span>
          {/if}
          <div class="finding-body">
            <h2>{row.title}</h2>
            <p class="summary">{row.summary}</p>
            {#if f?.detail}
              <p class="detail"><span class="detail-label">{f.outcome}:</span> {f.detail}</p>
            {/if}
          </div>
        </article>
      {/each}
    </div>
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
    max-width: 72ch;
  }

  /* ---------- summary bar ---------- */

  .summary-bar {
    padding: 1rem 1.3rem;
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  .summary-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.8rem;
  }
  .summary-left {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    flex-wrap: wrap;
  }
  .summary-kind {
    font-family: var(--font-mono);
    font-size: 0.78rem;
    color: var(--text-tertiary);
  }
  .counts {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    font-size: 0.78rem;
    color: var(--text-secondary);
    font-family: var(--font-mono);
  }
  .counts span {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
  }
  .pass-dot {
    color: var(--status-success);
  }
  .behavioral-dot {
    color: var(--status-warning);
  }
  .violation-dot {
    color: var(--status-danger);
  }
  .summary-caveat {
    margin: 0;
    padding-top: 0.6rem;
    border-top: 1px solid var(--border-default);
    font-size: 0.76rem;
    color: var(--text-tertiary);
    line-height: 1.5;
  }
  .summary-caveat strong {
    color: var(--status-warning);
  }

  /* ---------- finding rows ---------- */

  .rows {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  /* Explicit column placement (rather than relying on source order) lets the DOM/reading
     order put the outcome right after the clause id — screen readers hear "what" then
     "what happened" then "why" — while the visual layout still keeps the pill pinned to
     the trailing edge, matching the original card shape. */
  .finding {
    display: grid;
    grid-template-columns: 6rem 1fr auto;
    align-items: start;
    gap: 1rem;
    padding: 1rem 1.3rem;
    border-left: 4px solid var(--border-default);
  }
  .finding-badge {
    grid-column: 1;
  }
  .finding-body {
    grid-column: 2;
  }
  .outcome-pill {
    grid-column: 3;
  }

  .finding.pass {
    border-left-color: var(--status-success);
  }
  .finding.behavioral {
    border-left-color: var(--status-warning);
  }
  .finding.violation {
    border-left-color: var(--status-danger);
  }

  @media (max-width: 700px) {
    .finding {
      grid-template-columns: 1fr;
    }
    .finding-badge,
    .finding-body,
    .outcome-pill {
      grid-column: auto;
    }
  }

  .finding-badge {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }
  .finding.pass .finding-badge {
    color: var(--status-success);
  }
  .finding.behavioral .finding-badge {
    color: var(--status-warning);
  }
  .finding.violation .finding-badge {
    color: var(--status-danger);
  }
  .fid {
    font-family: var(--font-mono);
    font-weight: 700;
    font-size: 0.82rem;
    color: var(--text-primary);
  }
  .fclause {
    font-family: var(--font-mono);
    font-size: 0.7rem;
    color: var(--text-tertiary);
  }

  .finding-body h2 {
    font-size: 0.98rem;
    margin-bottom: 0.3rem;
  }
  .summary,
  .detail {
    max-width: 68ch;
  }
  .summary {
    margin: 0;
    font-size: 0.82rem;
    color: var(--text-secondary);
    line-height: 1.5;
  }
  .detail {
    margin: 0.5rem 0 0;
    font-size: 0.78rem;
    color: var(--text-primary);
    background: var(--bg-base);
    border-radius: var(--radius-sm);
    padding: 0.5rem 0.7rem;
    line-height: 1.5;
  }
  .detail-label {
    text-transform: uppercase;
    font-family: var(--font-mono);
    font-size: 0.66rem;
    letter-spacing: 0.06em;
    color: var(--text-tertiary);
    margin-right: 0.3rem;
  }

  .outcome-pill {
    align-self: start;
    text-transform: uppercase;
  }
  .outcome-icon {
    font-size: 0.8em;
  }
  .outcome-unknown {
    background: var(--bg-elevated);
    color: var(--text-faint);
    border-color: var(--border-strong);
  }

  /* ---------- empty / loading states ---------- */

  .empty-state {
    text-align: center;
    padding: 2.6rem 1rem;
    color: var(--text-tertiary);
  }
  .empty-icon {
    display: inline-flex;
    width: 2.3rem;
    height: 2.3rem;
    align-items: center;
    justify-content: center;
    border: 1px solid var(--border-strong);
    border-radius: 50%;
    color: var(--text-faint);
    font-size: 1.05rem;
    margin-bottom: 0.65rem;
  }
  .empty-title {
    margin: 0 0 0.3rem;
    font-family: var(--font-mono);
    font-weight: 600;
    font-size: 0.88rem;
    color: var(--text-secondary);
  }
  .empty-copy {
    margin: 0 auto;
    font-size: 0.8rem;
    max-width: 40ch;
    line-height: 1.5;
  }

  @keyframes conf-pulse {
    0%,
    100% {
      opacity: 0.55;
    }
    50% {
      opacity: 1;
    }
  }
  /* Outer placeholders keep the real .panel shape (border/radius/background) and just pulse
     as a whole; only the inner bars need their own tone since they have no .panel of their
     own to inherit one from. */
  .skel-bar,
  .skel-finding {
    animation: conf-pulse 1.6s var(--ease) infinite;
  }
  .skel-bar {
    height: 4.6rem;
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 0.6rem;
  }
  .skel-finding {
    height: 4.6rem;
  }
  .skel {
    background: var(--bg-elevated);
    border-radius: var(--radius-sm);
  }
  .skel-pill {
    height: 1.1rem;
    width: 11rem;
  }
  .skel-counts {
    height: 0.9rem;
    width: 16rem;
  }
</style>
