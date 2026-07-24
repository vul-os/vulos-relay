<script lang="ts">
  import { client, ApiError } from '../lib/api';
  import type { SignedDescriptorDto, VisibilityClass, AssuranceLevel, OperatorPolicy } from '../lib/types';
  import { COORDINATOR_KINDS } from '../lib/types';
  import VisibilityBadge from '../lib/components/VisibilityBadge.svelte';
  import { isDowngrade, CLASS_LABEL, CLASS_DESCRIPTION, LEVEL_LABEL, LEVEL_DESCRIPTION } from '../lib/visibility';
  import { shortHex } from '../lib/format';

  const VISIBILITY_CLASSES: VisibilityClass[] = ['blind', 'blind-routing', 'terminating'];
  const ASSURANCE_LEVELS: AssuranceLevel[] = ['structural', 'attested', 'declared'];

  let descriptor = $state<SignedDescriptorDto | null>(null);
  let loading = $state(true);
  let loadError = $state<string | null>(null);

  let kind = $state<SignedDescriptorDto['kind']>('reachability-adapter');
  let visClass = $state<VisibilityClass>('blind-routing');
  let visLevel = $state<AssuranceLevel>('declared');
  let policy = $state<OperatorPolicy>({ region: '', capabilities: [], contact: '', notes: '' });
  let capabilitiesText = $state('');

  let confirmDowngrade = $state(false);
  let saving = $state(false);
  let errorMsg = $state<string | null>(null);
  let justPublished = $state(false);

  async function loadDescriptor() {
    loading = true;
    loadError = null;
    try {
      const d = await client.getDescriptor();
      descriptor = d;
      kind = d.kind;
      visClass = d.visibility.class;
      visLevel = d.visibility.level;
      policy = { ...d.policy };
      capabilitiesText = d.policy.capabilities.join(', ');
    } catch (e) {
      loadError = e instanceof ApiError ? e.message : 'Could not load the current descriptor.';
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    loadDescriptor();
  });

  let pendingVisibility = $derived({ class: visClass, level: visLevel });
  let wouldDowngrade = $derived(descriptor ? isDowngrade(descriptor.visibility, pendingVisibility) : false);

  async function publish() {
    if (!descriptor) return;
    errorMsg = null;
    saving = true;
    justPublished = false;
    try {
      const body = {
        kind,
        visibility: pendingVisibility,
        policy: {
          region: policy.region || null,
          capabilities: capabilitiesText
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean),
          contact: policy.contact || null,
          notes: policy.notes || null,
        },
        confirm_downgrade: confirmDowngrade,
      };
      const res = await client.putDescriptor(body);
      descriptor = res.descriptor;
      confirmDowngrade = false;
      justPublished = true;
    } catch (e) {
      errorMsg = e instanceof ApiError ? e.message : 'Could not publish the descriptor.';
    } finally {
      saving = false;
    }
  }
</script>

<div class="page">
  <div class="page-head reveal">
    <span class="kicker">Descriptor</span>
    <h1>Operator policy &amp; declared visibility</h1>
    <p class="lede">The signed, discovery-only artifact this coordinator publishes about itself (CONTRACT §2.1). No score, no price rank, no stake field — the type has none.</p>
  </div>

  {#if loadError}
    <section class="panel error-panel reveal" role="alert">
      <div class="panel-body error-body">
        <span class="error-icon" aria-hidden="true">✕</span>
        <div class="error-copy">
          <p class="error-title">Could not load the descriptor</p>
          <p class="error-detail">{loadError}</p>
        </div>
        <button type="button" class="btn" onclick={loadDescriptor}>Retry →</button>
      </div>
    </section>
  {:else if loading || !descriptor}
    <div class="layout skeleton-grid" aria-hidden="true">
      <div class="panel skeleton-panel reveal">
        <div class="panel-header">
          <div class="skeleton-stack">
            <span class="skel-bar skel-kicker"></span>
            <span class="skel-bar skel-title"></span>
          </div>
        </div>
        <div class="panel-body skeleton-stack">
          <span class="skel-bar skel-line" style="width: 40%"></span>
          <span class="skel-bar skel-row"></span>
          <span class="skel-bar skel-row"></span>
          <span class="skel-bar skel-row"></span>
          <span class="skel-bar skel-badge"></span>
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
          <span class="skel-bar skel-row"></span>
        </div>
      </div>
    </div>
    <p class="visually-hidden" role="status">Loading the current signed descriptor…</p>
  {:else}
    <div class="layout">
      <section class="panel reveal reveal-1">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Draft</span>
            <h2>Edit &amp; sign</h2>
          </div>
        </div>
        <div class="panel-body">
          <div class="field">
            <label for="kind">Coordinator kind</label>
            <select id="kind" bind:value={kind}>
              {#each COORDINATOR_KINDS as k (k)}
                <option value={k}>{k}</option>
              {/each}
            </select>
          </div>

          <div class="group">
            <span class="panel-kicker group-title">Content visibility</span>
            <div class="vis-groups">
              <fieldset class="vis-fieldset">
                <legend>Visibility class</legend>
                <div class="option-list">
                  {#each VISIBILITY_CLASSES as c (c)}
                    <label class="option" class:selected={visClass === c}>
                      <input type="radio" name="visClass" value={c} bind:group={visClass} />
                      <span class="option-text">
                        <span class="option-title">
                          {CLASS_LABEL[c]}
                          {#if visClass === c}<span class="check" aria-hidden="true">✓</span>{/if}
                        </span>
                        <span class="option-desc">{CLASS_DESCRIPTION[c]}</span>
                      </span>
                    </label>
                  {/each}
                </div>
              </fieldset>

              <fieldset class="vis-fieldset">
                <legend>Assurance level</legend>
                <div class="option-list">
                  {#each ASSURANCE_LEVELS as l (l)}
                    <label class="option" class:selected={visLevel === l}>
                      <input type="radio" name="visLevel" value={l} bind:group={visLevel} />
                      <span class="option-text">
                        <span class="option-title">
                          {LEVEL_LABEL[l]}
                          {#if visLevel === l}<span class="check" aria-hidden="true">✓</span>{/if}
                        </span>
                        <span class="option-desc">{LEVEL_DESCRIPTION[l]}</span>
                        {#if l === 'declared' && visClass !== 'terminating'}
                          <span class="option-warn">
                            <span aria-hidden="true">△</span> Declared, not verified — a relying party cannot check this claim independently.
                          </span>
                        {/if}
                      </span>
                    </label>
                  {/each}
                </div>
              </fieldset>
            </div>

            <div class="preview">
              <VisibilityBadge visibility={pendingVisibility} />
            </div>

            {#if wouldDowngrade}
              <div class="note note-danger">
                <span aria-hidden="true">⚠</span>
                <span>
                  <strong>This is a visibility downgrade.</strong> Moving from
                  <code>{descriptor.visibility.class} / {descriptor.visibility.level}</code> to
                  <code>{visClass} / {visLevel}</code> weakens the declared claim (CONTRACT §3.2 — no
                  <em>silent</em> downgrade). A real, intentional switch is legitimate as long as it's disclosed:
                  <label class="checkline">
                    <input type="checkbox" bind:checked={confirmDowngrade} />
                    I am intentionally disclosing this downgrade
                  </label>
                </span>
              </div>
            {/if}
          </div>

          <div class="group">
            <span class="panel-kicker group-title">Operator policy</span>

            <div class="two-col">
              <div class="field">
                <label for="region">Region</label>
                <input id="region" type="text" bind:value={policy.region} placeholder="eu-west" />
              </div>
              <div class="field">
                <label for="contact">Contact</label>
                <input id="contact" type="text" bind:value={policy.contact} placeholder="ops@example.org" />
              </div>
            </div>

            <div class="field">
              <label for="caps">Capabilities (comma-separated)</label>
              <input id="caps" type="text" bind:value={capabilitiesText} placeholder="reachability-adapter, sni-passthrough" />
              <p class="field-hint">Advertised in the signed descriptor exactly as typed — comma-separated tokens.</p>
            </div>

            <div class="field">
              <label for="notes">Notes</label>
              <textarea id="notes" rows="3" bind:value={policy.notes} placeholder="Free-text operator note."></textarea>
            </div>
          </div>

          {#if errorMsg}
            <div class="note note-danger" role="alert">
              <span aria-hidden="true">✕</span>
              <span>{errorMsg}</span>
            </div>
          {/if}

          <div class="sign-block">
            <button
              type="button"
              class="btn btn-primary btn-sign"
              disabled={saving || (wouldDowngrade && !confirmDowngrade)}
              aria-busy={saving}
              onclick={publish}
            >
              {#if saving}<span class="spinner" aria-hidden="true"></span>{/if}
              {saving ? 'Signing…' : 'Sign & publish'}
            </button>
            {#if wouldDowngrade && !confirmDowngrade}
              <p class="sign-hint">Confirm the downgrade disclosure above to enable signing.</p>
            {/if}

            {#if justPublished}
              <div class="note note-success" role="status">
                <span aria-hidden="true">✓</span>
                <span><strong>Published.</strong> Re-signed under the current key.</span>
              </div>
            {/if}
          </div>
        </div>
      </section>

      <section class="panel reveal reveal-2">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Live</span>
            <h2>Currently published</h2>
          </div>
          <div class="stamp stamp-signed" aria-hidden="true">Signed<br/>&amp; live</div>
        </div>
        <div class="panel-body published">
          <dl>
            <dt>Kind</dt>
            <dd>{descriptor.kind}</dd>
            <dt>Visibility</dt>
            <dd><VisibilityBadge visibility={descriptor.visibility} size="sm" /></dd>
            <dt>Identity (pubkey)</dt>
            <dd class="hex">{shortHex(descriptor.identity_hex, 12, 8)}</dd>
            <dt>Signature</dt>
            <dd class="hex">{shortHex(descriptor.sig_hex, 12, 8)}</dd>
            <dt>Deterministic CBOR</dt>
            <dd class="hex">{shortHex(descriptor.det_cbor_hex, 12, 8)}</dd>
            <dt>Policy — region</dt>
            <dd>{descriptor.policy.region ?? '—'}</dd>
            <dt>Policy — capabilities</dt>
            <dd>{descriptor.policy.capabilities.length ? descriptor.policy.capabilities.join(', ') : '—'}</dd>
            <dt>Policy — contact</dt>
            <dd>{descriptor.policy.contact ?? '—'}</dd>
            <dt>Policy — notes</dt>
            <dd class="notes">{descriptor.policy.notes ?? '—'}</dd>
          </dl>
          <div class="note">
            <span aria-hidden="true">◈</span>
            <span>{descriptor.note}</span>
          </div>
        </div>
      </section>
    </div>
  {/if}
</div>

<style>
  .page {
    display: flex;
    flex-direction: column;
    gap: var(--space-6);
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
  .layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    gap: var(--space-4);
    align-items: start;
  }
  @media (max-width: 980px) {
    .layout {
      grid-template-columns: 1fr;
    }
  }

  /* ---------- form composition: rhythm via the --space-* scale ---------- */
  .group {
    margin: var(--space-5) 0;
    padding-top: var(--space-5);
    border-top: 1px solid var(--border-subtle);
  }
  .group:first-child {
    margin-top: 0;
    padding-top: 0;
    border-top: none;
  }
  .group-title {
    display: block;
    margin-bottom: var(--space-3);
  }
  .two-col {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-4);
  }
  @media (max-width: 480px) {
    .two-col {
      grid-template-columns: 1fr;
    }
  }

  /* ---------- content-visibility declaration ---------- */
  .vis-groups {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-4);
    margin-bottom: var(--space-4);
  }
  @media (max-width: 640px) {
    .vis-groups {
      grid-template-columns: 1fr;
    }
  }
  .vis-fieldset {
    border: none;
    margin: 0;
    padding: 0;
    min-width: 0;
  }
  .vis-fieldset legend {
    font-family: var(--font-mono);
    font-size: 0.6875rem;
    font-weight: 500;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--text-muted);
    padding: 0;
    margin-bottom: var(--space-2);
  }
  .option-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .option {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    cursor: pointer;
    transition: border-color var(--dur-fast) var(--ease), background-color var(--dur-fast) var(--ease);
  }
  .option:hover {
    border-color: var(--border-emphasis);
    background: var(--bg-hover);
  }
  /* Selected is unmistakable through three independent, non-colour-only cues:
     the native radio's own filled dot, a border/fill step onto the shared
     --bg-selected token pair, and an explicit ✓ + bold label — so the state
     still reads correctly for anyone not relying on colour perception. */
  .option.selected {
    border-color: var(--bg-selected-border);
    background: var(--bg-selected);
  }
  .option input[type='radio'] {
    width: auto;
    margin: 0.2rem 0 0;
    accent-color: var(--accent);
    flex-shrink: 0;
    cursor: pointer;
  }
  .option-text {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    min-width: 0;
  }
  .option-title {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: 0.82rem;
    font-weight: 600;
    color: var(--text-primary);
  }
  .option.selected .option-title {
    color: var(--accent);
  }
  .check {
    color: var(--accent);
    font-weight: 700;
  }
  .option-desc {
    font-size: 0.74rem;
    line-height: 1.45;
    color: var(--text-tertiary);
  }
  .option-warn {
    display: flex;
    align-items: baseline;
    gap: 0.35rem;
    margin-top: 0.15rem;
    font-size: 0.7rem;
    line-height: 1.4;
    font-weight: 500;
    color: var(--status-warning);
  }

  .preview {
    margin: var(--space-4) 0;
  }
  .checkline {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    margin-top: 0.5rem;
    font-weight: 600;
    color: var(--text-primary);
    font-size: 0.78rem;
  }
  .checkline input {
    width: auto;
  }

  /* ---------- the signing action ---------- */
  .sign-block {
    margin-top: var(--space-5);
    padding-top: var(--space-4);
    border-top: 1px solid var(--border-subtle);
  }
  .btn-sign {
    width: 100%;
    justify-content: center;
    font-size: 0.88rem;
    padding: 0.75rem 1.2rem;
  }
  .sign-hint {
    margin: var(--space-2) 0 0;
    font-size: 0.74rem;
    color: var(--text-tertiary);
    text-align: center;
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

  /* success note — same shape as app.css's .note-caution/.note-danger variants,
     built from the same status-token formula, kept local since it's the one
     status colour those shared variants don't already cover. */
  .note-success {
    background: var(--status-success-soft);
    border-color: color-mix(in srgb, var(--status-success) 45%, var(--border-strong));
    color: var(--text-primary);
    margin-top: var(--space-3);
  }
  .note-success strong {
    color: var(--status-success);
  }

  /* ---------- loading skeleton ---------- */
  .skeleton-panel {
    padding: 0;
  }
  .skeleton-stack {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
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
  .skel-line {
    width: 60%;
    height: 0.8rem;
  }
  .skel-row {
    width: 100%;
    height: 2.2rem;
    border-radius: var(--radius-sm);
  }
  .skel-badge {
    width: 100%;
    height: 3.4rem;
    margin-top: var(--space-2);
  }
  .skel-btn {
    width: 100%;
    height: 2.4rem;
    margin-top: var(--space-2);
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

  /* ---------- initial-load error ---------- */
  .error-panel {
    border-color: color-mix(in srgb, var(--status-danger) 45%, var(--border-strong));
  }
  .error-body {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    flex-wrap: wrap;
  }
  .error-icon {
    color: var(--status-danger);
    font-size: 1.1rem;
    line-height: 1.4;
  }
  .error-copy {
    flex: 1;
    min-width: 12rem;
  }
  .error-title {
    margin: 0;
    font-weight: 700;
    font-size: 0.88rem;
    color: var(--text-primary);
  }
  .error-detail {
    margin: 0.25rem 0 0;
    font-size: 0.8rem;
    color: var(--text-secondary);
  }

  /* ---------- currently-published panel ---------- */
  .published dl {
    display: grid;
    grid-template-columns: 9.5rem 1fr;
    row-gap: var(--space-3);
    column-gap: var(--space-3);
    margin: 0 0 var(--space-4);
  }
  @media (max-width: 480px) {
    .published dl {
      grid-template-columns: 1fr;
      row-gap: var(--space-1);
    }
    .published dt {
      margin-top: var(--space-2);
    }
    .published dt:first-child {
      margin-top: 0;
    }
  }
  .published dt {
    font-family: var(--font-mono);
    font-size: 0.68rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-tertiary);
    align-self: center;
  }
  .published dd {
    margin: 0;
    font-size: 0.86rem;
    min-width: 0;
  }
  .published dd.notes {
    color: var(--text-secondary);
  }
  .published dd.hex {
    overflow-wrap: anywhere;
  }
</style>
