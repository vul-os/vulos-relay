<script lang="ts">
  import { client } from '../lib/api';
  import type { KeysDto, RotateResponse } from '../lib/types';
  import { shortHex } from '../lib/format';

  let keys = $state<KeysDto | null>(null);
  let loading = $state(true);
  let rotating = $state(false);
  let lastRotation = $state<RotateResponse | null>(null);
  let confirmOpen = $state(false);
  let copied = $state(false);
  let copyError = $state(false);
  let copyTimer: ReturnType<typeof setTimeout> | undefined;

  $effect(() => {
    (async () => {
      keys = await client.getKeys();
      loading = false;
    })();
  });

  async function rotate() {
    rotating = true;
    try {
      const res = await client.rotateKeys();
      lastRotation = res;
      keys = await client.getKeys();
      confirmOpen = false;
    } finally {
      rotating = false;
    }
  }

  /** Split a hex string into fixed-width groups so a 64-char key wraps and scans like a
   * hash rather than one unbroken ribbon of characters. Purely a display transform — the
   * value itself is untouched, and the full unbroken string still reaches assistive tech
   * via the hidden span next to it. */
  function hexGroups(hex: string, size = 8): string[] {
    const out: string[] = [];
    for (let i = 0; i < hex.length; i += size) out.push(hex.slice(i, i + size));
    return out;
  }

  async function copyKey() {
    if (!keys) return;
    clearTimeout(copyTimer);
    try {
      await navigator.clipboard.writeText(keys.public_key_hex);
      copied = true;
      copyError = false;
    } catch {
      copied = false;
      copyError = true;
    }
    copyTimer = setTimeout(() => {
      copied = false;
      copyError = false;
    }, 2200);
  }

  // The retired history plus the current key, read as one continuous ledger, newest first.
  // history_hex is append-only oldest→newest (admin/src/keys.rs pushes the outgoing key on
  // each rotation), so the live key's sequence number is simply the next one after the last
  // retired entry — no new ordering assumption beyond the one the original list already made.
  let ledgerRows = $derived(
    keys
      ? [
          ...keys.history_hex.map((hex, i) => ({ seq: i + 1, hex, live: false })),
          { seq: keys.history_hex.length + 1, hex: keys.public_key_hex, live: true },
        ].reverse()
      : [],
  );
</script>

<div class="page">
  <div class="page-head reveal">
    <span class="kicker">Keys</span>
    <h1>Signing identity</h1>
    <p class="lede">The operator's accountable identity (CONTRACT §2.1). Rotating generates a fresh key and re-signs the descriptor — the outgoing key is kept in history, never dropped.</p>
  </div>

  {#if loading || !keys}
    <div class="layout">
      <section class="panel reveal reveal-2" aria-busy="true">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Active</span>
            <h2>Current public key</h2>
          </div>
        </div>
        <div class="panel-body">
          <span class="visually-hidden" role="status">Loading signing identity…</span>
          <div class="skel skel-key" aria-hidden="true"></div>
          <div class="skel skel-btn" aria-hidden="true"></div>
        </div>
      </section>

      <section class="panel reveal reveal-3" aria-busy="true">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Never cleared</span>
            <h2>Rotation history</h2>
          </div>
        </div>
        <div class="panel-body">
          <div class="skel skel-row" aria-hidden="true"></div>
          <div class="skel skel-row" aria-hidden="true"></div>
          <div class="skel skel-row" aria-hidden="true"></div>
        </div>
      </section>
    </div>
  {:else}
    <div class="layout">
      <section class="panel reveal reveal-2">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Active</span>
            <h2>Current public key</h2>
          </div>
          <div class="stamp stamp-signed" aria-hidden="true">Live<br />key</div>
        </div>
        <div class="panel-body">
          <div class="stack">
            <div class="key-display">
              <code class="pubkey">
                <span class="visually-hidden">{keys.public_key_hex}</span>
                <span aria-hidden="true" class="key-groups">
                  {#each hexGroups(keys.public_key_hex) as g (g)}<span class="key-group">{g}</span>{/each}
                </span>
              </code>
              <button
                type="button"
                class="btn btn-ghost copy-btn"
                onclick={copyKey}
                aria-label={copied ? 'Public key copied to clipboard' : 'Copy public key to clipboard'}
              >
                <span aria-hidden="true">{copied ? '✓' : copyError ? '✕' : '⧉'}</span>
                {copied ? 'Copied' : copyError ? 'Copy failed' : 'Copy'}
              </button>
              <span class="visually-hidden" aria-live="polite">{copied ? 'Public key copied to clipboard.' : ''}</span>
            </div>

            {#if lastRotation}
              <div class="note">
                <span aria-hidden="true">◈</span>
                <span>
                  Rotated from <code class="hex">{shortHex(lastRotation.old_public_key_hex)}</code> to
                  <code class="hex">{shortHex(lastRotation.new_public_key_hex)}</code> — the descriptor was
                  re-signed under the new key in the same operation.
                </span>
              </div>
            {/if}

            {#if !confirmOpen}
              <button type="button" class="btn btn-danger-outline" onclick={() => (confirmOpen = true)}>
                <span aria-hidden="true">⚠</span> Rotate key →
              </button>
            {:else}
              <div class="confirm-box note note-danger" role="alert">
                <span aria-hidden="true">⚠</span>
                <div class="confirm-content">
                  <p>
                    This generates a brand-new signing key, makes it current immediately, and re-signs the
                    descriptor. The old key is <strong>not</strong> destroyed — it moves to history below so
                    anything that referenced it stays traceable.
                  </p>
                  <div class="confirm-actions">
                    <button type="button" class="btn" disabled={rotating} onclick={() => (confirmOpen = false)}>
                      Cancel
                    </button>
                    <button type="button" class="btn btn-danger-outline" disabled={rotating} onclick={rotate}>
                      {rotating ? 'Rotating…' : 'Confirm rotation'}
                    </button>
                  </div>
                </div>
              </div>
            {/if}
          </div>
        </div>
      </section>

      <section class="panel reveal reveal-3">
        <div class="panel-header">
          <div>
            <span class="panel-kicker">Never cleared</span>
            <h2>Rotation history</h2>
          </div>
          <span class="pill count-pill">
            {keys.history_hex.length + 1} signing key{keys.history_hex.length === 0 ? '' : 's'} total
          </span>
        </div>
        <div class="panel-body">
          <div class="stack">
            {#if keys.history_hex.length === 0}
              <div class="empty-state">
                <span class="empty-icon" aria-hidden="true">◈</span>
                <p class="empty-title">No rotations yet</p>
                <p class="empty-copy">This is the identity the coordinator started with — nothing has been retired.</p>
              </div>
            {:else}
              <div class="scroll-x">
                <table class="ledger">
                  <thead>
                    <tr>
                      <th class="num">Seq</th>
                      <th>Key</th>
                      <th>State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each ledgerRows as row (row.seq)}
                      <tr class:current-row={row.live}>
                        <td class="mono num">{row.seq}</td>
                        <td class="hex">{shortHex(row.hex)}</td>
                        <td>
                          {#if row.live}
                            <span class="state state-live"><span class="light-dot" aria-hidden="true"></span> Live</span>
                          {:else}
                            <span class="state state-retired">Retired</span>
                          {/if}
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {/if}

            <div class="note">
              <span aria-hidden="true">◈</span>
              <span>Rotation re-signs the descriptor only — a tariff already attached keeps its own signature under the previous key. Re-sign the tariff separately (Pricing) if you want it under the new key too.</span>
            </div>
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
    gap: 1.5rem;
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
    gap: 1.1rem;
    align-items: start;
  }
  @media (max-width: 980px) {
    .layout {
      grid-template-columns: 1fr;
    }
  }

  /* Flex column + gap for a panel-body's own content, so conditionally-rendered siblings
     (the last-rotation note, the confirm box) always get consistent breathing room without
     each one having to carry its own margin. */
  .stack {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  /* ---------- current key ---------- */

  .pubkey {
    display: block;
    font-size: 0.86rem;
    line-height: 1.6;
    background: var(--bg-base);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-md);
    padding: 0.85rem 1rem;
    color: var(--accent);
    margin: 0 0 0.6rem;
  }
  /* The wrap container has to be the element that actually holds the groups.
     Flexing .pubkey instead made .key-groups a single un-wrappable flex item,
     so a 64-char key overflowed the panel and was clipped. */
  .key-groups {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem 0.75rem;
  }
  .key-group {
    white-space: nowrap;
    letter-spacing: 0.03em;
  }
  .copy-btn {
    font-size: 0.76rem;
    padding: 0.4rem 0.75rem;
  }

  /* ---------- destructive action ---------- */

  .confirm-content {
    display: flex;
    flex-direction: column;
    gap: 0.8rem;
    min-width: 0;
  }
  .confirm-content p {
    margin: 0;
    font-size: 0.82rem;
    color: var(--text-primary);
    line-height: 1.5;
  }
  .confirm-actions {
    display: flex;
    gap: 0.6rem;
    flex-wrap: wrap;
  }

  /* ---------- rotation ledger ---------- */

  .count-pill {
    background: var(--bg-elevated);
    border-color: var(--border-strong);
    color: var(--text-tertiary);
    flex-shrink: 0;
  }
  .state {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font-family: var(--font-mono);
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }
  .state-live {
    color: var(--accent);
  }
  .state-retired {
    color: var(--text-tertiary);
  }
  tr.current-row td {
    background: color-mix(in srgb, var(--accent) 6%, transparent);
  }

  /* ---------- empty / loading states ---------- */

  .empty-state {
    text-align: center;
    padding: 2.1rem 1rem;
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
    max-width: 34ch;
    line-height: 1.5;
  }

  @keyframes key-pulse {
    0%,
    100% {
      opacity: 0.55;
    }
    50% {
      opacity: 1;
    }
  }
  .skel {
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-md);
    animation: key-pulse 1.6s var(--ease) infinite;
  }
  .skel-key {
    height: 4.6rem;
    margin-bottom: 1rem;
  }
  .skel-btn {
    height: 2.2rem;
    width: 9.5rem;
  }
  .skel-row {
    height: 2.4rem;
    margin-bottom: 0.55rem;
  }
  .skel-row:last-child {
    margin-bottom: 0;
  }
</style>
