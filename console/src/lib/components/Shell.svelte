<script lang="ts">
  import type { Snippet } from 'svelte';
  import { tick } from 'svelte';
  import { router, type Route } from '../router.svelte';
  import { theme } from '../theme.svelte';
  import { IS_MOCK } from '../api';

  let { children }: { children: Snippet } = $props();

  // Mobile: the sidebar collapses to a slide-in drawer behind a hamburger.
  let drawerOpen = $state(false);

  let hamburgerEl = $state<HTMLButtonElement>();
  let navEl = $state<HTMLElement>();

  async function openDrawer() {
    drawerOpen = true;
    // Move focus into the drawer landmark once it's slid into view — a
    // keyboard/AT user who just activated the hamburger should land inside
    // the panel they opened, not stay parked on a now-covered button.
    await tick();
    navEl?.focus();
  }

  function closeDrawer() {
    drawerOpen = false;
    // Return focus to the control that opened the drawer — never strand
    // focus on a menu item that just scrolled out of the viewport.
    hamburgerEl?.focus();
  }

  function go(id: Route) {
    router.go(id);
    if (drawerOpen) closeDrawer(); // dismiss the drawer after navigating on mobile
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape' && drawerOpen) closeDrawer();
  }

  // Grouped like the Vulos OS settings rail: plain labels under small muted
  // section headers, no leading numbers.
  const NAV_GROUPS: { heading: string; items: { id: Route; label: string }[] }[] = [
    {
      heading: 'Posture',
      items: [
        { id: 'overview', label: 'Overview' },
        { id: 'descriptor', label: 'Descriptor' },
        { id: 'conformance', label: 'Conformance' },
      ],
    },
    {
      heading: 'Billing',
      items: [
        { id: 'tariff', label: 'Pricing' },
        { id: 'billing', label: 'Ledger' },
      ],
    },
    {
      heading: 'Identity',
      items: [{ id: 'keys', label: 'Keys' }],
    },
  ];
</script>

<svelte:window onkeydown={onKeydown} />

<div class="shell" class:drawer-open={drawerOpen}>
  <a href="#main" class="skip-link">Skip to content</a>

  <!-- scrim behind the mobile drawer -->
  <button
    type="button"
    class="scrim"
    aria-label="Close menu"
    aria-hidden={!drawerOpen}
    tabindex={drawerOpen ? 0 : -1}
    onclick={closeDrawer}
  ></button>

  <aside class="nav" class:open={drawerOpen} bind:this={navEl} tabindex="-1">
    <div class="brandblock">
      <div class="mark" aria-hidden="true">
        <!-- The Ephor mark (brand/ephor.svg): a comma whose notch opens it into
             a lowercase "e". currentColor, tinted by .mark so it holds up on
             both the near-black and the warm-paper canvas. -->
        <svg viewBox="14 5 72 92" role="presentation">
          <defs>
            <mask id="shell-mark-cut">
              <rect x="-40" y="-40" width="200" height="200" fill="#fff"/>
              <rect x="31.5" y="29" width="32" height="14" rx="3" fill="#000"
                    transform="translate(16 5) rotate(200 47.5 36)"/>
            </mask>
          </defs>
          <g mask="url(#shell-mark-cut)" fill="currentColor">
            <g transform="rotate(350 50 50) translate(100 0) scale(-1 1)">
              <path d="M 50,10 C 68,10 80,23 80,41 C 80,64 64,82 46,90 C 40,93 35,85 40,81
                       C 51,73 57,65 60,56 C 55,61 48,63 41,62 C 28,60 20,51 20,39
                       C 20,23 32,10 50,10 Z"/>
            </g>
          </g>
        </svg>
      </div>
      <div class="wordblock">
        <span class="word">Ephor</span>
        <span class="sub">Operator Console</span>
      </div>
    </div>

    <nav aria-label="Console sections">
      {#each NAV_GROUPS as group (group.heading)}
        <p class="nav-heading">{group.heading}</p>
        <ul class="navlist">
          {#each group.items as item (item.id)}
            <li>
              <button
                type="button"
                class="navitem"
                class:active={router.current === item.id}
                onclick={() => go(item.id)}
                aria-current={router.current === item.id ? 'page' : undefined}
              >
                <span class="lbl">{item.label}</span>
              </button>
            </li>
          {/each}
        </ul>
      {/each}
    </nav>

    <div class="nav-foot">
      {#if IS_MOCK}
        <span class="mode-badge" title="This build is running on fixture data, not a live ephor-admin — see console/README.md">
          <span class="light-dot" aria-hidden="true"></span> Demo data
        </span>
      {/if}
      <p class="foot-note">Binds operator-local by default (127.0.0.1:8090). Bearer-token gated, fail-closed.</p>
    </div>
  </aside>

  <div class="content-col">
    <header class="topbar">
      <div class="crumbs">
        <button
          type="button"
          class="hamburger"
          aria-label="Open menu"
          aria-expanded={drawerOpen}
          bind:this={hamburgerEl}
          onclick={openDrawer}
        >
          <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M3 6h18M3 12h18M3 18h18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
        </button>
        <span class="crumb-kicker">Coordinator control plane</span>
      </div>
      <button
        type="button"
        class="theme-toggle"
        role="switch"
        aria-checked={theme.resolved() === 'dark'}
        aria-label={theme.resolved() === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
        onclick={() => theme.toggle()}
      >
        <span class="track" class:dark={theme.resolved() === 'dark'}>
          <span class="thumb">
            {#if theme.resolved() === 'dark'}
              <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M20 14.5A8.5 8.5 0 119.5 4a7 7 0 1010.5 10.5z" fill="currentColor"/></svg>
            {:else}
              <svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="4.5" fill="currentColor"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>
            {/if}
          </span>
        </span>
        <span class="tlabel" aria-hidden="true">{theme.resolved() === 'dark' ? 'Dark' : 'Light'}</span>
      </button>
    </header>

    <main id="main" tabindex="-1">
      {@render children()}
    </main>
  </div>
</div>

<style>
  .skip-link {
    position: absolute;
    left: -999px;
    top: 0;
    background: var(--text-primary);
    color: var(--bg-base);
    padding: 0.6rem 1rem;
    z-index: 100;
  }
  .skip-link:focus {
    left: 0.5rem;
    top: 0.5rem;
  }

  .shell {
    display: grid;
    grid-template-columns: 15.5rem 1fr;
    min-height: 100vh;
  }

  .nav {
    background: var(--bg-surface);
    border-right: 1px solid var(--border-default);
    display: flex;
    flex-direction: column;
    padding: 1.4rem 1.1rem;
    position: sticky;
    top: 0;
    height: 100vh;
  }

  /* The aside is a focus target (drawer open moves focus here) but should
     never show its own ring on desktop where it's never actually clicked
     into — only the drawer path (mobile, focused programmatically) cares. */
  .nav:focus-visible {
    outline: none;
    box-shadow: none;
  }

  /* Scrim is inert on desktop; only the mobile drawer reveals it. */
  .scrim {
    display: none;
    border: none;
    padding: 0;
  }

  /* ── Mobile: single column; the sidebar becomes a slide-in drawer ── */
  @media (max-width: 900px) {
    .shell {
      grid-template-columns: 1fr;
    }
    .nav {
      position: fixed;
      top: 0;
      left: 0;
      bottom: 0;
      z-index: 60;
      width: 16rem;
      max-width: 82vw;
      height: 100dvh;
      transform: translateX(-100%);
      transition: transform var(--dur) var(--ease);
      box-shadow: var(--shadow-lg);
      overflow-y: auto;
    }
    .nav.open {
      transform: translateX(0);
    }
    .scrim {
      display: block;
      position: fixed;
      inset: 0;
      z-index: 50;
      background: var(--nav-scrim);
      opacity: 0;
      pointer-events: none;
      transition: opacity var(--dur) var(--ease);
      cursor: default;
    }
    .shell.drawer-open .scrim {
      opacity: 1;
      pointer-events: auto;
    }
  }

  .brandblock {
    display: flex;
    align-items: center;
    gap: 0.65rem;
    padding: 0 0.3rem 1rem;
    margin-bottom: 0.7rem;
    border-bottom: 1px solid var(--border-default);
    position: relative;
  }

  /* A brighter hairline fading toward the trailing edge under the brand
     block, echoing the panel-header underline elsewhere in the console —
     the sidebar masthead gets the same "ruled letterhead" treatment. */
  .brandblock::after {
    content: '';
    position: absolute;
    left: 0.3rem;
    right: 0;
    bottom: -1px;
    height: 1px;
    background: linear-gradient(90deg, var(--border-emphasis), transparent 85%);
  }

  .mark svg {
    width: 2.15rem;
    height: 2.15rem;
    display: block;
  }

  .wordblock {
    display: flex;
    flex-direction: column;
    line-height: 1.2;
    min-width: 0;
  }

  .word {
    font-family: var(--font-mono);
    font-weight: 700;
    font-size: 1.05rem;
    letter-spacing: -0.02em;
    color: var(--text-primary);
  }

  .sub {
    font-family: var(--font-mono);
    font-size: 0.63rem;
    font-weight: 500;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--text-muted);
  }

  .nav-heading {
    font-family: var(--font-mono);
    font-size: 0.64rem;
    font-weight: 600;
    letter-spacing: 0.07em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin: 1.2rem 0 0.4rem;
    padding: 0 0.6rem;
  }
  .nav-heading:first-of-type {
    margin-top: 0.3rem;
  }

  /* Same small IDE-grade tick as .panel-kicker elsewhere in the console — a
     prompt mark, not a bullet — so the sidebar's own section labels read as
     part of the same typographic family as every panel header on the page. */
  .nav-heading::before {
    content: '';
    display: inline-block;
    width: 0.5em;
    height: 1px;
    margin-right: 0.5em;
    background: currentColor;
    opacity: 0.6;
    vertical-align: middle;
  }

  .navlist {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }

  .navitem {
    width: 100%;
    display: flex;
    align-items: center;
    padding: 0.48rem 0.65rem;
    border-radius: var(--radius-sm);
    border: none;
    background: transparent;
    color: var(--text-secondary);
    font-size: 0.87rem;
    font-weight: 500;
    text-align: left;
    cursor: pointer;
    transition: background-color var(--dur-fast) var(--ease), color var(--dur-fast) var(--ease),
      box-shadow var(--dur) var(--ease), transform var(--dur-fast) var(--ease);
  }

  .navitem:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .navitem:active {
    background: var(--bg-active);
    transition-duration: calc(var(--dur-fast) / 2);
  }

  /* Active state reaches for the tokens app.css built specifically for a
     selection surface (--bg-selected / --bg-selected-border, the Vulos
     selection pair retinted to Ephor bronze) rather than inventing a fresh
     accent-tint — a precise inset edge plus that surface reads as "this is
     where you are" without the tint feeling like a hover left on by mistake. */
  .navitem.active {
    background: var(--bg-selected);
    color: var(--text-primary);
    font-weight: 600;
    box-shadow: inset 0 0 0 1px var(--bg-selected-border), inset 2px 0 0 var(--accent);
  }

  .navitem.active:hover {
    background: color-mix(in srgb, var(--bg-selected) 85%, var(--bg-hover) 15%);
  }

  .lbl {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .nav-foot {
    margin-top: auto;
    padding-top: 1rem;
    border-top: 1px solid var(--border-default);
    display: flex;
    flex-direction: column;
    gap: 0.65rem;
  }

  .mode-badge {
    align-self: flex-start;
    display: inline-flex;
    align-items: center;
    gap: 0.42rem;
    font-family: var(--font-mono);
    font-size: 0.71rem;
    font-weight: 500;
    color: var(--accent);
    background: var(--accent-soft);
    border: 1px solid color-mix(in srgb, var(--accent) 40%, transparent);
    padding: 0.28rem 0.65rem;
    border-radius: var(--radius-full);
  }

  .foot-note {
    font-size: 0.68rem;
    color: var(--text-tertiary);
    line-height: 1.5;
    margin: 0;
  }

  .content-col {
    min-width: 0;
    display: flex;
    flex-direction: column;
  }

  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 1rem 1.8rem;
    border-bottom: 1px solid var(--border-default);
    background: var(--nav-scrim);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    box-shadow: var(--shadow-sm);
    position: sticky;
    top: 0;
    z-index: 10;
  }

  .crumbs {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    min-width: 0;
  }

  .crumb-kicker {
    font-family: var(--font-mono);
    font-size: 0.75rem;
    font-weight: 500;
    letter-spacing: 0.02em;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  /* Hamburger: hidden on desktop, shown when the sidebar is a drawer. */
  .hamburger {
    display: none;
    align-items: center;
    justify-content: center;
    width: 2.1rem;
    height: 2.1rem;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    color: var(--text-secondary);
    cursor: pointer;
    flex-shrink: 0;
    transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease),
      background-color var(--dur-fast) var(--ease);
  }
  .hamburger svg {
    width: 1.1rem;
    height: 1.1rem;
  }
  .hamburger:hover {
    color: var(--text-primary);
    border-color: var(--border-emphasis);
    background: var(--bg-hover);
  }
  .hamburger:active {
    background: var(--bg-active);
  }
  @media (max-width: 900px) {
    .hamburger {
      display: inline-flex;
    }
  }

  .theme-toggle {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    background: none;
    border: none;
    cursor: pointer;
    color: var(--text-secondary);
    padding: 0.2rem;
    border-radius: var(--radius-sm);
  }

  .track {
    width: 2.5rem;
    height: 1.4rem;
    border-radius: var(--radius-full);
    background: var(--bg-base);
    border: 1px solid var(--border-strong);
    display: flex;
    align-items: center;
    padding: 0.12rem;
    transition: background-color var(--dur) var(--ease), border-color var(--dur) var(--ease);
  }

  .track.dark {
    background: color-mix(in srgb, var(--accent) 30%, var(--bg-base));
    border-color: color-mix(in srgb, var(--accent) 45%, var(--border-strong));
    justify-content: flex-end;
  }

  .thumb {
    width: 1.05rem;
    height: 1.05rem;
    border-radius: 50%;
    background: var(--bg-elevated);
    color: var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: var(--shadow-sm);
    transition: transform var(--dur) var(--ease);
  }

  .theme-toggle:hover .thumb {
    transform: scale(1.06);
  }

  .thumb svg {
    width: 0.7rem;
    height: 0.7rem;
  }

  .tlabel {
    font-family: var(--font-mono);
    font-size: 0.78rem;
    color: var(--text-secondary);
  }

  main {
    padding: 1.8rem;
    max-width: 78rem;
    width: 100%;
    margin: 0 auto;
  }

  @media (max-width: 640px) {
    main {
      padding: 1.1rem;
    }
    .topbar {
      padding: 0.9rem 1.1rem;
    }
  }
</style>
