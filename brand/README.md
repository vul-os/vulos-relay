# Wakala brand

The Wakala mark is a **"W" built from five routing nodes joined by straight relay
lines** — read it as a broker diagram first and a letterform second. The two outer
peaks and two valleys are ordinary hand-off points; the **center node is the broker**,
ringed with a teal halo where the two routed paths meet, change hands, and continue —
sealed traffic passing through a coordinator that cannot read it. It renders
gradient-filled as the app tile (`logo-mark.svg`), single-colour via `currentColor`
(`logo-mono.svg`), heavier-stroked for tiny sizes (`favicon.svg`), and locked up with
the wordmark (`wordmark.svg`).

Wakala is a **sibling** of the [Envoir](../../envoir) mark, not a clone: same
build quality and lockup conventions (rounded-square gradient tile, mono variant via
`currentColor`, wordmark/og-image pattern), deliberately different hue and a
different core glyph — Envoir's continuous lowercase e/@ spiral (indigo→violet)
reads *identity/mail*; Wakala's five-node W (amber→ember) reads *brokerage/routing*.

## Concept

*Wakala* is Swahili for **agent/agency**: a swappable, fee-taking service point that
acts on a network's behalf. It's the broker/coordinator reference implementation of
KOTVA — it brokers reach between parties, is **content-blind** (it carries sealed
traffic it cannot read), is **hired, not depended-on**, and is **swappable**. The mark
encodes all four:

- **W** — names the product, immediately legible as a wordmark-free app icon.
- **Five nodes, straight relay lines** — a literal broker/hub diagram: two routed
  paths (left leg, right leg) pass through one coordination point.
- **The center halo** — the one node that's visually distinct: the broker doing the
  routing, not the traffic itself. It's a ring, not a lock or an eye — coordination
  and neutrality, not surveillance.
- **Diagonal warm gradient** — motion and value passing through, not a static badge.

## Palette — "Broker Amber"

A deliberately warm, transactional scheme — distinct from Envoir's cool indigo/violet.
Amber and ember read *value, energy, a fee changing hands*; the cool teal accent is
the odd one out on purpose, marking the single neutral broker node against an
otherwise warm, directional gradient.

| Token | Hex | Use |
|-------|-----|-----|
| Amber (gradient start) | `#FFC24B` | primary; gradient start |
| Ember Orange (gradient mid) | `#FF8A3D` | primary; gradient midpoint |
| Terracotta (gradient end) | `#E8543D` | primary; gradient end |
| Brand gradient | `#FFC24B → #FF8A3D → #E8543D` | the app tile, primary surfaces, CTAs |
| Signal Teal (accent) | `#14B8A6` | the broker halo, notifications, live/active state — used sparingly to pop |
| Ember (text) | `#C2410C` | wordmark fill, links, on-light text accents |
| Ink | `#241207` | text (a warm ember-black, not pure black); og-image background |
| Paper | `#FFFBF3` | background (a faint warm ivory) |

Neutrals are warm grays with a faint amber tint. Teal is the *only* cool accent —
one pop, kept rare, reserved for the broker node and "live" states.

## Files

| File | Use |
|------|-----|
| `logo-mark.svg` | App-tile mark (Broker Amber gradient, 240×240 viewBox, rounded tile). App icons, social avatars. |
| `logo-mono.svg` | Single-color W/relay mark via `currentColor` — light/dark UI, print, watermarks. |
| `favicon.svg` | Heavier strokes + a filled (not stroked) broker halo, tuned to stay legible at 16px. |
| `wordmark.svg` | Mark + "Wakala" lockup for headers/navbars. |
| `og-image.svg` | 1200×630 social card: mark, wordmark, tagline "The KOTVA broker". |
| `make-icons.mjs` | `node brand/make-icons.mjs` — rasterizes the above into `icons/` (16 through 512px, apple-touch-icon, favicon-16/32, og-image.png). Uses `rsvg-convert` if present, falls back to `npx playwright`. |
| `icons/` | Generated PNGs (not hand-maintained — regenerate via `make-icons.mjs`). |

The root `logo.png` is `logo-mark.svg` rasterized at 512×512
(`rsvg-convert -w 512 -h 512 brand/logo-mark.svg -o logo.png`).

## Type

No external fonts are embedded or required. `wordmark.svg` and `og-image.svg` set
"Wakala" with a system font stack (`system-ui, -apple-system, 'Segoe UI', Roboto,
sans-serif` / `'Helvetica Neue', Arial, sans-serif`) at a heavy weight — this keeps
the files small and dependency-free; it renders with whatever the OS's default UI
font is rather than a fixed typeface. If a locked, font-independent wordmark is ever
needed (e.g. for print), convert the `<text>` node to outlined `<path>` data with a
tool like `svg-text-to-path` and drop the `font-family`/`font-weight` attributes.

## Usage

- Keep clear space ≈ the tile corner radius around the mark.
- Don't recolor the gradient, stretch, skew, or add effects. Use `logo-mono.svg`
  when one flat color is needed.
- Don't detach the teal halo from the center node or apply it to any other node —
  it identifies the one broker point, not decoration.
- The mark scales down cleanly; `favicon.svg` trades the thin halo ring for a solid
  teal disc and thicker strokes so it still reads at 16px.
