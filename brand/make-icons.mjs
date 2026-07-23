// Rasterize the Wakala brand SVGs into PNG icons for app favicons / PWA / social cards.
// Usage: node brand/make-icons.mjs   (from the repo root or the brand/ dir)
//
// Uses `rsvg-convert` (librsvg) — a single, small, widely-packaged CLI
// (`brew install librsvg` / `apt install librsvg2-bin`) instead of a headless
// browser. If it isn't on PATH, falls back to `npx playwright` to screenshot
// each SVG at the target size — no other tooling required either way.
import { execFileSync } from "node:child_process";
import { mkdirSync, existsSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "icons");
mkdirSync(out, { recursive: true });

function haveRsvg() {
  try {
    execFileSync("rsvg-convert", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

async function renderWithPlaywright(svgPath, w, h, outPath) {
  const { chromium } = await import("playwright");
  const svg = readFileSync(svgPath, "utf8");
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: w, height: h } });
  await page.setContent(
    `<!doctype html><html><head><style>*{margin:0;padding:0}html,body{width:${w}px;height:${h}px;overflow:hidden;background:transparent}svg{display:block;width:${w}px;height:${h}px}</style></head><body>${svg}</body></html>`,
    { waitUntil: "networkidle" });
  await page.screenshot({ path: outPath, omitBackground: true });
  await browser.close();
}

function renderWithRsvg(svgPath, w, h, outPath) {
  execFileSync("rsvg-convert", ["-w", String(w), "-h", String(h), svgPath, "-o", outPath]);
}

async function render(rel, w, h, outName) {
  const svgPath = join(here, rel);
  const outPath = join(out, outName);
  if (haveRsvg()) renderWithRsvg(svgPath, w, h, outPath);
  else await renderWithPlaywright(svgPath, w, h, outPath);
}

const square = [16, 32, 48, 64, 180, 192, 256, 512];

for (const s of square) {
  await render("logo-mark.svg", s, s, `icon-${s}.png`);
}
// friendly aliases
await render("logo-mark.svg", 180, 180, "apple-touch-icon.png");
await render("favicon.svg", 32, 32, "favicon-32.png");
await render("favicon.svg", 16, 16, "favicon-16.png");
// social card
await render("og-image.svg", 1200, 630, "og-image.png");

console.log(`wrote icons to ${out}: ${square.map((s) => `icon-${s}`).join(", ")}, apple-touch-icon, favicon-16/32, og-image (1200x630)`);
