# ANISAS Enterprise Platform — Session Context (hand-off)

Copy this entire file into a new chat as the opening message.

> **⚠ UPDATE 2026-08-25 (late):** Per user request, the ENTIRE premium dual-theme redesign + FX layer was REVERTED. `index.html` is back to the pre-redesign dark command-center (original body bg `#05080d`, standard Tailwind palette + `soc` colors, FORCE MAP/DNS MAP/NETWORK intact with literal hex canvas colors, no theme toggle/rail/spotlight/tilt/stagger). Verified: tscheck `blocks=3 with_errors=0` (back to original count), py_compile OK, CDP smoke PASS (0 errors, 44-node force graph renders with original `#22d3ee` palette, full 248px sidebar). The removed redesign is fully preserved in `%TEMP%\opencode\index_redesign_backup_20260825.html` if ever wanted back. All theme/FX details below are now HISTORICAL — current file has NO `anisox-theme` style block, NO theme/FX engine JS, NO `__tok`/`__forcePalette` (static `__FORCE_C` object instead).

## Objective
- ANISAS cybersecurity platform (FastAPI backend `ai-service/main.py`, single-file vanilla frontend `ai-service/static/index.html` — NO build step, Tailwind CDN + vanilla JS). All 6 modules: ASN & ISP (M1/M01), Network Recon (M2), Security Perimeter (M3), Surveillance & IoT (M4), AI/ML Anomaly (M5), Unified Dashboard (M6) with DNS MAP + NETWORK + FORCE MAP topology views.
- COMPLETED across prior sessions: M1–M6 rebuilds, DNS MAP, NETWORK premium redesign, FORCE MAP (d3-force, hover dim/focus k=2.1/filter/drawer/back-to-DNS, dispersion tuning), **full premium dual-theme redesign**, **app-wide FX layer** (spotlight/tilt/stagger). Everything CDP-verified, zero console errors.
- Hard constraint honored throughout: ZERO changes to any `.py`/backend/logic/data contract — all work is CSS/markup/presentation-JS inside index.html only.

## Important Details
- Project root: `C:\Users\harshal Patel\OneDrive\Desktop\Cybersecurity\ANISAS_Enterprise_Platform`; Python: `C:\Users\harshal Patel\AppData\Local\Programs\Python\Python314\python.exe`.
- Gates: `$env:TEMP\opencode\jsvenv\Scripts\python.exe $env:TEMP\opencode\tscheck.py` → expect **`blocks=4 with_errors=0`** (4 JS blocks incl. theme engine + FX engine) AND `py_compile main.py` OK.
- Server: uvicorn on **port 9000**, currently RUNNING (restarted with inline `$env:GROQ_API_KEY="<REDACTED>"`). App URL: http://localhost:9000 (user told to Ctrl+F5).
- **Any server restart WIPES in-memory stores** → re-run `%TEMP%\opencode\dns_seed.py` (~58s) to re-seed github.com demo scan. Current store: github latest (force = 44 nodes/43 edges; 15 subdomains/11 IPs/12 CVEs/statuses 200×5). User's own live scan of `host-118-213-34-133.net` (3 nodes) remains stored but not "latest".
- **User actively uses the app mid-session** — scans can change "latest" under tests; make CDP assertions dynamic (e.g., compare rendered sim nodes vs `window.__lastTopo.force.nodes.length`, legend rows vs `FORCE_TYPES.length`=9).
- Tooling gotchas learned:
  - Edit tool oldString can fail near `</head>` (EOL quirk) → use `[System.IO.File]::ReadAllText/Replace/WriteAllText` with `UTF8Encoding($false)`; multi-line bash string replaces break on CRLF → single-line pairs or `ReadAllLines`+index write.
  - PowerShell `Get-Content`/`Set-Content` without `-Encoding UTF8` mangles non-ASCII (`·`→`?`) when roundtripping test files → use `[System.IO.File]::ReadAllLines($f,[System.Text.Encoding]::UTF8)`.
  - Headless Chrome defaults `prefers-color-scheme: LIGHT` → pre-paint picks light unless localStorage set; tests must clear localStorage + call `__anisasSetTheme('dark', true)` first.
  - Legacy hidden markup has DUPLICATE ids (`side-m1` etc., old header/sidebar blocks ~lines 516–648) → ALWAYS scope selectors (`#appSidebar #side-m1`, real toggle is `#themeToggleBtn`).
  - Purge stale headless chromes before every run (`Win32_Process Name='chrome.exe' CommandLine like '*--remote-debugging*'` → Stop-Process) + fresh port/profile per run (ports/profiles consumed up to **9269 / chrome-m9kx**). Sequential suites in ONE shell call collide on WS handshake — run separately with purge+sleep between.
  - MutationObserver callbacks fire post-microtask → CDP tests must sleep ~250ms after DOM injection before asserting classes.
  - FORCE_TYPES.length = 9 (includes port type); legend renders all rows unconditionally with counts — never assert hardcoded 8.

## Work State
### Completed (all verified)
- **Dual-theme system** (`index.html`): pre-paint script (localStorage `anisas-theme` > prefers-color-scheme > dark; sets `data-theme` on `<html>`, no FOUC); Google Fonts Space Grotesk/Inter/JetBrains Mono; Tailwind config rewritten so slate+gray ladders (`__twLadder`) and 13 accent hues (`__twAcc`: cyan/blue/sky/emerald/green/teal/amber/yellow/orange/red/rose/pink/violet/purple/indigo) resolve through `--tw-*` CSS vars with `<alpha-value>` — light theme uses inverted perceived-lightness ramps, NOT invert filter; full token sets (`--app-bg`, surfaces, borders, text, accents, glass-blur/sheen/shadows, grid/vignette/glows, topo label/stroke, `--fc-*` node colors, `--fe-*` edge colors) for both themes in `<style id="anisox-theme">` before `</head>`; glass-morphism upgrade (blur 18px+saturate, sheen ::before, hover lift), button press scale(.97), focus-visible rings, pulse dots, `.anisas-live-pill` (honest IDLE/SCANNING bound to existing `body.scan-running` class, 700ms poll — NO EventSource exists), `.anisas-clock` UTC ticker (`#utcClock`), `.theme-toggle` moon/sun icon swap, sidebar→76px icon rail @≥1024px with `data-tip` flyout tooltips, light-theme `.text-white` corrections (re-whitened inside gradient CTAs/brand mark), `#forceSvg` label fill/stroke + themed bg radial, `html.theme-transition` 340ms crossfade, `.shimmer`, prefers-reduced-motion kill-switch.
- **Canvas/theme wiring**: `__tok(name,fb)` helper; `__forcePalette()`; `__FORCE_C` refreshed first line of `__renderForceTopology`; `EDGE_STYLE` values tokenized (`--fe-cdn/--fe-satellite/--fe-resolve/--fe-cname/--fe-service`, fallback `--fe-root`); risk-badge stroke + rootHalo stroke + vis-network fonts/strokes read tokens; theme switch re-renders active view via signature bust (`window.__lastSigRendered=''` + `__setTopoMode(window.__topoMode)`).
- **Theme engine JS** (block #4, before window.onload): `__anisasApplyToggleUi`, `__anisasRerenderTopo`, `__anisasSetTheme(theme,skipAnim)` (transition class, persist, dispatches `anisas-themechange`), `__anisasToggleTheme`, public API `window.__anisasTheme.{get,set,toggle}`; UTC clock interval; scan-pill watcher; hero tilt bootstrap (`main > div > .glass-panel:first-child`, dataset.tiltInit guard, ±3°).
- **App-wide FX layer** (this session): CSS appended to `#anisox-theme` — `.fx-spotlight` cursor-follow radial glow (`--mx/--my`, accent 9%), `.fx-in` entrance keyframe with `--d` stagger var, row hover tint, `.fx-tilt-host`, `.fx-empty` unified empty-state utility. JS FX engine IIFE (before window.onload): `initSpotlight()` binds `#topoCanvasWrap` + `#topoForceWrap`; delegated passive `pointermove` on body tilts any `main .glass-panel` ≥220×90px ±1.6° perspective (excludes `.js-tilt` heroes, header/rail/drawer/`.soc-pipeline`/nav/canvas regions; pointerout clears after 60ms); MutationObserver staggers new `<tr>`s in ALL 6 dynamic tbodies (`m2PortsTableBody`, `m4AssetsTableBody`, `m4CveTableBody`, `m4SubnetCveTableBody`, `m2DnsTableBody`, `m2SubdomainsTableBody`) with 45ms/item capped 360ms; everything gated off under reduced-motion/touch.
- **Verification — ALL GREEN**: tscheck `blocks=4 with_errors=0`; py_compile OK; NEW `fx_cdp.py` PASS (stagger applied w/ delays, tilt transform `rotateX(0.94deg) rotateY(-1.4deg)` live, spotlight `--mx` tracks e.g. `16.23%`, emulated reduced-motion → zero fx, 0 errors); `m6_theme_cdp.py` PASS 16 checks (toggle flips bg rgb(5,8,16)⇄rgb(238,242,247), persists reload, rail width 60–95px, scoped data-tip regex `/^M01.{1,3}ASN & ISP$/`, ≥5 `.js-tilt`, both themes re-render matching payload, `--fc-ip` #22d3ee⇄#0891b2, no overflow @1440/1024/768/390); `m6_force_cdp.py` PASS (44 nodes/43 links, hover dim 41/44+41 edges restore 0, drawer detail, search-focus scale(2.1)+pulse, filter hides node, back-to-DNS); `m6_premium_cdp.py` PASS (chips/collapse/filter/tooltip/strip/trail/morph); `m6_dns_cdp.py` PASS (structure, click-strip content, net toggle persistence). Zero console errors everywhere.

### Active
- Nothing — feature work complete, all suites green, user given link http://localhost:9000.

### Blocked
- None.

## Flagged / intentionally skipped (per "skip-don't-force" rule)
1. Table empty-states: rendering placeholder rows requires touching each module's render functions (forbidden) → provided `.fx-empty` CSS utility; one-line wiring per tbody later if logic edits become acceptable.
2. Module 2 has no second canvas → ambient spotlight bound only to module 6 canvas region (spec's conditional).
3. M04 auto-runs a live scan on tab open — PRE-EXISTING behavior, deliberately untouched (warn user/tests).
4. Chart.js CDN loads but app has zero `new Chart(` calls — nothing to theme there.
5. Count-up number animations skipped (would require render-logic changes).

## Next Move
- No pending work. If continuing: candidates are (a) wire `.fx-empty` into tbodies when logic-touch is allowed, (b) human visual AA/eyeball pass of light theme (programmatic contrast pairs validated only), (c) if server restarted since, re-seed via `%TEMP%\opencode\dns_seed.py`.

## Relevant Files
- `ai-service/static/index.html` (~5100+ lines): ALL frontend changes. Key landmarks: head pre-paint script + font links + var-driven tailwind.config; `<style id="anisox-theme">` before `</head>` (both palettes + components + rail + FX CSS at end of block); topbar `#utcClock`/`#sseLivePill`/`#themeToggleBtn`; sidebar rail `data-tip`s; JS block ~3073–3240 region (`__tok`/`__forcePalette`/tokenized `__FORCE_C`/`EDGE_STYLE`/badge/halo strokes/vis fonts); theme-engine block then FX-engine block immediately before `window.onload` (~line 4896+). Legacy hidden dup-ID blocks still present (~lines 516–648).
- `ai-service/main.py`: UNTOUCHED all sessions (py_compile OK); force endpoint + helpers intact.
- `%TEMP%\opencode\fx_cdp.py`: FX-layer CDP suite (PORT 9265/chrome-m9kt last; bump per run).
- `%TEMP%\opencode\m6_theme_cdp.py`: theme/redesign suite (clears storage + forces dark first; scopes `#appSidebar #side-m1`; dynamic node/legend counts).
- `%TEMP%\opencode\m6_force_cdp.py` (patched: `legendRows == base["legendTypes"]` where base eval injects `legendTypes: FORCE_TYPES.length`), `m6_premium_cdp.py`, `m6_dns_cdp.py`: interaction regressions, all currently passing.
- `%TEMP%\opencode\dns_seed.py`: re-seeds github demo scan after restart.
- `%TEMP%\opencode\tscheck.py` + `%TEMP%\opencode\jsvenv\`: syntax gate (expect blocks=4 with_errors=0).
- `%TEMP%\opencode\m6_theme_shots.py` / `force_low.png` / `force_dense.png`: screenshot tooling (model cannot view images; user can).
