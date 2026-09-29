# Network Sweeper: muted desktop console redesign

Status: proposed, pending further review. No implementation has started.

This plan delivers the device workspace described in Release 1 of the roadmap (`docs/ROADMAP.md` on the `planning/network-sweeper-roadmap` branch). Once the last stage below has merged, fold what remains useful here into a UI section of `docs/ARCHITECTURE.md` and delete this file.

## Summary

Rework the UI around **device inventory and changes**, with a muted dark terminal aesthetic and full usability down to **640px window width**.

Keep the existing Go backend and vanilla HTML/CSS/JavaScript stack. Replace the page layout and presentation while preserving existing functionality. Ship dark mode only.

Source inspection identified the main issues: oversized header and scan setup, an 832px minimum-width device table, excessive filter stacking, notes preceding device information, and a long stacked AI layout. It also found three defects in the device modal that the redesign fixes rather than carries over: unsaved name/tag/note edits are discarded when a finished scan re-renders the open device; there is no guard against out-of-order detail responses when devices are selected quickly; and Escape or a backdrop click closes the modal without checking for pending edits. Rendered browser verification remains part of implementation.

## Why 640px

The app opens in whatever browser the user has, usually beside a terminal or as one half of a tiled screen. The widths that matter, and the layout band each one lands in:

| Situation | Content width | Table layout |
|---|---|---|
| Half of a 1920px screen, tiled | about 930px | four columns |
| Half of a 2560px screen, tiled | about 1260px | six columns; opening the inspector drops it to four |
| Full 1280px or wider window | 1280px+ | six columns, side inspector from 1200px |
| Quarter tile or a narrow side window | 640px | four columns, tight |

Below 640px is a fallback, not a supported layout.

## Delivery

Land the work as four reviewable stages, each leaving `main` shippable. Do not start a stage until the previous one has merged.

1. **Shell:** design tokens, system fonts, app bar, consent screen, prose measure, shell width, removal of gradients and entrance animations.
2. **Devices:** scan toolbar and Scan setup disclosure, search and Filters disclosure, profile selector placement, responsive table with container queries, sort selector, app-bar progress strip.
3. **Inspector:** side and modal inspector, editable name in the header, draft preservation, unsaved-edit guard, stale-request guard, inline errors with Retry, focus behaviour, rescan behaviour.
4. **Other views:** Changes, Findings, Analyze, Settings.

Stage 3 carries the most behaviour change and gets its own manual verification pass and its own synthetic-data cases.

## Workspace and visual design

- Replace the large introductory header with a compact app bar. Keep version, storage status, and privilege information accessible without competing with primary actions.
- Restyle the first-run consent screen to the same tokens: a plain panel, no entrance animation, the same control heights as the rest of the app.
- Retain top navigation: **Devices, Changes, Findings, Analyze, Settings**. Keep existing Analyze availability rules and keyboard navigation.
- Remove the 1120px shell cap for tables and lists; use available window width with consistent 16–24px gutters. Cap prose (help text, finding descriptions, Settings copy, AI messages) at roughly 70 characters so it stays readable on wide monitors.
- Use near-black charcoal backgrounds, subtly green surfaces, restrained green accents, thin borders, and 4–6px corner radii. Remove decorative gradients and entrance animations.
- Use system sans-serif for prose and controls, and system monospace for addresses, ports, counts, and compact section labels. Relative times such as "3 min ago" stay in the sans-serif face; absolute timestamps may use monospace. The stylesheet currently names Sora and JetBrains Mono without loading them, so this removes dead font references rather than a dependency.
- Target 14px primary text, 13px secondary text, and controls at least 32px tall. Maintain readable contrast, visible keyboard focus, and text labels alongside severity colors.

## Inventory and scan workflow

- Replace the tall scan panel with a compact toolbar showing selected ranges, Deep discovery state, and Scan/Stop.
- Put subnet selection, custom ranges, and capability explanations in an expandable **Scan setup** section. Expand initially when there is no inventory; collapse after a successful scan. Remember the user's last open/closed choice in `localStorage` through the existing `remembered`/`remember` helpers. Keep errors and authorization requirements visible even when collapsed.
- Move scan progress out of the Devices tab into a single slim strip under the app bar that shows phase, device count, and Stop on every tab while scanning. Preserve partial-result, timeout, save-failure, and discovery-limit messaging; the scan note and status line stay on Devices.
- Keep search always visible. Move the five secondary filters into a **Filters** disclosure with an active-filter count, removable filter chips, and Clear all. Remember the disclosure state like Scan setup.
- Place the network profile selector consistently above inventory and changes. Clearly distinguish the saved profile being viewed from the ranges selected for the next scan.
- Adapt the inventory to its **available content width**, including when the inspector is open. Use a CSS container query on the table's wrapper rather than window-width media queries or a `ResizeObserver`, so opening the inspector reflows the table with no JavaScript:
  - **960px and wider:** six columns—address, name, vendor, services, findings, last seen.
  - **640–959px:** four columns—device identity, services, findings, last seen. Combine name/address/vendor within identity.
  - **Below 640px:** compact stacked rows as a fallback.
- Provide a sort selector in compact layouts so all existing sort options remain accessible, including name and vendor once they have no header of their own. The selector drives the same `state.sort` as the header buttons, and the header's `aria-sort` reflects it in every layout. Preserve filters, sorting, selection, and scroll position across inspection and data refresh.
- Make device names explicit keyboard-accessible detail actions; retain row selection and arrow-key navigation. Mark the device open in the inspector with `aria-selected` on its row and keep that mark across re-renders.

## Device inspection and other views

- At window widths **1200px and above**, open a side inspector beside the current view. It starts at 400px, has a drag handle, is clamped between 360px and half the window, and remembers its width in `localStorage`. At narrower widths, use a full-width modal inspector with a fixed heading and close control.
- Build the modal inspector on a native `<dialog>` opened with `showModal()`. That provides the focus trap, the inert background, and Escape handling, and its `cancel` event is where the unsaved-edit guard intercepts Escape. Remove the hand-rolled Tab trap in `web/app.js` once nothing else uses the old modal.
- Put the editable device name in the inspector header, next to the address and rescan control, so renaming never requires tabbing through findings. Order the body as overview/identity, services, findings, tags/notes, then observation history.
- Preserve unsaved annotations during refresh and resizing, including the re-render that follows a finished scan and a reconnect. Keep one draft per device in memory so switching between devices does not lose or prompt for edits. Before closing the inspector or changing profiles with edits pending, offer Save, Discard, or Cancel. Failed saves retain the draft.
- Guard against stale detail requests when users select devices quickly: number each request and ignore responses that are not the latest. Show inline errors with Retry instead of silently failing.
- Implement appropriate focus behavior: the wide inspector allows access to the list; the narrow inspector traps focus and makes the background inert. Escape closes, subject to the unsaved-edit guard, and focus returns to the originating control.
- Rescan from the inspector keeps the inspector open on the same device and switches to Devices only when the inspector is modal. When the rescan finishes, the inspector refreshes in place, subject to the draft rule above.
- **Changes:** keep comparison selectors and change summaries first; place scan history below. Use compact history rows at narrow widths, retaining export actions and partial-scan labels.
- **Findings:** preserve severity, evidence confidence, review status, and remediation. Collapse evidence detail and review controls to reduce visual density, but the **confirmed / inferred** confidence label and severity stay visible on the collapsed card. That distinction is the honesty feature of Findings.
- **Analyze:** retain consent, masking, backend selection, prompt export, and chat. After setup, prioritize conversation; collapse setup and device references behind accessible disclosures in narrow windows. Keep the composer reachable and contain scrolling code blocks.
- **Settings:** group network permissions, storage/history, AI-related configuration where applicable, updates, and capabilities with consistent section styling.

## Implementation and verification

- Build from current `main`, including the merged AI work. Concentrate changes in `web/index.html`, `web/style.css`, and `web/app.js`; remove superseded styles in the stage that replaces them rather than layering overrides.
- Keep API contracts, saved inventory formats, session security, scan authorization, and AI consent semantics unchanged. No new production dependencies or Node build requirement.
- Container queries, `<dialog>`, and `inert` are supported by every current Chrome, Edge, Firefox and Safari release. The app opens in the user's default browser, so no fallback is needed for older engines.
- **Synthetic data.** There is no browser test harness and CI runs Go only, so UI verification is manual or agent-driven, not automated. To make it repeatable, commit a synthetic data directory under `testdata/ui/` in the store's own format (`inventory.json` plus `scans/<id>.json`), copy it to a temporary directory, and run the binary against it:

  ```bash
  cp -r testdata/ui /tmp/ns-ui && go run ./cmd/networksweeper -no-browser -data-dir /tmp/ns-ui
  ```

  The data set covers long names, many tags/services, multiple profiles, findings of every status, partial scans, and a device with a pending-edit scenario. Unavailable AI, empty results, disconnection, and failed saves are exercised by stopping the binary or the backend rather than by data.
- Inspect every view at **1920×1080, 1440×900, 1280×720, 960×720, 800×700, and 640×700**, plus a 390px fallback and 200% browser zoom.
- Acceptance: no page-level horizontal scrolling at supported widths; no clipped controls; essential inventory fields remain visible; the collapsed default Devices view shows at least five **ordinary rows** at 640×700, where an ordinary row is a device with a name, one badge, two tags, and four services.
- Verify keyboard-only navigation, inspector resizing, draft preservation across a finished scan, rapid device switching, filter/sort retention, scan cancellation from a non-Devices tab, annotations, finding review, comparison, exports, and AI setup/chat using the synthetic data and a stopped or absent backend.
- Run `make test` and `make build`. Capture representative wide and narrow screenshots for review. Use synthetic data for UI validation without initiating LAN scans or sending AI requests.
