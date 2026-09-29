# Network Sweeper: muted desktop console redesign

Status: proposed, pending further review. No implementation has started.

## Summary

Rework the UI around **device inventory and changes**, with a muted dark terminal aesthetic and full usability down to **640px window width**.

Keep the existing Go backend and vanilla HTML/CSS/JavaScript stack. Replace the page layout and presentation while preserving existing functionality. Ship dark mode only.

Source inspection identified the main issues: oversized header and scan setup, an 832px minimum-width device table, excessive filter stacking, notes preceding device information, and a long stacked AI layout. Rendered browser verification remains part of implementation.

## Workspace and visual design

- Replace the large introductory header with a compact app bar. Keep version, storage status, and privilege information accessible without competing with primary actions.
- Retain top navigation: **Devices, Changes, Findings, Analyze, Settings**. Keep existing Analyze availability rules and keyboard navigation.
- Remove the 1120px shell cap; use available window width with consistent 16–24px gutters.
- Use near-black charcoal backgrounds, subtly green surfaces, restrained green accents, thin borders, and 4–6px corner radii. Remove decorative gradients and entrance animations.
- Use system sans-serif for prose and controls; system monospace for addresses, ports, timestamps, counts, and compact section labels. Avoid external font dependencies.
- Target 14px primary text, 13px secondary text, and controls at least 32px tall. Maintain readable contrast, visible keyboard focus, and text labels alongside severity colors.

## Inventory and scan workflow

- Replace the tall scan panel with a compact toolbar showing selected ranges, Deep discovery state, and Scan/Stop.
- Put subnet selection, custom ranges, and capability explanations in an expandable **Scan setup** section. Expand initially when there is no inventory; collapse after a successful scan. Keep errors and authorization requirements visible.
- Show scan progress and Stop across tabs while scanning. Preserve partial-result, timeout, save-failure, and discovery-limit messaging.
- Keep search always visible. Move the five secondary filters into a **Filters** disclosure with an active-filter count, removable filter chips, and Clear all.
- Place the network profile selector consistently above inventory and changes. Clearly distinguish the saved profile being viewed from the ranges selected for the next scan.
- Adapt the inventory to its **available content width**, including when the inspector is open:
  - **960px and wider:** six columns—address, name, vendor, services, findings, last seen.
  - **640–959px:** four columns—device identity, services, findings, last seen. Combine name/address/vendor within identity.
  - **Below 640px:** compact stacked rows as a fallback.
- Provide a sort selector in compact layouts so all existing sort options remain accessible. Preserve filters, sorting, selection, and scroll position across inspection and data refresh.
- Make device names explicit keyboard-accessible detail actions; retain row selection and arrow-key navigation.

## Device inspection and other views

- At window widths **1200px and above**, open a 400px side inspector beside the current view. At narrower widths, use a full-width modal inspector with a fixed heading and close control.
- Order details as overview/identity, services, findings, notes/tags, then observation history. Keep rescan available in the inspector header.
- Preserve unsaved annotations during refresh and resizing. Before closing, switching devices, or changing profiles with edits pending, offer Save, Discard, or Cancel. Failed saves retain the draft.
- Guard against stale detail requests when users select devices quickly. Show inline errors with Retry instead of silently failing.
- Implement appropriate focus behavior: the wide inspector allows access to the list; the narrow inspector traps focus and makes the background inert. Escape closes, subject to the unsaved-edit guard, and focus returns to the originating control.
- **Changes:** keep comparison selectors and change summaries first; place scan history below. Use compact history rows at narrow widths, retaining export actions and partial-scan labels.
- **Findings:** preserve severity, evidence confidence, review status, and remediation. Use collapsible evidence and review controls to reduce visual density.
- **Analyze:** retain consent, masking, backend selection, prompt export, and chat. After setup, prioritize conversation; collapse setup and device references behind accessible disclosures in narrow windows. Keep the composer reachable and contain scrolling code blocks.
- **Settings:** group network permissions, storage/history, AI-related configuration where applicable, updates, and capabilities with consistent section styling.

## Implementation and verification

- Build from current `main`, including the merged AI work. Concentrate changes in `web/index.html`, `web/style.css`, and `web/app.js`; remove superseded styles rather than layering overrides.
- Keep API contracts, saved inventory formats, session security, scan authorization, and AI consent semantics unchanged. No new production dependencies or Node build requirement.
- Verify with synthetic populated data: long names, many tags/services, multiple profiles, findings of every status, partial scans, unavailable AI, empty results, disconnection, and failed saves.
- Inspect every view at **1920×1080, 1440×900, 1280×720, 960×720, 800×700, and 640×700**, plus a 390px fallback and 200% browser zoom.
- Acceptance: no page-level horizontal scrolling at supported widths; no clipped controls; essential inventory fields remain visible; the collapsed default Devices view shows at least five ordinary rows at 640×700.
- Verify keyboard-only navigation, inspector resizing, draft preservation, rapid device switching, filter/sort retention, scan cancellation, annotations, finding review, comparison, exports, and AI setup/chat using mocked responses.
- Run `make test` and `make build`. Capture representative wide and narrow screenshots for review. Use synthetic data for UI validation without initiating LAN scans or sending AI requests.
