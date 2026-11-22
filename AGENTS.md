# Repository Guidelines

## Project Structure & Module Organization

- `backend/src/`: Rust/Axum API, LDAP operations, host inventory, replication and maintenance coordination.
- `frontend/src/`: React/TypeScript views and styles; `frontend/public/` contains branding assets.
- `backend/assets/`: replica deployment templates embedded in the manager binary.
- `docker/`: manager, OpenLDAP supervisor and maintenance images; `compose.yaml` defines the primary deployment.
- `tests/`: Python integration harnesses, Playwright browser checks and Ubuntu client fixtures.
- `ansible/`: Ubuntu SSSD/PAM/NSS client role. `docs/` covers architecture, security and operations.

## Build, Test, and Development Commands

From the repository root:

- `npm ci --prefix frontend`: install locked frontend dependencies.
- `npm run dev --prefix frontend`: start Vite; `/api` proxies to localhost:8080. Use the development browser origin during setup.
- `npm run build --prefix frontend`: check TypeScript and build production assets.
- In `backend/`, run `cargo fmt --check`, `cargo test --locked` and `cargo clippy --locked -- -D warnings`.
- `docker compose build`: build all runtime images.
- `docker compose up -d --build`: launch the Linux deployment after configuring `.env` from `.env.example`.
- `python3 tests/integration.py`, `python3 tests/hardening.py`, `python3 tests/replication.py`: exercise real LDAP, recovery and replication.

## Coding Style & Naming Conventions

Use rustfmt for Rust, four-space Python indentation and Prettier for TypeScript/TSX/CSS. React components use PascalCase filenames, such as `SetupWizard.tsx`; Rust modules and Python functions use snake_case. Keep abstractions small. WebUI text should use direct labels and actionable instructions; avoid promotional slogans.

## WebUI Conventions

Keep explanations and instructions behind small “i” buttons that open contextual popovers when clicked or tapped. Reuse `frontend/src/Help.tsx` (`Help` and `FieldHelp`) beside the relevant heading or field. Support keyboard interaction and keep field names, operational status, errors and required confirmations visible.

Do not use JavaScript/browser confirmation boxes (`confirm()` or `window.confirm()`). Implement confirmations as accessible in-app dialogs matching the WebUI’s existing components, colors, spacing and dark/light themes. Provide explicit confirm and cancel actions, keyboard navigation and appropriate focus management.

## Testing Guidelines

Rust unit tests live in inline `#[cfg(test)]` modules. Python suites use assertions against disposable Compose projects; browser checks use Playwright. Add meaningful coverage for changed authentication, authorization, TLS, persistence and failure behavior. No numerical coverage threshold is configured. Build images before integration suites; never reset default installation volumes. See `docs/verification.md` for browser dependencies and optional Ubuntu checks. Report passed, failed and unavailable checks.

## Commit & Pull Request Guidelines

Use concise imperative subjects, matching history: `Remove promotional WebUI copy and redundant visual clutter`. Keep commits cohesive. PR descriptions should explain behavior, validation and operational risks; link relevant issues and include screenshots for visual changes. Document breaking storage or deployment changes explicitly. Do not force-push shared history.

## Security & Configuration

Never commit `.env`, private keys, credentials, recovery bundles or LDAP data. Preserve verified TLS, server-side authorization and CSRF protections. Keep privileged provisioning behind fixed operations; do not expose Docker sockets or command endpoints. Routine directory administration belongs in the WebUI; console recovery is reserved for administrator lockout.

Native clients may provision explicitly approved Forklift services through predefined operations. Existing SSSD, PAM/NSS, SSH and host resolver configuration stays read-only to avoid lockouts. Connectivity diagnostics must identify their probe source/path and transport; never claim a local listener proves remote firewall access, or change firewall rules automatically.

## Plain-language instructions and help

Write for someone who can use Docker but does not know LDAP or DNS internals. Explain what an option does, what the person needs to enter, and what happens next. Use short sentences, familiar words and concrete examples. Avoid implementation details, unexplained acronyms and terms such as “reconcile”, “provision”, “origin”, “attestation” or “credential epoch” when a plain description works. If a technical term is necessary, explain it on first use.

Keep help focused on the current task, usually two to four short sentences. Put longer procedures and troubleshooting in linked documentation. Keep explanations behind the existing “i” buttons; keep field names, status, errors and required confirmations visible. Errors should say what failed and what to do next. Confirmations must name the target and explain what will change, what data could be lost and whether the action can be undone. Preserve important security and recovery limits when simplifying text. Do not claim that a check proves more than it actually checks.

READMEs should provide a broad overview, prerequisites and a short first-run path. Link to detailed guides instead of filling the README with protocol details or development history. Review new user-facing text for clarity as part of every change.
