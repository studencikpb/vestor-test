# Vestor security audit remediation

Reviewed against `Vestor_Full_Security_Audit.pdf` on 2026-07-29.

| Audit item | Remediation |
|---|---|
| Stored XSS in profile/user list | Profile fields are length-limited and rendered with DOM `textContent`; market and wallet values used in HTML are escaped and URLs are protocol-validated. |
| Portfolio in `user_metadata` | Added `portfolio_positions` with per-user RLS. The client migrates legacy data and removes old copies only after a verified database write. |
| Persistent auth/API secrets in localStorage | Supabase Auth now uses `sessionStorage`. CoinGlass key collection/storage was removed. Portfolio performance and public-wallet session state moved to `sessionStorage`. |
| Missing browser security policy | Added CSP meta policy and production `_headers` with CSP, HSTS, anti-framing, MIME, referrer and permissions controls. |
| Owner role based on e-mail | Added `user_roles`, seeded once to the owner's UUID. Runtime owner checks use `get_my_role()`/`auth.uid()`. |
| Invitation controls | Invite RPC is restricted to the owner UUID role; all new accounts require the rotating invitation code and Supabase e-mail confirmation remains required. |
| Unpinned CDN code | Supabase JS, jsPDF, Tesseract, its worker and OCR core are pinned and served from `vendor/`. |
| Financial privacy in browser storage | Portfolio is moved to RLS storage; sensitive per-session caches use session storage and are cleared at logout after successful migration. |

## Residual platform limitations

- A fully `HttpOnly` authentication cookie requires a trusted application
  backend. A static GitHub Pages deployment cannot issue it; Vestor therefore
  uses tab-scoped Supabase sessions plus CSP/XSS defenses.
- GitHub Pages cannot set arbitrary HTTP response headers. Use Cloudflare in
  front of GitHub Pages (or Cloudflare Pages/Netlify) to apply `_headers`.
- The SQL migration must be executed in the Supabase project before production
  launch. Until then Vestor deliberately retains the legacy local portfolio so
  no holdings are lost.
- MFA and Supabase production URL configuration are administrative Supabase
  settings and must be enabled in the dashboard.
