# Vestor security and deployment

## Required before publishing

1. Run the complete `supabase-setup.sql` in the Supabase SQL Editor.
2. Confirm that e-mail confirmation remains enabled in Supabase Auth.
3. Add the final HTTPS GitHub Pages URL to Supabase Auth → URL Configuration:
   both **Site URL** and **Redirect URLs**.
4. Enable MFA for the owner account in Supabase.
5. Sign in once locally. Vestor will migrate the legacy portfolio to
   `portfolio_positions`; it removes the old browser/user-metadata copy only
   after a verified database write.

## Hosting headers

`_headers` contains the production CSP, HSTS and anti-framing headers for
platforms that support this format (for example Cloudflare Pages and Netlify).
GitHub Pages does not currently allow a repository to configure arbitrary HTTP
response headers. The app therefore also contains a CSP meta policy, but
`frame-ancestors`, HSTS and `X-Frame-Options` require a host or reverse proxy
that supports response headers. For the strongest production setup, place
Cloudflare in front of GitHub Pages or deploy to Cloudflare Pages.

## Data handling

- Auth sessions use `sessionStorage`, not persistent `localStorage`.
- Portfolio positions are private Supabase rows protected by RLS.
- Owner authorization uses the immutable Supabase user UUID and `user_roles`.
- No third-party API key is stored in the browser.
- Supabase, jsPDF and Tesseract builds are pinned and served locally.
