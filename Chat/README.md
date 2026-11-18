# Cosmic Chat

Cosmic Chat is a separate application under the `/Chat/` path of the Cosmic Pioneer GitHub Pages site. The existing homepage and CNAME are untouched.

## Files
- `index.html` — existing Cosmic Chat frontend with Supabase authentication and profile bootstrap.
- `config.js` — public Supabase project URL and publishable key.
- `manifest.webmanifest`, `sw.js` — installable PWA shell scoped to /Chat/.
- `database/Cosmic_Chat_Supabase_Setup.sql` — database schema, profile trigger, RLS policies, private media bucket and Realtime publication setup.

## Live URL
https://cosmicpioneer.com/Chat/

## Required setup
1. Run `database/Cosmic_Chat_Supabase_Setup.sql` in Supabase Dashboard → SQL Editor. This deployment does not execute SQL automatically.
2. In Supabase Authentication → URL Configuration, set Site URL to `https://cosmicpioneer.com/Chat/` and add the exact redirect URL.
3. Configure email confirmation and SMTP in Supabase. Keep SMTP credentials out of this repository.
4. If Google sign-in is required, enable the provider and configure OAuth credentials in Supabase and Google Cloud.
5. Test signup, verification, sign-in, sign-out and reset-email delivery.

## Current integration status
Authentication and profile bootstrap are wired in the existing frontend. The integration package documents that direct conversation creation, message history/send, group workflows and media upload are not yet fully connected. This is an initial deployment, not yet a complete public messaging service.

## Security
The publishable key in `config.js` is intended for browser use. Never add a Supabase service-role/secret key, database password or Brevo SMTP key to this repository. Keep Row Level Security enabled and the media bucket private.
