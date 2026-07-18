# DRAFT — upstream RFC issue for alandtse/alexa_media_player

> Status: draft, not yet posted. To be filed by the repo owner when approved.
> Suggested title: **RFC: Replace credential-persisting login with enrollment-only auth (no stored password/TOTP seed)**

---

Hi @alandtse — first, thank you for maintaining this integration; it's load-bearing in a lot of homes, including mine.

I've written a design proposal for replacing the authentication layer in `alexa_media_player` + `alexapy`, and before I build it I wanted to put it in front of you, since upstream is where it would help the most people.

## The problem

Today the integration persists, in plaintext in `.storage/core.config_entries`:

- the Amazon account **password**,
- the **TOTP shared secret** (not a one-time code — the seed itself, which effectively clones the user's authenticator onto the HA host and collapses 2FA factor independence for anyone who can read that file: backup leak, shared config, add-on with storage access),
- plus the durable OAuth tokens.

Related concerns have come up before (e.g. discussion #1385). Alongside that, the HTML-scraping login path is inherently adversarial against Amazon's markup changes, and `load_cookie()` still accepts pickle input, which is an RCE primitive if a tampered cookie file arrives via a restored backup or shared config.

## The proposal, in one paragraph

The integration already possesses the right primitive: the PKCE authorization-code → `/auth/register` device-registration exchange that yields a durable `refresh_token`. The proposal keeps exactly that and changes the bootstrap: the user authenticates **once, interactively, through Amazon's real login page** — password, OTP from their own authenticator, captcha, any challenge — and the integration persists only the minimized derived credentials (`refresh_token`, `mac_dms`, device serial) in a dedicated `Store(private=True)` file. The password and TOTP seed are never written to disk; the scraping path, the TOTP machinery (`pyotp`), and the entire pickle/cookie-persistence subsystem are deleted. Runtime re-mints access tokens and session cookies from the refresh token. Reauth is a standard `ConfigEntryAuthFailed` → `async_step_reauth` flow, with transient failures classified as `ConfigEntryNotReady` instead of forcing reauth.

The enrollment step can likely drop the capture proxy entirely in favor of the paste-URL pattern `mkb79/Audible` uses in production (`from_login_external()`): user logs in in their own browser, lands on `/ap/maplanding`, pastes the URL back; the code never transits our process.

## What I'm asking

1. **Is this direction something you'd accept upstream in principle?** It is a breaking change (one-time re-login for all users; removal of the stored-seed auto-2FA convenience) and would need a coordinated major bump of both `alexa_media_player` and `alexapy`.
2. Any institutional knowledge you can share on `/ap/maplanding` behavior (does it round-trip a `state` param?), on cookie reconstruction from the refresh token across all API/push paths, or on observed refresh-token longevity for this device identity — these are the validation spikes I'm running first.

## What I'm offering

The full design doc — including two adversarial review passes, a migration plan (validate-then-delete, lazy, non-destructive), threat-model calibration, and an HA/HACS spec-alignment audit — is here: https://github.com/superbeetle1973/alexa-auth-redesign

I'm building this regardless (as a fork if needed), but I'd much rather land it here. If you're open to it, I'll develop against upstream `dev` and submit it as a reviewable PR series (alexapy first, then the integration), with the migration path preserving existing valid refresh tokens so most users never re-login.

No response needed on any timeline — the design doc stands on its own if this is ever useful later.
