# DRAFT — upstream RFC issue for alandtse/alexa_media_player

> Status: draft, not yet posted — pending owner approval. To be filed by the repo owner.
> Suggested title: **RFC: Enrollment-only auth (no stored password/TOTP seed) — working, proven fork ready for upstreaming**

---

Hi @alandtse — first, thank you for maintaining this integration; it's load-bearing in a lot of homes, including mine.

I've built and validated a replacement authentication layer for `alexa_media_player` + `alexapy` and would like to upstream it if you're open to it. It's not a proposal on paper — it's running in my live Home Assistant right now, controlling real Echo devices, with a passing test suite and an end-to-end validation run against real Amazon. Details below.

## The problem

Today the integration persists, in plaintext in `.storage/core.config_entries`:

- the Amazon account **password**,
- the **TOTP shared secret** (not a one-time code — the seed itself, which effectively clones the user's authenticator onto the HA host and collapses 2FA factor independence for anyone who can read that file: backup leak, shared config, add-on with storage access),
- plus the durable OAuth tokens.

Related concerns have come up before (e.g. discussion #1385). Alongside that, the HTML-scraping login path is inherently adversarial against Amazon's markup changes, and `load_cookie()` still accepts pickle input, which is an RCE primitive if a tampered cookie file arrives via a restored backup or shared config.

## The approach

The integration already possesses the right primitive: the PKCE authorization-code → `/auth/register` device-registration exchange that yields a durable `refresh_token`. The redesign keeps exactly that and changes only the bootstrap and what's persisted:

- The user authenticates **once, interactively, through Amazon's real login page** — password, OTP from their own authenticator, captcha, any challenge — via the **paste-URL flow** (`mkb79/Audible`'s `from_login_external()` pattern): log in in your own browser, land on `/ap/maplanding`, paste the redirect URL back. **No capture proxy** — the password/OTP never transit our process.
- The integration persists **only** the minimized derived credentials (`refresh_token`, `mac_dms`, device serial) in a dedicated `Store(private=True)` (0600) file. Password and TOTP seed are never written to disk.
- The scraping path, the TOTP machinery (`pyotp`), and the entire pickle/cookie-persistence subsystem are **deleted**.
- Runtime re-mints access tokens and session cookies from the refresh token on every start.
- Reauth is a standard `ConfigEntryAuthFailed` → `async_step_reauth` flow; transient failures are classified as `ConfigEntryNotReady` (backoff/retry) instead of forcing reauth. Account binding uses `async_set_unique_id` + `_abort_if_unique_id_mismatch()`.

## Validation — this is proven, not assumed

I ran the full flow end-to-end against a real Amazon account, and it's now live in HA. Results:

**End-to-end auth run** (`prove` harness, real account):
- **Enrollment** — paste-URL login *including an MFA challenge* → `/ap/maplanding` → `/auth/register` → durable `refresh_token` + `mac_dms`. Password/OTP entered only on amazon.com.
- **Access-token refresh** — minted from the refresh token alone. ✅
- **Cookie reconstruction** — full session cookie set (`at-main`, `sess-at-main`, `session-id`, `ubid-main`, `x-main`) rebuilt from the refresh token, **with no persisted cookies**. ✅
- **API probe** — HTTP 200 on `/api/users/me`, `/api/devices-v2/device`, `/api/bluetooth`, `/api/dnd/device-status-list` using only the reconstructed cookies. ✅
- **Push** — HTTP2 push connection opens (`open_callback` fires); it authenticates via the session + `mac_dms`, so no persisted-cookie or serial dependency. ✅

**Empirical findings from the live `/ap/maplanding` redirect** (directly answering the open questions):
- **No `state` parameter** in Amazon's signed response (`openid.signed` list) — flow binding is PKCE-only, matching Audible. Binding is handled by the in-memory PKCE verifier + `unique_id` mismatch-abort rather than a round-tripped `state`.
- **MFA round-trips** through the proxy-free paste-URL flow (`openid.pape.auth_policies=…multi-factor`).
- **The account identifier is present pre-exchange** (`claimed_id`/`identity` = `amzn1.account.…`, Amazon-signed), so `unique_id` can be bound at the paste step — stronger than binding only after token exchange.

**Automated tests:** 24 new unit tests (57 total green) covering the PKCE/enrollment primitives, the `/auth/register` exchange, the refresh lifecycle with transient-vs-terminal error classification, cookie re-minting, deregistration, and cross-process flow-state persistence.

**Live integration:** running as a HACS custom integration in my HA, 36 entities across 6 Echo devices, push connected, automations working, with the legacy integration fully removed. It cold-starts by reconstructing the session from the stored refresh token and never reads a cookie file.

## Prior-art basis

The runtime pattern (re-mint cookies from stored registration data, no persisted cookies) is what `Apollon77/alexa-cookie` v2+ has done in production for years across ioBroker.alexa2 and node alexa-remote, and what openHAB's amazonechocontrol does via `/ap/exchangetoken`. The paste-URL enrollment is `mkb79/Audible`'s production pattern. This redesign combines both against the endpoint family `alexapy` already uses.

## What I'm asking

1. **Would you accept this direction upstream in principle?** It is a breaking change — a one-time interactive re-login for all users and removal of the stored-seed auto-2FA convenience — and would need a coordinated major bump of both `alexa_media_player` and `alexapy`. (My design keeps a validate-then-delete migration so users with a live refresh token migrate with zero re-login.)
2. Any institutional knowledge on refresh-token longevity for this device identity, or on push/websocket edge cases you'd want covered, would sharpen the PR.

## What I'm offering

- The full design doc — two adversarial review passes, a lazy/validate-then-delete migration plan, threat-model calibration, and an HA/HACS spec-alignment audit: https://github.com/superbeetle1973/alexa-auth-redesign
- Working reference implementations (library + integration) with the test suite and the `prove` validation harness, already running live.

If you're open to it, I'll develop against upstream `dev` and submit it as a reviewable PR series (`alexapy` first, then the integration), preserving existing valid refresh tokens so most users never re-login. I'm maintaining a fork either way, but I'd much rather land it here where it helps everyone.

No response needed on any timeline — the design and the proof stand on their own if this is ever useful later.
