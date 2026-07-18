# Alexa Media Player — Auth Replacement Design

**Date:** 2026-07-18
**Author:** Claude (analysis of `alandtse/alexa_media_player` + `keatontaylor/alexapy`)
**Status:** PROVEN end-to-end against real Amazon (2026-07-18); reviewed (Codex adversarial + contradiction-resolution passes); delivery decided — fork-first, new domain
**Repo:** https://github.com/superbeetle1973/alexa-auth-redesign (public)
**Implementation:** https://github.com/superbeetle1973/alexapy-secure (`secureauth` module, PR #2)

## Proof of concept — VERIFIED 2026-07-18

Ran the `alexapy_secure.prove` harness against a real Amazon account
(interactive login by the operator). All steps green:

- **enroll:** paste-URL login (MFA challenge included) → maplanding redirect →
  authorization code → `/auth/register` exchange → durable `refresh_token` +
  `mac_dms` stored at `0600`. Password/OTP only ever entered on amazon.com.
- **refresh:** 375-char access token minted from the refresh token alone.
- **cookies:** session cookies (`at-main`, `sess-at-main`, `session-id`,
  `ubid-main`, `x-main`) reconstructed from the refresh token — **no persisted
  cookies** — validating the cookie-reconstruction assumption (OQ3).
- **probe:** HTTP 200 on `/api/users/me`, `/api/devices-v2/device`,
  `/api/bluetooth`, `/api/dnd/device-status-list` using only the reconstructed
  cookies — the re-minted session actually works.

Empirical confirmations from the live maplanding redirect:
- **No `state` parameter** in Amazon's signed response (`openid.signed` list) —
  confirms the PKCE-only binding decision (OQ5).
- **MFA round-tripped** (`openid.pape.auth_policies=…multi-factor`) through the
  proxy-free paste-URL flow (OQ1/OQ2).
- **Account identifier present pre-exchange** (`claimed_id`/`identity` =
  `amzn1.account.…`, Amazon-signed) — the config entry `unique_id` can be bound
  at the paste step, stronger than the "only after exchange" fallback the
  design assumed.

The two load-bearing unknowns (paste-URL viability, cookie reconstruction) are
now measured facts, not precedent-based assumptions.

## Scope

Redesign authentication for the Home Assistant `alexa_media_player` integration
and its `alexapy` library. The current model stores replayable secrets (password
and TOTP seed) at rest and bootstraps durable tokens through fragile HTML
scraping. This document identifies the underlying problems and specifies a
replacement built on the OAuth primitive the code already possesses.

## Current auth model (as-is)

All real auth lives in `alexapy/alexalogin.py` (~2,250 lines). Two entangled
paths:

1. **HTML-scraping login** — `login()` → `_process_page()`
   (`alexalogin.py:1041`–`2170`). Fetches Amazon's sign-in page and scrapes it
   by element ID (`signIn`, `auth-captcha-image`, `auth-mfa-otpcode`,
   `claimspicker`, `auth-select-device-form`, `verify`, `pollingForm`,
   `ap_error_return_home`; lines 1965–2119). Fills the form, generates the TOTP
   code itself from a stored seed, and re-POSTs.

2. **Auth-capture-proxy login** — `alexaproxy.py`, built on `authcaptureproxy`.
   Stands up a local proxy; the user logs in through Amazon's *actual* page in
   their browser; the proxy captures `openid.oa2.authorization_code` off the
   `/ap/maplanding` redirect (`alexaproxy.py:60`–`72`).

Either path then calls `get_tokens()` (`alexalogin.py:1255`) — a device
registration exchange with PKCE against `/auth/register`, returning a durable
`refresh_token`, `access_token`, and `mac_dms` (lines 1303–1359). PKCE is set up
correctly in `start_url` (`code_challenge_method=S256`, `scope=device_auth_access
offline_access`, lines 552–579). Runtime uses `refresh_access_token()` (1647) and
`exchange_token_for_cookies()` (1710).

Be precise about what this is: **not** a standard, supported OAuth flow. It is an
OpenID 2.0 / Login-with-Amazon extension that impersonates a first-party device
client (device type `A2IVLV5VM2W81`, bundle `com.amazon.echo`) against
*undocumented* endpoints. PKCE is used correctly and protects the authorization
code from interception, but PKCE does not legitimize the client, make the
endpoints stable, or stop Amazon from blocking or revoking the registration.

**The token-exchange machinery is the least-bad primitive available and is
mechanically correct. The problems are in how it is bootstrapped, what it stores,
and how it persists state — none of which the PKCE correctness addresses.**

## Underlying problems

### 1. The TOTP seed is stored — collapses factor independence for this data (most serious)

`CONF_OTPSECRET` (the TOTP *shared secret*, not a one-time code) is written to
the HA config entry `data` in plaintext (`config_flow.py:539/563`, persisted via
`data=self.config` at `config_flow.py:547`, re-read at `__init__.py:668`,
`set_totp` at `alexalogin.py:605`). It lives in `.storage/core.config_entries`
next to the password.

TOTP is meant to be an independent second factor derived from a seed that lives
only on the user's phone. Storing the seed on the same server, in the same
at-rest blob as the password, effectively clones the authenticator into HA:
anyone who reads that data recovers both factors from one file read (backup leak,
misconfigured share, compromised add-on). To be precise — this does not make
Amazon's 2FA universally void against unrelated attackers; it collapses factor
*independence* specifically against compromise of this HA data, which is exactly
the boundary the integration is responsible for. It's done by design, to enable
unattended re-login.

### 2. The password is also retained at rest

`self.config[CONF_PASSWORD] = self.login.password` (`config_flow.py:458`) is
persisted in the same entry. The `cleaned_config.pop(CONF_PASSWORD, None)` at
`__init__.py:1317` only strips a **copy** handed to platform setup — the
persisted entry keeps it. Password + TOTP seed + durable tokens all live
together in plaintext.

### 3. Secrets reach the logs

`set_totp()` logs the seed via `hide_serial()` (`alexalogin.py:617`);
`get_totp_token()` logs the generated OTP partially masked (`alexalogin.py:647`).
These are partial maskers, not redaction. Support routinely asks users to enable
debug logging.

### 4. HTML scraping is inherently fragile and adversarial

The scraping path couples the integration to Amazon's exact login markup. Every
captcha change, anti-automation JS injection, new challenge type, or renamed
element ID breaks it — the code already carries handling for
`anti-automation-js.html` and forgot-password lockouts (`alexalogin.py:2103`–
2112). Amazon actively fights automated form submission. This path cannot be made
robust, only maintained reactively.

### 5. OTP concatenated onto the password field

`self._data["password"] = self._password + securitycode` (`alexalogin.py:2197`).
Mimics Amazon's combined-field behavior but is brittle and handles the second
factor as a string glued to the first.

### 6. Pickle deserialization of cookie files is an RCE vector

`load_cookie()` still calls `pickle.loads(raw_cookie_file)`
(`alexalogin.py:713`) and `MozillaCookieJar.load` as "migration" fallbacks.
Deserializing a tampered cookie file is an RCE primitive: a malicious
`.storage/alexa_media.*.pickle` executes arbitrary code on load. Calibrated: an
attacker who can already modify HA's protected `.storage` often has a strong
execution path anyway, so the real value is closing the *lower-privilege* boundary
— a poisoned file arriving via a restored backup, a shared config, or an add-on
with narrower filesystem access than full code execution. Cheap to remove, worth
removing. The JSON format is good; **accepting** pickle is the hole.

### 7. Cookie persistence depends on aiohttp private internals

`_serialize_cookie_jar()` reaches into `_host_only_cookies`, `_expirations`,
`_cookies` (`alexalogin.py:166`–173); the module monkeypatches `Morsel._reserved`
(line 70). This is why cookie handling breaks across aiohttp/Python upgrades. The
durable `refresh_token` already makes persisted cookies unnecessary.

### 8. Durable tokens stored in plaintext

The `oauth` dict — `refresh_token`, `access_token`, `mac_dms`, `code_verifier`,
`authorization_code` — is written to the config entry in plaintext
(`__init__.py:1370`). The `refresh_token` alone is full, durable account access.
HA has no first-class secret vault (partly a platform gap), but the integration
stores more than it needs and never encrypts.

## Reality check on "documented correct auth"

Amazon publishes no public API for third-party control of a *personal* Alexa
account. The documented paths — Login with Amazon (LWA) OAuth2, Alexa Voice
Service (AVS) for device makers, the Smart Home Skill API — don't grant the
arbitrary account control this integration needs. A "fully correct" replacement
can't become a blessed public API. It can only (a) use the least-bad primitive
available — the first-party-device registration exchange, which is unsupported
and can break or be blocked without notice — and (b) stop *persisting* replayable
secrets. The integration already uses that primitive (PKCE authorization-code →
device `refresh_token`); the design builds on it and deletes the fragile scraping
and cookie-persistence layers around it.

**Operational and account risk (must stay visible):** this flow is unsupported
and adversarial. It may violate Amazon's terms, can break on any server-side
change, and may trigger account challenges, throttling, or accumulation of
registered devices on the account. That risk is inherent to the integration's
existence; this redesign reduces the *secret-handling* blast radius but does not
make the flow supported or durable-by-contract.

## Replacement design

**Core principle:** authenticate interactively **once** through Amazon's own
page, exchange for a durable device `refresh_token`, then never *persist* the
password or the TOTP seed. Everything at runtime derives from the refresh token.

**Important boundary — exposure vs. persistence.** The current auth-capture proxy
(`authcaptureproxy`) is a man-in-the-middle: it terminates and re-forwards
Amazon's login traffic, so it *can observe* the password, the typed OTP, cookies,
and challenge responses while they pass through. This design does **not** claim
the integration never *sees* those values — with the MITM proxy it necessarily
does. What it guarantees is that they are never *written to disk* and are
discarded when the flow ends. Eliminating exposure entirely (not just
persistence) would require a direct-to-Amazon browser flow with a safe callback,
never routing credentials through our process. That is the stronger target and is
called out under Open questions.

### Enrollment (one time, and on reauth)

1. Generate a fresh PKCE `code_verifier`/`code_challenge`, a `state` value for
   CSRF/flow-ownership binding, and a stable device `serial`/`uuid` (existing,
   `alexalogin.py:482`–499).
2. Launch the auth-capture-proxy pointed at Amazon's real `/ap/register`
   authorize URL (existing `start_url`).
3. **The user logs in through Amazon's actual page** — password, an OTP generated
   by the user's own authenticator (never the seed), captcha, push-to-approve,
   any challenge Amazon presents, handled by Amazon's own JS. These values transit
   the proxy but are never persisted.
4. The proxy captures `authorization_code` from `/ap/maplanding`
   (`alexaproxy.py:60`). Acceptance is gated on the flow-integrity design
   resolved by validation spike 5; do not assume that this non-standard
   OpenID 2.0/device-registration redirect round-trips an arbitrary `state`
   parameter. Account identity must be verified at the earliest point the
   exchange exposes a trustworthy account identifier, which may be only after
   token exchange.
5. Call `/auth/register` with `authorization_code` + `code_verifier` →
   `refresh_token` + `mac_dms` (existing `get_tokens()`).
6. **Discard** `authorization_code`, `code_verifier`, the proxy session, and any
   transient password/OTP; never persist password or otp_secret.

### What gets stored

Only `refresh_token`, `mac_dms`, and the device `serial`, protected at rest (see
below). This is a smaller set than today, but be honest about it: `refresh_token`
is a replayable bearer credential and `mac_dms` is device authentication material
(usable for replay/cloning and request signing), **not** harmless metadata. The
stored set alone is sufficient for account access, so it needs redaction in logs,
rotation on re-enrollment, and revocation semantics — it is *minimized* durable
credential material, not *eliminated* durable credential material.

### Runtime

- `refresh_access_token()` mints short-lived access tokens from the refresh
  token (existing, `alexalogin.py:1647`).
- `exchange_token_for_cookies()` re-mints session cookies each start from the
  refresh token (existing, `alexalogin.py:1710`). Cookies are not persisted,
  which deletes the `load_cookie`/`save_cookiefile`/serialization subsystem
  (problems 6 and 7). **Precedent-backed:** `Apollon77/alexa-cookie` v2+ has
  re-minted cookies from stored registration data (no re-login, no persisted
  cookies) in production for years across ioBroker.alexa2 and node
  alexa-remote; openHAB's amazonechocontrol does the same via
  `/ap/exchangetoken` (`source_token_type=refresh_token` → `auth_cookies`) —
  the identical endpoint family alexapy already calls. Verified implicitly by
  the fork's own first restart during development rather than a pre-work
  spike.
- **Refresh failures must be classified, not blindly treated as reauth.** HA
  expects `async_step_reauth` only on genuine *authentication* failure
  (revoked/expired token, password change). Transient network/server errors and
  rate limiting must instead back off and retry (`ConfigEntryNotReady`), or every
  Amazon blip forces needless human intervention. The refresh path also needs:
  refresh-token rotation with atomic replacement, a lock around concurrent
  refreshes, crash recovery (validate new credentials before committing), and
  exponential backoff. Only terminal auth errors escalate to interactive
  enrollment.

### What this deletes

- `login()` + `_process_page()` + `_populate_data()` HTML scraping (~700 lines)
  — problems 4, 5.
- All TOTP seed handling and generation (`set_totp`, `get_totp_token`, the
  `pyotp` dependency) — problems 1, 3. There is no stored-seed opt-in or legacy
  auto-2FA mode; users complete any MFA challenge interactively through Amazon.
- Password persistence — problem 2.
- `load_cookie`/`pickle`/`MozillaCookieJar`/`_serialize_cookie_jar` — problems
  6, 7.

### Protecting the stored credentials at rest (limits, stated honestly)

HA has no built-in secret vault and stores config entries as plaintext JSON — a
genuine platform gap. Be clear about the threat model first: **on-host encryption
with a key stored on the same host is data hygiene, not protection from host
compromise.** Anyone who can read the HA filesystem, backups, process memory, or
the integration's own code can obtain both the ciphertext and the key. So the
realistic goal is: (a) shrink what's stored to the minimum, (b) reduce the chance
of *accidental* disclosure of a single file (backups, config sharing, add-on
access), not (c) defeat a root-level attacker — which is out of reach here.

Given that, least-bad options in order:

1. Keep `refresh_token`/`mac_dms` in a **dedicated**
   `homeassistant.helpers.storage.Store` file with `0600` perms, separate from
   the shared config entry — smaller blast radius, excluded from casual config
   sharing, redacted from diagnostics.
2. If encrypting: use an authenticated-encryption format (AEAD), and **specify
   key management explicitly** — where the root key lives, backup/restore
   behavior, rotation, and corruption recovery. An unspecified "derived from a
   per-install secret" is not a design.
3. Do **not** rely on the OS keyring. It is largely unavailable or unsuitable
   across HA OS / Container / Core and their restore workflows; an optional
   `keyring` dependency introduces nondeterministic behavior. Treat it as
   out-of-scope, not a fallback.
4. Upstream a feature request to HA for a first-class secret store — the correct
   long-term fix, worth filing regardless.

### The honest tradeoff

Fully-unattended re-authentication with no human is impossible **if** Amazon
forces interactive 2FA — that's the point of 2FA. A registered-device
`refresh_token` is *intended* to be long-lived (it's how the real Alexa app stays
logged in for extended periods), but **that durability is assumed by analogy, not
measured for this emulated device identity.** Amazon may revoke on risk score,
device-registration limits, inactivity, server-side changes, or account/password
events. Before making unattended operation a product promise, run a spike to
measure actual token longevity and failure rates; until then, treat long-lived
operation as best-effort, not contract. Only genuine revocation or a password
change forces re-enrollment, which *should* require a person.

Reauth itself has a real operational cost worth stating: it needs an available HA
administrator, a reachable callback/proxy URL, and browser access. **Headless or
remote installs may stay broken until a human is physically able to complete the
flow** — there is no unattended recovery path once the refresh token is dead.

The stored-seed auto-2FA convenience is deliberately removed, not retained as
an opt-in. Keeping it would preserve the exact factor-independence failure this
redesign is intended to eliminate and would leave the TOTP generation and
secret-storage paths alive indefinitely. Any Amazon MFA challenge therefore
requires interactive completion by a person.

**Product contract:** after enrollment, operation is unattended while the
stored device credentials can refresh access and reconstruct the required
session state. Transient connectivity, throttling, and Amazon server failures
are retried without user action; a confirmed terminal authentication failure
marks the config entry as requiring interactive reauthentication. There is no
promise of unattended recovery after revocation: headless and remote
installations explicitly accept that the integration may remain unavailable
until an administrator can complete Amazon's browser flow.

### Migration

Existing installs may already hold an `oauth` dict with a `refresh_token`, but
a present token is not proof of validity or of correct association with the
stored `serial`/`mac_dms`. Migration is therefore local, lazy, and
non-destructive until Amazon can be reached:

1. Read the existing `oauth` dict and write `refresh_token`/`mac_dms` plus the
   associated device identity to the new protected store using an atomic write.
2. Mark the entry as **pending credential validation and legacy-secret
   cleanup**. Do not require an Amazon request for the schema migration itself,
   and do not delete or rewrite the legacy credentials yet.
3. Start the integration normally. If HA is offline, Amazon is unreachable,
   throttles the request, or returns another transient failure, leave both the
   migrated credentials and legacy data intact, retry with backoff, and keep
   the entry pending validation; do not trigger reauth.
4. On the first successful `refresh_access_token()` plus
   `exchange_token_for_cookies()` round-trip, atomically mark the migrated
   credential set valid. Only after that commit succeeds, delete `password`,
   `otp_secret`, `access_token`, `authorization_code`, and `code_verifier` from
   the config entry and remove legacy `.pickle`/`.txt`/`.cookies` files.
5. If Amazon returns a classified terminal authentication failure, preserve the
   legacy data and trigger interactive reauthentication. After successful
   re-enrollment and an atomic write of the replacement credentials, delete the
   legacy secrets and files; if reauth is abandoned or fails, leave them intact
   so migration cannot strand the entry.

Users whose migrated credentials validate continue without re-login. Offline
starts and transient Amazon failures merely defer cleanup; only a confirmed
terminal authentication failure requires interactive reauthentication.

## Problem → fix mapping

| Problem | Fix |
|---|---|
| TOTP seed stored (collapses factor independence for this HA data) | Remove seed collection, storage, and local OTP generation entirely; users complete MFA interactively with their own authenticator |
| Password stored at rest | Discard after enrollment; never persist (transits the proxy but is not written) |
| Secrets in logs | Remove TOTP logging; `refresh_token`/`mac_dms` redacted, never logged |
| Fragile HTML scraping | Delete it; drive login through Amazon's real page via the paste-URL flow (Audible-precedented) |
| Pickle RCE on cookie load | Delete cookie persistence entirely |
| aiohttp-internals coupling | Delete cookie serialization; re-mint cookies from the refresh token |
| Plaintext durable tokens | Store only `refresh_token` + `mac_dms`, minimized, isolated, protected at rest |

The through-line: the integration already uses the least-bad primitive available
(PKCE authorization-code → durable device refresh token). The replacement keeps
that, drives the interactive step through Amazon's own page, and **stops
*persisting* the primary credentials and the TOTP seed while minimizing the
durable derived credentials it must retain.** It does not eliminate replayable
credentials entirely — `refresh_token` and `mac_dms` remain — and it does not make
the underlying flow supported.

## Open questions — resolved by ecosystem precedent (2026-07-18)

Originally framed as pre-implementation validation spikes. Decision
(2026-07-18): **do not time-gate implementation on spikes.** Each question is
answered by projects running the same device-registration flow in production;
the assumptions below are adopted as design defaults and verified as ordinary
checkpoints during development, not before it.

**Precedent base:**
- `mkb79/Audible` — paste-URL external login (`external_login()` parses
  `openid.oa2.authorization_code` from the pasted `/ap/maplanding` URL),
  `build_oauth_url()` parameter set, `deregister_device()`.
- `Apollon77/alexa-cookie` v2+ — registers "as the Amazon mobile Apps", stores
  `formerRegistrationData`, re-mints cookies on a 5–13-day cycle without
  re-login; powers ioBroker.alexa2 and node alexa-remote in production since
  ~2019; v4 added `macDms` for push.
- `openhab/openhab-addons` amazonechocontrol — Java implementation of the same
  flow; `/ap/exchangetoken` with `source_token_type=refresh_token`,
  `requested_token_type=auth_cookies`.

**Resolutions:**

1. **Enrollment flow — RESOLVED: paste-URL, no proxy.** Audible ships this in
   production; the code never transits our process and no reachable callback
   exists. Adopted as the enrollment flow (details retained below for
   reference).
2. **Bootstrap matrix — DEMOTED to the fork's normal test matrix.** MFA
   variants, captcha, regional domains, etc. are exercised during development
   and beta, not as pre-work; Amazon's own page handles all challenge types in
   the paste-URL flow, which is precisely why the scraping matrix shrinks.
3. **Cookie reconstruction — ASSUMED YES (strong precedent).** alexa-cookie
   and openHAB have re-minted session cookies from stored registration data
   for years across the full API + push surface. Checkpoint: first restart of
   the fork exercises it end to end.
4. **Token longevity — ASSUMED LONG-LIVED (field precedent).** Across the
   ioBroker/openHAB/Audible ecosystems, registrations survive until a
   password change or account security event; Amazon login-page changes break
   *new* logins (scraping/proxy paths), not existing registrations — e.g.
   ioBroker.alexa2 #1374 broke proxy login while existing tokens kept
   working. Design consequence: build the reauth path as the recovery story,
   add passive telemetry (log refresh ages), and drop the measurement spike.
   The "durability by analogy" caveat in the tradeoff section stays true —
   this is an assumption, now a precedented one.
5. **Flow integrity — RESOLVED BY DESIGN: no `state` reliance.** Audible's
   production `build_oauth_url()` contains **no `state` parameter at all**;
   the flow binds via PKCE `code_challenge` only, and no precedent project
   relies on maplanding round-tripping extra params — so the design assumes
   it does not. Binding controls, all framework-native or already in the
   design: the PKCE `code_verifier` lives only in the in-progress config
   flow's memory (a pasted code from any other flow fails the exchange);
   flows expire with the config-flow session and the ~5-minute code lifetime;
   `async_set_unique_id` + `_abort_if_unique_id_mismatch()` rejects an
   exchange that resolves to a different Amazon account (blocks account
   substitution / login-CSRF). The paste-URL flow has no listening callback
   to attack — the residual risk is a user pasting an attacker-supplied URL,
   which the unique-id check catches.

Original spike list retained below for the record:

1. **Direct-browser flow vs. MITM proxy.** Can enrollment avoid routing
   credentials through our process at all, eliminating *exposure* and not just
   *persistence*? This is the stronger security target. **Primary candidate
   (2026-07-18 investigation): the paste-URL flow** — the user logs into Amazon
   in their own browser with no proxy, lands on `/ap/maplanding` (a harmless
   error page), and pastes the full redirect URL into the HA config flow, which
   extracts `openid.oa2.authorization_code` locally and completes the existing
   PKCE `get_tokens()` exchange (the `code_verifier` never leaves the
   integration). This is production-proven in `mkb79/Audible`
   (`from_login_external()`) and needs no reachable callback URL, removing the
   `authcaptureproxy` dependency and the `public_url` fragility entirely. See
   "Alternatives investigation" below for risks (mobile URL-bar access, Amazon
   app-link interception, ~5-minute code expiry, regional domain selection).
2. **Proxy-free bootstrap matrix.** Prove end-to-end enrollment across: fresh
   login, each MFA variant, captcha, account selection, regional domains, Prime
   households, restart, cookie minting, and HA reauth — before deleting the
   scraping/cookie paths.
3. **Cookie reconstruction.** Confirm all API/push/websocket paths work after
   restart from stored device credentials alone (gates cookie-persistence
   removal).
4. **Token longevity.** Measure real `refresh_token` lifetime and failure modes
   for this device identity (gates the unattended-operation promise).
5. **Flow-integrity controls and `/ap/maplanding` behavior.** Empirically verify
   whether Amazon preserves and returns an arbitrary, high-entropy `state`
   parameter unchanged through the complete `/ap/register` →
   `/ap/maplanding` flow, across regional domains and challenge variants. If it
   does, bind and consume `state` as a single-use, expiring flow identifier; if
   it does not, specify an equivalent binding using an unguessable per-flow
   proxy route/session, the in-memory PKCE verifier, strict expiry, and
   single-use callback consumption. Also define replay rejection, concurrent
   config-flow handling, and how the exchanged credentials are bound to the
   intended Amazon account; PKCE alone does not prevent login CSRF or account
   substitution.

---

## HA / HACS spec alignment audit (2026-07-18)

Verified against developers.home-assistant.io (config entries, config flow
handler, setup failures, diagnostics), hacs.xyz publishing docs, and HA core
source (`helpers/storage.py`, `util/file.py`). Verdict: the design is
spec-compliant; the following bindings make it concrete.

### Confirmed aligned, with the exact HA mechanism to use

- **Refresh-failure classification** matches HA semantics exactly:
  `ConfigEntryAuthFailed` puts the entry in a failure state and starts the
  reauth flow; `ConfigEntryNotReady` gets automatic retry with backoff.
  Spec constraints to honor: `ConfigEntryAuthFailed` is only effective when
  raised from `async_setup_entry` or from within a `DataUpdateCoordinator`,
  and the integration must not log non-debug messages about retries (HA
  handles that).
- **Reauth flow:** implement `async_step_reauth` → `async_step_reauth_confirm`;
  on success the flow must update the existing entry and abort — never create
  a new entry — via `async_update_reload_and_abort(self._get_reauth_entry(),
  data_updates=...)`. `strings.json` needs the `reauth_confirm` step and the
  `reauth_successful` abort key.
- **Account binding lands on `unique_id`.** HA's
  `async_set_unique_id(account_id)` + `_abort_if_unique_id_mismatch()` in the
  reauth flow is the framework-native implementation of the account-binding
  control Open question 5 requires: after the token exchange exposes the
  Amazon account identifier, set it as the flow's unique ID and abort on
  mismatch, so a reauth cannot silently rebind the entry to a different
  Amazon account. Fold this into the OQ5 spike as the required mechanism.
- **Migration:** bump the config flow `VERSION` (major) and implement
  `async_migrate_entry` in `__init__.py`; it runs automatically during setup
  when versions differ and must return `True` on success. The plan's
  local-only schema migration is the correct shape — a failed migration fails
  setup, so no network I/O belongs in `async_migrate_entry`; the live
  validation happens afterward in normal setup, per the lazy-migration design.
  Note the documented downgrade cost: a major version bump makes the entry
  fail setup on downgrade without a backup restore.
- **Teardown:** `async_remove_entry` is the sanctioned hook and is called
  after the entry is already deleted from `hass.config_entries` — correct
  place for the best-effort `/auth/deregister` call plus protected-store
  deletion.
- **Protected store (source-verified):** `helpers.storage.Store(...,
  private=True, atomic_writes=True)` writes to `.storage/` and skips the
  `0o644` chmod, leaving the tempfile-created `0o600` mode — exactly the
  "dedicated 0600 store with atomic writes" the design specifies. Caveat the
  design already makes stands: `.storage` is included in HA backups, so this
  is hygiene, not host-compromise protection.
- **Diagnostics:** HA requires redaction of passwords/API keys/tokens via
  `async_redact_data` + a `TO_REDACT` list. The implementation must include
  `refresh_token`, `mac_dms`, `access_token`, and the device `serial` in
  `TO_REDACT`.
- **Paste-URL step:** config flow forms support the required multiline
  `TextSelector`; no framework obstacle.

### HACS constraints (bind the fork path)

- Structure: one integration per repo under `custom_components/<domain>/`;
  `hacs.json` (with `name`) at repo root; `manifest.json` must carry `domain`,
  `name`, `version`, `documentation`, `issue_tracker`, `codeowners`.
- Versioning: publish full GitHub **releases**, not bare tags — HACS ignores
  tag-only versioning.
- Default-store inclusion (if the fork goes that route): public repo, HACS
  Action + Hassfest actions passing, a release published after the actions
  run, and brand assets (repo `brand/icon.png` or home-assistant/brands).
  Submission must come from the repo owner's personal account.
- **alexapy coupling:** HACS ships only the integration; `alexapy` arrives via
  `manifest.json` `requirements`. A fork that changes alexapy internals must
  publish the forked library under a new PyPI name (alexapy is pure Python, so
  no wheel issues) and pin it — it cannot ride the upstream `alexapy==` pin.
- **Domain choice tradeoff (fork path):** keeping upstream's `alexa_media`
  domain preserves users' entities/automations when switching but collides
  with the upstream repo (users cannot install both, and default-store
  coexistence is unclear); a new domain coexists cleanly but regenerates every
  entity ID, breaking existing automations. The migration section's guarantees
  only hold on the same-domain path.
  **DECIDED 2026-07-18: new domain.** The operator has few entities and a
  couple of automations to re-point; clean coexistence with upstream (side by
  side install during cutover, no HACS collision) outweighs entity-ID
  continuity. Consequence: the in-place migration machinery in "### Migration"
  is NOT needed for the fork — first-run enrollment is a fresh interactive
  login, after which the upstream integration and its stored secrets are
  removed. The migration section stays in the doc because it becomes required
  again if this design is later upstreamed into the same-domain integration.

---

## Alternatives investigation (2026-07-18, Haiku research agents)

Three parallel investigations into gaps the second review pass surfaced.
Findings are research-grade (web/OSS survey by lower-tier agents); anything
load-bearing still needs the validation spikes above before implementation.

### A. Paste-URL enrollment (proxy-free) — VIABLE, adopt as primary candidate

- **Precedent:** `mkb79/Audible` ships `from_login_external()` in production:
  generate login URL → user authenticates in own browser → lands on
  `/ap/maplanding` error page → pastes full URL back → library extracts
  `openid.oa2.authorization_code` and completes the same PKCE `/auth/register`
  exchange. The Alexa ecosystem (alexa-cookie2, alexa-remote-control, alexapy)
  uniformly uses proxies or token refresh — nobody has shipped paste-URL for
  Alexa yet, but the Amazon-side flow is identical to Audible's.
- **PKCE compatible:** verifier is generated and held by the integration;
  nothing about paste-URL changes the `get_tokens()` exchange.
- **HA support:** config flow multiline `TextSelector` handles the paste step;
  no framework obstacle.
- **Top risks:** (1) mobile browsers hide/restrict the URL bar and the Amazon
  app can intercept `/ap/maplanding` via app links — mitigate with desktop-
  browser instructions and a fallback path; (2) authorization codes expire in
  ~5 minutes — config flow needs expiry-aware retry messaging; (3) regional
  domain must be selected upfront and validated against the pasted URL.
- **Calibration:** the agent's claim that maplanding round-trips `state` cites
  *standard* LWA authorization-grant docs, not the undocumented `/ap/register`
  device flow. Open question 5's empirical verification stands. Note the
  paste-URL flow shrinks the CSRF surface anyway: there is no listening
  callback to spoof — the user hand-carries the code into their own HA session.

### B. Delivery strategy — fork-first, with a 2-week upstream RFC probe

- **Repo health:** both upstream projects are alive (alexa_media_player
  v5.15.6, 2026-07-02; alexapy 1.29.25, 2026-06-30; alandtse responsive).
- **Receptivity:** security concern about storing password + TOTP seed is
  already on record upstream (discussion #1385), but no prior auth-redesign
  RFC exists; recent auth work is reactive (Amazon breakage), not proactive.
- **Coupling:** manifest.json pins alexapy exactly (`alexapy==1.29.25`), so
  the redesign requires a coordinated major bump of both repos in the same
  release window.
- **Fork landscape:** no maintained alternative forks; upstream is the only
  game in town.
- **Recommendation (superseded — see decision):** open an upstream RFC issue
  in alexa_media_player linking this threat model; allocate ~2 weeks for
  maintainer response. If dismissed or ignored, pivot to a maintained fork
  pair (both repos, new HACS name, weekly upstream cherry-pick automation).
  A domain-colliding local HACS patch is viable only as a stopgap — it cannot
  reach the alexapy internals this design changes.
  **DECIDED 2026-07-18: fork-first, RFC in parallel.** Rationale: the RFC
  probe gates shipping on a maintainer response to a proposal with no prior
  community demand, while the fork delivers the security fix to the operator
  immediately and loses nothing — the RFC can still be filed as an invitation
  (linking this public repo), and if upstream adopts the design the fork
  retires. Concretely: fork both repos, new integration domain (per the
  domain decision below), forked alexapy published under a new PyPI name and
  pinned in `manifest.json`, weekly upstream cherry-pick automation, full
  GitHub releases per HACS requirements. The upstream RFC is a courtesy
  follow-up, not a gate; filing it awaits operator go-ahead since it is a
  public post under the operator's account.

### C. Device deregistration on teardown — IMPLEMENTABLE, add to design

- **Precedent:** `mkb79/Audible` implements `Authenticator.deregister_device()`
  (with a `deregister_all` variant) against Amazon's **`/auth/deregister`**
  endpoint — the direct counterpart of the `/auth/register` call this
  integration already makes. It authenticates with a fresh `access_token`
  (refreshed first; ~60-minute lifetime) and treats revocation failures as
  ignorable. This is the endpoint to spike, since it targets the same emulated
  app-device registration class. (The research agent also surfaced the Alexa
  Smart Properties `POST /v2/endpoints/{id}/deregister` API; that is a B2B
  property-management surface and likely the wrong endpoint for a consumer
  device registration — verify against `/auth/deregister` first.)
- **Effects (per Audible behavior, unverified for this device type):**
  deregistration invalidates that device registration (subsequent API calls
  401) without terminating other sessions/devices; explicit `refresh_token` /
  `mac_dms` revocation semantics are undocumented and need the spike.
- **Current gaps:** `alexapy` has logout/local-cleanup only — no deregister
  call exists; `alexa_media_player` implements `async_unload_entry()` but not
  `async_remove_entry()`. HA's OAuth2 helpers have no built-in revocation
  either, so this is a custom handler in both layers.
- **Design additions:**
  1. `alexapy`: new `deregister_device()` calling `/auth/deregister` with a
     freshly refreshed access token; failures logged and swallowed (never
     block entry removal on Amazon availability).
  2. `alexa_media_player`: implement `async_remove_entry()` → best-effort
     deregister, then delete the protected credential store.
  3. Re-enrollment: deregister the old device identity before registering the
     new one, so repeated reauth cannot accumulate phantom devices — directly
     mitigating the risk-score/accumulation concern under operational risk.
  4. Docs: note phantom devices remain manually removable via the Alexa app /
     Amazon "Manage Your Content and Devices" if best-effort cleanup fails.
- **Spike prerequisite:** confirm `/auth/deregister` accepts this device type
  (A2IVLV5VM2W81) and what identifier it keys on (the registration response's
  device info must be persisted at enrollment for later deregistration).

---

## Critique (Codex gpt-5.6-sol, 2026-07-18)

Adversarial review. Thread `019f7586-af01-7653-9d6e-b6f734734e6b`. **All findings
below have been folded into the doc body above** (exposure-vs-persistence boundary,
"least-bad primitive" framing, refresh-failure classification, credential-at-rest
threat model, migration validate-then-delete, `mac_dms` treatment, flow-integrity
controls, and the Open questions / validation-spike list). Retained verbatim as
the review record.

### Blocker

- **"The integration never sees the password" is false.** The auth-capture
  proxy terminates and forwards Amazon login traffic, so it *can* observe
  password, OTP codes, cookies, and challenge responses in transit. Avoiding
  *persistence* is achievable; avoiding *exposure* requires a direct-to-Amazon
  browser flow with a safe callback, not a MITM proxy. The "never sees the
  password / TOTP seed" language (Enrollment §3) is wrong and must be downgraded
  to "never persists." This is the central factual error.
- **"Sound OAuth primitive" is overstated.** The `/auth/register` exchange is an
  OpenID 2.0 / LWA extension impersonating a first-party device client against an
  *undocumented* endpoint — not a supported third-party grant or standard OAuth
  device-authorization flow. PKCE protects code interception; it does not
  legitimize the client or stabilize the endpoint. Drop "token machinery is
  sound" / "legitimate OAuth primitive" framing.
- **No proven proxy-free bootstrap.** Deleting the scraping/cookie paths needs a
  tested matrix first (fresh enrollment, MFA variants, captcha, account
  selection, regional domains, Prime households, restart, cookie minting, HA
  reauth) — a validation spike, not an implementation assumption.

### Major

- **Refresh-token durability is asserted by analogy, not measured.** Define
  measured longevity and failure rates before making unattended operation the
  contract.
- **Refresh lifecycle is incomplete.** Missing: token rotation, atomic
  replacement, concurrent-refresh locking, crash recovery, transient-vs-terminal
  error classification, backoff, rate limiting. Treating *every* refresh failure
  as reauth causes needless human intervention — HA expects reauth only on
  auth failures, not network/server errors.
- **Reauth operational cost understated.** Reauth needs an available admin, a
  usable callback/proxy URL, and browser access; headless installs may stay
  broken. State this explicitly.
- **Encryption proposal has no useful threat model.** A per-install key stored on
  the same host protects mainly against one file leaking; anyone who can read the
  filesystem, backups, or process memory gets both ciphertext and key. `0600` +
  file separation is data hygiene, not protection from host compromise.
- **Key management unspecified.** Where the root secret lives, backup/restore, key
  rotation, AEAD format, corruption recovery, multi-instance migration. OS
  keyrings are largely unavailable/unsuitable across HA OS/Container/Core.
- **`mac_dms` understated.** It is device authentication material (replay/cloning,
  signing implications), not harmless metadata. Needs redaction/rotation/
  revocation treatment.
- **Conclusion contradicts the design.** It claims to stop storing "any secret
  that can be replayed" while persisting `refresh_token` + `mac_dms`, both
  replayable. Correct claim: "stop persisting primary credentials and the TOTP
  seed; minimize durable derived credentials."
- **Migration is optimistic.** A present refresh token isn't proof of validity or
  correct association with serial/`mac_dms`. Validate the full credential set and
  new persistence *before* deleting old data; specify rollback/backup.
- **Missing CSRF/session-binding analysis.** Doc covers PKCE but not `state`,
  replay protection, flow ownership, concurrent config flows, callback expiry, or
  code/account binding. PKCE alone doesn't prevent login CSRF or account
  substitution.

### Minor

- "Structurally voids 2FA" overstates: it collapses factor independence against
  compromise of *that HA data*, not against unrelated attackers universally.
- Problem→fix table "Type it once in-browser" wrongly implies the *seed*; the
  user enters an OTP from their own authenticator, not the seed.
- "Cookies never persisted" needs evidence every API/push/websocket path can
  reconstruct required cookies + CSRF from stored device credentials after
  restart, else restarts become latent outages.
- Pickle-RCE risk needs threat calibration: an attacker who can modify protected
  `.storage` often already has an execution path; name the real boundary
  (backups / add-ons / shares).
- Operational/account risk omitted: document that the flow is unsupported, may
  trigger account challenges or device-registration accumulation, and can break
  without notice.

---

## Contradiction resolution (Codex gpt-5.6-sol, second pass, 2026-07-18)

A follow-up review pass (Claude Fable) found four contradictions/gaps introduced
by the first fold-in. Resolved with Codex on the same thread
(`019f7586-af01-7653-9d6e-b6f734734e6b`); all four resolutions are applied to
the body above:

1. **TOTP opt-in removed entirely** — "What this deletes", "The honest
   tradeoff", and the problem→fix table now consistently state there is no
   stored-seed auto-2FA mode; MFA is always interactive.
2. **Enrollment step 4 no longer asserts `state` verification** — it is gated
   on validation spike 5, which now requires empirical verification of
   `/ap/maplanding` parameter round-tripping and specifies a fallback binding
   mechanism if Amazon drops arbitrary params.
3. **Product contract added** to "The honest tradeoff": unattended refresh is
   promised, unattended reauthentication is not; headless installs accept
   unavailability until an admin completes the browser flow.
4. **Migration rewritten as local, lazy, and non-destructive** — no live Amazon
   round-trip required at migration time; legacy secrets are deleted only after
   the first successful validation commit or successful re-enrollment.
