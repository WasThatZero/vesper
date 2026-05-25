# vesper

![](readme_img.png)

A reverse-engineered reimplementation of the [Dreamtonics](https://dreamtonics.com) product manager backend, served locally via [mitmproxy](https://mitmproxy.org/). Intercepts all traffic to authr3.dreamtonics.com and account.dreamtonics.com and responds from a local in-memory store.

> Named after ANDI Vesper, the AUDIOLOGIE voicebank whose then-unreleased product listing started this whole thing

> **DISCLAIMER:** This is a personal research/learning project. All product data was captured from the real API using a local HTTPS proxy. No Dreamtonics servers are/were modified or attacked. Use responsibly and for educational purposes only.

> I also tried my best not to make *my* code look AI-generated since that's apparently something you need to worry about nowadays. Excuse the potential lack of comments and documentation outside this README. And yes, I am bitter about this.

---

## What it does

- **Full Keycloak OIDC auth** - proper PKCE authorization code flow, RS256-signed JWTs, any email + any password accepted
- **Complete product catalog** - 177 products (169 real + 8 custom fakes), with real filtering, sorting, and pagination
- **Per-user license store** - in-memory, keyed by JWT sub, resets on proxy close
- **Trial activation** - `start_trial` validates trialability and tracks active trials per user
- **EULA fetching** - `product/eula/get` returns real EULA markdown (for some vendors)
- **Purchase info** - `purchase/info/get` returns store URLs
- **Activation code redeem** - `add_license_by_activation_code` accepts any 25-char code and grants the full catalog
- **UI injection** - injects a 'Mark as Owned' button into every product card on `my.dreamtonics.com`, which creates a full permanent license and refreshes the UI live via Pinia store actions. Mildly bugged though, PRs welcome!!


---

## Requirements

```bash
pip install -r requirements.txt
```

Python 3.11+ recommended

---

## Setup

### 1. Install the mitmproxy CA certificate

Run mitmproxy once to generate the certificate:

```bash
mitmweb
```

Then install `~/.mitmproxy/mitmproxy-ca-cert.pem` as a trusted CA:

**Firefox:** Settings -> Privacy & Security -> Certificates -> View Certificates -> Authorities -> Import

**System-wide (Arch):**
```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /etc/ca-certificates/trust-source/anchors/mitmproxy.crt
sudo update-ca-trust
```
*(note though that I don't use Arch myself)*

**System-wide (Debian/Ubuntu):**
```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

### 2. Configure your browser proxy

Point your browser (or system) to `127.0.0.1:8080`

In Firefox: Settings -> Proxy settings -> -> Configure proxy -> Manual proxy configuration -> HTTP `127.0.0.1` port `8080`, check 'Also use this proxy for HTTPS'

---

## Usage

### Full stack (auth + intercept + UI injection)

```bash
mitmweb -s dreamtonics_auth.py -s dreamtonics_intercept.py -s dreamtonics_inject.py
```

Go to [my.dreamtonics.com](https://my.dreamtonics.com) and log in with any email and password

The mitmweb UI is available at http://127.0.0.1:8081 for inspecting traffic.

### Logger only (for further reverse engineering)

```bash
mitmweb -s dreamtonics_logger.py
```

Captures all traffic to 'authr3.dreamtonics.com' and 'account.dreamtonics.com' and writes to:
- dreamtonics_api.log - human-readable pretty-printed log
- dreamtonics_api.json - structured JSON, one entry per request

---

## API coverage

All endpoints served by the reimplementation:

### Auth (account.dreamtonics.com)

| Endpoint | Description/Purpose |
|---|---|
| `GET /realms/Dreamtonics/.well-known/openid-configuration` | OIDC discovery |
| `GET /realms/Dreamtonics/protocol/openid-connect/certs` | JWKS public keys |
| `GET /realms/Dreamtonics/protocol/openid-connect/auth` | Authorization endpoint - serves login form |
| `POST /realms/Dreamtonics/login-actions/authenticate` | Login form submission -> 302 with auth code |
| `POST /realms/Dreamtonics/protocol/openid-connect/token` | Token exchange (authorization_code + refresh_token) |
| `GET /realms/Dreamtonics/protocol/openid-connect/userinfo` | User profile |
| `GET /realms/Dreamtonics/protocol/openid-connect/logout` | Logout |
| `GET /realms/Dreamtonics/account` | Keycloak account info |

### Product Manager (authr3.dreamtonics.com/api/v1)

| Endpoint | Description |
|---|---|
| `GET /client/me` | Current user permission levels |
| `GET /client/my_licenses` | All licenses for current user |
| `GET /client/my_entitlements` | Promotional entitlements |
| `GET /client/my_devices` | Offline license devices |
| `POST /client/start_trial` | Activate a product trial |
| `POST /client/add_license_by_activation_code` | Redeem an activation code (any 25-char code grants everything) |
| `POST /client/test_enroll` | Enroll in beta test program |
| `POST /client/test_quit` | Leave beta test program |
| `GET /product/query` | Paginated product catalog with filtering + sorting |
| `GET /product/dict/get` | Filter enum values (vendors, genres, languages, etc.) |
| `GET /product/eula/get` | Fetch EULA markdown by ID |
| `GET /purchase/info/get` | Get store purchase URL for a product |
| `GET /update/get_download_url` | Get download package URLs for a product |
| `GET /translation/get` | UI i18n strings (en-US, ja, zh-CN) |
| `POST /client/mark_owned` | **Custom endpoint** - grants a full permanent license (used by injected UI button) |

---

## Adding custom products

See [GUIDE.md](GUIDE.md)

---

## The Mark as Owned button

The inject addon modifies 'my.dreamtonics.com' HTML responses in-transit to append a script that:

1. Sniffs the Bearer token from the app's own outgoing API requests
2. Uses a `MutationObserver` to watch for product cards appearing in the DOM
3. Injects a Quasar-styled **Mark as Owned** button into each card's action area
4. On click, POSTs to `/api/v1/client/mark_owned`, then calls `session.loadMyInfo()`, `session.loadMyProducts()`, and `session.loadAllProducts()` on the Pinia store directly to refresh the UI without a page reload

---

## Custom/fake products

Eight custom products are included in the seed for testing:

| Name | Vendor |
|---|---|
| ANDI Vesper Lite |
| ANDI Test | AUDIOLOGIE |
| ANRI Requiem RDX | AUDIOLOGIE |
| ANRI Requiem Arcane | AUDIOLOGIE |
| JUN Nocturne RDX | AUDIOLOGIE |
| Amara 3 | Dreamtonics Co., Ltd. |
| ZERO | AUDIOLOGIE | 
| Totally not ANDI | Totally not AUDIOLOGIE |

All have a release date of 2026-03-30 16:00 UTC and are trialable.

---

## What's not implemented

- Desktop editor-specific endpoints
- 'my_devices' device schema
- Persistence: all licenses are in-memory and reset when the proxy closes. PRs VERY welcome.

---

## On AI-generated pull requests

Due to the increasing volume of AI slop PRs on GitHub, pull requests that appear to be AI-generated will likely be rejected. That said, each one will still be reviewed individually — if yours happens to be genuinely useful, it'll get a fair look.

If you used AI assistance in any capacity, please say so in your PR description. Transparency is appreciated.

---

## ...How?

All API endpoints were discovered by running dreamtonics_logger.py alongside normal use of the web frontend, then inspecting the captured dreamtonics_api.json to reverse-engineer request/response shapes. Auth was captured separately to understand the full Keycloak PKCE flow.

The product database (dreamtonics_seed.json) was built by paging through all 17 pages of the product catalog and extracting every product object from the captured responses.