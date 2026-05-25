import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
import uuid

from mitmproxy import http
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# keygen (not that kind)

print("[auth] Generating RSA-2048 keypair for access/id tokens...")
_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
_PUBLIC_KEY  = _PRIVATE_KEY.public_key()
_PUB_NUMS    = _PUBLIC_KEY.public_numbers()
_KID         = "dreamtonics-fake-key-1"

# HMAC secret for refresh tokens (like keycloaks's HS512)
_HMAC_SECRET = secrets.token_bytes(64)

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _int_to_b64url(n: int) -> str:
    return _b64url(n.to_bytes((n.bit_length() + 7) // 8, "big"))

_PUB_N = _int_to_b64url(_PUB_NUMS.n)
_PUB_E = _int_to_b64url(_PUB_NUMS.e)
print(f"[auth] Keypair ready  kid={_KID}")

# config

AUTH_HOST  = "account.dreamtonics.com"
REALM      = "Dreamtonics"
ISSUER     = f"https://{AUTH_HOST}/realms/{REALM}"
CLIENT_ID  = "authr3-frontend"
ACCESS_TTL = 1800    # 30min
REFRESH_TTL= 86400   # 24hrs

CORS = {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, Origin, X-Requested-With",
}

def _cors_headers(flow: http.HTTPFlow) -> dict:
    origin = flow.request.headers.get("origin", "*")
    return {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, Origin, X-Requested-With",
        "Access-Control-Allow-Credentials": "true",
        "Vary": "Origin",
    }

# shared user store
# shared with dreamtonics_intercept.py, keyed by sub (uuid str)
# { sub: { email, given_name, family_name, licenses, entitlements, devices } }
USER_STORE: dict[str, dict] = {}

# pending auth codes: code -> { sub, redirect_uri, nonce, state }
_AUTH_CODES: dict[str, dict] = {}

# pending PKCE challenges: state -> { code_challenge, code_challenge_method, nonce, redirect_uri }
_AUTH_SESSIONS: dict[str, dict] = {}

# helpers

def _sub_for_email(email: str) -> str:
    return str(uuid.UUID(hashlib.md5(email.lower().encode()).hexdigest()))

def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def _make_rs256_jwt(payload: dict) -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": _KID}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = _PRIVATE_KEY.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64url(sig)}"

def _make_hs256_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": "refresh-key"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(_HMAC_SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"

def _decode_jwt_payload(token: str) -> dict:
    try:
        return json.loads(_b64url_decode(token.split(".")[1]))
    except Exception:
        return {}

def _parse_form(body: bytes) -> dict:
    return dict(urllib.parse.parse_qsl(body.decode("utf-8", errors="replace")))

def _parse_qs(query: str) -> dict:
    return dict(urllib.parse.parse_qsl(query))

def json_resp(data, status=200, cors: dict | None = None) -> http.Response:
    headers = cors or CORS
    return http.Response.make(status, json.dumps(data, ensure_ascii=False), headers)

def html_resp(html: str) -> http.Response:
    return http.Response.make(200, html.encode(), {"Content-Type": "text/html; charset=utf-8"})

def redirect(url: str) -> http.Response:
    return http.Response.make(302, b"", {"Location": url, "Cache-Control": "no-store"})

# token builder

def _issue_tokens(sub: str, nonce: str | None = None) -> dict:
    u   = USER_STORE[sub]
    now = int(time.time())
    sid = str(uuid.uuid4())

    base = {
        "exp": now + ACCESS_TTL,
        "iat": now,
        "auth_time": now,
        "jti": str(uuid.uuid4()),
        "iss": ISSUER,
        "sub": sub,
        "typ": "Bearer",
        "azp": CLIENT_ID,
        "sid": sid,
        "acr": "1",
        "allowed-origins": [
            "https://my.dreamtonics.com.cn/",
            "https://my.dreamtonics.com.cn",
            "https://my.dreamtonics.com",
        ],
        "resource_access": {"authr3-backend": {"roles": ["access"]}},
        "scope": "openid email profile",
        "email_verified": True,
        "name": f"{u['given_name']} {u['family_name']}",
        "preferred_username": u["email"],
        "locale": "en-US",
        "given_name": u["given_name"],
        "family_name": u["family_name"],
        "email": u["email"],
    }

    access_payload  = {**base, "aud": "authr3-backend"}
    id_payload      = {**base, "aud": CLIENT_ID, "at_hash": _b64url(hashlib.sha256(b"fake").digest()[:16])}
    if nonce:
        id_payload["nonce"] = nonce

    refresh_payload = {
        "exp": now + REFRESH_TTL,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "iss": ISSUER,
        "aud": ISSUER,
        "sub": sub,
        "typ": "Refresh",
        "azp": CLIENT_ID,
        "sid": sid,
        "scope": "openid web-origins acr email roles basic profile",
    }

    return {
        "access_token":       _make_rs256_jwt(access_payload),
        "expires_in":         ACCESS_TTL,
        "refresh_expires_in": REFRESH_TTL,
        "refresh_token":      _make_hs256_jwt(refresh_payload),
        "token_type":         "Bearer",
        "id_token":           _make_rs256_jwt(id_payload),
        "not-before-policy":  0,
        "session_state":      sid,
        "scope":              "openid email profile",
    }

# html auth form

def _login_form(action_url: str, error: str = "") -> str:
    err_html = f'<p class="error">{error}</p>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign In</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #111; display: flex; align-items: center; justify-content: center;
          min-height: 100vh; font-family: system-ui, sans-serif; color: #ccc; }}
  form {{ width: 280px; display: flex; flex-direction: column; gap: 8px; }}
  h1 {{ font-size: 18px; font-weight: 600; color: #fff; margin-bottom: 4px; }}
  input {{ background: #1e1e1e; border: 1px solid #333; border-radius: 4px;
           padding: 8px 10px; font-size: 14px; color: #ccc; outline: none; }}
  input:focus {{ border-color: #7b6cff; }}
  button {{ background: #7b6cff; color: #fff; border: none; border-radius: 4px;
            padding: 9px; font-size: 14px; cursor: pointer; margin-top: 2px; }}
  button:hover {{ background: #6b5ce7; }}
  .error {{ color: #f66; font-size: 13px; }}
</style>
</head>
<body>
<form method="POST" action="{action_url}">
  <h1>Sign In</h1>
  {err_html}
  <input type="email" name="username" autofocus required placeholder="Email">
  <input type="password" name="password" required placeholder="Password">
  <input type="hidden" name="credentialId" value="">
  <button type="submit">Sign In</button>
</form>
</body>
</html>"""

# static oidc responses

OIDC_CONFIG = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
    "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
    "userinfo_endpoint": f"{ISSUER}/protocol/openid-connect/userinfo",
    "end_session_endpoint": f"{ISSUER}/protocol/openid-connect/logout",
    "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
    "response_types_supported": ["code", "token", "id_token token"],
    "grant_types_supported": ["authorization_code", "refresh_token", "password"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
    "claims_supported": ["sub", "email", "name", "given_name", "family_name", "preferred_username", "nonce", "sid"],
    "code_challenge_methods_supported": ["S256", "plain"],
}

JWKS = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": _KID, "n": _PUB_N, "e": _PUB_E}]}

# router

class DreamtonicsAuth:

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.pretty_host != AUTH_HOST:
            return

        method = flow.request.method
        path   = flow.request.path.split("?")[0].rstrip("/")
        qs     = dict(flow.request.query)
        prefix = f"/realms/{REALM}/protocol/openid-connect"

        if method == "OPTIONS":
            flow.response = http.Response.make(200, b"", CORS)
            return

        # oidc discovery
        if path == f"/realms/{REALM}/.well-known/openid-configuration":
            flow.response = json_resp(OIDC_CONFIG, cors=_cors_headers(flow))
            print("[auth] OIDC discovery")
            return

        # jwks
        if path == f"{prefix}/certs":
            flow.response = json_resp(JWKS, cors=_cors_headers(flow))
            print("[auth] JWKS")
            return

        # realm info
        if path == f"/realms/{REALM}":
            flow.response = json_resp({"realm": REALM, "public_key": _PUB_N,
                                       "token-service": f"{ISSUER}/protocol/openid-connect"},
                                      cors=_cors_headers(flow))
            return

        # 1: auth endpoint, serve login form
        if method == "GET" and path == f"{prefix}/auth":
            state    = qs.get("state", str(uuid.uuid4()))
            nonce    = qs.get("nonce", "")
            redirect_uri = qs.get("redirect_uri", "https://my.dreamtonics.com/my-products")
            code_challenge        = qs.get("code_challenge", "")
            code_challenge_method = qs.get("code_challenge_method", "S256")

            _AUTH_SESSIONS[state] = {
                "code_challenge":        code_challenge,
                "code_challenge_method": code_challenge_method,
                "nonce":                 nonce,
                "redirect_uri":          redirect_uri,
                "response_mode":         qs.get("response_mode", "query"),
            }

            # build the form action url
            action_qs = urllib.parse.urlencode({
                "client_id": CLIENT_ID,
                "state":     state,
                "redirect_uri": redirect_uri,
            })
            action = f"https://{AUTH_HOST}/realms/{REALM}/login-actions/authenticate?{action_qs}"
            flow.response = html_resp(_login_form(action))
            print(f"[auth] Served login form  state={state[:8]}…")
            return

        # 2: login form submission -> issue code -> 302
        if method == "POST" and path == f"/realms/{REALM}/login-actions/authenticate":
            flow.response = self._handle_login(flow, qs)
            return

        # 3: token endpoint
        if method == "POST" and path == f"{prefix}/token":
            flow.response = self._handle_token(flow)
            return

        # userinfo
        if path == f"{prefix}/userinfo":
            flow.response = self._userinfo(flow)
            return

        # logout
        if method in ("GET", "POST") and path == f"{prefix}/logout":
            redirect_uri = qs.get("post_logout_redirect_uri", "https://my.dreamtonics.com")
            flow.response = redirect(redirect_uri)
            print("[auth] Logout")
            return

        # acc info
        if method == "GET" and path == f"/realms/{REALM}/account":
            flow.response = self._account(flow)
            return

        print(f"[auth] UNHANDLED {method} {path}")

    # handlers

    def _handle_login(self, flow: http.HTTPFlow, qs: dict) -> http.Response:
        form  = _parse_form(flow.request.content)
        email = form.get("username", "").strip()
        state = qs.get("state", "")
        redirect_uri = qs.get("redirect_uri", "https://my.dreamtonics.com/my-products")

        if not email:
            action_qs = urllib.parse.urlencode({"client_id": CLIENT_ID, "state": state, "redirect_uri": redirect_uri})
            action = f"https://{AUTH_HOST}/realms/{REALM}/login-actions/authenticate?{action_qs}"
            return html_resp(_login_form(action, "Please enter an email address"))

        # create or get user
        sub = _sub_for_email(email)
        given  = email.split("@")[0].replace(".", " ").title()
        family = "User"
        if sub not in USER_STORE:
            USER_STORE[sub] = {"email": email, "given_name": given, "family_name": family}
            print(f"[auth] New user  email={email}  sub={sub[:8]}…")
        else:
            print(f"[auth] Login  email={email}  sub={sub[:8]}…")

        session       = _AUTH_SESSIONS.get(state, {})
        nonce         = session.get("nonce", "")
        response_mode = session.get("response_mode", "query")

        # issue auth code
        code = secrets.token_urlsafe(32)
        _AUTH_CODES[code] = {"sub": sub, "redirect_uri": redirect_uri, "nonce": nonce, "state": state}

        # redirect back to spa, use fragment if response_mode=fragment (which my.dreamtonics.com uses so idk why i put this here but What Ever)
        params = urllib.parse.urlencode({"code": code, "state": state, "session_state": str(uuid.uuid4())})
        if response_mode == "fragment":
            dest = f"{redirect_uri}#{params}"
        else:
            sep  = "&" if "?" in redirect_uri else "?"
            dest = f"{redirect_uri}{sep}{params}"
        print(f"[auth] Redirecting with code  sub={sub[:8]}…  dest={redirect_uri}")
        resp = redirect(dest)
        resp.headers["Set-Cookie"] = f"dt-session={sub}; Path=/; SameSite=Lax"
        return resp

    def _handle_token(self, flow: http.HTTPFlow) -> http.Response:
        cors  = _cors_headers(flow)
        form  = _parse_form(flow.request.content)
        grant = form.get("grant_type", "")

        # auth code exchange (PKCE)
        if grant == "authorization_code":
            code         = form.get("code", "")
            code_verifier= form.get("code_verifier", "")
            redirect_uri = form.get("redirect_uri", "")

            entry = _AUTH_CODES.pop(code, None)
            if entry is None:
                print("[auth] Token exchange - unknown code")
                return json_resp({"error": "invalid_grant", "error_description": "Unknown code"}, 400, cors=cors)

            sub   = entry["sub"]
            nonce = entry.get("nonce", "")
            _AUTH_SESSIONS.pop(entry.get("state", ""), {})

            print(f"[auth] Token exchange (code)  sub={sub[:8]}…")
            return json_resp(_issue_tokens(sub, nonce), cors=cors)

        # refresh token
        if grant == "refresh_token":
            refresh_jwt = form.get("refresh_token", "")
            payload     = _decode_jwt_payload(refresh_jwt)
            sub         = payload.get("sub", "")
            if sub not in USER_STORE:
                return json_resp({"error": "invalid_grant"}, 400, cors=cors)
            print(f"[auth] Token refresh  sub={sub[:8]}…")
            return json_resp(_issue_tokens(sub), cors=cors)

        return json_resp({"error": "unsupported_grant_type"}, 400, cors=cors)

    def _account(self, flow: http.HTTPFlow) -> http.Response:
        cors = _cors_headers(flow)
        auth = flow.request.headers.get("authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        payload = _decode_jwt_payload(token)
        sub = payload.get("sub", "")
        u = USER_STORE.get(sub, {})
        return json_resp({
            "id":            sub,
            "username":      u.get("email", ""),
            "firstName":     u.get("given_name", ""),
            "lastName":      u.get("family_name", ""),
            "email":         u.get("email", ""),
            "emailVerified": True,
            "attributes":    {"locale": ["en-US"]},
            "userProfileMetadata": {
                "attributes": [
                    {"name": "locale",    "displayName": "locale",     "required": False, "readOnly": False, "validators": {}, "multivalued": False},
                    {"name": "username",  "displayName": "${username}", "required": False, "readOnly": True,  "validators": {}, "multivalued": False},
                    {"name": "email",     "displayName": "${email}",    "required": True,  "readOnly": False, "validators": {}, "multivalued": False},
                    {"name": "firstName", "displayName": "${firstName}","required": False, "readOnly": False, "validators": {}, "multivalued": False},
                    {"name": "lastName",  "displayName": "${lastName}", "required": False, "readOnly": False, "validators": {}, "multivalued": False},
                ]
            },
        }, cors=cors)

    def _userinfo(self, flow: http.HTTPFlow) -> http.Response:
        cors    = _cors_headers(flow)
        auth    = flow.request.headers.get("authorization", "")
        token   = auth.removeprefix("Bearer ").strip()
        payload = _decode_jwt_payload(token)
        sub     = payload.get("sub", "")
        u       = USER_STORE.get(sub, {})
        return json_resp({
            "sub":                sub,
            "email":              u.get("email", ""),
            "email_verified":     True,
            "name":               f"{u.get('given_name','')} {u.get('family_name','')}".strip(),
            "given_name":         u.get("given_name", ""),
            "family_name":        u.get("family_name", ""),
            "preferred_username": u.get("email", ""),
            "locale":             "en-US",
        }, cors=cors)


addons = [DreamtonicsAuth()]