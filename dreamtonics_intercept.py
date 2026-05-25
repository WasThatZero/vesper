# intercepts all authr3.dreamtonics.com traffic and answers it locally
# so requests never actually reach dreamtonics' servers
# basically: the glue of the whole fucking thing

import base64
import json
import os
import time
import uuid
from mitmproxy import http

# config

TARGET_HOST = "authr3.dreamtonics.com"
SEED_FILE   = os.path.join(os.path.dirname(__file__), "dreamtonics_seed.json")

# load seed data

def _load_seed():
    if os.path.exists(SEED_FILE):
        with open(SEED_FILE, encoding="utf-8") as f:
            return json.load(f)
    print(f"[intercept] WARNING: {SEED_FILE} not found - using empty product database")
    return {"products": [], "downloads": {}, "translations": {}}

_seed = _load_seed()

# global state

# product DB: id -> product dict
PRODUCTS: dict[str, dict] = {p["id"]: p for p in _seed.get("products", [])}

# download URL DB: product_id -> list of package dicts
DOWNLOADS: dict[str, list] = _seed.get("downloads", {})

# translation data
TRANSLATIONS: dict = _seed.get("translations", {})

EULAS: dict[str, dict] = _seed.get("eulas", {})
PURCHASE_INFO: dict[str, dict] = _seed.get("purchase_info", {})

print(f"[intercept] Loaded {len(PRODUCTS)} products, {len(DOWNLOADS)} downloads, {len(EULAS)} EULAs")

# per-user state, keyed by JWT sub claim, shared with dreamtonics_auth.py
# { sub: { email, given_name, family_name, licenses, entitlements, devices, in_beta_test } }

try:
    # import shared USER_STORE from auth addon if loaded alongside
    from dreamtonics_auth import USER_STORE as _AUTH_USER_STORE
    USER_STORE = _AUTH_USER_STORE
    print("[intercept] Sharing USER_STORE with dreamtonics_auth")
except ImportError:
    USER_STORE: dict[str, dict] = {}
    print("[intercept] Running standalone - USER_STORE is local")


def _get_user(sub: str) -> dict:
    if sub not in USER_STORE:
        USER_STORE[sub] = {
            "email": f"{sub[:8]}@unknown.local",
            "given_name": "User",
            "family_name": sub[:8],
        }
    u = USER_STORE[sub]
    u.setdefault("licenses", {})
    u.setdefault("entitlements", [])
    u.setdefault("devices", [])
    u.setdefault("in_beta_test", False)
    return u

# jwt decode (no verification - we issued it ourselves)

def _decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split(".")
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


def _sub_from_flow(flow: http.HTTPFlow) -> str:
    auth = flow.request.headers.get("authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    payload = _decode_jwt_payload(token)
    sub = payload.get("sub", "")
    if sub and sub != "anonymous":
        return sub
    # fallback: dt-session cookie set by auth addon on login
    cookies = flow.request.headers.get("cookie", "")
    for part in cookies.split(";"):
        k, _, v = part.strip().partition("=")
        if k.strip() == "dt-session" and v.strip():
            return v.strip()
    return "anonymous"

# helpers

CORS_HEADERS = {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, Origin, X-Requested-With",
}

def _cors(flow: http.HTTPFlow) -> dict:
    origin = flow.request.headers.get("origin", "*")
    return {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": origin if origin != "*" else "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, Origin, X-Requested-With",
        "Access-Control-Allow-Credentials": "true",
        "Vary": "Origin",
    }

def ok(data, flow: http.HTTPFlow | None = None) -> http.Response:
    headers = _cors(flow) if flow else CORS_HEADERS
    body = json.dumps({"status": 200, "data": data}, ensure_ascii=False)
    return http.Response.make(200, body, headers)

def err(code: str, message: str, status: int = 400, flow: http.HTTPFlow | None = None) -> http.Response:
    headers = _cors(flow) if flow else CORS_HEADERS
    body = json.dumps(
        {"status": status, "error": {"code": code, "message": message}},
        ensure_ascii=False,
    )
    return http.Response.make(status, body, headers)

def preflight(flow: http.HTTPFlow) -> http.Response:
    return http.Response.make(200, b"", _cors(flow))


def make_license(product: dict, license_type: str = "trial") -> dict:
    trial_days = product.get("trial_days_total") or 7
    valid_to = int(time.time()) + trial_days * 86400 if license_type == "trial" else None
    return {
        "id": str(uuid.uuid4()),
        "product": product,
        "license_type": license_type,
        "valid_to": valid_to,
        "status": "active",
    }

# product filtering and pagination

def _matches_filter(p: dict, params: dict, user_licenses: dict) -> bool:
    if "vendor" in params and p.get("vendor") != params["vendor"]:
        return False
    if "gender" in params and p.get("gender") != params["gender"]:
        return False
    if "genre" in params and params["genre"] not in (p.get("genres") or []):
        return False
    if "language" in params and params["language"] not in (p.get("languages") or []):
        return False
    if "type" in params and p.get("type") != params["type"]:
        return False
    if params.get("is_trialable") == "true" and not p.get("is_trialable"):
        return False
    if params.get("filter") == "user_trialable":
        if not p.get("is_trialable"):
            return False
        already = any(lic["product"]["id"] == p["id"] for lic in user_licenses.values())
        if already:
            return False
    return True


def _sort_key(p: dict, sort: str):
    if sort == "product_name":
        return (p.get("name") or "").lower()
    if sort == "release_order":
        return p.get("release_date") or 0
    return (p.get("order") or 0, p.get("release_date") or 0)


def query_products(params: dict, user_licenses: dict) -> dict:
    page      = int(params.get("page", 1))
    page_size = int(params.get("page_size", 10))
    sort      = params.get("sort", "default")
    sort_dir  = params.get("sort_direction", "desc")

    filtered = [p for p in PRODUCTS.values() if _matches_filter(p, params, user_licenses)]
    reverse  = sort_dir == "desc"
    filtered.sort(key=lambda p: _sort_key(p, sort), reverse=reverse)

    total      = len(filtered)
    page_total = max(1, (total + page_size - 1) // page_size)
    start      = (page - 1) * page_size
    page_data  = filtered[start : start + page_size]

    return {
        "status": 200,
        "data": page_data,
        "metadata": {
            "current_page": page,
            "page_size": page_size,
            "page_total": page_total,
            "total": total,
        },
    }

# dict/enum values

def build_dict() -> dict:
    types   = sorted({p["type"] for p in PRODUCTS.values() if p.get("type")})
    vendors = sorted({p["vendor"] for p in PRODUCTS.values() if p.get("vendor")})
    langs   = sorted({l for p in PRODUCTS.values() for l in (p.get("languages") or [])})
    genders = sorted({p["gender"] for p in PRODUCTS.values() if p.get("gender")})
    genres  = {g for p in PRODUCTS.values() for g in (p.get("genres") or [])}
    genre_order = [
        "C-Pop","J-Pop","K-Pop","Pop",
        "C-R&B","C-Rock","J-R&B","J-Rock","Rock",
        "Gospel","R&B","Soul","Jazz",
        "Country","Folk","Cinematic",
        "Electronic","Hip-Hop","Classical","Opera",
        "Children's Music",
    ]
    genres_ordered = [g for g in genre_order if g in genres] + [g for g in sorted(genres) if g not in genre_order]
    return {
        "type": types,
        "vendor": vendors,
        "language": langs,
        "gender": genders,
        "genre": genres_ordered,
    }

# router

class DreamtonicsIntercept:

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.pretty_host != TARGET_HOST:
            return

        method = flow.request.method
        path   = flow.request.path.split("?")[0].rstrip("/")
        params = dict(flow.request.query)

        if method == "OPTIONS":
            flow.response = preflight(flow)
            return

        sub  = _sub_from_flow(flow)
        user = _get_user(sub)
        licenses = user["licenses"]

        # GET /api/v1/client/me
        if method == "GET" and path == "/api/v1/client/me":
            flow.response = ok({
                "user_permission_levels": ["beta", "release"],
                "user_type": "retail",
            })
            print(f"[intercept] GET  /client/me  sub={sub[:8]}…")
            return

        # GET /api/v1/client/my_licenses
        if method == "GET" and path == "/api/v1/client/my_licenses":
            flow.response = ok(list(licenses.values()), flow)
            print(f"[intercept] GET  /client/my_licenses  sub={sub[:8]}… -> {len(licenses)} licenses")
            return

        # GET /api/v1/client/my_entitlements
        if method == "GET" and path == "/api/v1/client/my_entitlements":
            flow.response = ok(user["entitlements"], flow)
            print(f"[intercept] GET  /client/my_entitlements  sub={sub[:8]}…")
            return

        # GET /api/v1/client/my_devices
        if method == "GET" and path == "/api/v1/client/my_devices":
            flow.response = ok({"offline_license_devices": user["devices"]}, flow)
            print(f"[intercept] GET  /client/my_devices  sub={sub[:8]}…")
            return

        # POST /api/v1/client/start_trial
        if method == "POST" and path == "/api/v1/client/start_trial":
            flow.response = self._start_trial(flow, sub, user)
            return

        # POST /api/v1/client/mark_owned  (custom - injected UI)
        if method == "POST" and path == "/api/v1/client/mark_owned":
            flow.response = self._mark_owned(flow, sub, user)
            return

        # POST /api/v1/client/test_enroll
        if method == "POST" and path == "/api/v1/client/test_enroll":
            user["in_beta_test"] = True
            print(f"[intercept] POST /client/test_enroll  sub={sub[:8]}…")
            flow.response = ok({"status": "success"}, flow)
            return

        # POST /api/v1/client/test_quit
        if method == "POST" and path == "/api/v1/client/test_quit":
            user["in_beta_test"] = False
            print(f"[intercept] POST /client/test_quit  sub={sub[:8]}…")
            flow.response = ok({"status": "success"}, flow)
            return

        # GET /api/v1/product/query
        if method == "GET" and path == "/api/v1/product/query":
            result = query_products(params, licenses)
            flow.response = http.Response.make(
                200, json.dumps(result, ensure_ascii=False), _cors(flow)
            )
            meta = result["metadata"]
            print(f"[intercept] GET  /product/query  sub={sub[:8]}… -> {meta['total']} products (page {meta['current_page']}/{meta['page_total']})")
            return

        # GET /api/v1/product/dict/get
        if method == "GET" and path == "/api/v1/product/dict/get":
            flow.response = ok(build_dict(), flow)
            print(f"[intercept] GET  /product/dict/get")
            return

        # GET /api/v1/update/get_download_url
        if method == "GET" and path == "/api/v1/update/get_download_url":
            pid = params.get("product", "")
            packages = DOWNLOADS.get(pid, [])
            flow.response = ok(packages, flow)
            print(f"[intercept] GET  /update/get_download_url  product={pid[:8]}… -> {len(packages)} packages")
            return

        # GET /api/v1/translation/get
        if method == "GET" and path == "/api/v1/translation/get":
            flow.response = ok(TRANSLATIONS, flow)
            print(f"[intercept] GET  /translation/get  key={params.get('key')}")
            return

        # GET /api/v1/product/eula/get
        if method == "GET" and path == "/api/v1/product/eula/get":
            eula_id = params.get("eula_id", "")
            eula = EULAS.get(eula_id)
            if eula:
                flow.response = ok(eula, flow)
            else:
                flow.response = err("eula-not-found", "EULA not found", 404, flow)
            print(f"[intercept] GET  /product/eula/get  eula_id={eula_id[:8]}… -> {'found' if eula else 'not found'}")
            return

        # GET /api/v1/purchase/info/get
        if method == "GET" and path == "/api/v1/purchase/info/get":
            pid = params.get("product_id", "")
            info = PURCHASE_INFO.get(pid)
            if not info:
                product = PRODUCTS.get(pid)
                name = product["name"] if product else pid
                info = {"product": name, "url": f"https://store.dreamtonics.com/"}
            flow.response = ok(info, flow)
            print(f"[intercept] GET  /purchase/info/get  product={pid[:8]}…")
            return

        # POST /api/v1/client/add_license_by_activation_code
        if method == "POST" and path == "/api/v1/client/add_license_by_activation_code":
            flow.response = self._redeem_code(flow, sub, user)
            return

        print(f"[intercept] UNHANDLED {method} {path} - passing through")

    def _redeem_code(self, flow: http.HTTPFlow, sub: str, user: dict) -> http.Response:
        try:
            body = json.loads(flow.request.content)
            code = body["payload"]["code"].strip().upper()
        except Exception:
            return err("bad-request", "Malformed request body", flow=flow)

        # accept any 25char alphanumeric code as a wildcard, grants all products
        if len(code) == 25 and code.replace("-", "").isalnum():
            licenses = user["licenses"]
            added = []
            for product in PRODUCTS.values():
                already = any(l["product"]["id"] == product["id"] and l["status"] == "active"
                              for l in licenses.values())
                if not already:
                    lic = make_license(product, "full")
                    licenses[lic["id"]] = lic
                    added.append(lic)
            print(f"[intercept] POST /client/add_license_by_activation_code  sub={sub[:8]}… code={code[:8]}… -> granted {len(added)} licenses")
            return ok({"status": "success", "added_licenses": added}, flow)

        print(f"[intercept] POST /client/add_license_by_activation_code  sub={sub[:8]}… -> invalid code")
        return err("activation-code-invalid", "Invalid activation code", flow=flow)

    def _mark_owned(self, flow: http.HTTPFlow, sub: str, user: dict) -> http.Response:
        try:
            body = json.loads(flow.request.content)
            product_id = body["product_id"]
        except Exception:
            return err("bad-request", "Malformed request body", flow=flow)

        product = PRODUCTS.get(product_id)
        if product is None:
            return err("product-invalid", "Invalid product", flow=flow)

        licenses = user["licenses"]

        # remove any existing license for this product first
        to_remove = [lid for lid, lic in licenses.items() if lic["product"]["id"] == product_id]
        for lid in to_remove:
            del licenses[lid]

        lic = {
            "id": str(uuid.uuid4()),
            "product": product,
            "license_type": "full",
            "valid_to": None,
            "status": "active",
        }
        licenses[lic["id"]] = lic
        print(f"[intercept] POST /client/mark_owned  sub={sub[:8]}…  {product['name']} -> marked as owned")
        return ok({"status": "success", "license": lic}, flow)

    def _start_trial(self, flow: http.HTTPFlow, sub: str, user: dict) -> http.Response:
        try:
            body = json.loads(flow.request.content)
            product_id = body["payload"]["product_id"]
        except Exception:
            return err("bad-request", "Malformed request body", flow=flow)

        product = PRODUCTS.get(product_id)
        if product is None:
            print(f"[intercept] POST /client/start_trial  sub={sub[:8]}… -> 400 product-invalid")
            return err("product-invalid", "Invalid product", flow=flow)

        if not product.get("is_trialable"):
            print(f"[intercept] POST /client/start_trial  {product['name']} -> 400 not trialable")
            return err("product-not-trialable", f"{product['name']} is not trialable", flow=flow)

        licenses = user["licenses"]
        for lic in licenses.values():
            if lic["product"]["id"] == product_id and lic["status"] == "active":
                print(f"[intercept] POST /client/start_trial  {product['name']} -> 400 already active")
                return err("trial-already-active", "An active trial already exists for this product", flow=flow)

        lic = make_license(product, "trial")
        licenses[lic["id"]] = lic
        print(f"[intercept] POST /client/start_trial  sub={sub[:8]}…  {product['name']} -> trial started")
        return ok({"status": "success", "added_licenses": [lic]}, flow)


addons = [DreamtonicsIntercept()]