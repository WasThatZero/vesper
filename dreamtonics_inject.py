"""
dreamtonics_inject.py — UI injection addon
==========================================

Intercepts my.dreamtonics.com HTML responses and injects a script that:
  1. Patches window.fetch to intercept /product/query responses and build
     a product name → id map as the Vue app loads data
  2. Uses MutationObserver to watch for product cards appearing in the DOM
  3. Adds a "Mark as Owned" button to each card
  4. On click, POSTs to /api/v1/client/mark_owned (handled by dreamtonics_intercept.py)
     then triggers a page data refresh

Run alongside the other addons:
  mitmweb -s dreamtonics_auth.py -s dreamtonics_intercept.py -s dreamtonics_inject.py
"""

from mitmproxy import http
import json, os

TARGET_HOST = "my.dreamtonics.com"
SEED_FILE   = os.path.join(os.path.dirname(__file__), "dreamtonics_seed.json")

def _load_product_map() -> str:
    """Build a JS object literal mapping lowercase name → id from seed."""
    try:
        with open(SEED_FILE, encoding="utf-8") as f:
            seed = json.load(f)
        m = {p["name"].lower(): p["id"] for p in seed.get("products", []) if p.get("name") and p.get("id")}
        return json.dumps(m)
    except Exception as e:
        print(f"[inject] WARNING: could not load seed: {e}")
        return "{}"

SCRIPT_TEMPLATE = r"""
<script>
(function() {
  // ── Product map: name (lowercase) → id — embedded at inject time ─────────
  const productMap = __PRODUCT_MAP__;

  // ── Helpers ──────────────────────────────────────────────────────────────
  // ── Token — sniff from the app's own outgoing authr3 requests ────────────
  let _cachedToken = null;

  const _origFetch = window.fetch.bind(window);
  window.fetch = async function(input, init, ...rest) {
    try {
      const url = typeof input === 'string' ? input : (input?.url || '');
      if (url.includes('authr3.dreamtonics.com')) {
        const headers = init?.headers || input?.headers;
        let auth = '';
        if (headers instanceof Headers) auth = headers.get('authorization') || '';
        else if (headers) auth = headers['Authorization'] || headers['authorization'] || '';
        if (auth.startsWith('Bearer ')) _cachedToken = auth.slice(7);
      }
    } catch {}
    return _origFetch(input, init, ...rest);
  };

  // Also patch XHR since Axios may use it
  const _origXHROpen = XMLHttpRequest.prototype.open;
  const _origXHRSetHeader = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    this._dt_url = url;
    return _origXHROpen.call(this, method, url, ...args);
  };
  XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
    if ((this._dt_url || '').includes('authr3.dreamtonics.com') &&
        name.toLowerCase() === 'authorization' && value.startsWith('Bearer ')) {
      _cachedToken = value.slice(7);
    }
    return _origXHRSetHeader.call(this, name, value);
  };

  function getToken() { return _cachedToken; }

  // ── Name normalisation — handle UI display names differing from API names ─
  function normaliseName(name) {
    return name
      .toLowerCase()
      .replace(/\s*-\s*collection\s*/i, ' #')   // "Choir Voices - Collection 1" → "choir voices #1"
      .replace(/\s+/g, ' ')
      .trim();
  }

  async function markOwned(productId, productName, btn, label) {
    const token = getToken();
    btn.disabled = true;
    label.textContent = '⏳';
    try {
      const res = await _origFetch('https://authr3.dreamtonics.com/api/v1/client/mark_owned', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(getToken() ? { 'Authorization': `Bearer ${getToken()}` } : {}),
        },
        body: JSON.stringify({ product_id: productId }),
      });
      const data = await res.json();
      if (data?.data?.status === 'success') {
        btn.className = btn.className.replace('text-primary', 'text-positive');
        label.textContent = '✓ Owned';
        btn.disabled = true;
        // Refresh the Pinia session store so licenses update without a page reload
        try {
          const session = document.querySelector('#q-app').__vue_app__.config.globalProperties.$pinia._s.get('session');
          await session.loadMyInfo();
          await session.loadMyProducts();
          await session.loadAllProducts();
        } catch(e) {
          console.warn('[dt] store refresh failed, falling back to reload', e);
          setTimeout(() => window.location.reload(), 500);
        }
      } else {
        label.textContent = '✗ Failed';
        btn.disabled = false;
      }
    } catch(e) {
      console.error('[inject] mark_owned error', e);
      label.textContent = '✗ Error';
      btn.disabled = false;
    }
  }

  function makeButton(productId, productName) {
    const btn = document.createElement('button');
    btn.className = 'q-btn q-btn-item non-selectable no-outline q-btn--outline q-btn--rectangle text-primary q-btn--actionable q-focusable q-hoverable';
    btn.style.marginLeft = '6px';
    btn.dataset.dtInject = productId;
    btn.title = `Mark "${productName}" as owned`;

    const inner = document.createElement('span');
    inner.className = 'q-btn__content text-center col items-center q-anchor--skip justify-center row';
    const label = document.createElement('span');
    label.className = 'block';
    label.textContent = '★ Mark as Owned';
    inner.appendChild(label);
    btn.appendChild(inner);

    btn.onclick = (e) => {
      e.stopPropagation();
      markOwned(productId, productName, btn, label);
    };
    return btn;
  }

  function getProductName(card) {
    return card.querySelector('.text-h3')?.textContent?.trim() ?? null;
  }

  function getButtonContainer(card) {
    return card.querySelector('.action-buttons') ?? card;
  }

  function injectCard(card) {
    if (card.dataset.dtInjected) return;
    const name = getProductName(card);
    if (!name) return;
    const productId = productMap[normaliseName(name)];
    if (!productId) return;
    card.dataset.dtInjected = '1';
    getButtonContainer(card).appendChild(makeButton(productId, name));
  }

  const CARD_SEL = '.product-item, [class*="product-card"]';

  function scanCards() {
    document.querySelectorAll(CARD_SEL).forEach(injectCard);
  }

  const observer = new MutationObserver(scanCards);
  observer.observe(document.body, { childList: true, subtree: true });

  setTimeout(scanCards, 500);
  setTimeout(scanCards, 2000);

  // ── Debug helper ─────────────────────────────────────────────────────────
  window.dtDebug = () => {
    const t = getToken();
    console.log('[dt] token:', t ? t.slice(0,40)+'…' : 'NULL');
    console.log('[dt] productMap entries:', Object.keys(productMap).length);
    const cards = document.querySelectorAll(CARD_SEL);
    console.log('[dt] cards found:', cards.length);
    cards.forEach((card, i) => {
      const name = getProductName(card);
      const pid  = name ? productMap[normaliseName(name)] : null;
      console.log(`[dt] card[${i}] name="${name}" pid=${pid}`);
    });
  };

  console.log('[dreamtonics-inject] active —', Object.keys(productMap).length, 'products in map');
})();
</script>
"""

def _make_script() -> str:
    return SCRIPT_TEMPLATE.replace("__PRODUCT_MAP__", _load_product_map())

class DreamtonicsInject:

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.request.pretty_host != TARGET_HOST:
            return
        if not flow.response:
            return

        # Strip Content-Security-Policy — it blocks our injected inline script
        flow.response.headers.pop("content-security-policy", None)
        flow.response.headers.pop("content-security-policy-report-only", None)

        # Strip caching headers — prevents browser serving stale uninjected page
        flow.response.headers.pop("etag", None)
        flow.response.headers.pop("last-modified", None)
        flow.response.headers["cache-control"] = "no-store"
        flow.response.headers["pragma"] = "no-cache"

        ct = flow.response.headers.get("content-type", "")
        if "text/html" not in ct:
            return

        try:
            html = flow.response.content.decode("utf-8")
        except Exception:
            return

        if "</body>" not in html:
            return

        html = html.replace("</body>", _make_script() + "\n</body>", 1)
        flow.response.content = html.encode("utf-8")

        if "content-length" in flow.response.headers:
            flow.response.headers["content-length"] = str(len(flow.response.content))

        print(f"[inject] Injected into {flow.request.path}")


addons = [DreamtonicsInject()]