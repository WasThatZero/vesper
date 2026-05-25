"""
mitmproxy addon — Spoofs the Dreamtonics AUDIOLOGIE product query endpoint.

Usage:
    mitmproxy -s audiologie_spoof.py
  or (headless):
    mitmdump -s audiologie_spoof.py

Then configure your system / app to use the proxy at 127.0.0.1:8080.
On first run, install the mitmproxy CA cert so HTTPS interception works:
  https://docs.mitmproxy.org/stable/concepts-certificates/
"""

import json
from mitmproxy import http

TARGET_HOST = "authr3.dreamtonics.com"
TARGET_PATH = "/api/v1/product/query"
TARGET_PARAMS = {
    "page": "1",
    "page_size": "10",
    "vendor": "AUDIOLOGIE",
    "sort": "release_order",
    "sort_direction": "desc",
}

SPOOFED_RESPONSE = {
    "status": 200,
    "data": [
        {
            "id": "e27233a3-b3ab-4f97-ad91-a720d3187366",
            "type": "Voice Databases 2",
            "name": "ANDI Vesper",
            "vendor": "AUDIOLOGIE",
            "icon": "https://authr3-media.r2.dreamtonics.com/products/icons/ANDI-Vesper/ANDIV_256x256_PEydG7NxLGuBHEUc.png",
            "keywords": "Andy Linh Heart's Reprieve TAKE2!",
            "languages": ["English"],
            "gender": "Masculine",
            "tags": [
                "web-style-download-button-outlined",
                "web-text-download-description-v2-voice-v2-only",
            ],
            "eula": {
                "name": "EULA - AUDIOLOGIE - ANDI - VESPER",
                "id": "c6715114-5686-497e-a519-f7fafc27db23",
            },
            "genres": ["Pop", "Rock", "Electronic"],
            "pitch_range_min": 45,
            "pitch_range_max": 69,
            "audio_url": None,
            "show_language_tags": True,
            "show_purchase_button": True,
            "show_download_button": True,
            "show_download_button_in_editor": True,
            "show_upgrade_button": False,
            "upgrade_to_version": None,
            "editor_version": "2.0",
            "is_trialable": True,
            "release_date": 1775480400,
            "trial_days_total": 7,
            "order": 100,
            "version": {
                "version_name": "201",
                "version_number": 51584,
                "minimal_editor_version_name": "131328",
                "minimal_editor_version_number": 131328,
            },
            "version_latest_v2model": {
                "version_name": "201",
                "version_number": 51584,
                "minimal_editor_version_name": "131328",
                "minimal_editor_version_number": 131328,
            },
            "version_latest_update": None,
        },
        {
            "id": "1b373844-e759-47b8-9c7b-ff410b210119",
            "type": "Voice Databases 2",
            "name": "ANRI Requiem",
            "vendor": "AUDIOLOGIE",
            "icon": "https://authr3-media.r2.dreamtonics.com/products/icons/ANRI-Requiem/ANRI_Requiem_256x256_EZllBlsKc8FCaQW7.png",
            "keywords": "\u94c3\u7231\u8389 \u674f\u91cc \u5b89\u91cc Airi Lin TAKE2!",
            "languages": ["English"],
            "gender": "Feminine",
            "tags": [
                "web-style-download-button-outlined",
                "web-text-download-description-v2-voice-v2-only",
            ],
            "eula": {
                "name": "EULA - AUDIOLOGIE - ANRI - REQUIEM",
                "id": "f9498ec1-25af-4e60-b2bc-17fcf7e58831",
            },
            "genres": ["Pop", "Electronic", "Hip-Hop"],
            "pitch_range_min": 55,
            "pitch_range_max": 76,
            "audio_url": None,
            "show_language_tags": True,
            "show_purchase_button": True,
            "show_download_button": True,
            "show_download_button_in_editor": True,
            "show_upgrade_button": False,
            "upgrade_to_version": None,
            "editor_version": "2.0",
            "is_trialable": True,
            "release_date": 1775480400,
            "trial_days_total": 7,
            "order": 100,
            "version": {
                "version_name": "201",
                "version_number": 51584,
                "minimal_editor_version_name": "131328",
                "minimal_editor_version_number": 131328,
            },
            "version_latest_v2model": {
                "version_name": "201",
                "version_number": 51584,
                "minimal_editor_version_name": "131328",
                "minimal_editor_version_number": 131328,
            },
            "version_latest_update": None,
        },
    ],
    "metadata": {
        "current_page": 1,
        "page_size": 10,
        "page_total": 1,
        "total": 2,
    },
}


def _query_matches(flow: http.HTTPFlow) -> bool:
    """Return True only when every expected query param is present and matches."""
    actual = dict(flow.request.query)
    return all(actual.get(k) == v for k, v in TARGET_PARAMS.items())


class AudiologieSpoof:
    def request(self, flow: http.HTTPFlow) -> None:
        if (
            flow.request.pretty_host == TARGET_HOST
            and flow.request.path.startswith(TARGET_PATH)
            and _query_matches(flow)
        ):
            flow.response = http.Response.make(
                200,
                json.dumps(SPOOFED_RESPONSE),
                {
                    "Content-Type": "application/json; charset=utf-8",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                },
            )
            print(f"[audiologie_spoof] Intercepted → returned spoofed response")


addons = [AudiologieSpoof()]
