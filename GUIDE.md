# How to add custom products to vesper: an exhaustive guide on creating peak

This guide is going to be in waaaaaay more of a casual tone because its 00:30 as I'm writing this and I frankly cannot be assed to speak like a normal person right now

This guide also assumes you have basic JSON knowledge - it's decently easy to figure out and you can just copypaste from entries in the seed

The name is also misleading because this document goes over more what everything *means* rather than how to specifically add custom products

## Voicebanks (voice databases)

id - the specific product ID, must be unique

type - product type, for voicebanks it's either "Voice Database" for SV1 or "Voice Databases 2" for SV2

name - product name, shows up in the UI

vendor - vendor name, shows up in the UI

icon - icon URL, should be a PNG file but JPG might work (haven't tested)

keywords - search keywords

languages - table listing main language(s), usually one but can be multiple

gender - voice gender

tags - tells the UI how to render the card, there are some variations:
- web-style-download-button-outlined - render the DL button with an outline
- web-style-download-button-solid - render the DL button filled
- web-text-download-description-v2-voice-v2-only - shows popup that you must DL from within SV2
- web-text-download-description-v2-voice-v1-compatible - shows popup saying it has an SV1 installer, but also a native and proper SV2 version
- web-text-download-description-v1-voice - shows a DL popup with the SV1 installer

eula - eula info, needs two values:
- name - eula name
- id - eula ID

genres - table listing voice genres

pitch_range_min/pitch_range_max - min and max recommended pitches for the voice in midi numbers, see https://inspiredacoustics.com/en/MIDI_note_numbers_and_center_frequencies for a list

audio_url - url for voice preview

show_language_tags - true or false

show_purchase_button - true or false

show_download_button - true or false

show_download_button_in_editor - true or false (n/a since vesper has no support for the in-editor PM)

show_upgrade_button - true or false

upgrade_to_version - version to upgrade to (n/a unless show_upgrade_button is true)

editor_version - min sv2 editor version for the voice to work (n/a since vesper has no support for the in-editor PM)

is_trialable - true or false

release_date - release date (in unix time)

trial_days_total - max trial time in days (n/a unless is_trialable is true)

order - sort order

version - version number

version_latest_v2model - likely the version of the AI model file inside the package, potentially used to offer model-only updates without a full reinstall

version_latest_update - mirrors version in all known cases, likely reserved for showing an available update separate from the currently installed version

## Editors/non-voice products

essentially the same as above
