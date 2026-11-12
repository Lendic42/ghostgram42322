#!/bin/bash
# Turn a device IPA into one a free Apple ID can install without hand-editing.
#
#   build-system/GGSideloadIpa.sh Ghostgram.ipa Ghostgram-sideload.ipa
#
# Drops PlugIns (Share, Widget, notification extensions, intents, broadcast) and
# Watch, then re-signs ad hoc without the app-group and keychain-group entitlements
# those extensions required. Sideloadly replaces this signature with the Apple ID.

set -euo pipefail

src="${1:?usage: GGSideloadIpa.sh <input.ipa> <output.ipa>}"
dest="${2:?usage: GGSideloadIpa.sh <input.ipa> <output.ipa>}"
dest="$(cd "$(dirname "$dest")" && pwd)/$(basename "$dest")"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
unzip -q "$src" -d "$stage"

app="$(echo "$stage"/Payload/*.app)"
[ -d "$app" ] || { echo "no .app in $src" >&2; exit 1; }
rm -rf "$app/PlugIns" "$app/Watch"

ent="$stage/entitlements.plist"
if codesign -d --entitlements :- "$app" > "$ent" 2>/dev/null && [ -s "$ent" ]; then
    python3 - "$ent" <<'PY'
import plistlib
import sys

path = sys.argv[1]
data = open(path, "rb").read()
start = data.find(b"<?xml")
if start < 0:
    start = data.find(b"<plist")
if start > 0:
    data = data[start:]
plist = plistlib.loads(data)
drop = (
    "com.apple.security.application-groups",
    "keychain-access-groups",
    "com.apple.developer.ubiquity-kvstore-identifier",
    "com.apple.developer.ubiquity-container-identifiers",
    "com.apple.developer.icloud-container-identifiers",
    "com.apple.developer.icloud-container-environment",
    "com.apple.developer.icloud-services",
    "com.apple.developer.icloud-container-development-container-identifiers",
    "aps-environment",
    "com.apple.developer.associated-domains",
    "com.apple.developer.usernotifications.communication",
    "com.apple.developer.usernotifications.filtering",
    "com.apple.developer.siri",
    "com.apple.developer.carplay-messaging",
    "com.apple.developer.pushkit.unrestricted-voip",
    "com.apple.developer.in-app-payments",
    "com.apple.developer.applesignin",
    "com.apple.developer.background-tasks.continued-processing.gpu",
    "beta-reports-active",
)
for key in drop:
    plist.pop(key, None)
with open(path, "wb") as handle:
    plistlib.dump(plist, handle)
print("sideload entitlements:", ", ".join(sorted(plist)))
PY
else
    echo "could not read entitlements; ad-hoc signature will carry none"
    ent=""
fi

# Inside out: a framework signed after its host is invalid.
find "$app" -depth \( -name '*.framework' -o -name '*.dylib' \) -print0 |
    while IFS= read -r -d '' item; do
        codesign --force --sign - --timestamp=none "$item"
    done

if [ -n "$ent" ]; then
    codesign --force --sign - --timestamp=none --entitlements "$ent" "$app"
else
    codesign --force --sign - --timestamp=none "$app"
fi

rm -f "$dest"
(cd "$stage" && zip -qry "$dest" Payload)
ls -lh "$dest"
