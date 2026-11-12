#!/bin/sh
# Run the integration playbooks against a throwaway CrowdSec LAPI container.
#
# Usage: tests/integration/run.sh [crowdsec image tag]
#
# Needs docker or podman, and the collection installed or on ANSIBLE_COLLECTIONS_PATH.
# cscli is reached through a wrapper that runs it in the container with "exec".

set -eu

tag=${1:-${CROWDSEC_VERSION:-latest}}
engine=${CONTAINER_ENGINE:-$(command -v docker || command -v podman)}
name=crowdsec-collection-test-$$
dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)

cleanup() {
    "$engine" rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$tmp"
}
trap cleanup EXIT

"$engine" run -d --name "$name" \
    -e DISABLE_ONLINE_API=true \
    -e CROWDSEC_BYPASS_DB_VOLUME_CHECK=true \
    "docker.io/crowdsecurity/crowdsec:$tag" >/dev/null

printf '#!/bin/sh\nexec %s exec %s cscli "$@"\n' "$engine" "$name" > "$tmp/cscli"
chmod +x "$tmp/cscli"

echo "Waiting for the CrowdSec LAPI..."
i=0
until "$tmp/cscli" lapi status >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge 60 ]; then
        "$engine" logs "$name"
        exit 1
    fi
    sleep 2
done
"$tmp/cscli" version

for playbook in "$dir"/*.yml; do
    ansible-playbook -i localhost, -e "cscli_wrapper=$tmp/cscli" "$playbook"
done
