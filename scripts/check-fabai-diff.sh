#!/usr/bin/env bash
# Checks that this fork differs from its pinned upstream release only in
# FabAI's gateway client patches and their tests. Upstream's own files,
# tests included, must be unchanged, so upstream's test suite runs against
# the patched client with no FabAI option set.
#
#   scripts/check-fabai-diff.sh             # compare HEAD with the pin
#   scripts/check-fabai-diff.sh --upstream  # also check the pin against the upstream tag
#
# The pinned commit must be in this checkout's history (fetch-depth: 0).
set -euo pipefail

readonly UPSTREAM_REPO="https://github.com/tinfoilsh/tinfoil-js"
readonly UPSTREAM_TAG="v2.0.0-rc.4"
readonly UPSTREAM_COMMIT="99ba5641881f51acd12f9a9fa185b5741d312153"

# Every path the patches may add or change.
readonly ALLOWED=(
	.github/workflows/fabai-test.yml
	.github/workflows/fabai-release.yml
	packages/tinfoil/src/gateway-client.ts
	packages/tinfoil/src/http.ts
	packages/tinfoil/src/internal/enclave.ts
	packages/tinfoil/src/internal/gateway/catalog.ts
	packages/tinfoil/src/internal/gateway/fabai.ts
	packages/tinfoil/src/internal/gateway/policy.ts
	packages/tinfoil/src/internal/gateway/transport.ts
	packages/tinfoil/src/internal/sealcheck.ts
	packages/tinfoil/src/internal/transport/ehbp.ts
	packages/tinfoil/src/internal/transport/tls.ts
	packages/tinfoil/src/internal/transport/transport.ts
	packages/tinfoil/src/internal/verified.ts
	packages/tinfoil/src/options.ts
	packages/tinfoil/test/fabai.test.ts
	scripts/check-fabai-diff.sh
)

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ "${1:-}" == "--upstream" ]]; then
	# A lightweight tag lists the commit; an annotated one lists its tag
	# object, then the commit under ^{}.
	tagged="$(git ls-remote "$UPSTREAM_REPO" "refs/tags/$UPSTREAM_TAG" "refs/tags/$UPSTREAM_TAG^{}" | awk 'END { print $1 }')"
	if [[ "$tagged" != "$UPSTREAM_COMMIT" ]]; then
		printf '%s %s is %s, not the pinned %s\n' "$UPSTREAM_REPO" "$UPSTREAM_TAG" "${tagged:-missing}" "$UPSTREAM_COMMIT" >&2
		exit 1
	fi
elif [[ $# -gt 0 ]]; then
	printf 'usage: %s [--upstream]\n' "$0" >&2
	exit 2
fi

if ! git merge-base --is-ancestor "$UPSTREAM_COMMIT" HEAD; then
	printf 'the pinned %s (%s) is not in HEAD'"'"'s history: fetch the full history, or rebase onto it\n' "$UPSTREAM_TAG" "$UPSTREAM_COMMIT" >&2
	exit 1
fi

status=0
while IFS= read -r path; do
	allowed=false
	for candidate in "${ALLOWED[@]}"; do
		if [[ "$path" == "$candidate" ]]; then
			allowed=true
			break
		fi
	done
	if [[ "$allowed" == false ]]; then
		printf 'changed outside the FabAI patches: %s\n' "$path" >&2
		status=1
	fi
done < <(git diff --name-only --no-renames "$UPSTREAM_COMMIT" HEAD)

if [[ "$status" -eq 0 ]]; then
	printf 'only the FabAI patches differ from %s (%s)\n' "$UPSTREAM_TAG" "$UPSTREAM_COMMIT"
fi
exit "$status"
