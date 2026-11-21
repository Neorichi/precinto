#!/bin/sh
# Installs shellcheck and fish on a CI runner (ubuntu or macOS), so the shim
# tests (shellcheck -s sh, TESTPLAN HOOK-4) and the live fish run of the
# shell integration (D29, D69) never skip in CI. Owner: G7.
set -eu
case "$(uname -s)" in
Linux)
	sudo apt-get update -q
	sudo apt-get install -y -q shellcheck fish
	;;
Darwin)
	# Only what is missing: an installed formula is left as it is.
	for f in shellcheck fish; do
		brew list "$f" >/dev/null 2>&1 || brew install "$f"
	done
	;;
*)
	echo "install-shells: unsupported runner $(uname -s)" >&2
	exit 1
	;;
esac
command -v shellcheck
command -v fish
