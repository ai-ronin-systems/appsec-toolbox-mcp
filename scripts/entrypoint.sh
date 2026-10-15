#!/bin/sh
set -eu
mkdir -p "${HOME:-/tmp/home}" "${XDG_CACHE_HOME:-/tmp/cache}" /tmp/makefile-mcp output
exec "$@"
