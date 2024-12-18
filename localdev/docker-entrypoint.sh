#!/bin/bash
set -e

echo never >/sys/kernel/mm/transparent_hugepage/enabled
echo never >/sys/kernel/mm/transparent_hugepage/defrag

# https://github.com/valkey-io/valkey-container/blob/mainline/docker-entrypoint.sh

# first arg is `-f` or `--some-option`
# or first arg is `something.conf`
if [[ "${1#-}" != "$1" ]] || [[ "${1%.conf}" != "$1" ]]; then
    set -- valkey-server "$@"
fi

# # allow the container to be started with `--user`
# # shellcheck disable=SC2108,SC2312
# if [[ "$1" = 'valkey-server' -a "$(id -u)" = '0' ]]; then
# 	find . \! -user valkey -exec chown valkey '{}' +
# 	exec setpriv --reuid=valkey --regid=valkey --clear-groups -- "$0" "$@"
# fi

# set an appropriate umask (if one isn't set already)
um="$(umask)"
# shellcheck disable=SC2250
if [[ "$um" = '0022' ]]; then
    umask 0077
fi

valkey-server --save 60 1 --loglevel warning
