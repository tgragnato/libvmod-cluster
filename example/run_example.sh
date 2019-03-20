#!/bin/bash

# varnish server sharding example setup shell script
#
# Copyright 2019 UPLEX Nils Goroll Systemoptimierung
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

cat <<'EOF'
vshard example setup
--------------------

this script will demo a cluster/sharding setup on linux.

It will reconfigure three addresses 127.0.1.{1-3} on the loopback
interface lo and require sudo privileges to do so.

Then three varnish instances in a cluster will be started with
varnish-cache.org as their backend on 127.0.1.{1-3}:8080

Requirements:

* varnish installed

* this vmod installed

* constant vmod from https://code.uplex.de/uplex-varnish/varnish-objvar
  installed

* PATH contains directories to find varnishd and varnishadm

Press [enter] to continue...
EOF

read foo

typeset -r base="$(realpath $(dirname $0))"

typeset -ra cmds=(
    varnishadm
    varnishd
)

typeset -a pids=()

for cmd in "${cmds[@]}" ; do
    if ! type "${cmd}" ; then
	echo >&2 Required command not found in PATH
	exit 1
    fi
done

set -eux

exit_handler() {
    set +e
    local -i i
    kill "${pids[@]}"
    for((i=1; i<=3; i++)) ; do
	sudo ifconfig lo:$i down
    done
}

trap 'exit_handler $?' EXIT

typeset -i i
for((i=1; i<=3; i++)) ; do
    # nutch the kernel to choose the source ip we want
    sudo ifconfig lo:${i} 127.0.1.${i}/32 up
    varnishd -F -p vcl_path="${base}"/../vcl -f "${base}/vshard.example.vcl" \
	     -a 127.0.1.${i}:8080 -n varnish-${i} -i varnish-${i} &
    pids+=($!)
done

sleep 1

cat <<'EOF'
If all went well, the test-setup should be working now.

Things to try:

* in three terminals, watch the varnishds:

  varnishlog -n varnish-1 -q 'not Begin ~ "^sess" and not ReqHeader:Host ~^vshard"'
  varnishlog -n varnish-2 -q 'not Begin ~ "^sess" and not ReqHeader:Host ~^vshard"'
  varnishlog -n varnish-3 -q 'not Begin ~ "^sess" and not ReqHeader:Host ~^vshard"'

* send requests

  curl -I -H 'Host: varnish-cache.org' 127.0.1.1:8080

  -> shard master is varnish-3

     It should cache for whatever time remainting from max-age - age

  -> varnish-1 should forward to varnish-3

     It should cache for max 5 minutes (TTL VCL ... showing Age + 5m)

  curl -I -H 'Host: varnish-cache.org' 127.0.1.1:8080/_static/varnish-bunny.png

  -> shard master is varnish-1, so same as the above, but if the request
     is repeated to varnish-3 / 127.0.1.3:8080, it should forward it to
     varnish-1

Press [enter] to stop test setup...
EOF
read foo
