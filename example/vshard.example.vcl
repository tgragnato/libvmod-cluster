# varnish server sharding example VCL
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

vcl 4.1;

import cluster;
import directors;
import std;
# https://code.uplex.de/uplex-varnish/varnish-objvar
import constant;

backend default {
	.host = "www.varnish-cache.org";
	.port = "80";
}

# TODO:
#
# * names (e.g. varnish-1) must be identical to the actual
#   server.identity or the use of server.identity below must be
#   replaced with the actual varnish name
#
# * the probe should be kept unless you know what you are doing
#
# * change IPs

include "cluster/vshard_probe.inc.vcl";

backend varnish-1 {
	.host = "127.0.1.1";
	.port = "8080";
	.probe = probe_vshard;
}
backend varnish-2 {
	.host = "127.0.1.2";
	.port = "8080";
	.probe = probe_vshard;
}
backend varnish-3 {
	.host = "127.0.1.3";
	.port = "8080";
	.probe = probe_vshard;
}
# TODO: add more servers

# TODO: same IPs as in backends above
acl acl_vshard {
	"127.0.1.1"/32;
	"127.0.1.2"/32;
	"127.0.1.3"/32;
}

sub vcl_init {
	new vshard = directors.shard();

	# TODO: add all servers defined above
	vshard.add_backend(varnish-1);
	vshard.add_backend(varnish-2);
	vshard.add_backend(varnish-3);
	vshard.reconfigure();

	new vcluster = cluster.cluster(vshard.backend());
	vcluster.deny(directors.lookup(server.identity));

	# only the cluster master has the full ttl to improve total
	# cache memory scalability
	#
	# choose your secondary server TTL
	#
	# for use without the constant vmod, replace cluster_ttl.get()
	# in vshard.inc.vcl (2x)

	new vcluster_ttl = constant.duration(5m);
}

include "cluster/vshard.inc.vcl";

# return (synth(404)) here for manual control as in the example
#
# the sub must be defined for vshard.inc.vcl even if empty
sub vshard_recv_healthcheck_override {
	# if (! std.file_exists("/tmp/varnish_online")) {
	#	return (synth(404));
	#}
}

sub vcl_recv {
	# FIRST
	call vshard_recv;

	# then any additional processing for clients,
	# for example...
	set req.http.X-Real-IP = client.ip;
}

sub vcl_deliver {
	# FIRST
	call vshard_deliver;

	# then any additional processing for clients
}

sub vcl_backend_fetch {
	# FIRST
	call vshard_backend_fetch;

	# the processing when talking to a real backend
}

sub vcl_backend_response {
	# FIRST
	call vshard_backend_response;

	# the processing when talking to a real backend
}
