# varnish server sharding VCL library
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
#
# Cluster rules:
#
# within the cluster, we only want minimal processing, so we want to
# process each vcl sub's user/business logic only at one place
#
# * vcl_recv:    facing the client
# * vcl_deliver: facing the client
#
# -> iow no user logic when our remote.ip is a varnish
#
# * vcl_backend_fetch:    on the primary cluster member
# * vcl_backend_response: on the primary cluster member
#
# -> iow no user logic when our backend is a varnish

sub vshard_recv {
	if (remote.ip ~ acl_vshard) {
		if (req.http.Host == "vshard") {
			if (req.url == "/cluster_health") {
				call vshard_recv_healthcheck_override;
				return (synth(200));
			}
			return (synth(404));
		}

		# if we're async, don't deliver stale
		if (req.http.X-Cluster-bgfetch == "true") {
			set req.grace = 0s;
		}

		return (hash);
	}
}

sub vshard_backend_fetch {
	unset bereq.http.X-Cluster-bgfetch;
	if (vcluster.cluster_selected(
	    real = bereq.backend,
	    direct = bereq.retries > 0 || remote.ip ~ acl_vshard)) {
		set bereq.http.X-Cluster-bgfetch = bereq.is_bgfetch;
		return (fetch);
	}
	# bereq.backend == vcluster.get_real() || bereq.backend == NULL
}

sub vshard_backend_response {
	# bereq.http.X-Cluster-bgfetch is only set if this is a
	# cluster request
	if (bereq.http.X-Cluster-bgfetch) {
		if (beresp.http.X-Cluster-TTL) {
			set beresp.ttl = std.duration(
			    beresp.http.X-Cluster-TTL + "s", 1s);
			if (beresp.ttl > vcluster_ttl.get()) {
				set beresp.ttl = vcluster_ttl.get();
			}
			unset beresp.http.X-Cluster-TTL;
		} else {
			set beresp.uncacheable = true;
		}
		return (deliver);
	}
}

sub vshard_deliver {
	# irrespective of cache-control headers, communicate the ttl to the
	# cluster upstream and return without any additional processing.
	#
	# no header = uncacheable
	#
	# ordinary vcl_deliver is only called facing the real client
	unset resp.http.X-Cluster-TTL;
	if (remote.ip ~ acl_vshard && req.http.X-Cluster-bgfetch) {
		if (! obj.uncacheable) {
			set resp.http.X-Cluster-TTL = obj.ttl;
		}
		return (deliver);
	}
}
