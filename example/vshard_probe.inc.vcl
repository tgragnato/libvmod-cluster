probe probe_vshard {
	.request = "HEAD /cluster_health HTTP/1.1"
	    "Connection: close"
	    "Host: vshard";
	.interval = 1s;
}
