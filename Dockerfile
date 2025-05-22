FROM varnish:7.7-alpine AS builder
USER root
RUN apk add --no-cache curl automake autoconf libtool make py3-docutils
WORKDIR /workspace
COPY . .
RUN ./bootstrap
RUN ./configure
RUN make -j"$(nproc)" VERBOSE=1 install

FROM varnish:7.7-alpine
COPY --from=builder /usr/lib/varnish/vmods/libvmod_cluster.la /usr/lib/varnish/vmods/libvmod_cluster.la
COPY --from=builder /usr/lib/varnish/vmods/libvmod_cluster.so /usr/lib/varnish/vmods/libvmod_cluster.so
COPY --from=builder /usr/share/doc/libvmod-cluster /usr/share/doc/libvmod-cluster
COPY --from=builder /usr/share/man/man3/vmod_cluster.3 /usr/share/man/man3/vmod_cluster.3
COPY --from=builder /usr/share/varnish/vcl/cluster /usr/share/varnish/vcl/cluster
LABEL org.opencontainers.image.title="libvmod-cluster"
LABEL org.opencontainers.image.description="Varnish cache with director to facilitate clustering/sharding"
LABEL org.opencontainers.image.url="https://code.uplex.de/uplex-varnish/libvmod-cluster"
LABEL org.opencontainers.image.source="https://github.com/tgragnato/libvmod-cluster"
LABEL org.opencontainers.image.licenses="BSD-2-Clause license"
LABEL io.containers.autoupdate=registry
