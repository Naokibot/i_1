ARG OPENSSL_VERSION=3.5.7
FROM debian:bookworm-slim AS openssl-build
ARG OPENSSL_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl perl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl --fail --location --proto '=https' --tlsv1.2 \
    "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    -o openssl.tar.gz \
 && curl --fail --location --proto '=https' --tlsv1.2 \
    "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz.sha256" \
    -o openssl.sha256 \
 && sed -i 's#  openssl-[^ ]*\.tar\.gz#  openssl.tar.gz#' openssl.sha256 \
 && sha256sum -c openssl.sha256 \
 && tar -xzf openssl.tar.gz \
 && cd "openssl-${OPENSSL_VERSION}" \
 && ./config --prefix=/opt/openssl --openssldir=/opt/openssl/ssl shared no-tests \
 && make -j"$(nproc)" \
 && make install_sw

FROM debian:bookworm-slim AS gateway-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config \
 && rm -rf /var/lib/apt/lists/*
COPY --from=openssl-build /opt/openssl /opt/openssl
ENV PATH="/opt/openssl/bin:${PATH}" \
    LD_LIBRARY_PATH="/opt/openssl/lib64:/opt/openssl/lib" \
    PKG_CONFIG_PATH="/opt/openssl/lib64/pkgconfig:/opt/openssl/lib/pkgconfig" \
    CMAKE_PREFIX_PATH="/opt/openssl"
WORKDIR /src
COPY . .
RUN /opt/openssl/bin/openssl version \
 && cmake -S . -B build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_PREFIX_PATH=/opt/openssl \
      -DOPENSSL_ROOT_DIR=/opt/openssl \
      -DOPENSSL_USE_STATIC_LIBS=FALSE \
 && cmake --build build \
 && cmake --install build --prefix /opt/gateway \
 && ldd /opt/gateway/bin/pqm-tls-gateway \
 && ! ldd /opt/gateway/bin/pqm-tls-gateway | grep -q 'not found'

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home gateway
COPY --from=openssl-build /opt/openssl /opt/openssl
COPY --from=gateway-build /opt/gateway /opt/gateway
RUN printf '%s\n' /opt/openssl/lib64 /opt/openssl/lib \
      > /etc/ld.so.conf.d/openssl-3.5.conf \
 && ldconfig \
 && ldd /opt/gateway/bin/pqm-tls-gateway \
 && ! ldd /opt/gateway/bin/pqm-tls-gateway | grep -q 'not found'
ENV PATH="/opt/openssl/bin:${PATH}" \
    LD_LIBRARY_PATH="/opt/openssl/lib64:/opt/openssl/lib"
USER gateway
ENTRYPOINT ["/opt/gateway/bin/pqm-tls-gateway"]
