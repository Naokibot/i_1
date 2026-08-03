ARG OPENSSL_VERSION=3.5.7
ARG LIBOQS_VERSION=0.15.0
ARG OQS_PROVIDER_VERSION=0.11.0
FROM debian:bookworm-slim AS build
ARG OPENSSL_VERSION
ARG LIBOQS_VERSION
ARG OQS_PROVIDER_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates cmake curl git ninja-build perl pkg-config python3 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl --fail --location --proto '=https' --tlsv1.2 \
      "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" -o openssl.tar.gz \
 && curl --fail --location --proto '=https' --tlsv1.2 \
      "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz.sha256" -o openssl.sha256 \
 && expected="$(cut -d ' ' -f 1 openssl.sha256)" \
 && printf '%s  %s\n' "$expected" openssl.tar.gz | sha256sum -c - \
 && tar -xzf openssl.tar.gz \
 && cd "openssl-${OPENSSL_VERSION}" \
 && ./config --prefix=/opt/openssl --openssldir=/opt/openssl/ssl shared no-tests \
 && make -j"$(nproc)" \
 && make install_sw

ENV PATH="/opt/openssl/bin:${PATH}" \
    LD_LIBRARY_PATH="/opt/openssl/lib64:/opt/openssl/lib:/opt/oqs/lib64:/opt/oqs/lib" \
    PKG_CONFIG_PATH="/opt/openssl/lib64/pkgconfig:/opt/openssl/lib/pkgconfig:/opt/oqs/lib/pkgconfig" \
    CMAKE_PREFIX_PATH="/opt/openssl;/opt/oqs"

RUN git clone --depth 1 --branch "${LIBOQS_VERSION}" https://github.com/open-quantum-safe/liboqs.git \
 && cmake -S liboqs -B liboqs/build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/oqs \
      -DCMAKE_INSTALL_LIBDIR=lib \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON \
 && cmake --build liboqs/build \
 && cmake --install liboqs/build

RUN git clone --depth 1 --branch "${OQS_PROVIDER_VERSION}" https://github.com/open-quantum-safe/oqs-provider.git \
 && cmake -S oqs-provider -B oqs-provider/build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/oqs-provider \
      -DCMAKE_INSTALL_LIBDIR=lib \
      -DCMAKE_PREFIX_PATH="/opt/openssl;/opt/oqs" \
      -DOPENSSL_ROOT_DIR=/opt/openssl \
      -DOPENSSL_USE_STATIC_LIBS=FALSE \
      -Dliboqs_DIR=/opt/oqs/lib/cmake/liboqs \
 && cmake --build oqs-provider/build \
 && cmake --install oqs-provider/build \
 && test -f /opt/oqs-provider/lib/ossl-modules/oqsprovider.so \
 && OPENSSL_MODULES=/opt/oqs-provider/lib/ossl-modules \
      /opt/openssl/bin/openssl list \
        -provider-path /opt/oqs-provider/lib/ossl-modules \
        -provider default \
        -provider oqsprovider \
        -providers | grep -q oqsprovider

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends coreutils \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home oqs
COPY --from=build /opt/openssl /opt/openssl
COPY --from=build /opt/oqs /opt/oqs
COPY --from=build /opt/oqs-provider /opt/oqs-provider
COPY openssl.cnf /etc/pqm/openssl.cnf
COPY smoke.sh /usr/local/bin/oqs-smoke
RUN printf '%s\n' \
      /opt/openssl/lib64 \
      /opt/openssl/lib \
      /opt/oqs/lib64 \
      /opt/oqs/lib \
      > /etc/ld.so.conf.d/pqm-crypto.conf \
 && ldconfig \
 && chmod 0755 /usr/local/bin/oqs-smoke \
 && test -f /opt/oqs-provider/lib/ossl-modules/oqsprovider.so \
 && ldd /opt/oqs-provider/lib/ossl-modules/oqsprovider.so \
 && ! ldd /opt/oqs-provider/lib/ossl-modules/oqsprovider.so | grep -q 'not found'
ENV PATH="/opt/openssl/bin:${PATH}" \
    LD_LIBRARY_PATH="/opt/openssl/lib64:/opt/openssl/lib:/opt/oqs/lib64:/opt/oqs/lib" \
    OPENSSL_CONF="/etc/pqm/openssl.cnf" \
    OPENSSL_MODULES="/opt/oqs-provider/lib/ossl-modules"
USER oqs
ENTRYPOINT ["oqs-smoke"]
