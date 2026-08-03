FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go test ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/runtime-controller ./cmd/runtime-controller \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/gateway-agent ./cmd/gateway-agent \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/telemetry-reporter ./cmd/telemetry-reporter \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/recrypt-worker ./cmd/recrypt-worker \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/emergency-sign ./cmd/emergency-sign

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home pqm
COPY --from=build /out/* /usr/local/bin/
USER pqm
ENTRYPOINT ["runtime-controller"]
