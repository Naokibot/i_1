FROM golang:1.25.12-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go test ./... \
 && CGO_ENABLED=0 go vet ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/observer ./cmd/observer

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/observer /app/observer
VOLUME ["/app/data"]
EXPOSE 8080
ENTRYPOINT ["/app/observer","-listen=:8080","-data=/app/data/observatory.json","-source-root=/workspace"]
