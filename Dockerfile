# Build a small standalone Linux executable, then copy it into a minimal runtime image.
FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/vernam-share .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --from=builder /out/vernam-share /app/vernam-share
USER app
EXPOSE 8080
ENV ADDR=:8080
ENV MESSAGE_TTL=24h
ENTRYPOINT ["/app/vernam-share"]
