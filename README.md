# Vernam Share

A small Go service for sharing a message through a URL with a configurable view limit. The message is encrypted with a byte-wise XOR one-time pad (Vernam cipher). A cryptographically secure random key, exactly as long as the UTF-8 message, is generated per message.

The web UI is embedded into the Go executable at build time. **The resulting binary runs without a separate `web/` directory or Go installed on the target machine.**

## Build a standalone binary

Requires Go 1.22+ on the build machine. Run these commands from the project directory (the directory containing `go.mod`).

### Linux

```sh
go build -trimpath -ldflags="-s -w" -o vernam-share .
./vernam-share
```

### macOS

```sh
go build -trimpath -ldflags="-s -w" -o vernam-share .
./vernam-share
```

### Windows (PowerShell)

```powershell
go build -trimpath -ldflags="-s -w" -o vernam-share.exe .
.\vernam-share.exe
```

The `-trimpath` flag removes local filesystem paths from the binary, and `-ldflags="-s -w"` strips debugging symbols to reduce its size. To cross-compile, set `GOOS` and `GOARCH` for the target platform before running `go build`; for example, from Linux or macOS to 64-bit Windows:

```sh
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o vernam-share.exe .
```

Build for 64-bit Linux:

```sh
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o vernam-share .
```

Build for Apple Silicon macOS:

```sh
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o vernam-share .
```

After building, copy **only the executable** to the target machine and run it. The embedded web UI is included in the executable. The target machine does not need Go installed. By default, open http://localhost:8080.

Optional environment variables:

```sh
ADDR=:8080 MESSAGE_TTL=24h ./vernam-share
```

On Windows PowerShell:

```powershell
$env:ADDR=":8080"
$env:MESSAGE_TTL="24h"
.\vernam-share.exe
```

`MESSAGE_TTL` accepts Go durations such as `30m`, `24h`, or `168h`.

## Build and run with Docker

Build the image from the project directory (the directory containing `Dockerfile`):

```sh
docker build -t vernam-share .
```

Run it with the default port and 24-hour message lifetime:

```sh
docker run --rm --name vernam-share -p 8080:8080 vernam-share
```

Open http://localhost:8080.

To configure the listening address or message lifetime, pass environment variables:

```sh
docker run --rm --name vernam-share \\
  -p 8080:8080 \\
  -e ADDR=:8080 \\
  -e MESSAGE_TTL=30m \\
  vernam-share
```

The Docker image uses a multi-stage build: Go compiles the application and embeds the web UI, then only the executable and CA certificates are copied into the runtime image. The process runs as an unprivileged user. Messages are held in memory, so they are lost when the container stops or restarts. For production, terminate HTTPS at a trusted reverse proxy or load balancer.

For a different target CPU architecture, adjust `GOARCH` in the Dockerfile's build stage (for example, `arm64`) or use Docker Buildx for multi-platform builds.

## Run from source (development)

Requires Go 1.22+.

```sh
go run .
```

The embedded web assets are still used when running from source.

## API

Create:

```sh
curl -s http://localhost:8080/api/messages \
  -H 'Content-Type: application/json' \
  -d '{"message":"secret text","maxViews":3}'
```

`maxViews` is optional, defaults to `1`, and accepts values from `1` to `1000`. The response includes the ID, secret key, expiry, and view counters. The `key` is secret; never log or send it to the server again.

Retrieve a view:

```sh
curl -s http://localhost:8080/api/messages/MESSAGE_ID
```

Each successful retrieval atomically increments `viewsUsed`. The message is deleted once `viewsUsed` reaches `maxViews`. The response includes `maxViews`, `viewsUsed`, and `viewsRemaining`.

Health check: `GET /healthz`.

## Important security notes

- **This is a true one-time pad only if the key is uniformly random, as long as the plaintext, kept secret, and never reused.** The implementation uses `crypto/rand`, generates a fresh key for every message, and does not persist keys.
- The browser places the key in the URL **fragment** (`#id=...&key=...`). URL fragments are not sent in HTTP requests, so the server never receives the key when the recipient opens the link.
- Anyone possessing the full URL can decrypt the message. Treat the URL like a password.
- The in-memory store is lost on restart and is not shared across multiple service instances. Use a single instance or replace it with a shared store that supports atomic consume.
- Use HTTPS in production. Add rate limiting, abuse controls, and operational monitoring before public deployment. Do not log request fragments, keys, or plaintext.
- One-time delivery means one successful retrieval from the server. It cannot stop a recipient from copying, photographing, or forwarding the decrypted message.
- The service intentionally does not persist messages. Expiration cleanup is best-effort; expired messages are also rejected at retrieval time.

## Why not AES?

A correctly implemented one-time pad offers information-theoretic confidentiality, but key distribution is the hard part. This project follows the requested Vernam cipher. For most production applications, authenticated encryption (for example, XChaCha20-Poly1305) is easier to operate safely; if using a one-time pad, never reuse keys.
