FROM node:24.11.1-bookworm-slim@sha256:48abc13a19400ca3985071e287bd405a1d99306770eb81d61202fb6b65cf0b57 AS web
WORKDIR /web
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build
FROM rust:1.91.1-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33 AS rust
WORKDIR /src
COPY backend/ ./
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target cargo build --release --locked && cp target/release/forklift /tmp/forklift
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
LABEL io.forklift.maintenance-version="1"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 curl && rm -rf /var/lib/apt/lists/* && mkdir /data /app && chown 10001:10001 /data
COPY --from=rust /tmp/forklift /app/forklift
COPY --from=web /web/dist /app/web
USER 10001:10001
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["sh", "-c", "umask 077; exec /app/forklift"]
