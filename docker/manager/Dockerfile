FROM node:24.11.1-bookworm-slim AS web
WORKDIR /web
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build
FROM rust:1.91.1-bookworm AS rust
WORKDIR /src
COPY backend/ ./
RUN cargo build --release --locked
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 curl && rm -rf /var/lib/apt/lists/* && mkdir /data /app && chown 10001:10001 /data
COPY --from=rust /src/target/release/forklift /app/forklift
COPY --from=web /web/dist /app/web
USER 10001:10001
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["/app/forklift"]
