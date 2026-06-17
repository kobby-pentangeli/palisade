# syntax=docker/dockerfile:1

FROM rust:1.85-slim-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src

ENV RUSTFLAGS="-C strip=symbols"
RUN cargo build --release --locked --bin palisade

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /build/target/release/palisade /usr/local/bin/palisade

# The data-plane listener. Mount a TOML config at /etc/palisade/config.toml
# and bind it to 0.0.0.0 so the proxy is reachable from outside the container.
EXPOSE 8100

ENTRYPOINT ["/usr/local/bin/palisade"]
CMD ["--config", "/etc/palisade/config.toml", "--log-format", "json"]
