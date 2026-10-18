# Build and run a witness-log witness (c2sp.org/tlog-witness).
#
#   docker build -t witness-log-witness -f deploy/witness/Dockerfile .
#   docker run --rm -v witness-state:/state witness-log-witness \
#       witness init /state --name witness.example/w1 --org "Example Org" \
#       --url https://witness.example --compute hetzner
#   docker run -d --name witness -p 7380:7380 -v witness-state:/state witness-log-witness
#
# The volume holds the key AND the memory of every head cosigned. Back it
# up as one unit; see OPERATORS.md.

FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p witness-log-cli \
 && strip target/release/witness-log

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home /state --shell /usr/sbin/nologin witness \
 && mkdir -p /state && chown witness:witness /state
COPY --from=build /src/target/release/witness-log /usr/local/bin/witness-log
USER witness
VOLUME ["/state"]
EXPOSE 7380
HEALTHCHECK --interval=30s --timeout=3s CMD ["witness-log", "witness", "info", "http://127.0.0.1:7380"]
ENTRYPOINT ["witness-log"]
# The default per-IP limits apply, because `docker run -p 7380:7380` above
# exposes the witness directly and a per-IP cap equal to the global one
# would let one client take every slot. Behind a reverse proxy every client
# shares the proxy's address; then raise them, as the release image does
# with WITNESS_BEHIND_PROXY=1 (see OPERATORS.md):
#   ... --max-conns-per-ip 256 --enroll-rate 6000
CMD ["witness", "serve", "/state", "--listen", "0.0.0.0:7380", "--open-enrollment"]
