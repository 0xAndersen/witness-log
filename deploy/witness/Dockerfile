# Build and run a witness-log witness (c2sp.org/tlog-witness) from source.
#
#   docker build -t witness-log-witness -f deploy/witness/Dockerfile .
#   docker run -d --name witness -p 7380:7380 -v witness-state:/state \
#       -e WITNESS_ORG="Example Org" -e WITNESS_URL=https://witness.example \
#       witness-log-witness
#
# The entrypoint is the same docker-entrypoint.sh the release image uses:
# on first start with an empty /state it runs `witness init` from the
# environment (WITNESS_ORG is required), prints the directory entry, then
# serves. Arguments replace that and go to the binary, e.g.
#   docker run --rm -v witness-state:/state witness-log-witness \
#       witness init /state --name witness.example/w1 --org "Example Org" \
#       --url https://witness.example --compute hetzner
#
# render.yaml (repository root) and deploy/fly/fly.toml build this file.
# Those platforms mount the state disk owned by root, so they build with
# --build-arg WITNESS_IMAGE_USER=0:0: the entrypoint then starts as root,
# gives /state to uid 10001 and runs everything else as that user. Leave the
# default anywhere a Docker volume is used.
#
# The volume holds the key AND the memory of every head cosigned. Back it
# up as one unit; see OPERATORS.md.

FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p witness-log-cli \
 && strip target/release/witness-log

FROM debian:bookworm-slim
RUN groupadd --system --gid 10001 witness \
 && useradd --system --uid 10001 --gid 10001 --home /state --shell /usr/sbin/nologin witness \
 && mkdir -p /state && chown 10001:10001 /state && chmod 0700 /state
COPY --from=build /src/target/release/witness-log /usr/local/bin/witness-log
COPY --chmod=0755 deploy/witness/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# 10001 unless a platform config sets 0:0 (see the top of this file).
ARG WITNESS_IMAGE_USER=10001:10001
USER ${WITNESS_IMAGE_USER}
VOLUME ["/state"]
EXPOSE 7380
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD ["witness-log", "witness", "info", "http://127.0.0.1:7380"]
# No CMD: with no arguments the entrypoint initialises (first start) and
# serves with the default per-address limits, because `docker run -p` above
# exposes the witness directly. Behind a reverse proxy every client shares
# the proxy's address; then set WITNESS_BEHIND_PROXY=1 (OPERATORS.md), as
# the Render and Fly.io configurations do.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
