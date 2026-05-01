# Prosody 0.12.x on Debian Bookworm — no current "official" image exists
# (prosody/prosody on Docker Hub stopped at 0.11 / 2021), so build from
# the upstream apt repository. First build is ~60s; cached thereafter.

FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg \
    && curl -fsSL https://packages.prosody.im/debian/pubkey.asc \
        | gpg --dearmor -o /usr/share/keyrings/prosody.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/prosody.gpg] https://packages.prosody.im/debian bookworm main" \
        > /etc/apt/sources.list.d/prosody.list \
    && apt-get update && apt-get install -y --no-install-recommends \
        prosody \
        lua-zlib lua-dbi-sqlite3 lua-event \
    && apt-get purge -y curl gnupg \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 5222

COPY prosody.cfg.lua /etc/prosody/prosody.cfg.lua

RUN mkdir -p /var/run/prosody /var/lib/prosody \
    && chown -R prosody:prosody /var/run/prosody /var/lib/prosody

USER prosody
WORKDIR /var/lib/prosody

# Idempotent user creation, then exec into Prosody. `|| true` because
# `prosodyctl register` exits non-zero when the user already exists.
ENTRYPOINT ["sh", "-c", "prosodyctl register alice localhost alicepass || true; prosodyctl register bob localhost bobpass || true; prosodyctl register charlie localhost charliepass || true; exec prosody"]
