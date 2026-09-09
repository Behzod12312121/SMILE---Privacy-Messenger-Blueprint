# One image, two roles. The gateway and the oblivious relay are the same code
# started at different entry points, so they share a build and diverge only in
# the command and the environment.
#
# Multi-stage because better-sqlite3 and libsignal are native modules: they need
# a toolchain to build and nothing but the compiled output to run. Shipping the
# toolchain would triple the image and hand an attacker a compiler.
FROM node:22-bookworm-slim AS build

# node-gyp needs these to compile better-sqlite3. Present only in this stage.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 make g++ ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY package.json package-lock.json ./
COPY packages ./packages
COPY tsconfig*.json ./
RUN npm ci
RUN npm run build
# Drop dev dependencies once the TypeScript is compiled.
RUN npm prune --omit=dev

FROM node:22-bookworm-slim AS runtime

# Runs as the node user, never root. This is the isolation that matters: an
# application-level bug in a process running as root owns the host, and a
# gateway reachable from the internet is exactly where that bug would be
# reached. The image carries no shell tooling worth having either.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build --chown=node:node /build/node_modules ./node_modules
COPY --from=build --chown=node:node /build/packages ./packages
COPY --from=build --chown=node:node /build/package.json ./package.json

# The database lives on a mounted volume, owned by the same unprivileged user.
RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]

USER node
ENV NODE_ENV=production

# Overridden per role in compose. Default is the gateway.
CMD ["node", "--enable-source-maps", "packages/server/dist/index.js"]
