# ── Stage 1: install + build (TypeScript → dist/) ─────────────────────────
FROM artifacts.home.romaine.life/dockerhub/library/node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS builder

WORKDIR /app
ENV NPM_CONFIG_REGISTRY=https://artifacts.home.romaine.life/npm/npm/

COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY drizzle.config.ts ./
COPY src/ src/
RUN npm run build

# Re-install only production deps so the runtime image is smaller.
RUN npm ci --omit=dev && npm cache clean --force

# ── Stage 2: runtime ──────────────────────────────────────────────────────
FROM artifacts.home.romaine.life/dockerhub/library/node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a

WORKDIR /app

COPY --from=builder --chown=1001:1001 /app/node_modules node_modules
COPY --from=builder --chown=1001:1001 /app/dist dist
COPY --from=builder --chown=1001:1001 /app/package.json package.json

# The release version the footer shows; a local build shows dev.
ARG APP_VERSION=dev
ENV APP_VERSION=$APP_VERSION

RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown nodejs:nodejs /app
USER nodejs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# An entrypoint, so the image check's `--self-test` reaches it (src/entry.ts).
ENTRYPOINT ["node", "dist/entry.js"]
