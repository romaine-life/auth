# ── Stage 1: install + build (TypeScript → dist/) ─────────────────────────
FROM artifacts.home.romaine.life/dockerhub/library/node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS builder

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
FROM artifacts.home.romaine.life/dockerhub/library/node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293

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

CMD ["node", "dist/server.js"]
