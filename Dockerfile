# ─────────────────────────────────────────────
# Stage 1: Builder
# ─────────────────────────────────────────────
FROM node:20-alpine AS builder

# Install dependencies needed for native modules
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy dependency manifests first (layer cache optimization)
COPY src/package*.json ./

# Install only production dependencies
RUN npm ci --omit=dev

# Copy source code
COPY src/ .

# ─────────────────────────────────────────────
# Stage 2: Runtime
# ─────────────────────────────────────────────
FROM node:20-alpine AS runtime

# Install Trivy for SBOM generation
RUN apk add --no-cache curl bash && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Security: run as non-root user
RUN addgroup -S dsabot && adduser -S dsabot -G dsabot

WORKDIR /app

# Copy built app from builder stage
COPY --from=builder /app /app

# Set ownership
RUN chown -R dsabot:dsabot /app

USER dsabot

# ─────────────────────────────────────────────
# Environment Variables (override via .env or docker run -e)
# ─────────────────────────────────────────────
ENV NODE_ENV=production \
    PORT=3000 \
    # GitHub
    GITHUB_TOKEN="" \
    GITHUB_ORG="" \
    GITHUB_WEBHOOK_SECRET="" \
    # Dependency Track
    DEPENDENCY_TRACK_URL="" \
    DEPENDENCY_TRACK_API_KEY="" \
    # Defect Dojo
    DEFECT_DOJO_URL="" \
    DEFECT_DOJO_API_KEY="" \
    # AWS S3 (for SBOM storage)
    AWS_REGION="" \
    AWS_ACCESS_KEY_ID="" \
    AWS_SECRET_ACCESS_KEY="" \
    S3_BUCKET_NAME=""

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:3000/status || exit 1

CMD ["node", "index.js"]
