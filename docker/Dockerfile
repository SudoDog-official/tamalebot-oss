FROM node:22-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends chromium && \
    rm -rf /var/lib/apt/lists/*

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV CHROMIUM_PATH=/usr/bin/chromium

# Create non-root user
RUN useradd -m -s /bin/bash agentuser

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

COPY dist/ ./dist/
COPY config/ ./config/

# Create writable directories
RUN mkdir -p /tmp/workspace /tmp/logs && \
    chown -R agentuser:agentuser /tmp/workspace /tmp/logs

USER agentuser

ENV TAMALEBOT_MODE=http
ENV PORT=8080

EXPOSE 8080

ENTRYPOINT ["node", "dist/agent/index.js"]
