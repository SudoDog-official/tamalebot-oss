FROM node:22-slim

# Create non-root user
RUN useradd -m -s /bin/bash agentuser

# Install SSH client and Git for remote access and repo operations
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-client git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

COPY dist/ ./dist/

# Create writable directories for agent workspace, logs, and SSH
RUN mkdir -p /tmp/workspace /tmp/logs /home/agentuser/.ssh && \
    chmod 700 /home/agentuser/.ssh && \
    chown -R agentuser:agentuser /tmp/workspace /tmp/logs /home/agentuser/.ssh

# No root, no privilege escalation
USER agentuser

EXPOSE 8080

ENV TAMALEBOT_MODE=http
ENV PORT=8080

ENTRYPOINT ["node", "dist/agent/index.js"]
