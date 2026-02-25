---
name: Deploy Helper
description: Assist with deployment tasks including Docker builds, CI/CD pipelines, cloud deployments, and infrastructure configuration.
---

## Deploy Helper Skill

When the user needs help with deployment:

### Docker
- Review Dockerfile for best practices (multi-stage builds, layer caching, security)
- Help compose docker-compose.yml configurations
- Debug build failures by reading error output

### CI/CD
- Help write GitHub Actions, GitLab CI, or other pipeline configs
- Set up test/build/deploy stages
- Configure environment variables and secrets

### Cloud Deployment
- Help with Cloudflare Workers/Pages deployment configs
- Assist with AWS, GCP, or Azure deployment scripts
- Configure DNS, SSL, and domain settings

### Process
1. Ask what is being deployed and where (if not specified)
2. Check existing configuration files in the workspace
3. Identify what needs to change or be created
4. Write config files and scripts
5. Validate by running dry-run commands where possible
6. Provide a clear deployment checklist

Always prefer infrastructure-as-code over manual steps. Warn about potential downtime.
