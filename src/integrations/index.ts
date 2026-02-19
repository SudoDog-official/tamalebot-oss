// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Integration Layer
 *
 * Each integration connects the agent to an external service.
 * Integrations are open source so the community can add more.
 *
 * Phase 1: Telegram, Web browsing (via tools)
 * Phase 2: Email (Gmail), Slack, Calendar
 * Phase 3: Discord, WhatsApp
 * Phase 4: iMessage (via relay)
 */

export interface Integration {
  name: string;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  isConnected(): boolean;
}

export { TelegramIntegration } from "./telegram.js";
