// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 TamaleBot Contributors

/**
 * Credential Vault
 *
 * Encrypted credential storage backed by R2 (or any StorageBackend).
 * Credentials are encrypted at rest using AES-256-GCM with a key
 * derived from TAMALEBOT_VAULT_KEY (or TAMALEBOT_API_KEY as fallback).
 *
 * Used by SSH and Git tools to securely store and retrieve keys.
 * All access is logged to the audit trail.
 */

import { createCipheriv, createDecipheriv, randomBytes, pbkdf2Sync, generateKeyPairSync } from "node:crypto";
import type { StorageBackend } from "../storage/index.js";
import type { AuditTrail } from "./audit-trail.js";

const CREDENTIAL_NAME_PATTERN = /^[A-Z][A-Z0-9_]{1,63}$/;
const VAULT_PREFIX = "vault/";
const ENCRYPTION_ALGO = "aes-256-gcm";
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_KEYLEN = 32;
const PBKDF2_DIGEST = "sha256";

export type CredentialType = "api_key" | "ssh_key" | "ssh_key_pub" | "token" | "database_url" | "generic";

export interface CredentialMeta {
  type: CredentialType;
  description?: string;
  createdAt: string;
}

interface StoredCredential {
  encrypted: string; // base64-encoded ciphertext
  iv: string;        // base64-encoded IV
  tag: string;       // base64-encoded auth tag
  meta: CredentialMeta;
}

export class CredentialVault {
  private storage: StorageBackend;
  private audit: AuditTrail;
  private agentId: string;
  private encryptionKey: Buffer;

  constructor(storage: StorageBackend, audit: AuditTrail, agentId: string, vaultKeySource: string) {
    this.storage = storage;
    this.audit = audit;
    this.agentId = agentId;
    // Derive a stable 256-bit key from the vault key source
    this.encryptionKey = pbkdf2Sync(
      vaultKeySource,
      `tamalebot-vault-${agentId}`,
      PBKDF2_ITERATIONS,
      PBKDF2_KEYLEN,
      PBKDF2_DIGEST,
    );
  }

  private encrypt(plaintext: string): { encrypted: string; iv: string; tag: string } {
    const iv = randomBytes(12);
    const cipher = createCipheriv(ENCRYPTION_ALGO, this.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      encrypted: encrypted.toString("base64"),
      iv: iv.toString("base64"),
      tag: tag.toString("base64"),
    };
  }

  private decrypt(encrypted: string, iv: string, tag: string): string {
    const decipher = createDecipheriv(
      ENCRYPTION_ALGO,
      this.encryptionKey,
      Buffer.from(iv, "base64"),
    );
    decipher.setAuthTag(Buffer.from(tag, "base64"));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encrypted, "base64")),
      decipher.final(),
    ]);
    return decrypted.toString("utf-8");
  }

  validateName(name: string): boolean {
    return CREDENTIAL_NAME_PATTERN.test(name);
  }

  async set(name: string, value: string, meta: { type: CredentialType; description?: string }): Promise<void> {
    if (!this.validateName(name)) {
      throw new Error(`Invalid credential name: ${name}. Must match [A-Z][A-Z0-9_]{1,63}`);
    }
    if (!value || value.length > 16384) {
      throw new Error("Credential value must be 1-16384 characters");
    }

    const { encrypted, iv, tag } = this.encrypt(value);
    const stored: StoredCredential = {
      encrypted,
      iv,
      tag,
      meta: {
        type: meta.type,
        description: meta.description,
        createdAt: new Date().toISOString(),
      },
    };

    await this.storage.put(`${VAULT_PREFIX}${name}.json`, JSON.stringify(stored));
    this.audit.log(this.agentId, "vault_set", name, "allowed", undefined, { type: meta.type });
  }

  async get(name: string): Promise<{ value: string; meta: CredentialMeta } | null> {
    if (!this.validateName(name)) return null;

    const data = await this.storage.get(`${VAULT_PREFIX}${name}.json`);
    if (!data) {
      this.audit.log(this.agentId, "vault_get", name, "allowed", "not found");
      return null;
    }

    try {
      const stored = JSON.parse(data.toString("utf-8")) as StoredCredential;
      const value = this.decrypt(stored.encrypted, stored.iv, stored.tag);
      this.audit.log(this.agentId, "vault_get", name, "allowed");
      return { value, meta: stored.meta };
    } catch (err) {
      this.audit.log(this.agentId, "vault_get", name, "blocked", "decryption failed");
      return null;
    }
  }

  async delete(name: string): Promise<void> {
    if (!this.validateName(name)) return;
    await this.storage.delete(`${VAULT_PREFIX}${name}.json`);
    this.audit.log(this.agentId, "vault_delete", name, "allowed");
  }

  async list(): Promise<{ name: string; type: CredentialType; description?: string; createdAt: string }[]> {
    const keys = await this.storage.list(VAULT_PREFIX);
    const results: { name: string; type: CredentialType; description?: string; createdAt: string }[] = [];

    for (const key of keys) {
      const cleanKey = key.replace(VAULT_PREFIX, "").replace(".json", "");
      if (!cleanKey) continue;

      try {
        const data = await this.storage.get(`${VAULT_PREFIX}${key.endsWith(".json") ? cleanKey : key}.json`);
        if (!data) continue;
        const stored = JSON.parse(data.toString("utf-8")) as StoredCredential;
        results.push({
          name: cleanKey,
          type: stored.meta.type,
          description: stored.meta.description,
          createdAt: stored.meta.createdAt,
        });
      } catch {
        // Skip corrupted entries
      }
    }

    this.audit.log(this.agentId, "vault_list", `${results.length} credentials`, "allowed");
    return results;
  }

  async getSSHKey(name: string): Promise<string | null> {
    const cred = await this.get(name);
    if (!cred) return null;
    if (cred.meta.type !== "ssh_key") {
      this.audit.log(this.agentId, "vault_get", name, "blocked", `expected ssh_key, got ${cred.meta.type}`);
      return null;
    }
    return cred.value;
  }

  async setSSHKey(name: string, privateKey: string, publicKey: string): Promise<void> {
    await this.set(name, privateKey, { type: "ssh_key", description: "SSH private key" });
    await this.set(`${name}_PUB`, publicKey, { type: "ssh_key_pub", description: "SSH public key" });
  }

  async generateSSHKey(name: string): Promise<string> {
    if (!this.validateName(name)) {
      throw new Error(`Invalid key name: ${name}`);
    }

    const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    // Convert PEM to OpenSSH format for the public key
    const pubKeyBase64 = publicKey
      .replace("-----BEGIN PUBLIC KEY-----", "")
      .replace("-----END PUBLIC KEY-----", "")
      .replace(/\s/g, "");
    const pubKeyBuffer = Buffer.from(pubKeyBase64, "base64");
    // Extract raw ed25519 key (last 32 bytes of the SPKI structure)
    const rawPub = pubKeyBuffer.subarray(pubKeyBuffer.length - 32);
    // Build OpenSSH format
    const typePrefix = Buffer.from("ssh-ed25519");
    const typeLenBuf = Buffer.alloc(4);
    typeLenBuf.writeUInt32BE(typePrefix.length, 0);
    const keyLenBuf = Buffer.alloc(4);
    keyLenBuf.writeUInt32BE(rawPub.length, 0);
    const sshPubKey = `ssh-ed25519 ${Buffer.concat([typeLenBuf, typePrefix, keyLenBuf, rawPub]).toString("base64")} tamalebot-${name.toLowerCase()}`;

    await this.setSSHKey(name, privateKey, sshPubKey);
    this.audit.log(this.agentId, "vault_generate_ssh_key", name, "allowed");
    return sshPubKey;
  }
}
