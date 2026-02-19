// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { SecretManager } from "../../src/security/secret-manager.js";

describe("SecretManager", () => {
  const manager = new SecretManager();

  describe("name validation", () => {
    it("accepts valid uppercase names", () => {
      expect(manager.validateName("API_KEY")).toBe(true);
      expect(manager.validateName("ANTHROPIC_API_KEY")).toBe(true);
      expect(manager.validateName("DB_PASSWORD_2")).toBe(true);
    });

    it("rejects lowercase names", () => {
      expect(manager.validateName("api_key")).toBe(false);
    });

    it("rejects names starting with numbers", () => {
      expect(manager.validateName("2_KEY")).toBe(false);
    });

    it("rejects empty names", () => {
      expect(manager.validateName("")).toBe(false);
    });

    it("rejects single character names", () => {
      expect(manager.validateName("A")).toBe(false);
    });
  });

  describe("value validation", () => {
    it("accepts normal values", () => {
      expect(manager.validateValue("sk-ant-abc123")).toBe(true);
    });

    it("rejects values with newlines", () => {
      expect(manager.validateValue("line1\nline2")).toBe(false);
    });

    it("rejects values with null bytes", () => {
      expect(manager.validateValue("has\0null")).toBe(false);
    });

    it("rejects empty values", () => {
      expect(manager.validateValue("")).toBe(false);
    });

    it("rejects values over 4096 characters", () => {
      expect(manager.validateValue("x".repeat(4097))).toBe(false);
    });
  });

  describe("masking", () => {
    it("masks secrets preserving first N chars", () => {
      expect(manager.mask("sk-ant-abc123xyz", 4)).toBe("sk-a************");
    });

    it("fully masks short secrets", () => {
      expect(manager.mask("abc", 4)).toBe("***");
    });
  });

  describe("bulk masking", () => {
    it("masks all known secrets in text", () => {
      manager.set("API_KEY", "sk-ant-secret-value-12345");
      const text = "Using key sk-ant-secret-value-12345 for request";
      const masked = manager.maskAll(text);
      expect(masked).not.toContain("sk-ant-secret-value-12345");
      expect(masked).toContain("sk-a");
    });
  });

  describe("env var generation", () => {
    it("generates KEY=value format", () => {
      const mgr = new SecretManager();
      mgr.set("MY_KEY", "my-value");
      const envVars = mgr.toEnvVars();
      expect(envVars).toContain("MY_KEY=my-value");
    });
  });
});
