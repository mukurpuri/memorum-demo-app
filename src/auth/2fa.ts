/**
 * Two-Factor Authentication (2FA) Module
 * 
 * Implements TOTP-based 2FA with backup codes for account recovery.
 * 
 * Security considerations:
 * - TOTP secrets are encrypted before storage
 * - Backup codes are hashed (one-way)
 * - Rate limiting on verification attempts
 * - Audit logging for all 2FA events
 */
import crypto from "crypto";
import { prisma } from "@/db/client";
import { TwoFactorMethod } from "@prisma/client";

const TOTP_SECRET_LENGTH = 20;
const BACKUP_CODE_COUNT = 10;
const BACKUP_CODE_LENGTH = 8;
const MAX_ATTEMPTS_PER_HOUR = 5;

// Encryption key for TOTP secrets (must be 32 bytes for AES-256)
const ENCRYPTION_KEY = process.env.TWO_FACTOR_ENCRYPTION_KEY!;

export interface TwoFactorSetupResult {
  secret: string;
  qrCodeUrl: string;
  backupCodes: string[];
}

export interface TwoFactorVerifyResult {
  valid: boolean;
  method: TwoFactorMethod;
  remainingAttempts?: number;
}

/**
 * Generate a cryptographically secure TOTP secret
 */
function generateTotpSecret(): string {
  return crypto.randomBytes(TOTP_SECRET_LENGTH).toString("base32");
}

/**
 * Encrypt a TOTP secret for secure storage
 */
function encryptSecret(secret: string): string {
  const iv = crypto.randomBytes(16);
  const key = Buffer.from(ENCRYPTION_KEY, "hex");
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  
  let encrypted = cipher.update(secret, "utf8", "hex");
  encrypted += cipher.final("hex");
  
  const authTag = cipher.getAuthTag();
  
  return `${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted}`;
}

/**
 * Decrypt a stored TOTP secret
 */
function decryptSecret(encryptedData: string): string {
  const [ivHex, authTagHex, encrypted] = encryptedData.split(":");
  
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");
  const key = Buffer.from(ENCRYPTION_KEY, "hex");
  
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  
  return decrypted;
}

/**
 * Generate backup codes for account recovery
 * Returns both plain codes (for display) and hashed versions (for storage)
 */
function generateBackupCodes(): { plain: string[]; hashed: string[] } {
  const plain: string[] = [];
  const hashed: string[] = [];
  
  for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
    const code = crypto.randomBytes(BACKUP_CODE_LENGTH / 2).toString("hex").toUpperCase();
    plain.push(code);
    hashed.push(hashBackupCode(code));
  }
  
  return { plain, hashed };
}

/**
 * Hash a backup code for secure storage
 */
function hashBackupCode(code: string): string {
  return crypto.createHash("sha256").update(code.toUpperCase()).digest("hex");
}

/**
 * Generate TOTP code for current time window
 */
function generateTotp(secret: string, time: number = Date.now()): string {
  const counter = Math.floor(time / 30000);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigInt64BE(BigInt(counter));
  
  const hmac = crypto.createHmac("sha1", Buffer.from(secret, "base32"));
  hmac.update(counterBuffer);
  const hash = hmac.digest();
  
  const offset = hash[hash.length - 1] & 0x0f;
  const code = (
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff)
  ) % 1000000;
  
  return code.toString().padStart(6, "0");
}

/**
 * Verify a TOTP code with time drift tolerance
 */
function verifyTotp(secret: string, code: string, window: number = 1): boolean {
  const now = Date.now();
  
  for (let i = -window; i <= window; i++) {
    const time = now + (i * 30000);
    const expected = generateTotp(secret, time);
    
    if (crypto.timingSafeEqual(Buffer.from(code), Buffer.from(expected))) {
      return true;
    }
  }
  
  return false;
}

/**
 * Initialize 2FA setup for a user
 * Returns secret and QR code URL for authenticator app
 */
export async function setup2FA(userId: string, email: string): Promise<TwoFactorSetupResult> {
  const secret = generateTotpSecret();
  const backupCodes = generateBackupCodes();
  
  const encryptedSecret = encryptSecret(secret);
  
  await prisma.twoFactorAuth.upsert({
    where: { userId },
    create: {
      userId,
      secret: encryptedSecret,
      backupCodes: backupCodes.hashed,
      enabled: false,
    },
    update: {
      secret: encryptedSecret,
      backupCodes: backupCodes.hashed,
      enabled: false,
      verifiedAt: null,
    },
  });
  
  const issuer = "ACME";
  const qrCodeUrl = `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
  
  console.log(`[2FA] Setup initiated for user ${userId}`);
  
  return {
    secret,
    qrCodeUrl,
    backupCodes: backupCodes.plain,
  };
}

/**
 * Verify 2FA setup with initial code
 * Must be called to enable 2FA after setup
 */
export async function verify2FASetup(userId: string, code: string): Promise<boolean> {
  const twoFactor = await prisma.twoFactorAuth.findUnique({
    where: { userId },
  });
  
  if (!twoFactor) {
    return false;
  }
  
  const secret = decryptSecret(twoFactor.secret);
  const valid = verifyTotp(secret, code);
  
  if (valid) {
    await prisma.twoFactorAuth.update({
      where: { userId },
      data: {
        enabled: true,
        verifiedAt: new Date(),
      },
    });
    
    console.log(`[2FA] Enabled for user ${userId}`);
  }
  
  return valid;
}

/**
 * Check rate limiting for 2FA verification attempts
 */
async function checkRateLimit(userId: string, ipAddress?: string): Promise<{ allowed: boolean; remaining: number }> {
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
  
  const attempts = await prisma.twoFactorAttempt.count({
    where: {
      userId,
      createdAt: { gte: oneHourAgo },
      successful: false,
    },
  });
  
  const remaining = MAX_ATTEMPTS_PER_HOUR - attempts;
  
  return {
    allowed: remaining > 0,
    remaining: Math.max(0, remaining),
  };
}

/**
 * Record a 2FA verification attempt
 */
async function recordAttempt(
  userId: string,
  successful: boolean,
  method: TwoFactorMethod,
  ipAddress?: string,
  userAgent?: string
): Promise<void> {
  await prisma.twoFactorAttempt.create({
    data: {
      userId,
      successful,
      method,
      ipAddress,
      userAgent,
    },
  });
}

/**
 * Verify a 2FA code (TOTP or backup code)
 */
export async function verify2FA(
  userId: string,
  code: string,
  ipAddress?: string,
  userAgent?: string
): Promise<TwoFactorVerifyResult> {
  const rateLimit = await checkRateLimit(userId, ipAddress);
  
  if (!rateLimit.allowed) {
    console.log(`[2FA] Rate limit exceeded for user ${userId}`);
    return {
      valid: false,
      method: "TOTP",
      remainingAttempts: 0,
    };
  }
  
  const twoFactor = await prisma.twoFactorAuth.findUnique({
    where: { userId },
  });
  
  if (!twoFactor || !twoFactor.enabled) {
    return { valid: false, method: "TOTP" };
  }
  
  // Try TOTP first
  const secret = decryptSecret(twoFactor.secret);
  if (verifyTotp(secret, code)) {
    await recordAttempt(userId, true, "TOTP", ipAddress, userAgent);
    return { valid: true, method: "TOTP" };
  }
  
  // Try backup code
  const hashedInput = hashBackupCode(code);
  const backupCodeIndex = twoFactor.backupCodes.indexOf(hashedInput);
  
  if (backupCodeIndex !== -1) {
    const updatedCodes = [...twoFactor.backupCodes];
    updatedCodes.splice(backupCodeIndex, 1);
    
    await prisma.twoFactorAuth.update({
      where: { userId },
      data: {
        backupCodes: updatedCodes,
        backupCodesUsed: twoFactor.backupCodesUsed + 1,
      },
    });
    
    await recordAttempt(userId, true, "BACKUP_CODE", ipAddress, userAgent);
    console.log(`[2FA] Backup code used for user ${userId}, ${updatedCodes.length} remaining`);
    
    return { valid: true, method: "BACKUP_CODE" };
  }
  
  // Invalid code
  await recordAttempt(userId, false, "TOTP", ipAddress, userAgent);
  
  return {
    valid: false,
    method: "TOTP",
    remainingAttempts: rateLimit.remaining - 1,
  };
}

/**
 * Disable 2FA for a user
 * Should require re-authentication before calling
 */
export async function disable2FA(userId: string): Promise<void> {
  await prisma.twoFactorAuth.delete({
    where: { userId },
  });
  
  console.log(`[2FA] Disabled for user ${userId}`);
}

/**
 * Regenerate backup codes for a user
 * Returns new codes and invalidates old ones
 */
export async function regenerateBackupCodes(userId: string): Promise<string[]> {
  const backupCodes = generateBackupCodes();
  
  await prisma.twoFactorAuth.update({
    where: { userId },
    data: {
      backupCodes: backupCodes.hashed,
      backupCodesUsed: 0,
    },
  });
  
  console.log(`[2FA] Backup codes regenerated for user ${userId}`);
  
  return backupCodes.plain;
}

/**
 * Check if user has 2FA enabled
 */
export async function has2FAEnabled(userId: string): Promise<boolean> {
  const twoFactor = await prisma.twoFactorAuth.findUnique({
    where: { userId },
    select: { enabled: true },
  });
  
  return twoFactor?.enabled ?? false;
}

/**
 * Get 2FA status for a user
 */
export async function get2FAStatus(userId: string): Promise<{
  enabled: boolean;
  verifiedAt: Date | null;
  backupCodesRemaining: number;
}> {
  const twoFactor = await prisma.twoFactorAuth.findUnique({
    where: { userId },
  });
  
  if (!twoFactor) {
    return {
      enabled: false,
      verifiedAt: null,
      backupCodesRemaining: 0,
    };
  }
  
  return {
    enabled: twoFactor.enabled,
    verifiedAt: twoFactor.verifiedAt,
    backupCodesRemaining: twoFactor.backupCodes.length,
  };
}
