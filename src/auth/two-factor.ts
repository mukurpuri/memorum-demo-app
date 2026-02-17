/**
 * Two-Factor Authentication Service
 * 
 * Implements TOTP (Time-based One-Time Password) authentication
 * compatible with Google Authenticator, Authy, 1Password, etc.
 * 
 * Security considerations:
 * - Secrets are encrypted at rest with AES-256-GCM
 * - Backup codes are hashed with bcrypt (single-use)
 * - Rate limiting on verification attempts
 * - Automatic lockout after failed attempts
 */

import crypto from "crypto";
import { prisma } from "@/db/client";
import { TwoFactorMethod } from "@prisma/client";

// Configuration
const TOTP_DIGITS = 6;
const TOTP_PERIOD = 30; // seconds
const TOTP_ALGORITHM = "SHA1";
const BACKUP_CODE_COUNT = 10;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 15;

// Encryption key from environment (should be 32 bytes for AES-256)
const ENCRYPTION_KEY = process.env.TWO_FACTOR_ENCRYPTION_KEY || "default-dev-key-change-in-prod!!";

// ============================================================================
// TOTP Core Functions
// ============================================================================

/**
 * Generate a new TOTP secret for a user
 * Returns the secret and a QR code URL for authenticator apps
 */
export async function generateTwoFactorSecret(
  userId: string,
  email: string
): Promise<{
  secret: string;
  qrCodeUrl: string;
  backupCodes: string[];
}> {
  // Generate cryptographically secure secret (20 bytes = 160 bits)
  const secretBuffer = crypto.randomBytes(20);
  const secret = base32Encode(secretBuffer);
  
  // Generate backup codes
  const backupCodes = generateBackupCodes(BACKUP_CODE_COUNT);
  const hashedBackupCodes = await hashBackupCodes(backupCodes);
  
  // Encrypt the secret for storage
  const encryptedSecret = encryptSecret(secret);
  
  // Store in database (not yet verified)
  await prisma.twoFactorAuth.upsert({
    where: { userId },
    create: {
      userId,
      secret: encryptedSecret,
      algorithm: TOTP_ALGORITHM,
      digits: TOTP_DIGITS,
      period: TOTP_PERIOD,
      backupCodes: hashedBackupCodes,
      verified: false,
    },
    update: {
      secret: encryptedSecret,
      backupCodes: hashedBackupCodes,
      verified: false,
      failedAttempts: 0,
      lockedUntil: null,
    },
  });
  
  // Generate QR code URL (otpauth:// format)
  const issuer = "ACME Platform";
  const qrCodeUrl = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=${TOTP_ALGORITHM}&digits=${TOTP_DIGITS}&period=${TOTP_PERIOD}`;
  
  return { secret, qrCodeUrl, backupCodes };
}

/**
 * Verify a TOTP code during login or setup
 * Returns true if valid, false otherwise
 */
export async function verifyTwoFactorCode(
  userId: string,
  code: string,
  context?: { ipAddress?: string; userAgent?: string }
): Promise<{ valid: boolean; reason?: string }> {
  const twoFactor = await prisma.twoFactorAuth.findUnique({
    where: { userId },
  });
  
  if (!twoFactor) {
    return { valid: false, reason: "2FA not configured" };
  }
  
  // Check if locked out
  if (twoFactor.lockedUntil && twoFactor.lockedUntil > new Date()) {
    await logAttempt(userId, TwoFactorMethod.TOTP, false, "locked", context);
    return { valid: false, reason: "Account temporarily locked" };
  }
  
  // Decrypt the secret
  const secret = decryptSecret(twoFactor.secret);
  
  // Generate valid codes for current and adjacent time windows
  // (allows for clock skew)
  const now = Math.floor(Date.now() / 1000);
  const validCodes = [
    generateTOTP(secret, now - TOTP_PERIOD), // Previous window
    generateTOTP(secret, now),                // Current window
    generateTOTP(secret, now + TOTP_PERIOD),  // Next window
  ];
  
  const isValid = validCodes.includes(code);
  
  if (isValid) {
    // Reset failed attempts and update last used
    await prisma.twoFactorAuth.update({
      where: { userId },
      data: {
        failedAttempts: 0,
        lockedUntil: null,
        lastUsedAt: new Date(),
        verified: true, // Mark as verified if this is first successful use
        enabledAt: twoFactor.enabledAt || new Date(),
      },
    });
    
    await logAttempt(userId, TwoFactorMethod.TOTP, true, null, context);
    return { valid: true };
  } else {
    // Increment failed attempts
    const newFailedAttempts = twoFactor.failedAttempts + 1;
    const shouldLock = newFailedAttempts >= MAX_FAILED_ATTEMPTS;
    
    await prisma.twoFactorAuth.update({
      where: { userId },
      data: {
        failedAttempts: newFailedAttempts,
        lockedUntil: shouldLock 
          ? new Date(Date.now() + LOCKOUT_DURATION_MINUTES * 60 * 1000)
          : null,
      },
    });
    
    await logAttempt(userId, TwoFactorMethod.TOTP, false, "invalid_code", context);
    
    if (shouldLock) {
      return { valid: false, reason: `Too many failed attempts. Locked for ${LOCKOUT_DURATION_MINUTES} minutes.` };
    }
    
    return { valid: false, reason: "Invalid code" };
  }
}

/**
 * Verify a backup code (single-use)
 */
export async function verifyBackupCode(
  userId: string,
  code: string,
  context?: { ipAddress?: string; userAgent?: string }
): Promise<{ valid: boolean; remainingCodes?: number; reason?: string }> {
  const twoFactor = await prisma.twoFactorAuth.findUnique({
    where: { userId },
  });
  
  if (!twoFactor) {
    return { valid: false, reason: "2FA not configured" };
  }
  
  // Check each hashed backup code
  const normalizedCode = code.replace(/\s|-/g, "").toUpperCase();
  
  for (let i = 0; i < twoFactor.backupCodes.length; i++) {
    const hashedCode = twoFactor.backupCodes[i];
    if (hashedCode && await verifyHash(normalizedCode, hashedCode)) {
      // Remove the used code
      const updatedCodes = [...twoFactor.backupCodes];
      updatedCodes[i] = ""; // Mark as used
      
      await prisma.twoFactorAuth.update({
        where: { userId },
        data: {
          backupCodes: updatedCodes,
          backupCodesUsed: twoFactor.backupCodesUsed + 1,
          lastUsedAt: new Date(),
          failedAttempts: 0,
          lockedUntil: null,
        },
      });
      
      await logAttempt(userId, TwoFactorMethod.BACKUP_CODE, true, null, context);
      
      const remainingCodes = updatedCodes.filter(c => c !== "").length;
      return { valid: true, remainingCodes };
    }
  }
  
  await logAttempt(userId, TwoFactorMethod.BACKUP_CODE, false, "invalid_code", context);
  return { valid: false, reason: "Invalid backup code" };
}

/**
 * Disable 2FA for a user (requires password verification first)
 */
export async function disableTwoFactor(userId: string): Promise<void> {
  await prisma.twoFactorAuth.delete({
    where: { userId },
  });
  
  await prisma.user.update({
    where: { id: userId },
    data: {
      twoFactorEnabled: false,
      twoFactorSecret: null,
      twoFactorBackupCodes: [],
    },
  });
}

/**
 * Check if user has 2FA enabled
 */
export async function isTwoFactorEnabled(userId: string): Promise<boolean> {
  const twoFactor = await prisma.twoFactorAuth.findUnique({
    where: { userId },
    select: { verified: true },
  });
  
  return twoFactor?.verified ?? false;
}

/**
 * Regenerate backup codes (invalidates old ones)
 */
export async function regenerateBackupCodes(userId: string): Promise<string[]> {
  const backupCodes = generateBackupCodes(BACKUP_CODE_COUNT);
  const hashedBackupCodes = await hashBackupCodes(backupCodes);
  
  await prisma.twoFactorAuth.update({
    where: { userId },
    data: {
      backupCodes: hashedBackupCodes,
      backupCodesUsed: 0,
    },
  });
  
  return backupCodes;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate TOTP code for a given timestamp
 */
function generateTOTP(secret: string, timestamp: number): string {
  const counter = Math.floor(timestamp / TOTP_PERIOD);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigInt64BE(BigInt(counter));
  
  const decodedSecret = base32Decode(secret);
  const hmac = crypto.createHmac("sha1", decodedSecret);
  hmac.update(counterBuffer);
  const hash = hmac.digest();
  
  const offset = hash[hash.length - 1] & 0x0f;
  const code = (
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff)
  ) % Math.pow(10, TOTP_DIGITS);
  
  return code.toString().padStart(TOTP_DIGITS, "0");
}

/**
 * Generate random backup codes
 */
function generateBackupCodes(count: number): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    // Format: XXXX-XXXX (8 alphanumeric characters)
    const code = crypto.randomBytes(4).toString("hex").toUpperCase();
    codes.push(`${code.slice(0, 4)}-${code.slice(4)}`);
  }
  return codes;
}

/**
 * Hash backup codes for storage
 */
async function hashBackupCodes(codes: string[]): Promise<string[]> {
  const bcrypt = await import("bcrypt");
  return Promise.all(
    codes.map(code => bcrypt.hash(code.replace(/-/g, ""), 10))
  );
}

/**
 * Verify a code against a hash
 */
async function verifyHash(code: string, hash: string): Promise<boolean> {
  if (!hash) return false;
  const bcrypt = await import("bcrypt");
  return bcrypt.compare(code, hash);
}

/**
 * Encrypt secret with AES-256-GCM
 */
function encryptSecret(secret: string): string {
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(ENCRYPTION_KEY, "salt", 32);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  
  let encrypted = cipher.update(secret, "utf8", "hex");
  encrypted += cipher.final("hex");
  
  const authTag = cipher.getAuthTag();
  
  return `${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted}`;
}

/**
 * Decrypt secret
 */
function decryptSecret(encryptedData: string): string {
  const [ivHex, authTagHex, encrypted] = encryptedData.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");
  const key = crypto.scryptSync(ENCRYPTION_KEY, "salt", 32);
  
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  
  return decrypted;
}

/**
 * Base32 encoding (RFC 4648)
 */
function base32Encode(buffer: Buffer): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let result = "";
  let bits = 0;
  let value = 0;
  
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  
  if (bits > 0) {
    result += alphabet[(value << (5 - bits)) & 0x1f];
  }
  
  return result;
}

/**
 * Base32 decoding
 */
function base32Decode(encoded: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  
  for (const char of encoded.toUpperCase()) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  
  return Buffer.from(bytes);
}

/**
 * Log 2FA attempt for security monitoring
 */
async function logAttempt(
  userId: string,
  method: TwoFactorMethod,
  success: boolean,
  failReason: string | null,
  context?: { ipAddress?: string; userAgent?: string }
): Promise<void> {
  await prisma.twoFactorAttempt.create({
    data: {
      userId,
      method,
      success,
      failReason,
      ipAddress: context?.ipAddress,
      userAgent: context?.userAgent,
    },
  });
}
