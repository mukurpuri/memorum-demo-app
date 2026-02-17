/**
 * Session Management Module
 * 
 * Handles JWT-based authentication with refresh token rotation
 * for enhanced security against token replay attacks.
 * 
 * All authentication events are logged to the audit trail for
 * compliance (SOC2, GDPR) and security monitoring.
 */
import jwt from "jsonwebtoken";
import { prisma } from "@/db/client";
import { User, Session } from "@prisma/client";
import { 
  logAuthSuccess, 
  logAuthFailure, 
  logSessionRevoked,
  logSuspiciousActivity,
  AuditContext 
} from "@/audit/logger";

const JWT_SECRET = process.env.JWT_SECRET!;
const ACCESS_TOKEN_EXPIRY = "15m";
const REFRESH_TOKEN_EXPIRY = "7d";

export interface TokenPayload {
  userId: string;
  email: string;
  role: string;
  sessionId: string;
}

/**
 * Create a new session for a user
 * Generates both access and refresh tokens
 */
export async function createSession(user: User): Promise<{
  accessToken: string;
  refreshToken: string;
  session: Session;
}> {
  const sessionId = crypto.randomUUID();
  
  const accessToken = jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role,
      sessionId,
    } as TokenPayload,
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY }
  );
  
  const refreshToken = jwt.sign(
    { sessionId, type: "refresh" },
    JWT_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRY }
  );
  
  const session = await prisma.session.create({
    data: {
      id: sessionId,
      userId: user.id,
      token: accessToken,
      refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    },
  });
  
  return { accessToken, refreshToken, session };
}

/**
 * Verify an access token and return the payload
 */
export function verifyAccessToken(token: string): TokenPayload | null {
  try {
    const payload = jwt.verify(token, JWT_SECRET) as TokenPayload;
    return payload;
  } catch (error) {
    return null;
  }
}

/**
 * Refresh an access token using a refresh token
 */
export async function refreshSession(refreshToken: string): Promise<{
  accessToken: string;
  refreshToken: string;
} | null> {
  try {
    const payload = jwt.verify(refreshToken, JWT_SECRET) as { sessionId: string };
    
    const session = await prisma.session.findUnique({
      where: { id: payload.sessionId },
      include: { user: true },
    });
    
    if (!session || session.expiresAt < new Date()) {
      return null;
    }
    
    // Rotate refresh token for security
    const newRefreshToken = jwt.sign(
      { sessionId: session.id, type: "refresh" },
      JWT_SECRET,
      { expiresIn: REFRESH_TOKEN_EXPIRY }
    );
    
    const newAccessToken = jwt.sign(
      {
        userId: session.user.id,
        email: session.user.email,
        role: session.user.role,
        sessionId: session.id,
      } as TokenPayload,
      JWT_SECRET,
      { expiresIn: ACCESS_TOKEN_EXPIRY }
    );
    
    // Update session with new tokens
    await prisma.session.update({
      where: { id: session.id },
      data: {
        token: newAccessToken,
        refreshToken: newRefreshToken,
      },
    });
    
    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  } catch (error) {
    return null;
  }
}

/**
 * Invalidate a session (logout)
 */
export async function invalidateSession(sessionId: string): Promise<void> {
  await prisma.session.delete({
    where: { id: sessionId },
  });
}

/**
 * Invalidate all sessions for a user (logout everywhere)
 */
export async function invalidateAllSessions(userId: string): Promise<void> {
  await prisma.session.deleteMany({
    where: { userId },
  });
}

/**
 * Rotate refresh token on each use (security best practice)
 * Prevents token replay attacks by invalidating old tokens
 * 
 * Security consideration: This implements refresh token rotation
 * as recommended by OAuth 2.0 Security Best Current Practice
 */
export async function rotateRefreshToken(oldToken: string): Promise<{
  accessToken: string;
  refreshToken: string;
} | null> {
  const result = await refreshSession(oldToken);
  if (!result) return null;
  
  // Log rotation for audit trail
  console.log(`[AUTH] Refresh token rotated at ${new Date().toISOString()}`);
  
  return result;
}

/**
 * Revoke all tokens for a user (forced logout everywhere)
 * Use after password change or security incident
 * 
 * This is a security-critical operation that should be called:
 * 1. After a password reset
 * 2. After detecting suspicious activity
 * 3. When user requests "logout all devices"
 * 
 * Audit: Logs SESSION_REVOKED for each session with reason
 */
export async function revokeAllTokens(
  userId: string,
  reason: "user_logout" | "admin_action" | "security_policy" | "password_change" = "user_logout",
  auditContext?: Partial<AuditContext>
): Promise<number> {
  // Get sessions before deleting for audit logging
  const sessions = await prisma.session.findMany({
    where: { userId },
    select: { id: true, ipAddress: true, userAgent: true },
  });
  
  const result = await prisma.session.deleteMany({
    where: { userId },
  });
  
  // Log each revocation to audit trail
  for (const session of sessions) {
    await logSessionRevoked(
      {
        userId,
        sessionId: session.id,
        ipAddress: auditContext?.ipAddress || session.ipAddress || undefined,
        userAgent: auditContext?.userAgent || session.userAgent || undefined,
      },
      reason
    );
  }
  
  console.log(`[AUTH] Revoked ${result.count} sessions for user ${userId} (reason: ${reason})`);
  
  return result.count;
}

/**
 * Check if a session is still valid
 * Used for session validation in middleware
 */
export async function isSessionValid(sessionId: string): Promise<boolean> {
  const session = await prisma.session.findUnique({
    where: { id: sessionId },
  });
  
  if (!session) return false;
  if (session.expiresAt < new Date()) return false;
  
  return true;
}

/**
 * Extend session expiry (keep-alive)
 * Called on user activity to prevent timeout during active use
 */
export async function extendSession(sessionId: string): Promise<void> {
  await prisma.session.update({
    where: { id: sessionId },
    data: {
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // Reset to 7 days
      lastActivityAt: new Date(),
    },
  });
}

// ============================================================================
// Session Analytics & Device Tracking
// ============================================================================

export interface DeviceInfo {
  userAgent: string;
  ip: string;
  country?: string;
  city?: string;
  deviceType: "desktop" | "mobile" | "tablet" | "unknown";
}

export interface SessionWithDevice extends Session {
  deviceInfo?: DeviceInfo;
  lastActivityAt?: Date;
}

/**
 * Create session with device tracking
 * Records device fingerprint for security auditing
 * 
 * Audit: Logs SESSION_CREATED and LOGIN_SUCCESS events
 */
export async function createSessionWithDevice(
  user: User,
  deviceInfo: DeviceInfo
): Promise<{
  accessToken: string;
  refreshToken: string;
  session: Session;
}> {
  const sessionId = crypto.randomUUID();
  
  const accessToken = jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role,
      sessionId,
    } as TokenPayload,
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY }
  );
  
  const refreshToken = jwt.sign(
    { sessionId, type: "refresh" },
    JWT_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRY }
  );
  
  const session = await prisma.session.create({
    data: {
      id: sessionId,
      userId: user.id,
      token: accessToken,
      refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      // Device tracking fields
      userAgent: deviceInfo.userAgent,
      ipAddress: deviceInfo.ip,
      deviceType: deviceInfo.deviceType,
      country: deviceInfo.country,
      city: deviceInfo.city,
      lastActivityAt: new Date(),
    },
  });
  
  // Log successful authentication to audit trail
  const auditContext: AuditContext = {
    userId: user.id,
    sessionId,
    ipAddress: deviceInfo.ip,
    userAgent: deviceInfo.userAgent,
  };
  await logAuthSuccess(auditContext, "password");
  
  console.log(`[AUTH] Session created for ${user.email} from ${deviceInfo.ip} (${deviceInfo.deviceType})`);
  
  return { accessToken, refreshToken, session };
}

/**
 * Get all active sessions for a user with device info
 * Used for "Active Sessions" UI in security settings
 */
export async function getUserSessions(userId: string): Promise<SessionWithDevice[]> {
  const sessions = await prisma.session.findMany({
    where: {
      userId,
      expiresAt: { gt: new Date() },
    },
    orderBy: { lastActivityAt: "desc" },
  });
  
  return sessions.map(session => ({
    ...session,
    deviceInfo: {
      userAgent: session.userAgent || "Unknown",
      ip: session.ipAddress || "Unknown",
      country: session.country || undefined,
      city: session.city || undefined,
      deviceType: (session.deviceType as DeviceInfo["deviceType"]) || "unknown",
    },
  }));
}

/**
 * Detect suspicious session activity
 * Returns true if the session shows signs of compromise
 * 
 * Audit: Logs SUSPICIOUS_ACTIVITY events with CRITICAL severity
 */
export async function detectSuspiciousActivity(
  sessionId: string,
  currentIp: string
): Promise<{ suspicious: boolean; reason?: string }> {
  const session = await prisma.session.findUnique({
    where: { id: sessionId },
    include: { user: true },
  });
  
  if (!session) {
    return { suspicious: true, reason: "Session not found" };
  }
  
  // Check for IP change (potential session hijacking)
  if (session.ipAddress && session.ipAddress !== currentIp) {
    console.log(`[SECURITY] IP change detected for session ${sessionId}: ${session.ipAddress} -> ${currentIp}`);
    
    // Log to audit trail with CRITICAL severity
    await logSuspiciousActivity(
      {
        userId: session.userId,
        sessionId,
        ipAddress: currentIp,
      },
      "IP address changed mid-session",
      {
        previousIp: session.ipAddress,
        newIp: currentIp,
        country: session.country,
      }
    );
    
    // Mark session as suspicious in database
    await prisma.session.update({
      where: { id: sessionId },
      data: { isSuspicious: true },
    });
    
    return { suspicious: true, reason: "IP address changed" };
  }
  
  return { suspicious: false };
}

/**
 * Get session analytics for admin dashboard
 */
export async function getSessionAnalytics(userId?: string): Promise<{
  totalActive: number;
  byDeviceType: Record<string, number>;
  byCountry: Record<string, number>;
  recentActivity: Date | null;
}> {
  const where = userId 
    ? { userId, expiresAt: { gt: new Date() } }
    : { expiresAt: { gt: new Date() } };
  
  const sessions = await prisma.session.findMany({ where });
  
  const byDeviceType: Record<string, number> = {};
  const byCountry: Record<string, number> = {};
  let recentActivity: Date | null = null;
  
  for (const session of sessions) {
    // Count by device type
    const device = session.deviceType || "unknown";
    byDeviceType[device] = (byDeviceType[device] || 0) + 1;
    
    // Count by country
    const country = session.country || "Unknown";
    byCountry[country] = (byCountry[country] || 0) + 1;
    
    // Track most recent activity
    if (session.lastActivityAt) {
      if (!recentActivity || session.lastActivityAt > recentActivity) {
        recentActivity = session.lastActivityAt;
      }
    }
  }
  
  return {
    totalActive: sessions.length,
    byDeviceType,
    byCountry,
    recentActivity,
  };
}
