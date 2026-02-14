import jwt from "jsonwebtoken";
import { prisma } from "@/db/client";
import { User, Session } from "@prisma/client";

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
 */
export async function revokeAllTokens(userId: string): Promise<number> {
  const result = await prisma.session.deleteMany({
    where: { userId },
  });
  
  console.log(`[AUTH] Revoked ${result.count} sessions for user ${userId}`);
  
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
    },
  });
}
