import { NextRequest, NextResponse } from "next/server";
import { verifyAccessToken, TokenPayload } from "./session";
import { prisma } from "@/db/client";

export interface AuthenticatedRequest extends NextRequest {
  user: TokenPayload;
}

/**
 * Authentication middleware
 * Verifies the access token and attaches user info to the request
 */
export async function authMiddleware(
  request: NextRequest
): Promise<{ authorized: boolean; user?: TokenPayload; error?: string }> {
  const authHeader = request.headers.get("authorization");
  
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return { authorized: false, error: "Missing authorization header" };
  }
  
  const token = authHeader.substring(7);
  const payload = verifyAccessToken(token);
  
  if (!payload) {
    return { authorized: false, error: "Invalid or expired token" };
  }
  
  // Verify session still exists
  const session = await prisma.session.findUnique({
    where: { id: payload.sessionId },
  });
  
  if (!session || session.expiresAt < new Date()) {
    return { authorized: false, error: "Session expired" };
  }
  
  return { authorized: true, user: payload };
}

/**
 * Role-based authorization check
 */
export function requireRole(
  user: TokenPayload,
  allowedRoles: string[]
): boolean {
  return allowedRoles.includes(user.role);
}

/**
 * Create unauthorized response
 */
export function unauthorizedResponse(message: string): NextResponse {
  return NextResponse.json(
    { error: message },
    { status: 401 }
  );
}

/**
 * Create forbidden response
 */
export function forbiddenResponse(message: string): NextResponse {
  return NextResponse.json(
    { error: message },
    { status: 403 }
  );
}

/**
 * Rate limit check for authentication endpoints
 * Prevents brute force attacks on login
 */
const loginAttempts = new Map<string, { count: number; resetAt: number }>();

export function checkLoginRateLimit(ip: string): { allowed: boolean; retryAfter?: number } {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxAttempts = 5;
  
  const record = loginAttempts.get(ip);
  
  if (!record || record.resetAt < now) {
    loginAttempts.set(ip, { count: 1, resetAt: now + windowMs });
    return { allowed: true };
  }
  
  if (record.count >= maxAttempts) {
    const retryAfter = Math.ceil((record.resetAt - now) / 1000);
    return { allowed: false, retryAfter };
  }
  
  record.count++;
  return { allowed: true };
}

/**
 * Log authentication events for security audit
 */
export function logAuthEvent(
  event: "login" | "logout" | "token_refresh" | "failed_login",
  userId: string | null,
  ip: string,
  userAgent: string
): void {
  const logEntry = {
    timestamp: new Date().toISOString(),
    event,
    userId,
    ip,
    userAgent: userAgent.substring(0, 100), // Truncate for storage
  };
  
  // In production, send to logging service
  console.log("[AUTH_AUDIT]", JSON.stringify(logEntry));
}
