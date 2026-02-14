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
