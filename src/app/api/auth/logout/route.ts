import { NextRequest, NextResponse } from "next/server";
import { authMiddleware, unauthorizedResponse } from "@/auth/middleware";
import { invalidateSession } from "@/auth/session";

/**
 * POST /api/auth/logout
 * Invalidate the current session (logout this device).
 */
export async function POST(request: NextRequest) {
  const auth = await authMiddleware(request);

  if (!auth.authorized) {
    return NextResponse.json({ success: true }); // Idempotent: already logged out
  }

  await invalidateSession(auth.user!.sessionId);

  return NextResponse.json({ success: true });
}
