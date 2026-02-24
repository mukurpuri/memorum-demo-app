import { NextRequest, NextResponse } from "next/server";
import { authMiddleware, unauthorizedResponse } from "@/auth/middleware";
import { revokeAllTokens } from "@/auth/session";

/**
 * POST /api/auth/logout-all
 * Revoke all sessions for the current user (logout everywhere).
 */
export async function POST(request: NextRequest) {
  const auth = await authMiddleware(request);

  if (!auth.authorized) {
    return NextResponse.json({ success: true });
  }

  await revokeAllTokens(auth.user!.userId, "user_logout");

  return NextResponse.json({ success: true });
}
