import { NextRequest, NextResponse } from "next/server";
import { authMiddleware, unauthorizedResponse } from "@/auth/middleware";
import { getUserSessions } from "@/auth/session";

/**
 * GET /api/sessions
 * List active sessions for the current user (device info, last activity).
 * Used by the dashboard Active Sessions UI.
 */
export async function GET(request: NextRequest) {
  const auth = await authMiddleware(request);

  if (!auth.authorized) {
    return unauthorizedResponse(auth.error!);
  }

  const sessions = await getUserSessions(auth.user!.userId);

  return NextResponse.json({ sessions });
}
