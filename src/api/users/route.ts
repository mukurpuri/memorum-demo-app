import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/db/client";
import { authMiddleware, requireRole, unauthorizedResponse, forbiddenResponse } from "@/auth/middleware";
import { getUserSessions, invalidateSession, getSessionAnalytics } from "@/auth/session";
import { z } from "zod";

const UpdateUserSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  email: z.string().email().optional(),
});

const BulkActionSchema = z.object({
  userIds: z.array(z.string()).min(1).max(100),
  action: z.enum(["suspend", "activate", "delete", "revoke_sessions"]),
});

/**
 * GET /api/users
 * List all users (admin only)
 * Includes session analytics for each user
 */
export async function GET(request: NextRequest) {
  const auth = await authMiddleware(request);
  
  if (!auth.authorized) {
    return unauthorizedResponse(auth.error!);
  }
  
  if (!requireRole(auth.user!, ["ADMIN", "SUPER_ADMIN"])) {
    return forbiddenResponse("Admin access required");
  }

  const { searchParams } = new URL(request.url);
  const includeAnalytics = searchParams.get("includeAnalytics") === "true";
  
  const users = await prisma.user.findMany({
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      createdAt: true,
      _count: {
        select: { sessions: true },
      },
    },
    orderBy: { createdAt: "desc" },
  });

  // Optionally include session analytics for each user
  if (includeAnalytics) {
    const usersWithAnalytics = await Promise.all(
      users.map(async (user) => {
        const analytics = await getSessionAnalytics(user.id);
        return {
          ...user,
          sessionAnalytics: analytics,
        };
      })
    );
    return NextResponse.json({ users: usersWithAnalytics });
  }
  
  return NextResponse.json({ users });
}

/**
 * PATCH /api/users
 * Update current user profile
 */
export async function PATCH(request: NextRequest) {
  const auth = await authMiddleware(request);
  
  if (!auth.authorized) {
    return unauthorizedResponse(auth.error!);
  }
  
  const body = await request.json();
  const parsed = UpdateUserSchema.safeParse(body);
  
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid request", details: parsed.error.errors },
      { status: 400 }
    );
  }
  
  const updated = await prisma.user.update({
    where: { id: auth.user!.userId },
    data: parsed.data,
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
    },
  });
  
  return NextResponse.json({ user: updated });
}

/**
 * POST /api/users
 * Bulk user actions (admin only)
 * Supports: suspend, activate, delete, revoke_sessions
 */
export async function POST(request: NextRequest) {
  const auth = await authMiddleware(request);
  
  if (!auth.authorized) {
    return unauthorizedResponse(auth.error!);
  }
  
  if (!requireRole(auth.user!, ["SUPER_ADMIN"])) {
    return forbiddenResponse("Super admin access required for bulk actions");
  }

  const body = await request.json();
  const parsed = BulkActionSchema.safeParse(body);
  
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid request", details: parsed.error.errors },
      { status: 400 }
    );
  }

  const { userIds, action } = parsed.data;
  const results: { userId: string; success: boolean; error?: string }[] = [];

  for (const userId of userIds) {
    try {
      switch (action) {
        case "suspend":
          await prisma.user.update({
            where: { id: userId },
            data: { role: "USER" }, // Downgrade to basic user
          });
          // Revoke all sessions on suspend
          await prisma.session.deleteMany({ where: { userId } });
          results.push({ userId, success: true });
          break;

        case "activate":
          await prisma.user.update({
            where: { id: userId },
            data: { role: "USER" },
          });
          results.push({ userId, success: true });
          break;

        case "delete":
          await prisma.user.delete({ where: { id: userId } });
          results.push({ userId, success: true });
          break;

        case "revoke_sessions":
          const deleted = await prisma.session.deleteMany({ where: { userId } });
          console.log(`[ADMIN] Revoked ${deleted.count} sessions for user ${userId}`);
          results.push({ userId, success: true });
          break;
      }
    } catch (error) {
      results.push({ 
        userId, 
        success: false, 
        error: error instanceof Error ? error.message : "Unknown error" 
      });
    }
  }

  const successful = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;

  console.log(`[ADMIN] Bulk ${action}: ${successful} successful, ${failed} failed`);

  return NextResponse.json({
    action,
    results,
    summary: { total: userIds.length, successful, failed },
  });
}

/**
 * DELETE /api/users
 * Revoke specific session for current user
 * Used in "Active Sessions" UI
 */
export async function DELETE(request: NextRequest) {
  const auth = await authMiddleware(request);
  
  if (!auth.authorized) {
    return unauthorizedResponse(auth.error!);
  }

  const { searchParams } = new URL(request.url);
  const sessionId = searchParams.get("sessionId");

  if (!sessionId) {
    return NextResponse.json({ error: "Session ID required" }, { status: 400 });
  }

  // Verify the session belongs to the current user
  const session = await prisma.session.findUnique({
    where: { id: sessionId },
  });

  if (!session || session.userId !== auth.user!.userId) {
    return NextResponse.json({ error: "Session not found" }, { status: 404 });
  }

  // Don't allow revoking current session via this endpoint
  if (session.id === auth.user!.sessionId) {
    return NextResponse.json(
      { error: "Cannot revoke current session. Use logout instead." },
      { status: 400 }
    );
  }

  await invalidateSession(sessionId);

  return NextResponse.json({ 
    success: true, 
    message: "Session revoked successfully" 
  });
}
