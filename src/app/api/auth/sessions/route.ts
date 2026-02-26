/**
 * Session Management API
 * 
 * GET /api/auth/sessions - List all active sessions
 * DELETE /api/auth/sessions/:id - Revoke a specific session
 * DELETE /api/auth/sessions - Revoke all other sessions
 */
import { NextRequest, NextResponse } from "next/server";
import { authMiddleware, unauthorizedResponse } from "@/auth/middleware";
import { prisma } from "@/db/client";

interface SessionInfo {
  id: string;
  deviceName: string;
  browser: string;
  os: string;
  ip: string;
  location: string;
  lastActive: Date;
  createdAt: Date;
  isCurrent: boolean;
}

/**
 * GET - List all active sessions for the current user
 */
export async function GET(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const { userId, sessionId: currentSessionId } = auth.user!;

  const sessions = await prisma.session.findMany({
    where: {
      userId,
      expiresAt: { gt: new Date() },
      revokedAt: null,
    },
    orderBy: { lastActiveAt: "desc" },
  });

  const sessionInfos: SessionInfo[] = sessions.map((session) => ({
    id: session.id,
    deviceName: parseDeviceName(session.userAgent),
    browser: parseBrowser(session.userAgent),
    os: parseOS(session.userAgent),
    ip: maskIp(session.ipAddress),
    location: session.location || "Unknown",
    lastActive: session.lastActiveAt,
    createdAt: session.createdAt,
    isCurrent: session.id === currentSessionId,
  }));

  return NextResponse.json({
    sessions: sessionInfos,
    total: sessionInfos.length,
  });
}

/**
 * DELETE - Revoke sessions
 * If ?all=true, revoke all sessions except current
 * If ?id=xxx, revoke specific session
 */
export async function DELETE(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const { userId, sessionId: currentSessionId } = auth.user!;
  const { searchParams } = new URL(request.url);
  const revokeAll = searchParams.get("all") === "true";
  const targetSessionId = searchParams.get("id");

  if (revokeAll) {
    const result = await prisma.session.updateMany({
      where: {
        userId,
        id: { not: currentSessionId },
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
        revokeReason: "user_revoked_all",
      },
    });

    await createSecurityEvent(userId, "sessions_revoked_all", {
      count: result.count,
    });

    return NextResponse.json({
      success: true,
      revokedCount: result.count,
      message: `Revoked ${result.count} session(s)`,
    });
  }

  if (targetSessionId) {
    if (targetSessionId === currentSessionId) {
      return NextResponse.json(
        { error: "Cannot revoke current session. Use logout instead." },
        { status: 400 }
      );
    }

    const session = await prisma.session.findFirst({
      where: {
        id: targetSessionId,
        userId,
        revokedAt: null,
      },
    });

    if (!session) {
      return NextResponse.json(
        { error: "Session not found or already revoked" },
        { status: 404 }
      );
    }

    await prisma.session.update({
      where: { id: targetSessionId },
      data: {
        revokedAt: new Date(),
        revokeReason: "user_revoked",
      },
    });

    await createSecurityEvent(userId, "session_revoked", {
      sessionId: targetSessionId,
      deviceName: parseDeviceName(session.userAgent),
    });

    return NextResponse.json({
      success: true,
      message: "Session revoked successfully",
    });
  }

  return NextResponse.json(
    { error: "Specify ?all=true or ?id=<sessionId>" },
    { status: 400 }
  );
}

async function createSecurityEvent(
  userId: string,
  type: string,
  metadata: Record<string, any>
) {
  await prisma.securityEvent.create({
    data: {
      userId,
      type,
      metadata,
      timestamp: new Date(),
    },
  });
}

function parseDeviceName(userAgent: string | null): string {
  if (!userAgent) return "Unknown Device";
  if (userAgent.includes("iPhone")) return "iPhone";
  if (userAgent.includes("iPad")) return "iPad";
  if (userAgent.includes("Android")) return "Android Device";
  if (userAgent.includes("Mac")) return "Mac";
  if (userAgent.includes("Windows")) return "Windows PC";
  if (userAgent.includes("Linux")) return "Linux";
  return "Unknown Device";
}

function parseBrowser(userAgent: string | null): string {
  if (!userAgent) return "Unknown";
  if (userAgent.includes("Chrome") && !userAgent.includes("Edg")) return "Chrome";
  if (userAgent.includes("Firefox")) return "Firefox";
  if (userAgent.includes("Safari") && !userAgent.includes("Chrome")) return "Safari";
  if (userAgent.includes("Edg")) return "Edge";
  return "Unknown";
}

function parseOS(userAgent: string | null): string {
  if (!userAgent) return "Unknown";
  if (userAgent.includes("Mac OS")) return "macOS";
  if (userAgent.includes("Windows")) return "Windows";
  if (userAgent.includes("Linux")) return "Linux";
  if (userAgent.includes("iOS")) return "iOS";
  if (userAgent.includes("Android")) return "Android";
  return "Unknown";
}

function maskIp(ip: string | null): string {
  if (!ip) return "Unknown";
  const parts = ip.split(".");
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.*.*`;
  }
  return ip.substring(0, ip.length / 2) + "***";
}
