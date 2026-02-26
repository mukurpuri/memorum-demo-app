/**
 * Notifications API
 * 
 * Manages user notifications across channels (in-app, email, push).
 * GET /api/notifications - List notifications
 * POST /api/notifications - Create notification
 * PATCH /api/notifications - Mark as read
 * DELETE /api/notifications - Delete notifications
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { authMiddleware, unauthorizedResponse } from "@/auth/middleware";
import { prisma } from "@/db/client";

const CreateNotificationSchema = z.object({
  type: z.enum(["info", "warning", "error", "success"]),
  title: z.string().min(1).max(100),
  message: z.string().min(1).max(500),
  channel: z.enum(["in_app", "email", "push", "all"]).default("in_app"),
  targetUserId: z.string().optional(),
  metadata: z.record(z.any()).optional(),
});

const MarkReadSchema = z.object({
  notificationIds: z.array(z.string()).min(1),
});

export async function GET(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const { userId } = auth.user!;
  const { searchParams } = new URL(request.url);
  
  const unreadOnly = searchParams.get("unread") === "true";
  const limit = Math.min(parseInt(searchParams.get("limit") || "50"), 100);
  const offset = parseInt(searchParams.get("offset") || "0");

  const where = {
    userId,
    ...(unreadOnly ? { readAt: null } : {}),
  };

  const [notifications, total, unreadCount] = await Promise.all([
    prisma.notification.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: limit,
      skip: offset,
    }),
    prisma.notification.count({ where }),
    prisma.notification.count({
      where: { userId, readAt: null },
    }),
  ]);

  return NextResponse.json({
    notifications,
    pagination: {
      total,
      limit,
      offset,
      hasMore: offset + notifications.length < total,
    },
    unreadCount,
  });
}

export async function POST(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const body = await request.json();
  const parsed = CreateNotificationSchema.safeParse(body);

  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid notification data", details: parsed.error.issues },
      { status: 400 }
    );
  }

  const { type, title, message, channel, targetUserId, metadata } = parsed.data;
  const userId = targetUserId || auth.user!.userId;

  const notification = await prisma.notification.create({
    data: {
      userId,
      type,
      title,
      message,
      channel,
      metadata: metadata || {},
    },
  });

  if (channel === "email" || channel === "all") {
    await queueEmailNotification(userId, title, message);
  }

  if (channel === "push" || channel === "all") {
    await sendPushNotification(userId, title, message);
  }

  return NextResponse.json({ notification }, { status: 201 });
}

export async function PATCH(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const body = await request.json();
  const parsed = MarkReadSchema.safeParse(body);

  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid request", details: parsed.error.issues },
      { status: 400 }
    );
  }

  const { userId } = auth.user!;
  const { notificationIds } = parsed.data;

  const result = await prisma.notification.updateMany({
    where: {
      id: { in: notificationIds },
      userId,
    },
    data: {
      readAt: new Date(),
    },
  });

  return NextResponse.json({
    marked: result.count,
    message: `Marked ${result.count} notification(s) as read`,
  });
}

export async function DELETE(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const { userId } = auth.user!;
  const { searchParams } = new URL(request.url);
  
  const notificationId = searchParams.get("id");
  const deleteAll = searchParams.get("all") === "true";
  const deleteRead = searchParams.get("read") === "true";

  if (deleteAll) {
    const result = await prisma.notification.deleteMany({
      where: { userId },
    });
    return NextResponse.json({
      deleted: result.count,
      message: "All notifications deleted",
    });
  }

  if (deleteRead) {
    const result = await prisma.notification.deleteMany({
      where: { userId, readAt: { not: null } },
    });
    return NextResponse.json({
      deleted: result.count,
      message: "Read notifications deleted",
    });
  }

  if (notificationId) {
    await prisma.notification.delete({
      where: { id: notificationId, userId },
    });
    return NextResponse.json({ deleted: 1, message: "Notification deleted" });
  }

  return NextResponse.json(
    { error: "Specify ?id=xxx, ?all=true, or ?read=true" },
    { status: 400 }
  );
}

async function queueEmailNotification(
  userId: string,
  title: string,
  message: string
) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { email: true, emailNotifications: true },
  });

  if (!user?.emailNotifications) return;

  await prisma.emailQueue.create({
    data: {
      to: user.email,
      subject: title,
      body: message,
      status: "PENDING",
    },
  });
}

async function sendPushNotification(
  userId: string,
  title: string,
  message: string
) {
  const tokens = await prisma.pushToken.findMany({
    where: { userId, active: true },
  });

  for (const token of tokens) {
    await prisma.pushQueue.create({
      data: {
        token: token.token,
        title,
        body: message,
        status: "PENDING",
      },
    });
  }
}
// v2
