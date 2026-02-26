/**
 * Notification Preferences API
 * 
 * Manages user notification preferences and settings.
 * GET /api/notifications/preferences - Get preferences
 * PUT /api/notifications/preferences - Update preferences
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { authMiddleware, unauthorizedResponse } from "@/auth/middleware";
import { prisma } from "@/db/client";

const PreferencesSchema = z.object({
  emailEnabled: z.boolean().optional(),
  pushEnabled: z.boolean().optional(),
  inAppEnabled: z.boolean().optional(),
  digestFrequency: z.enum(["realtime", "hourly", "daily", "weekly"]).optional(),
  quietHoursStart: z.string().regex(/^\d{2}:\d{2}$/).optional(),
  quietHoursEnd: z.string().regex(/^\d{2}:\d{2}$/).optional(),
  categories: z.object({
    security: z.boolean().optional(),
    billing: z.boolean().optional(),
    updates: z.boolean().optional(),
    marketing: z.boolean().optional(),
    team: z.boolean().optional(),
  }).optional(),
});

export async function GET(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const { userId } = auth.user!;

  let preferences = await prisma.notificationPreferences.findUnique({
    where: { userId },
  });

  if (!preferences) {
    preferences = await prisma.notificationPreferences.create({
      data: {
        userId,
        emailEnabled: true,
        pushEnabled: true,
        inAppEnabled: true,
        digestFrequency: "realtime",
        categories: {
          security: true,
          billing: true,
          updates: true,
          marketing: false,
          team: true,
        },
      },
    });
  }

  return NextResponse.json({ preferences });
}

export async function PUT(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const body = await request.json();
  const parsed = PreferencesSchema.safeParse(body);

  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid preferences", details: parsed.error.issues },
      { status: 400 }
    );
  }

  const { userId } = auth.user!;
  const updates = parsed.data;

  const existing = await prisma.notificationPreferences.findUnique({
    where: { userId },
  });

  let categories = existing?.categories as Record<string, boolean> || {};
  if (updates.categories) {
    categories = { ...categories, ...updates.categories };
  }

  const preferences = await prisma.notificationPreferences.upsert({
    where: { userId },
    update: {
      ...updates,
      categories,
    },
    create: {
      userId,
      emailEnabled: updates.emailEnabled ?? true,
      pushEnabled: updates.pushEnabled ?? true,
      inAppEnabled: updates.inAppEnabled ?? true,
      digestFrequency: updates.digestFrequency ?? "realtime",
      quietHoursStart: updates.quietHoursStart,
      quietHoursEnd: updates.quietHoursEnd,
      categories,
    },
  });

  return NextResponse.json({
    preferences,
    message: "Preferences updated successfully",
  });
}
