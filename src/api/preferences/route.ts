import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/db/client";
import { authMiddleware, unauthorizedResponse } from "@/auth/middleware";
import { z } from "zod";

const UpdatePreferencesSchema = z.object({
  theme: z.enum(["LIGHT", "DARK", "SYSTEM"]).optional(),
  language: z.string().min(2).max(10).optional(),
  timezone: z.string().optional(),
  dateFormat: z.string().optional(),
  emailNotifications: z.boolean().optional(),
  pushNotifications: z.boolean().optional(),
  weeklyDigest: z.boolean().optional(),
  marketingEmails: z.boolean().optional(),
  compactMode: z.boolean().optional(),
  showTutorials: z.boolean().optional(),
  keyboardShortcuts: z.boolean().optional(),
  profileVisibility: z.enum(["PUBLIC", "TEAM", "PRIVATE"]).optional(),
  activityVisibility: z.enum(["PUBLIC", "TEAM", "PRIVATE"]).optional(),
});

/**
 * GET /api/preferences
 * Get current user's preferences
 */
export async function GET(request: NextRequest) {
  const auth = await authMiddleware(request);
  
  if (!auth.authorized) {
    return unauthorizedResponse(auth.error!);
  }
  
  let preferences = await prisma.userPreferences.findUnique({
    where: { userId: auth.user!.userId },
  });
  
  // Create default preferences if not exists
  if (!preferences) {
    preferences = await prisma.userPreferences.create({
      data: { userId: auth.user!.userId },
    });
  }
  
  return NextResponse.json({ preferences });
}

/**
 * PATCH /api/preferences
 * Update current user's preferences
 */
export async function PATCH(request: NextRequest) {
  const auth = await authMiddleware(request);
  
  if (!auth.authorized) {
    return unauthorizedResponse(auth.error!);
  }
  
  const body = await request.json();
  const parsed = UpdatePreferencesSchema.safeParse(body);
  
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid request", details: parsed.error.errors },
      { status: 400 }
    );
  }
  
  const preferences = await prisma.userPreferences.upsert({
    where: { userId: auth.user!.userId },
    create: {
      userId: auth.user!.userId,
      ...parsed.data,
    },
    update: parsed.data,
  });
  
  return NextResponse.json({ preferences });
}

/**
 * DELETE /api/preferences
 * Reset preferences to defaults
 */
export async function DELETE(request: NextRequest) {
  const auth = await authMiddleware(request);
  
  if (!auth.authorized) {
    return unauthorizedResponse(auth.error!);
  }
  
  await prisma.userPreferences.delete({
    where: { userId: auth.user!.userId },
  });
  
  // Recreate with defaults
  const preferences = await prisma.userPreferences.create({
    data: { userId: auth.user!.userId },
  });
  
  return NextResponse.json({ 
    message: "Preferences reset to defaults",
    preferences,
  });
}
