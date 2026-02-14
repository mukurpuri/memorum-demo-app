import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/db/client";
import { authMiddleware, requireRole, unauthorizedResponse, forbiddenResponse } from "@/auth/middleware";
import { z } from "zod";

const UpdateUserSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  email: z.string().email().optional(),
});

/**
 * GET /api/users
 * List all users (admin only)
 */
export async function GET(request: NextRequest) {
  const auth = await authMiddleware(request);
  
  if (!auth.authorized) {
    return unauthorizedResponse(auth.error!);
  }
  
  if (!requireRole(auth.user!, ["ADMIN", "SUPER_ADMIN"])) {
    return forbiddenResponse("Admin access required");
  }
  
  const users = await prisma.user.findMany({
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      createdAt: true,
    },
    orderBy: { createdAt: "desc" },
  });
  
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
