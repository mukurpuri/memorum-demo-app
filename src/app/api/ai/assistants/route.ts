/**
 * AI Assistants Configuration API
 * 
 * Manages AI assistant configurations for the platform.
 * Each organization can have multiple AI assistants with different
 * personalities, capabilities, and access permissions.
 * 
 * GET /api/ai/assistants - List all assistants
 * POST /api/ai/assistants - Create new assistant
 * PATCH /api/ai/assistants/:id - Update assistant config
 * DELETE /api/ai/assistants/:id - Delete assistant
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { authMiddleware, unauthorizedResponse } from "@/auth/middleware";
import { prisma } from "@/db/client";

const AssistantConfigSchema = z.object({
  name: z.string().min(1).max(50),
  description: z.string().max(500).optional(),
  model: z.enum(["gpt-4o", "gpt-4o-mini", "claude-3-opus", "claude-3-sonnet"]),
  temperature: z.number().min(0).max(2).default(0.7),
  maxTokens: z.number().min(100).max(8000).default(2000),
  systemPrompt: z.string().max(4000),
  capabilities: z.object({
    codeGeneration: z.boolean().default(false),
    dataAnalysis: z.boolean().default(false),
    webSearch: z.boolean().default(false),
    fileAccess: z.boolean().default(false),
    apiCalls: z.boolean().default(false),
  }),
  permissions: z.object({
    allowedUsers: z.array(z.string()).optional(),
    allowedRoles: z.array(z.string()).optional(),
    rateLimit: z.number().min(1).max(1000).default(100),
    costLimit: z.number().min(0).optional(),
  }),
  metadata: z.record(z.any()).optional(),
});

export async function GET(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const { organizationId } = auth.user!;

  const assistants = await prisma.aiAssistant.findMany({
    where: { organizationId },
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      name: true,
      description: true,
      model: true,
      capabilities: true,
      isActive: true,
      usageCount: true,
      lastUsedAt: true,
      createdAt: true,
    },
  });

  const usage = await prisma.aiUsage.aggregate({
    where: { organizationId },
    _sum: { tokensUsed: true, cost: true },
  });

  return NextResponse.json({
    assistants,
    totalAssistants: assistants.length,
    usage: {
      totalTokens: usage._sum.tokensUsed || 0,
      totalCost: usage._sum.cost || 0,
    },
  });
}

export async function POST(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const body = await request.json();
  const parsed = AssistantConfigSchema.safeParse(body);

  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid assistant configuration", details: parsed.error.issues },
      { status: 400 }
    );
  }

  const { organizationId, userId } = auth.user!;
  const config = parsed.data;

  // Check organization limits
  const existingCount = await prisma.aiAssistant.count({
    where: { organizationId },
  });

  const orgLimits = await getOrganizationLimits(organizationId!);
  if (existingCount >= orgLimits.maxAssistants) {
    return NextResponse.json(
      { error: `Assistant limit reached (${orgLimits.maxAssistants})` },
      { status: 403 }
    );
  }

  // Validate model access
  const hasModelAccess = await checkModelAccess(organizationId!, config.model);
  if (!hasModelAccess) {
    return NextResponse.json(
      { error: `Model ${config.model} not available on your plan` },
      { status: 403 }
    );
  }

  const assistant = await prisma.aiAssistant.create({
    data: {
      organizationId: organizationId!,
      createdById: userId,
      name: config.name,
      description: config.description,
      model: config.model,
      temperature: config.temperature,
      maxTokens: config.maxTokens,
      systemPrompt: config.systemPrompt,
      capabilities: config.capabilities,
      permissions: config.permissions,
      metadata: config.metadata || {},
      isActive: true,
    },
  });

  await createAuditLog(organizationId!, userId, "assistant.created", {
    assistantId: assistant.id,
    name: config.name,
    model: config.model,
  });

  return NextResponse.json({ assistant }, { status: 201 });
}

async function getOrganizationLimits(organizationId: string) {
  const org = await prisma.organization.findUnique({
    where: { id: organizationId },
    select: { plan: true },
  });

  const limits: Record<string, { maxAssistants: number; allowedModels: string[] }> = {
    FREE: { maxAssistants: 1, allowedModels: ["gpt-4o-mini"] },
    STARTER: { maxAssistants: 3, allowedModels: ["gpt-4o-mini", "claude-3-sonnet"] },
    PRO: { maxAssistants: 10, allowedModels: ["gpt-4o-mini", "gpt-4o", "claude-3-sonnet"] },
    ENTERPRISE: { maxAssistants: 100, allowedModels: ["gpt-4o-mini", "gpt-4o", "claude-3-opus", "claude-3-sonnet"] },
  };

  return limits[org?.plan || "FREE"] || limits.FREE;
}

async function checkModelAccess(organizationId: string, model: string): Promise<boolean> {
  const limits = await getOrganizationLimits(organizationId);
  return limits.allowedModels.includes(model);
}

async function createAuditLog(
  organizationId: string,
  userId: string,
  action: string,
  metadata: Record<string, any>
) {
  await prisma.auditLog.create({
    data: {
      organizationId,
      userId,
      action,
      metadata,
      timestamp: new Date(),
    },
  });
}
