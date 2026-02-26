/**
 * AI Chat API
 * 
 * Handles conversations with configured AI assistants.
 * Includes rate limiting, usage tracking, and audit logging.
 * 
 * POST /api/ai/chat - Send message to assistant
 * GET /api/ai/chat/history - Get conversation history
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { authMiddleware, unauthorizedResponse } from "@/auth/middleware";
import { prisma } from "@/db/client";

const ChatRequestSchema = z.object({
  assistantId: z.string(),
  message: z.string().min(1).max(10000),
  conversationId: z.string().optional(),
  context: z.object({
    files: z.array(z.string()).optional(),
    codeSnippets: z.array(z.string()).optional(),
    urls: z.array(z.string()).optional(),
  }).optional(),
});

export async function POST(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const body = await request.json();
  const parsed = ChatRequestSchema.safeParse(body);

  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid chat request", details: parsed.error.issues },
      { status: 400 }
    );
  }

  const { userId, organizationId } = auth.user!;
  const { assistantId, message, conversationId, context } = parsed.data;

  // Load assistant configuration
  const assistant = await prisma.aiAssistant.findFirst({
    where: {
      id: assistantId,
      organizationId,
      isActive: true,
    },
  });

  if (!assistant) {
    return NextResponse.json(
      { error: "Assistant not found or inactive" },
      { status: 404 }
    );
  }

  // Check rate limits
  const rateLimitCheck = await checkRateLimit(userId, assistant);
  if (!rateLimitCheck.allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded", retryAfter: rateLimitCheck.retryAfter },
      { status: 429 }
    );
  }

  // Check user permissions
  const permissions = assistant.permissions as any;
  if (permissions.allowedUsers && !permissions.allowedUsers.includes(userId)) {
    return NextResponse.json(
      { error: "You don't have access to this assistant" },
      { status: 403 }
    );
  }

  // Get or create conversation
  let conversation;
  if (conversationId) {
    conversation = await prisma.aiConversation.findFirst({
      where: { id: conversationId, userId },
    });
  }

  if (!conversation) {
    conversation = await prisma.aiConversation.create({
      data: {
        userId,
        assistantId,
        organizationId: organizationId!,
        title: message.substring(0, 50) + (message.length > 50 ? "..." : ""),
      },
    });
  }

  // Load conversation history for context
  const history = await prisma.aiMessage.findMany({
    where: { conversationId: conversation.id },
    orderBy: { createdAt: "asc" },
    take: 20,
  });

  // Call AI provider
  const startTime = Date.now();
  const response = await callAIProvider(assistant, message, history, context);
  const latencyMs = Date.now() - startTime;

  // Save messages
  await prisma.aiMessage.createMany({
    data: [
      {
        conversationId: conversation.id,
        role: "user",
        content: message,
        metadata: context || {},
      },
      {
        conversationId: conversation.id,
        role: "assistant",
        content: response.content,
        tokensUsed: response.tokensUsed,
        metadata: { model: assistant.model, latencyMs },
      },
    ],
  });

  // Track usage
  await prisma.aiUsage.create({
    data: {
      organizationId: organizationId!,
      userId,
      assistantId,
      tokensUsed: response.tokensUsed,
      cost: calculateCost(assistant.model, response.tokensUsed),
      model: assistant.model,
    },
  });

  // Update assistant stats
  await prisma.aiAssistant.update({
    where: { id: assistantId },
    data: {
      usageCount: { increment: 1 },
      lastUsedAt: new Date(),
    },
  });

  return NextResponse.json({
    conversationId: conversation.id,
    message: {
      role: "assistant",
      content: response.content,
    },
    usage: {
      tokensUsed: response.tokensUsed,
      latencyMs,
    },
  });
}

async function checkRateLimit(
  userId: string,
  assistant: any
): Promise<{ allowed: boolean; retryAfter?: number }> {
  const permissions = assistant.permissions as any;
  const limit = permissions.rateLimit || 100;

  const windowStart = new Date(Date.now() - 60 * 60 * 1000); // 1 hour
  const recentUsage = await prisma.aiUsage.count({
    where: {
      userId,
      assistantId: assistant.id,
      createdAt: { gte: windowStart },
    },
  });

  if (recentUsage >= limit) {
    return { allowed: false, retryAfter: 3600 };
  }

  return { allowed: true };
}

async function callAIProvider(
  assistant: any,
  message: string,
  history: any[],
  context?: any
): Promise<{ content: string; tokensUsed: number }> {
  // This would integrate with OpenAI/Anthropic APIs
  // Simplified for demo
  const messages = [
    { role: "system", content: assistant.systemPrompt },
    ...history.map((m) => ({ role: m.role, content: m.content })),
    { role: "user", content: message },
  ];

  // Simulated response for demo
  return {
    content: `[AI Response from ${assistant.model}] Processing your request...`,
    tokensUsed: Math.floor(Math.random() * 500) + 100,
  };
}

function calculateCost(model: string, tokens: number): number {
  const rates: Record<string, number> = {
    "gpt-4o": 0.00003,
    "gpt-4o-mini": 0.000001,
    "claude-3-opus": 0.00006,
    "claude-3-sonnet": 0.00001,
  };
  return (rates[model] || 0.00001) * tokens;
}
