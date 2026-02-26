/**
 * Subscription Management API
 * 
 * GET /api/subscriptions - Get current subscription details
 * POST /api/subscriptions/upgrade - Upgrade to higher plan
 * POST /api/subscriptions/downgrade - Downgrade to lower plan
 * DELETE /api/subscriptions - Cancel subscription
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { authMiddleware, unauthorizedResponse } from "@/auth/middleware";
import { prisma } from "@/db/client";
import {
  getSubscriptionSummary,
  changeSubscriptionPlan,
  previewSubscriptionChange,
  cancelSubscription,
  PRICE_IDS,
} from "@/payments/stripe";

const ChangePlanSchema = z.object({
  newPlan: z.enum(["STARTER", "PRO", "ENTERPRISE"]),
  preview: z.boolean().optional(),
});

/**
 * GET - Get current subscription details
 */
export async function GET(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const { userId } = auth.user!;

  const subscription = await prisma.subscription.findUnique({
    where: { userId },
  });

  if (!subscription) {
    return NextResponse.json({
      hasSubscription: false,
      message: "No active subscription",
    });
  }

  const summary = await getSubscriptionSummary(subscription.stripeCustomerId);

  return NextResponse.json({
    hasSubscription: true,
    subscription: {
      plan: getPlanName(subscription.stripePriceId),
      status: subscription.status,
      currentPeriodEnd: subscription.currentPeriodEnd,
      ...summary,
    },
  });
}

/**
 * PUT - Change subscription plan (upgrade or downgrade)
 */
export async function PUT(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const body = await request.json();
  const parsed = ChangePlanSchema.safeParse(body);

  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid plan. Must be STARTER, PRO, or ENTERPRISE." },
      { status: 400 }
    );
  }

  const { userId } = auth.user!;
  const { newPlan, preview } = parsed.data;

  const subscription = await prisma.subscription.findUnique({
    where: { userId },
  });

  if (!subscription) {
    return NextResponse.json(
      { error: "No active subscription to modify" },
      { status: 400 }
    );
  }

  const newPriceId = PRICE_IDS[newPlan];

  if (preview) {
    const previewResult = await previewSubscriptionChange(
      subscription.stripeCustomerId,
      subscription.stripeCustomerId,
      newPriceId
    );

    if (!previewResult) {
      return NextResponse.json(
        { error: "Failed to preview subscription change" },
        { status: 500 }
      );
    }

    return NextResponse.json({
      preview: true,
      ...previewResult,
    });
  }

  const result = await changeSubscriptionPlan(
    subscription.stripeCustomerId,
    newPriceId
  );

  if (!result.success) {
    return NextResponse.json(
      { error: result.error || "Failed to change plan" },
      { status: 500 }
    );
  }

  await prisma.subscription.update({
    where: { userId },
    data: { stripePriceId: newPriceId },
  });

  return NextResponse.json({
    success: true,
    newPlan,
    prorationAmount: result.prorationAmount,
    message: `Successfully changed to ${newPlan} plan`,
  });
}

/**
 * DELETE - Cancel subscription
 */
export async function DELETE(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const { userId } = auth.user!;
  const { searchParams } = new URL(request.url);
  const immediate = searchParams.get("immediate") === "true";

  const subscription = await prisma.subscription.findUnique({
    where: { userId },
  });

  if (!subscription) {
    return NextResponse.json(
      { error: "No active subscription to cancel" },
      { status: 400 }
    );
  }

  try {
    await cancelSubscription(subscription.stripeCustomerId, immediate);

    await prisma.subscription.update({
      where: { userId },
      data: {
        status: immediate ? "CANCELED" : "ACTIVE",
        canceledAt: immediate ? new Date() : null,
      },
    });

    return NextResponse.json({
      success: true,
      immediate,
      message: immediate
        ? "Subscription canceled immediately"
        : "Subscription will cancel at end of billing period",
    });
  } catch (error) {
    console.error("[SUBSCRIPTIONS] Cancel failed:", error);
    return NextResponse.json(
      { error: "Failed to cancel subscription" },
      { status: 500 }
    );
  }
}

function getPlanName(priceId: string): string {
  for (const [name, id] of Object.entries(PRICE_IDS)) {
    if (id === priceId) return name;
  }
  return "UNKNOWN";
}
// Trigger webhook
// v2
// v3
