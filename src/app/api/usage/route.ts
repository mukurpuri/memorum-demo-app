/**
 * Usage Tracking API
 * 
 * Tracks API usage for metered billing and analytics.
 * GET /api/usage - Get usage summary for current billing period
 * GET /api/usage/history - Get usage history across billing periods
 */
import { NextRequest, NextResponse } from "next/server";
import { authMiddleware, unauthorizedResponse } from "@/auth/middleware";
import { prisma } from "@/db/client";
import { addInvoiceItem } from "@/payments/stripe";

interface UsageSummary {
  periodStart: Date;
  periodEnd: Date;
  apiCalls: number;
  dataTransferMB: number;
  storageUsedMB: number;
  activeUsers: number;
  limits: {
    apiCalls: number;
    dataTransferMB: number;
    storageUsedMB: number;
  };
  percentUsed: {
    apiCalls: number;
    dataTransfer: number;
    storage: number;
  };
}

/**
 * GET - Get usage summary for current billing period
 */
export async function GET(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const { userId, organizationId } = auth.user!;
  const { searchParams } = new URL(request.url);
  const historyMode = searchParams.get("history") === "true";

  if (historyMode) {
    return getUsageHistory(organizationId || userId);
  }

  return getCurrentUsage(organizationId || userId);
}

async function getCurrentUsage(entityId: string): Promise<NextResponse> {
  const now = new Date();
  const periodStart = new Date(now.getFullYear(), now.getMonth(), 1);
  const periodEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0);

  const usageRecords = await prisma.usageRecord.findMany({
    where: {
      entityId,
      timestamp: {
        gte: periodStart,
        lte: periodEnd,
      },
    },
  });

  const aggregated = aggregateUsage(usageRecords);
  const limits = await getEntityLimits(entityId);

  const summary: UsageSummary = {
    periodStart,
    periodEnd,
    ...aggregated,
    limits,
    percentUsed: {
      apiCalls: Math.round((aggregated.apiCalls / limits.apiCalls) * 100),
      dataTransfer: Math.round(
        (aggregated.dataTransferMB / limits.dataTransferMB) * 100
      ),
      storage: Math.round(
        (aggregated.storageUsedMB / limits.storageUsedMB) * 100
      ),
    },
  };

  if (summary.percentUsed.apiCalls > 80) {
    await checkAndNotifyUsageThreshold(entityId, "apiCalls", summary.percentUsed.apiCalls);
  }

  return NextResponse.json(summary);
}

async function getUsageHistory(entityId: string): Promise<NextResponse> {
  const sixMonthsAgo = new Date();
  sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

  const history = await prisma.usageRecord.groupBy({
    by: ["billingPeriod"],
    where: {
      entityId,
      timestamp: { gte: sixMonthsAgo },
    },
    _sum: {
      apiCalls: true,
      dataTransferBytes: true,
    },
    orderBy: {
      billingPeriod: "desc",
    },
  });

  return NextResponse.json({
    history: history.map((h) => ({
      period: h.billingPeriod,
      apiCalls: h._sum.apiCalls || 0,
      dataTransferMB: Math.round((h._sum.dataTransferBytes || 0) / 1024 / 1024),
    })),
  });
}

function aggregateUsage(records: any[]) {
  let apiCalls = 0;
  let dataTransferBytes = 0;
  let storageBytes = 0;
  const activeUserIds = new Set<string>();

  for (const record of records) {
    apiCalls += record.apiCalls || 0;
    dataTransferBytes += record.dataTransferBytes || 0;
    storageBytes = Math.max(storageBytes, record.storageBytes || 0);
    if (record.userId) activeUserIds.add(record.userId);
  }

  return {
    apiCalls,
    dataTransferMB: Math.round(dataTransferBytes / 1024 / 1024),
    storageUsedMB: Math.round(storageBytes / 1024 / 1024),
    activeUsers: activeUserIds.size,
  };
}

async function getEntityLimits(entityId: string) {
  const subscription = await prisma.subscription.findFirst({
    where: {
      OR: [{ userId: entityId }, { organizationId: entityId }],
    },
  });

  if (!subscription) {
    return { apiCalls: 1000, dataTransferMB: 100, storageUsedMB: 500 };
  }

  const planLimits: Record<string, { apiCalls: number; dataTransferMB: number; storageUsedMB: number }> = {
    STARTER: { apiCalls: 10000, dataTransferMB: 1000, storageUsedMB: 5000 },
    PRO: { apiCalls: 100000, dataTransferMB: 10000, storageUsedMB: 50000 },
    ENTERPRISE: { apiCalls: 1000000, dataTransferMB: 100000, storageUsedMB: 500000 },
  };

  return planLimits[subscription.plan] || planLimits.STARTER;
}

async function checkAndNotifyUsageThreshold(
  entityId: string,
  metric: string,
  percentUsed: number
) {
  const thresholdKey = `usage_alert_${metric}_${percentUsed >= 100 ? "exceeded" : "80"}`;
  
  const existing = await prisma.notification.findFirst({
    where: {
      entityId,
      type: thresholdKey,
      createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
    },
  });

  if (existing) return;

  await prisma.notification.create({
    data: {
      entityId,
      type: thresholdKey,
      message:
        percentUsed >= 100
          ? `Your ${metric} usage has exceeded your plan limit`
          : `Your ${metric} usage is at ${percentUsed}% of your plan limit`,
      read: false,
    },
  });
}
