/**
 * AI Usage Analytics API
 * 
 * Provides usage statistics, cost tracking, and billing insights
 * for AI assistant usage across the organization.
 * 
 * GET /api/ai/usage - Get usage summary and breakdown
 * GET /api/ai/usage/export - Export usage data as CSV
 */
import { NextRequest, NextResponse } from "next/server";
import { authMiddleware, unauthorizedResponse, requireRole } from "@/auth/middleware";
import { prisma } from "@/db/client";

export async function GET(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const roleCheck = requireRole(auth, ["admin", "owner", "billing"]);
  if (!roleCheck.authorized) {
    return NextResponse.json(
      { error: "Insufficient permissions to view usage data" },
      { status: 403 }
    );
  }

  const { organizationId } = auth.user!;
  const { searchParams } = new URL(request.url);
  const period = searchParams.get("period") || "30d";
  const groupBy = searchParams.get("groupBy") || "day";

  const startDate = getStartDate(period);

  // Overall usage summary
  const summary = await prisma.aiUsage.aggregate({
    where: {
      organizationId,
      createdAt: { gte: startDate },
    },
    _sum: { tokensUsed: true, cost: true },
    _count: true,
  });

  // Usage by model
  const byModel = await prisma.aiUsage.groupBy({
    by: ["model"],
    where: {
      organizationId,
      createdAt: { gte: startDate },
    },
    _sum: { tokensUsed: true, cost: true },
    _count: true,
  });

  // Usage by assistant
  const byAssistant = await prisma.$queryRaw`
    SELECT 
      au."assistantId",
      aa.name as "assistantName",
      SUM(au."tokensUsed") as "totalTokens",
      SUM(au.cost) as "totalCost",
      COUNT(*) as "requestCount"
    FROM "AiUsage" au
    JOIN "AiAssistant" aa ON aa.id = au."assistantId"
    WHERE au."organizationId" = ${organizationId}
      AND au."createdAt" >= ${startDate}
    GROUP BY au."assistantId", aa.name
    ORDER BY "totalCost" DESC
    LIMIT 10
  `;

  // Top users
  const topUsers = await prisma.$queryRaw`
    SELECT 
      au."userId",
      u.name as "userName",
      u.email as "userEmail",
      SUM(au."tokensUsed") as "totalTokens",
      SUM(au.cost) as "totalCost",
      COUNT(*) as "requestCount"
    FROM "AiUsage" au
    JOIN "User" u ON u.id = au."userId"
    WHERE au."organizationId" = ${organizationId}
      AND au."createdAt" >= ${startDate}
    GROUP BY au."userId", u.name, u.email
    ORDER BY "totalCost" DESC
    LIMIT 10
  `;

  // Daily trend
  const dailyTrend = await getDailyTrend(organizationId!, startDate);

  // Billing projection
  const projection = calculateProjection(summary, period);

  // Cost alerts
  const alerts = await checkCostAlerts(organizationId!, summary._sum.cost || 0);

  return NextResponse.json({
    period,
    summary: {
      totalTokens: summary._sum.tokensUsed || 0,
      totalCost: summary._sum.cost || 0,
      totalRequests: summary._count || 0,
    },
    breakdown: {
      byModel,
      byAssistant,
      topUsers,
    },
    trend: dailyTrend,
    projection,
    alerts,
  });
}

function getStartDate(period: string): Date {
  const now = new Date();
  switch (period) {
    case "7d": return new Date(now.setDate(now.getDate() - 7));
    case "30d": return new Date(now.setDate(now.getDate() - 30));
    case "90d": return new Date(now.setDate(now.getDate() - 90));
    case "1y": return new Date(now.setFullYear(now.getFullYear() - 1));
    default: return new Date(now.setDate(now.getDate() - 30));
  }
}

async function getDailyTrend(organizationId: string, startDate: Date) {
  return prisma.$queryRaw`
    SELECT 
      DATE("createdAt") as date,
      SUM("tokensUsed") as tokens,
      SUM(cost) as cost,
      COUNT(*) as requests
    FROM "AiUsage"
    WHERE "organizationId" = ${organizationId}
      AND "createdAt" >= ${startDate}
    GROUP BY DATE("createdAt")
    ORDER BY date ASC
  `;
}

function calculateProjection(
  summary: any,
  period: string
): { monthlyEstimate: number; yearlyEstimate: number } {
  const days = period === "7d" ? 7 : period === "30d" ? 30 : period === "90d" ? 90 : 365;
  const dailyAverage = (summary._sum.cost || 0) / days;
  
  return {
    monthlyEstimate: dailyAverage * 30,
    yearlyEstimate: dailyAverage * 365,
  };
}

async function checkCostAlerts(
  organizationId: string,
  currentCost: number
): Promise<Array<{ type: string; message: string; severity: "warning" | "critical" }>> {
  const org = await prisma.organization.findUnique({
    where: { id: organizationId },
    select: { 
      costLimit: true,
      warningThreshold: true,
    },
  });

  const alerts: Array<{ type: string; message: string; severity: "warning" | "critical" }> = [];

  if (org?.costLimit) {
    const usagePercent = (currentCost / org.costLimit) * 100;
    
    if (usagePercent >= 100) {
      alerts.push({
        type: "COST_LIMIT_EXCEEDED",
        message: `Monthly cost limit ($${org.costLimit}) exceeded`,
        severity: "critical",
      });
    } else if (usagePercent >= (org.warningThreshold || 80)) {
      alerts.push({
        type: "COST_WARNING",
        message: `Approaching cost limit: ${usagePercent.toFixed(1)}% used`,
        severity: "warning",
      });
    }
  }

  return alerts;
}
