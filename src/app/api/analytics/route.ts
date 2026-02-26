/**
 * Analytics API
 * 
 * Provides aggregated metrics and insights for the dashboard.
 * GET /api/analytics - Get analytics summary
 * GET /api/analytics?period=7d - Get analytics for specific period
 */
import { NextRequest, NextResponse } from "next/server";
import { authMiddleware, unauthorizedResponse } from "@/auth/middleware";
import { prisma } from "@/db/client";

interface AnalyticsSummary {
  period: string;
  users: {
    total: number;
    active: number;
    new: number;
    churnRate: number;
  };
  revenue: {
    total: number;
    mrr: number;
    arr: number;
    growth: number;
  };
  engagement: {
    dailyActiveUsers: number;
    weeklyActiveUsers: number;
    avgSessionDuration: number;
    pageViews: number;
  };
  topFeatures: Array<{
    name: string;
    usage: number;
    trend: "up" | "down" | "stable";
  }>;
}

const PERIODS: Record<string, number> = {
  "24h": 1,
  "7d": 7,
  "30d": 30,
  "90d": 90,
};

export async function GET(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const { searchParams } = new URL(request.url);
  const period = searchParams.get("period") || "7d";
  const days = PERIODS[period] || 7;

  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  const previousStartDate = new Date(startDate);
  previousStartDate.setDate(previousStartDate.getDate() - days);

  const [
    totalUsers,
    activeUsers,
    newUsers,
    previousNewUsers,
    subscriptions,
    previousSubscriptions,
    sessions,
    pageViews,
    featureUsage,
  ] = await Promise.all([
    prisma.user.count(),
    prisma.user.count({
      where: { lastActiveAt: { gte: startDate } },
    }),
    prisma.user.count({
      where: { createdAt: { gte: startDate } },
    }),
    prisma.user.count({
      where: {
        createdAt: { gte: previousStartDate, lt: startDate },
      },
    }),
    prisma.subscription.findMany({
      where: { status: "ACTIVE" },
      select: { amount: true },
    }),
    prisma.subscription.findMany({
      where: {
        status: "ACTIVE",
        createdAt: { lt: startDate },
      },
      select: { amount: true },
    }),
    prisma.session.findMany({
      where: { createdAt: { gte: startDate } },
      select: { duration: true },
    }),
    prisma.pageView.count({
      where: { timestamp: { gte: startDate } },
    }),
    prisma.featureUsage.groupBy({
      by: ["featureName"],
      where: { timestamp: { gte: startDate } },
      _count: { featureName: true },
      orderBy: { _count: { featureName: "desc" } },
      take: 5,
    }),
  ]);

  const currentMRR = subscriptions.reduce((sum, s) => sum + (s.amount || 0), 0);
  const previousMRR = previousSubscriptions.reduce((sum, s) => sum + (s.amount || 0), 0);
  const mrrGrowth = previousMRR > 0 ? ((currentMRR - previousMRR) / previousMRR) * 100 : 0;

  const avgSessionDuration = sessions.length > 0
    ? sessions.reduce((sum, s) => sum + (s.duration || 0), 0) / sessions.length
    : 0;

  const churnedUsers = await prisma.user.count({
    where: {
      lastActiveAt: { lt: startDate },
      createdAt: { lt: startDate },
    },
  });
  const churnRate = totalUsers > 0 ? (churnedUsers / totalUsers) * 100 : 0;

  const previousFeatureUsage = await prisma.featureUsage.groupBy({
    by: ["featureName"],
    where: {
      timestamp: { gte: previousStartDate, lt: startDate },
    },
    _count: { featureName: true },
  });

  const previousUsageMap = new Map(
    previousFeatureUsage.map((f) => [f.featureName, f._count.featureName])
  );

  const topFeatures = featureUsage.map((f) => {
    const currentCount = f._count.featureName;
    const previousCount = previousUsageMap.get(f.featureName) || 0;
    let trend: "up" | "down" | "stable" = "stable";
    if (currentCount > previousCount * 1.1) trend = "up";
    else if (currentCount < previousCount * 0.9) trend = "down";

    return {
      name: f.featureName,
      usage: currentCount,
      trend,
    };
  });

  const summary: AnalyticsSummary = {
    period,
    users: {
      total: totalUsers,
      active: activeUsers,
      new: newUsers,
      churnRate: Math.round(churnRate * 10) / 10,
    },
    revenue: {
      total: currentMRR * 12,
      mrr: currentMRR,
      arr: currentMRR * 12,
      growth: Math.round(mrrGrowth * 10) / 10,
    },
    engagement: {
      dailyActiveUsers: Math.round(activeUsers / days),
      weeklyActiveUsers: activeUsers,
      avgSessionDuration: Math.round(avgSessionDuration),
      pageViews,
    },
    topFeatures,
  };

  return NextResponse.json(summary);
}
// Analytics v2
