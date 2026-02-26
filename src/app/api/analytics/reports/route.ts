/**
 * Analytics Reports API
 * 
 * Generate and export analytics reports.
 * POST /api/analytics/reports - Generate a new report
 * GET /api/analytics/reports - List available reports
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { authMiddleware, unauthorizedResponse } from "@/auth/middleware";
import { prisma } from "@/db/client";

const GenerateReportSchema = z.object({
  type: z.enum(["revenue", "users", "engagement", "churn"]),
  startDate: z.string().datetime(),
  endDate: z.string().datetime(),
  format: z.enum(["json", "csv"]).default("json"),
  includeCharts: z.boolean().default(false),
});

export async function GET(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const { organizationId } = auth.user!;

  const reports = await prisma.report.findMany({
    where: { organizationId },
    orderBy: { createdAt: "desc" },
    take: 20,
    select: {
      id: true,
      type: true,
      status: true,
      createdAt: true,
      completedAt: true,
      downloadUrl: true,
    },
  });

  return NextResponse.json({ reports });
}

export async function POST(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const body = await request.json();
  const parsed = GenerateReportSchema.safeParse(body);

  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid report parameters", details: parsed.error.issues },
      { status: 400 }
    );
  }

  const { userId, organizationId } = auth.user!;
  const { type, startDate, endDate, format } = parsed.data;

  const report = await prisma.report.create({
    data: {
      type,
      status: "PENDING",
      organizationId: organizationId!,
      createdById: userId,
      parameters: {
        startDate,
        endDate,
        format,
      },
    },
  });

  generateReportAsync(report.id, parsed.data);

  return NextResponse.json({
    id: report.id,
    status: "PENDING",
    message: "Report generation started. Check back for download link.",
  });
}

async function generateReportAsync(
  reportId: string,
  params: z.infer<typeof GenerateReportSchema>
) {
  try {
    await prisma.report.update({
      where: { id: reportId },
      data: { status: "PROCESSING" },
    });

    const startDate = new Date(params.startDate);
    const endDate = new Date(params.endDate);

    let data: any;

    switch (params.type) {
      case "revenue":
        data = await generateRevenueReport(startDate, endDate);
        break;
      case "users":
        data = await generateUsersReport(startDate, endDate);
        break;
      case "engagement":
        data = await generateEngagementReport(startDate, endDate);
        break;
      case "churn":
        data = await generateChurnReport(startDate, endDate);
        break;
    }

    const downloadUrl = `/api/analytics/reports/${reportId}/download`;

    await prisma.report.update({
      where: { id: reportId },
      data: {
        status: "COMPLETED",
        completedAt: new Date(),
        downloadUrl,
        data,
      },
    });
  } catch (error) {
    console.error("[REPORTS] Generation failed:", error);
    await prisma.report.update({
      where: { id: reportId },
      data: {
        status: "FAILED",
        error: error instanceof Error ? error.message : "Unknown error",
      },
    });
  }
}

async function generateRevenueReport(startDate: Date, endDate: Date) {
  const transactions = await prisma.transaction.findMany({
    where: {
      createdAt: { gte: startDate, lte: endDate },
    },
    orderBy: { createdAt: "asc" },
  });

  const dailyRevenue = new Map<string, number>();
  for (const tx of transactions) {
    const day = tx.createdAt.toISOString().split("T")[0];
    dailyRevenue.set(day, (dailyRevenue.get(day) || 0) + tx.amount);
  }

  return {
    totalRevenue: transactions.reduce((sum, tx) => sum + tx.amount, 0),
    transactionCount: transactions.length,
    dailyBreakdown: Array.from(dailyRevenue.entries()).map(([date, amount]) => ({
      date,
      amount,
    })),
  };
}

async function generateUsersReport(startDate: Date, endDate: Date) {
  const users = await prisma.user.findMany({
    where: {
      createdAt: { gte: startDate, lte: endDate },
    },
    select: {
      id: true,
      createdAt: true,
      lastActiveAt: true,
      plan: true,
    },
  });

  return {
    newUsers: users.length,
    byPlan: users.reduce((acc, user) => {
      acc[user.plan || "free"] = (acc[user.plan || "free"] || 0) + 1;
      return acc;
    }, {} as Record<string, number>),
  };
}

async function generateEngagementReport(startDate: Date, endDate: Date) {
  const [sessions, pageViews] = await Promise.all([
    prisma.session.findMany({
      where: { createdAt: { gte: startDate, lte: endDate } },
      select: { duration: true, userId: true },
    }),
    prisma.pageView.count({
      where: { timestamp: { gte: startDate, lte: endDate } },
    }),
  ]);

  const uniqueUsers = new Set(sessions.map((s) => s.userId)).size;
  const avgDuration = sessions.length > 0
    ? sessions.reduce((sum, s) => sum + (s.duration || 0), 0) / sessions.length
    : 0;

  return {
    totalSessions: sessions.length,
    uniqueUsers,
    avgSessionDuration: Math.round(avgDuration),
    totalPageViews: pageViews,
  };
}

async function generateChurnReport(startDate: Date, endDate: Date) {
  const churned = await prisma.subscription.findMany({
    where: {
      canceledAt: { gte: startDate, lte: endDate },
    },
    select: {
      canceledAt: true,
      cancelReason: true,
      plan: true,
    },
  });

  const byReason = churned.reduce((acc, sub) => {
    const reason = sub.cancelReason || "unknown";
    acc[reason] = (acc[reason] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return {
    totalChurned: churned.length,
    byReason,
    byPlan: churned.reduce((acc, sub) => {
      acc[sub.plan || "unknown"] = (acc[sub.plan || "unknown"] || 0) + 1;
      return acc;
    }, {} as Record<string, number>),
  };
}
