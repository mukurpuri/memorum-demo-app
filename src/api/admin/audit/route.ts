/**
 * Audit Logs API
 * 
 * Admin-only endpoint for querying audit logs.
 * Used for security monitoring, compliance reporting, and incident investigation.
 * 
 * Security: Requires ADMIN or SUPER_ADMIN role
 */

import { NextRequest, NextResponse } from "next/server";
import { verifyAccessToken } from "@/auth/session";
import { queryAuditLogs, getSecurityEvents, AuditQueryParams } from "@/audit/logger";
import { AuditAction, AuditSeverity } from "@prisma/client";
import { logPermissionDenied } from "@/audit/logger";

/**
 * GET /api/admin/audit
 * 
 * Query audit logs with filters
 * 
 * Query params:
 * - userId: Filter by user
 * - action: Filter by action type
 * - resource: Filter by resource type
 * - severity: Filter by severity level
 * - startDate: ISO date string
 * - endDate: ISO date string
 * - limit: Number of results (default 50, max 200)
 * - offset: Pagination offset
 */
export async function GET(request: NextRequest) {
  // Verify authentication
  const authHeader = request.headers.get("authorization");
  const token = authHeader?.replace("Bearer ", "");
  
  if (!token) {
    return NextResponse.json(
      { error: "Unauthorized" },
      { status: 401 }
    );
  }
  
  const payload = verifyAccessToken(token);
  if (!payload) {
    return NextResponse.json(
      { error: "Invalid token" },
      { status: 401 }
    );
  }
  
  // Check admin permission
  if (payload.role !== "ADMIN" && payload.role !== "SUPER_ADMIN") {
    // Log the permission denial
    await logPermissionDenied(
      {
        userId: payload.userId,
        sessionId: payload.sessionId,
        ipAddress: request.headers.get("x-forwarded-for") || undefined,
        userAgent: request.headers.get("user-agent") || undefined,
      },
      "audit_logs",
      "ADMIN"
    );
    
    return NextResponse.json(
      { error: "Forbidden: Admin access required" },
      { status: 403 }
    );
  }
  
  // Parse query parameters
  /**
   * Query params:
   * - userId: Filter by user
   * - action: Filter by action type
   * - resource: Filter by resource type
   * - severity: Filter by severity level
   * - startDate: ISO date string
   * - endDate: ISO date string
   * - limit: Number of results (default 50, max 200)
   * - offset: Pagination offset
   */
  const searchParams = request.nextUrl.searchParams;
  
  const params: AuditQueryParams = {
    userId: searchParams.get("userId") || undefined,
    action: searchParams.get("action") as AuditAction | undefined,
    resource: searchParams.get("resource") || undefined,
    severity: searchParams.get("severity") as AuditSeverity | undefined,
    startDate: searchParams.get("startDate") 
      ? new Date(searchParams.get("startDate")!) 
      : undefined,
    endDate: searchParams.get("endDate") 
      ? new Date(searchParams.get("endDate")!) 
      : undefined,
    limit: Math.min(parseInt(searchParams.get("limit") || "50"), 200),
    offset: parseInt(searchParams.get("offset") || "0"),
  };
  
  try {
    const result = await queryAuditLogs(params);
    
    return NextResponse.json({
      success: true,
      data: result.logs,
      pagination: {
        total: result.total,
        limit: result.limit,
        offset: result.offset,
        hasMore: result.offset + result.logs.length < result.total,
      },
    });
  } catch (error) {
    console.error("[AUDIT API] Query failed:", error);
    return NextResponse.json(
      { error: "Failed to query audit logs" },
      { status: 500 }
    );
  }
}

/**
 * GET /api/admin/audit/user/:userId/security
 * 
 * Get security summary for a specific user
 * Used for account review and security notifications
 */
export async function POST(request: NextRequest) {
  // Verify authentication
  const authHeader = request.headers.get("authorization");
  const token = authHeader?.replace("Bearer ", "");
  
  if (!token) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  
  const payload = verifyAccessToken(token);
  if (!payload) {
    return NextResponse.json({ error: "Invalid token" }, { status: 401 });
  }
  
  // Check admin permission
  if (payload.role !== "ADMIN" && payload.role !== "SUPER_ADMIN") {
    return NextResponse.json(
      { error: "Forbidden: Admin access required" },
      { status: 403 }
    );
  }
  
  /**
   * Body:
   * - userId: User ID to get security events for
   * - days: Number of days to get security events for (default 30)
   */
  try {
    const body = await request.json();
    const { userId, days = 30 } = body;
    
    if (!userId) {
      return NextResponse.json(
        { error: "userId is required" },
        { status: 400 }
      );
    }
    
    const securityEvents = await getSecurityEvents(userId, days);
    
    return NextResponse.json({
      success: true,
      data: securityEvents,
    });
  } catch (error) {
    console.error("[AUDIT API] Security events query failed:", error);
    return NextResponse.json(
      { error: "Failed to query security events" },
      { status: 500 }
    );
  }
}
