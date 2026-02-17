/**
 * Audit Logging Service
 * 
 * Centralized audit logging for security-sensitive actions.
 * All authentication, authorization, and data access events are logged
 * for compliance (SOC2, GDPR) and incident investigation.
 * 
 * Design decisions:
 * - Fire-and-forget: Audit logs should not block the main operation
 * - Structured data: All logs follow a consistent schema for queryability
 * - Severity levels: INFO, WARNING, CRITICAL for filtering and alerting
 * - IP/UserAgent capture: Essential for security forensics
 */

import { prisma } from "@/db/client";
import { AuditAction, AuditSeverity } from "@prisma/client";

export interface AuditContext {
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface AuditLogParams {
  action: AuditAction;
  resource: string;
  resourceId?: string;
  details?: Record<string, unknown>;
  severity?: AuditSeverity;
  success?: boolean;
  errorCode?: string;
  errorMessage?: string;
}

/**
 * Log an audit event
 * 
 * This is designed to be non-blocking - failures are logged but don't
 * throw exceptions that would interrupt the main operation.
 */
export async function logAuditEvent(
  context: AuditContext,
  params: AuditLogParams
): Promise<void> {
  try {
    await prisma.auditLog.create({
      data: {
        userId: context.userId,
        sessionId: context.sessionId,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        action: params.action,
        resource: params.resource,
        resourceId: params.resourceId,
        details: params.details,
        severity: params.severity ?? AuditSeverity.INFO,
        success: params.success ?? true,
        errorCode: params.errorCode,
        errorMessage: params.errorMessage,
      },
    });
  } catch (error) {
    // Audit logging should never break the main flow
    // Log to console/external service for monitoring
    console.error("[AUDIT] Failed to write audit log:", error);
  }
}

/**
 * Log a successful authentication event
 */
export async function logAuthSuccess(
  context: AuditContext,
  method: "password" | "oauth" | "refresh"
): Promise<void> {
  await logAuditEvent(context, {
    action: AuditAction.LOGIN_SUCCESS,
    resource: "session",
    resourceId: context.sessionId,
    details: { method },
    severity: AuditSeverity.INFO,
  });
}

/**
 * Log a failed authentication attempt
 */
export async function logAuthFailure(
  context: AuditContext,
  reason: string,
  email?: string
): Promise<void> {
  await logAuditEvent(context, {
    action: AuditAction.LOGIN_FAILED,
    resource: "session",
    details: { reason, email: email ? maskEmail(email) : undefined },
    severity: AuditSeverity.WARNING,
    success: false,
    errorMessage: reason,
  });
}

/**
 * Log session revocation (logout)
 */
export async function logSessionRevoked(
  context: AuditContext,
  reason: "user_logout" | "admin_action" | "security_policy" | "password_change"
): Promise<void> {
  await logAuditEvent(context, {
    action: AuditAction.SESSION_REVOKED,
    resource: "session",
    resourceId: context.sessionId,
    details: { reason },
    severity: reason === "security_policy" ? AuditSeverity.WARNING : AuditSeverity.INFO,
  });
}

/**
 * Log suspicious activity detection
 */
export async function logSuspiciousActivity(
  context: AuditContext,
  reason: string,
  details?: Record<string, unknown>
): Promise<void> {
  await logAuditEvent(context, {
    action: AuditAction.SUSPICIOUS_ACTIVITY,
    resource: "session",
    resourceId: context.sessionId,
    details: { reason, ...details },
    severity: AuditSeverity.CRITICAL,
  });
}

/**
 * Log permission denied events
 */
export async function logPermissionDenied(
  context: AuditContext,
  resource: string,
  requiredPermission: string
): Promise<void> {
  await logAuditEvent(context, {
    action: AuditAction.PERMISSION_DENIED,
    resource,
    details: { requiredPermission },
    severity: AuditSeverity.WARNING,
    success: false,
  });
}

/**
 * Log password change events
 */
export async function logPasswordChanged(
  context: AuditContext,
  userId: string
): Promise<void> {
  await logAuditEvent(context, {
    action: AuditAction.PASSWORD_CHANGED,
    resource: "user",
    resourceId: userId,
    severity: AuditSeverity.INFO,
  });
}

/**
 * Log data export events (GDPR compliance)
 */
export async function logDataExport(
  context: AuditContext,
  dataTypes: string[]
): Promise<void> {
  await logAuditEvent(context, {
    action: AuditAction.DATA_EXPORTED,
    resource: "user",
    resourceId: context.userId,
    details: { dataTypes },
    severity: AuditSeverity.INFO,
  });
}

/**
 * Log data deletion events (GDPR compliance)
 */
export async function logDataDeleted(
  context: AuditContext,
  resource: string,
  resourceId: string
): Promise<void> {
  await logAuditEvent(context, {
    action: AuditAction.DATA_DELETED,
    resource,
    resourceId,
    severity: AuditSeverity.WARNING,
  });
}

// ============================================================================
// Query Functions
// ============================================================================

export interface AuditQueryParams {
  userId?: string;
  action?: AuditAction;
  resource?: string;
  severity?: AuditSeverity;
  startDate?: Date;
  endDate?: Date;
  limit?: number;
  offset?: number;
}

/**
 * Query audit logs with filters
 * Used for admin dashboard and incident investigation
 */
export async function queryAuditLogs(params: AuditQueryParams) {
  const {
    userId,
    action,
    resource,
    severity,
    startDate,
    endDate,
    limit = 50,
    offset = 0,
  } = params;

  const where: Record<string, unknown> = {};

  if (userId) where.userId = userId;
  if (action) where.action = action;
  if (resource) where.resource = resource;
  if (severity) where.severity = severity;

  if (startDate || endDate) {
    where.createdAt = {};
    if (startDate) (where.createdAt as Record<string, Date>).gte = startDate;
    if (endDate) (where.createdAt as Record<string, Date>).lte = endDate;
  }

  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: limit,
      skip: offset,
    }),
    prisma.auditLog.count({ where }),
  ]);

  return { logs, total, limit, offset };
}

/**
 * Get security-critical events for a user
 * Used for security notifications and account review
 */
export async function getSecurityEvents(
  userId: string,
  days: number = 30
): Promise<{
  loginFailures: number;
  suspiciousActivity: number;
  sessionsRevoked: number;
  recentEvents: Awaited<ReturnType<typeof prisma.auditLog.findMany>>;
}> {
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  const [loginFailures, suspiciousActivity, sessionsRevoked, recentEvents] =
    await Promise.all([
      prisma.auditLog.count({
        where: {
          userId,
          action: AuditAction.LOGIN_FAILED,
          createdAt: { gte: since },
        },
      }),
      prisma.auditLog.count({
        where: {
          userId,
          action: AuditAction.SUSPICIOUS_ACTIVITY,
          createdAt: { gte: since },
        },
      }),
      prisma.auditLog.count({
        where: {
          userId,
          action: AuditAction.SESSION_REVOKED,
          createdAt: { gte: since },
        },
      }),
      prisma.auditLog.findMany({
        where: {
          userId,
          severity: { in: [AuditSeverity.WARNING, AuditSeverity.CRITICAL] },
          createdAt: { gte: since },
        },
        orderBy: { createdAt: "desc" },
        take: 10,
      }),
    ]);

  return { loginFailures, suspiciousActivity, sessionsRevoked, recentEvents };
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Mask email for privacy in logs
 * "user@example.com" -> "u***@example.com"
 */
function maskEmail(email: string): string {
  const [local, domain] = email.split("@");
  if (!domain) return "***";
  const masked = local[0] + "***";
  return `${masked}@${domain}`;
}

/**
 * Retention policy: Delete old audit logs
 * Should be called by a scheduled job
 * 
 * Default retention: 90 days for INFO, 365 days for WARNING/CRITICAL
 */
export async function cleanupOldLogs(): Promise<{
  infoDeleted: number;
  criticalDeleted: number;
}> {
  const infoRetention = 90; // days
  const criticalRetention = 365; // days

  const infoThreshold = new Date(Date.now() - infoRetention * 24 * 60 * 60 * 1000);
  const criticalThreshold = new Date(Date.now() - criticalRetention * 24 * 60 * 60 * 1000);

  const [infoResult, criticalResult] = await Promise.all([
    prisma.auditLog.deleteMany({
      where: {
        severity: AuditSeverity.INFO,
        createdAt: { lt: infoThreshold },
      },
    }),
    prisma.auditLog.deleteMany({
      where: {
        severity: { in: [AuditSeverity.WARNING, AuditSeverity.CRITICAL] },
        createdAt: { lt: criticalThreshold },
      },
    }),
  ]);

  console.log(
    `[AUDIT] Cleanup complete: ${infoResult.count} INFO logs, ${criticalResult.count} WARNING/CRITICAL logs deleted`
  );

  return {
    infoDeleted: infoResult.count,
    criticalDeleted: criticalResult.count,
  };
}
