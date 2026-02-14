/**
 * Security Utilities Module
 * 
 * Centralized security functions for the authentication system.
 * Created as part of the February 2026 security audit.
 */

/**
 * Security configuration constants
 */
export const SECURITY_CONFIG = {
  // Rate limiting
  MAX_LOGIN_ATTEMPTS: 5,
  LOGIN_LOCKOUT_DURATION: 15 * 60 * 1000, // 15 minutes
  
  // Token settings
  ACCESS_TOKEN_EXPIRY: 15 * 60, // 15 minutes in seconds
  REFRESH_TOKEN_EXPIRY: 7 * 24 * 60 * 60, // 7 days in seconds
  
  // Password requirements
  MIN_PASSWORD_LENGTH: 8,
  REQUIRE_UPPERCASE: true,
  REQUIRE_LOWERCASE: true,
  REQUIRE_NUMBER: true,
  REQUIRE_SPECIAL: true,
  
  // Session settings
  MAX_SESSIONS_PER_USER: 10,
  SESSION_IDLE_TIMEOUT: 30 * 60 * 1000, // 30 minutes
  
  // OAuth settings
  OAUTH_STATE_EXPIRY: 10 * 60 * 1000, // 10 minutes
  OAUTH_RATE_LIMIT: 10, // max attempts per window
  OAUTH_RATE_WINDOW: 15 * 60 * 1000, // 15 minutes
};

/**
 * Security event types for audit logging
 */
export type SecurityEventType =
  | "login_success"
  | "login_failure"
  | "logout"
  | "password_change"
  | "password_reset_request"
  | "password_reset_complete"
  | "session_created"
  | "session_revoked"
  | "session_expired"
  | "token_refresh"
  | "token_revoked"
  | "oauth_initiated"
  | "oauth_success"
  | "oauth_failure"
  | "rate_limit_exceeded"
  | "suspicious_activity"
  | "account_locked"
  | "account_unlocked";

/**
 * Security event payload
 */
export interface SecurityEvent {
  type: SecurityEventType;
  timestamp: Date;
  userId?: string;
  ip: string;
  userAgent: string;
  details?: Record<string, unknown>;
}

/**
 * Log a security event for audit trail
 * In production, this should send to a SIEM or security monitoring service
 */
export function logSecurityEvent(event: SecurityEvent): void {
  const logEntry = {
    ...event,
    timestamp: event.timestamp.toISOString(),
    environment: process.env.NODE_ENV,
  };
  
  // Console log for now - in production, send to security service
  console.log("[SECURITY_AUDIT]", JSON.stringify(logEntry));
  
  // TODO: Send to security monitoring service (Datadog, Splunk, etc.)
  // TODO: Trigger alerts for critical events
}

/**
 * Check if an IP address is in the blocklist
 */
const ipBlocklist = new Set<string>();

export function isIpBlocked(ip: string): boolean {
  return ipBlocklist.has(ip);
}

export function blockIp(ip: string, duration: number): void {
  ipBlocklist.add(ip);
  setTimeout(() => ipBlocklist.delete(ip), duration);
  
  logSecurityEvent({
    type: "suspicious_activity",
    timestamp: new Date(),
    ip,
    userAgent: "system",
    details: { action: "ip_blocked", duration },
  });
}

/**
 * Validate that a request comes from a trusted origin
 */
export function validateOrigin(origin: string | null): boolean {
  if (!origin) return false;
  
  const trustedOrigins = [
    process.env.NEXT_PUBLIC_APP_URL,
    "https://acme-saas-platform.com",
    "https://www.acme-saas-platform.com",
  ].filter(Boolean);
  
  return trustedOrigins.some(trusted => origin.startsWith(trusted!));
}

/**
 * Generate a cryptographically secure random token
 */
export function generateSecureToken(length: number = 32): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Compute a fingerprint for device/session binding
 */
export function computeClientFingerprint(
  userAgent: string,
  ip: string,
  acceptLanguage: string
): string {
  const data = `${userAgent}|${ip}|${acceptLanguage}`;
  // Simple hash for demo - use proper crypto in production
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    const char = data.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(36);
}

/**
 * Check for common attack patterns in input
 */
export function detectInjectionAttempt(input: string): boolean {
  const patterns = [
    /<script/i,
    /javascript:/i,
    /on\w+=/i,
    /union\s+select/i,
    /;\s*drop\s+table/i,
    /'\s*or\s+'1'\s*=\s*'1/i,
  ];
  
  return patterns.some(pattern => pattern.test(input));
}
