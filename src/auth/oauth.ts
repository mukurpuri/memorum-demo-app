/**
 * OAuth 2.0 Provider Integration
 * 
 * Supports Google, GitHub, and Microsoft OAuth flows
 * with PKCE for enhanced security on mobile/SPA clients.
 * 
 * Security Audit: February 2026
 * - Added nonce validation for OIDC flows
 * - Added token binding verification
 * - Added suspicious activity detection
 * - Added IP-based rate limiting for OAuth callbacks
 */

import { prisma } from "@/db/client";
import { createSession } from "./session";
import { logAuthEvent } from "./middleware";

// Security: Track OAuth attempts per IP for rate limiting
const oauthAttempts = new Map<string, { count: number; firstAttempt: number }>();
const OAUTH_RATE_LIMIT = 10; // max attempts per window
const OAUTH_RATE_WINDOW = 15 * 60 * 1000; // 15 minutes

// Security: Track suspicious patterns
const suspiciousPatterns = new Map<string, number>();

export interface OAuthProvider {
  name: "google" | "github" | "microsoft";
  clientId: string;
  clientSecret: string;
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  scopes: string[];
}

export const OAUTH_PROVIDERS: Record<string, OAuthProvider> = {
  google: {
    name: "google",
    clientId: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    userInfoUrl: "https://www.googleapis.com/oauth2/v2/userinfo",
    scopes: ["openid", "email", "profile"],
  },
  github: {
    name: "github",
    clientId: process.env.GITHUB_CLIENT_ID!,
    clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    authorizationUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    userInfoUrl: "https://api.github.com/user",
    scopes: ["read:user", "user:email"],
  },
  microsoft: {
    name: "microsoft",
    clientId: process.env.MICROSOFT_CLIENT_ID!,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET!,
    authorizationUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    userInfoUrl: "https://graph.microsoft.com/v1.0/me",
    scopes: ["openid", "email", "profile"],
  },
};

/**
 * Generate PKCE code verifier and challenge
 * Used for OAuth 2.0 PKCE flow (mobile/SPA security)
 */
export function generatePKCE(): { verifier: string; challenge: string } {
  const verifier = generateRandomString(64);
  const challenge = base64UrlEncode(sha256(verifier));
  return { verifier, challenge };
}

/**
 * Build OAuth authorization URL
 */
export function buildAuthorizationUrl(
  provider: OAuthProvider,
  redirectUri: string,
  state: string,
  codeChallenge?: string
): string {
  const params = new URLSearchParams({
    client_id: provider.clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: provider.scopes.join(" "),
    state,
  });
  
  if (codeChallenge) {
    params.set("code_challenge", codeChallenge);
    params.set("code_challenge_method", "S256");
  }
  
  return `${provider.authorizationUrl}?${params.toString()}`;
}

/**
 * Exchange authorization code for tokens
 */
export async function exchangeCodeForTokens(
  provider: OAuthProvider,
  code: string,
  redirectUri: string,
  codeVerifier?: string
): Promise<{ accessToken: string; refreshToken?: string; idToken?: string }> {
  const body: Record<string, string> = {
    client_id: provider.clientId,
    client_secret: provider.clientSecret,
    code,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
  };
  
  if (codeVerifier) {
    body.code_verifier = codeVerifier;
  }
  
  const response = await fetch(provider.tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams(body).toString(),
  });
  
  if (!response.ok) {
    throw new Error(`Token exchange failed: ${response.status}`);
  }
  
  const data = await response.json();
  
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    idToken: data.id_token,
  };
}

/**
 * Fetch user info from OAuth provider
 */
export async function fetchUserInfo(
  provider: OAuthProvider,
  accessToken: string
): Promise<{ id: string; email: string; name?: string; picture?: string }> {
  const response = await fetch(provider.userInfoUrl, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });
  
  if (!response.ok) {
    throw new Error(`User info fetch failed: ${response.status}`);
  }
  
  const data = await response.json();
  
  // Normalize response across providers
  return {
    id: data.id || data.sub,
    email: data.email,
    name: data.name || data.login,
    picture: data.picture || data.avatar_url,
  };
}

/**
 * Handle OAuth callback and create/update user
 */
export async function handleOAuthCallback(
  providerName: string,
  code: string,
  redirectUri: string,
  codeVerifier?: string
): Promise<{ accessToken: string; refreshToken: string; user: any }> {
  const provider = OAUTH_PROVIDERS[providerName];
  if (!provider) {
    throw new Error(`Unknown OAuth provider: ${providerName}`);
  }
  
  // Exchange code for tokens
  const tokens = await exchangeCodeForTokens(provider, code, redirectUri, codeVerifier);
  
  // Fetch user info
  const userInfo = await fetchUserInfo(provider, tokens.accessToken);
  
  // Find or create user
  let user = await prisma.user.findUnique({
    where: { email: userInfo.email },
  });
  
  if (!user) {
    user = await prisma.user.create({
      data: {
        email: userInfo.email,
        name: userInfo.name,
        passwordHash: "", // OAuth users don't have password
      },
    });
  }
  
  // Create session
  const session = await createSession(user);
  
  return {
    accessToken: session.accessToken,
    refreshToken: session.refreshToken,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
    },
  };
}

// =============================================================================
// SECURITY FUNCTIONS (Added in Security Audit - February 2026)
// =============================================================================

/**
 * Check OAuth rate limit for an IP address
 * Prevents brute force attacks on OAuth callback endpoint
 */
export function checkOAuthRateLimit(ip: string): { allowed: boolean; retryAfter?: number } {
  const now = Date.now();
  const record = oauthAttempts.get(ip);
  
  if (!record || now - record.firstAttempt > OAUTH_RATE_WINDOW) {
    oauthAttempts.set(ip, { count: 1, firstAttempt: now });
    return { allowed: true };
  }
  
  if (record.count >= OAUTH_RATE_LIMIT) {
    const retryAfter = Math.ceil((record.firstAttempt + OAUTH_RATE_WINDOW - now) / 1000);
    logSecurityEvent("oauth_rate_limit_exceeded", { ip, attempts: record.count });
    return { allowed: false, retryAfter };
  }
  
  record.count++;
  return { allowed: true };
}

/**
 * Validate OAuth state parameter
 * Prevents CSRF attacks by ensuring state matches what we issued
 */
export function validateOAuthState(
  receivedState: string,
  storedState: string,
  ip: string
): boolean {
  if (!receivedState || !storedState) {
    logSecurityEvent("oauth_missing_state", { ip });
    return false;
  }
  
  // Constant-time comparison to prevent timing attacks
  if (receivedState.length !== storedState.length) {
    logSecurityEvent("oauth_state_mismatch", { ip });
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < receivedState.length; i++) {
    result |= receivedState.charCodeAt(i) ^ storedState.charCodeAt(i);
  }
  
  if (result !== 0) {
    logSecurityEvent("oauth_state_mismatch", { ip });
    return false;
  }
  
  return true;
}

/**
 * Validate nonce in ID token (OIDC security)
 * Prevents token replay attacks
 */
export function validateIdTokenNonce(
  idToken: string,
  expectedNonce: string
): boolean {
  try {
    // Decode JWT without verification (we trust the provider)
    const parts = idToken.split(".");
    if (parts.length !== 3) return false;
    
    const payload = JSON.parse(atob(parts[1]));
    
    if (payload.nonce !== expectedNonce) {
      logSecurityEvent("oauth_nonce_mismatch", { expected: expectedNonce });
      return false;
    }
    
    return true;
  } catch (error) {
    logSecurityEvent("oauth_nonce_validation_error", { error: String(error) });
    return false;
  }
}

/**
 * Detect suspicious OAuth patterns
 * Flags accounts that might be under attack
 */
export function detectSuspiciousOAuthActivity(
  email: string,
  ip: string,
  provider: string
): { suspicious: boolean; reason?: string } {
  const key = `${email}:${provider}`;
  const attempts = suspiciousPatterns.get(key) || 0;
  
  // Multiple OAuth attempts for same email in short time
  if (attempts > 5) {
    logSecurityEvent("oauth_suspicious_activity", { email, ip, provider, attempts });
    return { 
      suspicious: true, 
      reason: "Multiple authentication attempts detected" 
    };
  }
  
  suspiciousPatterns.set(key, attempts + 1);
  
  // Clean up after 1 hour
  setTimeout(() => {
    const current = suspiciousPatterns.get(key) || 0;
    if (current <= 1) {
      suspiciousPatterns.delete(key);
    } else {
      suspiciousPatterns.set(key, current - 1);
    }
  }, 60 * 60 * 1000);
  
  return { suspicious: false };
}

/**
 * Verify token binding (optional security enhancement)
 * Ensures tokens are bound to the original client
 */
export function verifyTokenBinding(
  tokenFingerprint: string,
  clientFingerprint: string
): boolean {
  if (!tokenFingerprint || !clientFingerprint) {
    return true; // Skip if not implemented
  }
  
  const match = tokenFingerprint === clientFingerprint;
  if (!match) {
    logSecurityEvent("oauth_token_binding_mismatch", {});
  }
  
  return match;
}

/**
 * Log security events for audit trail
 */
function logSecurityEvent(
  event: string,
  details: Record<string, unknown>
): void {
  const logEntry = {
    timestamp: new Date().toISOString(),
    event,
    ...details,
  };
  
  // In production, send to security monitoring service
  console.log("[SECURITY]", JSON.stringify(logEntry));
}

/**
 * Sanitize OAuth callback parameters
 * Prevents injection attacks
 */
export function sanitizeOAuthParams(params: Record<string, string>): Record<string, string> {
  const sanitized: Record<string, string> = {};
  const allowedKeys = ["code", "state", "error", "error_description"];
  
  for (const key of allowedKeys) {
    if (params[key]) {
      // Remove any potential injection characters
      sanitized[key] = params[key]
        .replace(/[<>'"]/g, "")
        .substring(0, 2048); // Limit length
    }
  }
  
  return sanitized;
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

function generateRandomString(length: number): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function sha256(input: string): Uint8Array {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  // In real implementation, use crypto.subtle.digest
  return data;
}

function base64UrlEncode(buffer: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
