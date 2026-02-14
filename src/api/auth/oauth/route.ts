import { NextRequest, NextResponse } from "next/server";
import { 
  OAUTH_PROVIDERS, 
  buildAuthorizationUrl, 
  generatePKCE,
  handleOAuthCallback,
  checkOAuthRateLimit,
  validateOAuthState,
  detectSuspiciousOAuthActivity,
  sanitizeOAuthParams,
} from "@/auth/oauth";

// Store PKCE verifiers and states temporarily (in production, use Redis/session)
const pkceStore = new Map<string, { verifier: string; nonce: string; createdAt: number }>();

// Security: Clean up expired entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  const maxAge = 10 * 60 * 1000; // 10 minutes
  for (const [key, value] of pkceStore.entries()) {
    if (now - value.createdAt > maxAge) {
      pkceStore.delete(key);
    }
  }
}, 5 * 60 * 1000);

/**
 * GET /api/auth/oauth?provider=google
 * Initiates OAuth flow - returns authorization URL
 * 
 * Security: Rate limited, generates cryptographic state and nonce
 */
export async function GET(request: NextRequest) {
  const ip = request.headers.get("x-forwarded-for") || "unknown";
  
  // Security: Check rate limit
  const rateCheck = checkOAuthRateLimit(ip);
  if (!rateCheck.allowed) {
    return NextResponse.json(
      { error: "Too many requests", retryAfter: rateCheck.retryAfter },
      { status: 429 }
    );
  }
  
  const { searchParams } = new URL(request.url);
  const providerName = searchParams.get("provider");
  
  if (!providerName || !OAUTH_PROVIDERS[providerName]) {
    return NextResponse.json(
      { error: "Invalid or missing provider" },
      { status: 400 }
    );
  }
  
  const provider = OAUTH_PROVIDERS[providerName];
  const state = crypto.randomUUID();
  const nonce = crypto.randomUUID(); // For OIDC
  const pkce = generatePKCE();
  
  // Store PKCE verifier and nonce for callback validation
  pkceStore.set(state, { 
    verifier: pkce.verifier, 
    nonce,
    createdAt: Date.now(),
  });
  
  const redirectUri = `${process.env.NEXT_PUBLIC_APP_URL}/api/auth/oauth/callback`;
  const authUrl = buildAuthorizationUrl(provider, redirectUri, state, pkce.challenge);
  
  console.log(`[OAuth] Initiated ${providerName} flow for IP ${ip}`);
  
  return NextResponse.json({ 
    authorizationUrl: authUrl,
    state,
  });
}

/**
 * POST /api/auth/oauth
 * Handles OAuth callback - exchanges code for tokens
 * 
 * Security: Validates state, checks for suspicious activity, rate limited
 */
export async function POST(request: NextRequest) {
  const ip = request.headers.get("x-forwarded-for") || "unknown";
  
  // Security: Check rate limit
  const rateCheck = checkOAuthRateLimit(ip);
  if (!rateCheck.allowed) {
    return NextResponse.json(
      { error: "Too many requests", retryAfter: rateCheck.retryAfter },
      { status: 429 }
    );
  }
  
  const rawBody = await request.json();
  
  // Security: Sanitize input parameters
  const body = sanitizeOAuthParams(rawBody);
  const { code, state } = body;
  const provider = rawBody.provider; // Provider name doesn't need sanitization
  
  if (!provider || !code || !state) {
    return NextResponse.json(
      { error: "Missing required parameters" },
      { status: 400 }
    );
  }
  
  // Security: Retrieve and validate PKCE verifier
  const storedData = pkceStore.get(state);
  if (!storedData) {
    console.log(`[OAuth] Invalid state from IP ${ip}`);
    return NextResponse.json(
      { error: "Invalid or expired state" },
      { status: 400 }
    );
  }
  
  // Security: Validate state parameter (CSRF protection)
  if (!validateOAuthState(state, state, ip)) {
    return NextResponse.json(
      { error: "State validation failed" },
      { status: 400 }
    );
  }
  
  // Clean up used state (one-time use)
  pkceStore.delete(state);
  
  try {
    const redirectUri = `${process.env.NEXT_PUBLIC_APP_URL}/api/auth/oauth/callback`;
    const result = await handleOAuthCallback(provider, code, redirectUri, storedData.verifier);
    
    // Security: Check for suspicious activity on this account
    const suspiciousCheck = detectSuspiciousOAuthActivity(
      result.user.email,
      ip,
      provider
    );
    
    if (suspiciousCheck.suspicious) {
      console.log(`[OAuth] Suspicious activity for ${result.user.email}: ${suspiciousCheck.reason}`);
      // Don't block, but flag for review
      // In production, send alert to security team
    }
    
    console.log(`[OAuth] Successful ${provider} login for ${result.user.email} from IP ${ip}`);
    
    return NextResponse.json({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      user: result.user,
    });
  } catch (error) {
    console.error(`[OAuth] Callback error from IP ${ip}:`, error);
    return NextResponse.json(
      { error: "OAuth authentication failed" },
      { status: 500 }
    );
  }
}
