import { NextRequest, NextResponse } from "next/server";
import { 
  OAUTH_PROVIDERS, 
  buildAuthorizationUrl, 
  generatePKCE,
  handleOAuthCallback 
} from "@/auth/oauth";

// Store PKCE verifiers temporarily (in production, use Redis/session)
const pkceStore = new Map<string, string>();

/**
 * GET /api/auth/oauth?provider=google
 * Initiates OAuth flow - returns authorization URL
 */
export async function GET(request: NextRequest) {
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
  const pkce = generatePKCE();
  
  // Store PKCE verifier for callback
  pkceStore.set(state, pkce.verifier);
  
  // Clean up old entries (simple cleanup)
  setTimeout(() => pkceStore.delete(state), 10 * 60 * 1000); // 10 minutes
  
  const redirectUri = `${process.env.NEXT_PUBLIC_APP_URL}/api/auth/oauth/callback`;
  const authUrl = buildAuthorizationUrl(provider, redirectUri, state, pkce.challenge);
  
  return NextResponse.json({ 
    authorizationUrl: authUrl,
    state,
  });
}

/**
 * POST /api/auth/oauth
 * Handles OAuth callback - exchanges code for tokens
 */
export async function POST(request: NextRequest) {
  const body = await request.json();
  const { provider, code, state } = body;
  
  if (!provider || !code || !state) {
    return NextResponse.json(
      { error: "Missing required parameters" },
      { status: 400 }
    );
  }
  
  // Retrieve PKCE verifier
  const codeVerifier = pkceStore.get(state);
  if (!codeVerifier) {
    return NextResponse.json(
      { error: "Invalid or expired state" },
      { status: 400 }
    );
  }
  
  // Clean up used state
  pkceStore.delete(state);
  
  try {
    const redirectUri = `${process.env.NEXT_PUBLIC_APP_URL}/api/auth/oauth/callback`;
    const result = await handleOAuthCallback(provider, code, redirectUri, codeVerifier);
    
    return NextResponse.json({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      user: result.user,
    });
  } catch (error) {
    console.error("OAuth callback error:", error);
    return NextResponse.json(
      { error: "OAuth authentication failed" },
      { status: 500 }
    );
  }
}
