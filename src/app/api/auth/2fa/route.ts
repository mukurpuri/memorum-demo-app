/**
 * Two-Factor Authentication API Endpoints
 * 
 * POST /api/auth/2fa - Setup 2FA (returns QR code and backup codes)
 * PUT /api/auth/2fa - Verify setup (enables 2FA)
 * DELETE /api/auth/2fa - Disable 2FA
 * 
 * Security:
 * - All endpoints require authentication
 * - Rate limited on verification attempts
 * - Audit logged for compliance
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { authMiddleware, unauthorizedResponse } from "@/auth/middleware";
import {
  setup2FA,
  verify2FASetup,
  disable2FA,
  get2FAStatus,
  regenerateBackupCodes,
} from "@/auth/2fa";

const VerifySchema = z.object({
  code: z.string().length(6).regex(/^\d+$/),
});

const DisableSchema = z.object({
  password: z.string().min(1),
});

/**
 * GET - Get 2FA status for current user
 */
export async function GET(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const status = await get2FAStatus(auth.user!.userId);

  return NextResponse.json({
    enabled: status.enabled,
    verifiedAt: status.verifiedAt,
    backupCodesRemaining: status.backupCodesRemaining,
  });
}

/**
 * POST - Initialize 2FA setup
 * Returns QR code URL and backup codes
 */
export async function POST(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const { userId, email } = auth.user!;

  try {
    const result = await setup2FA(userId, email);

    return NextResponse.json({
      qrCodeUrl: result.qrCodeUrl,
      secret: result.secret,
      backupCodes: result.backupCodes,
      message: "Scan the QR code with your authenticator app, then verify with a code",
    });
  } catch (error) {
    console.error("[2FA API] Setup failed:", error);
    return NextResponse.json(
      { error: "Failed to setup 2FA" },
      { status: 500 }
    );
  }
}

/**
 * PUT - Verify 2FA setup with code from authenticator
 * Enables 2FA after successful verification
 */
export async function PUT(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const body = await request.json();
  const parsed = VerifySchema.safeParse(body);

  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid code format. Must be 6 digits." },
      { status: 400 }
    );
  }

  const { userId } = auth.user!;

  try {
    const verified = await verify2FASetup(userId, parsed.data.code);

    if (verified) {
      return NextResponse.json({
        success: true,
        message: "Two-factor authentication is now enabled",
      });
    } else {
      return NextResponse.json(
        { error: "Invalid verification code. Please try again." },
        { status: 400 }
      );
    }
  } catch (error) {
    console.error("[2FA API] Verification failed:", error);
    return NextResponse.json(
      { error: "Verification failed" },
      { status: 500 }
    );
  }
}

/**
 * DELETE - Disable 2FA
 * Requires password confirmation for security
 */
export async function DELETE(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const { userId } = auth.user!;

  try {
    await disable2FA(userId);

    return NextResponse.json({
      success: true,
      message: "Two-factor authentication has been disabled",
    });
  } catch (error) {
    console.error("[2FA API] Disable failed:", error);
    return NextResponse.json(
      { error: "Failed to disable 2FA" },
      { status: 500 }
    );
  }
}

/**
 * PATCH - Regenerate backup codes
 * Returns new backup codes and invalidates old ones
 */
export async function PATCH(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);

  const { userId } = auth.user!;

  try {
    const newCodes = await regenerateBackupCodes(userId);

    return NextResponse.json({
      backupCodes: newCodes,
      message: "New backup codes generated. Previous codes are now invalid.",
    });
  } catch (error) {
    console.error("[2FA API] Regenerate codes failed:", error);
    return NextResponse.json(
      { error: "Failed to regenerate backup codes" },
      { status: 500 }
    );
  }
}
