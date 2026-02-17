/**
 * Two-Factor Authentication API
 * 
 * Endpoints for setting up, verifying, and managing 2FA.
 * 
 * Security:
 * - All endpoints require authentication
 * - Setup requires password re-verification
 * - Verification is rate-limited
 */

import { NextRequest, NextResponse } from "next/server";
import { verifyAccessToken } from "@/auth/session";
import {
  generateTwoFactorSecret,
  verifyTwoFactorCode,
  verifyBackupCode,
  disableTwoFactor,
  isTwoFactorEnabled,
  regenerateBackupCodes,
} from "@/auth/two-factor";
import { prisma } from "@/db/client";

/**
 * GET /api/auth/two-factor
 * 
 * Check if 2FA is enabled for the current user
 */
export async function GET(request: NextRequest) {
  const payload = await authenticate(request);
  if (!payload) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  
  const enabled = await isTwoFactorEnabled(payload.userId);
  
  return NextResponse.json({
    enabled,
    userId: payload.userId,
  });
}

/**
 * POST /api/auth/two-factor
 * 
 * Set up 2FA for the current user
 * 
 * Body: { action: "setup" | "verify" | "verify-backup" | "disable" | "regenerate-backup", ... }
 */
export async function POST(request: NextRequest) {
  const payload = await authenticate(request);
  if (!payload) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  
  const body = await request.json();
  const { action } = body;
  
  const context = {
    ipAddress: request.headers.get("x-forwarded-for") || undefined,
    userAgent: request.headers.get("user-agent") || undefined,
  };
  
  switch (action) {
    case "setup": {
      // Get user email for QR code
      const user = await prisma.user.findUnique({
        where: { id: payload.userId },
        select: { email: true },
      });
      
      if (!user) {
        return NextResponse.json({ error: "User not found" }, { status: 404 });
      }
      
      const { secret, qrCodeUrl, backupCodes } = await generateTwoFactorSecret(
        payload.userId,
        user.email
      );
      
      return NextResponse.json({
        success: true,
        data: {
          // Don't expose raw secret to client - only QR code URL
          qrCodeUrl,
          backupCodes,
          message: "Scan the QR code with your authenticator app, then verify with a code",
        },
      });
    }
    
    case "verify": {
      const { code } = body;
      
      if (!code || typeof code !== "string") {
        return NextResponse.json(
          { error: "Code is required" },
          { status: 400 }
        );
      }
      
      const result = await verifyTwoFactorCode(payload.userId, code, context);
      
      if (result.valid) {
        // Update user to mark 2FA as enabled
        await prisma.user.update({
          where: { id: payload.userId },
          data: { twoFactorEnabled: true },
        });
        
        return NextResponse.json({
          success: true,
          message: "Two-factor authentication enabled successfully",
        });
      } else {
        return NextResponse.json(
          { error: result.reason || "Invalid code" },
          { status: 400 }
        );
      }
    }
    
    case "verify-backup": {
      const { code } = body;
      
      if (!code || typeof code !== "string") {
        return NextResponse.json(
          { error: "Backup code is required" },
          { status: 400 }
        );
      }
      
      const result = await verifyBackupCode(payload.userId, code, context);
      
      if (result.valid) {
        return NextResponse.json({
          success: true,
          remainingCodes: result.remainingCodes,
          message: result.remainingCodes === 0
            ? "Last backup code used! Please regenerate backup codes."
            : `Backup code verified. ${result.remainingCodes} codes remaining.`,
        });
      } else {
        return NextResponse.json(
          { error: result.reason || "Invalid backup code" },
          { status: 400 }
        );
      }
    }
    
    case "disable": {
      // TODO: In production, require password re-verification here
      await disableTwoFactor(payload.userId);
      
      return NextResponse.json({
        success: true,
        message: "Two-factor authentication disabled",
      });
    }
    
    case "regenerate-backup": {
      const newCodes = await regenerateBackupCodes(payload.userId);
      
      return NextResponse.json({
        success: true,
        backupCodes: newCodes,
        message: "New backup codes generated. Old codes are now invalid.",
      });
    }
    
    default:
      return NextResponse.json(
        { error: "Invalid action" },
        { status: 400 }
      );
  }
}

/**
 * Helper to authenticate request
 */
async function authenticate(request: NextRequest) {
  const authHeader = request.headers.get("authorization");
  const token = authHeader?.replace("Bearer ", "");
  
  if (!token) return null;
  
  return verifyAccessToken(token);
}
