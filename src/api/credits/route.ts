import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import {
  getCreditBalance,
  reserveCredits,
  commitCredits,
  releaseCredits,
} from "@/payments/stripe";
import { verifySession } from "@/auth/session";

// ============================================================================
// Credits API Routes
// ============================================================================

/**
 * GET /api/credits
 * Returns the current credit balance for the authenticated user.
 */
export async function GET(request: NextRequest) {
  try {
    const session = await verifySession(request);
    if (!session) {
      return NextResponse.json(
        { error: "Unauthorized" },
        { status: 401 }
      );
    }

    const balance = await getCreditBalance(session.userId);
    
    if (!balance) {
      return NextResponse.json({
        available: 0,
        reserved: 0,
        lastRefill: null,
        expiresAt: null,
      });
    }

    return NextResponse.json({
      available: balance.available,
      reserved: balance.reserved,
      lastRefill: balance.lastRefill.toISOString(),
      expiresAt: balance.expiresAt?.toISOString() ?? null,
    });
  } catch (error) {
    console.error("[API] Error fetching credit balance:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

// ============================================================================
// Credit Operations (Reserve/Commit/Release)
// ============================================================================

const ReserveSchema = z.object({
  amount: z.number().int().positive().max(10000),
  operationId: z.string().min(1).max(255),
});

const ConfirmSchema = z.object({
  reservationId: z.string().min(1),
  action: z.enum(["commit", "release"]),
});

/**
 * POST /api/credits
 * Reserve, commit, or release credits.
 * 
 * Actions:
 * - reserve: Hold credits for an operation (returns reservationId)
 * - commit: Finalize a reservation (consumes credits)
 * - release: Cancel a reservation (returns credits)
 */
export async function POST(request: NextRequest) {
  try {
    const session = await verifySession(request);
    if (!session) {
      return NextResponse.json(
        { error: "Unauthorized" },
        { status: 401 }
      );
    }

    const body = await request.json();
    
    // Handle reserve action
    if ("amount" in body && "operationId" in body) {
      const { amount, operationId } = ReserveSchema.parse(body);
      
      const reservationId = await reserveCredits(
        session.userId,
        amount,
        operationId
      );
      
      if (!reservationId) {
        return NextResponse.json(
          { error: "Insufficient credits" },
          { status: 402 }  // Payment Required
        );
      }
      
      return NextResponse.json({
        success: true,
        reservationId,
        message: `Reserved ${amount} credits`,
      });
    }
    
    // Handle commit/release action
    if ("reservationId" in body && "action" in body) {
      const { reservationId, action } = ConfirmSchema.parse(body);
      
      let success: boolean;
      if (action === "commit") {
        success = await commitCredits(reservationId);
      } else {
        success = await releaseCredits(reservationId);
      }
      
      if (!success) {
        return NextResponse.json(
          { error: "Failed to process reservation" },
          { status: 400 }
        );
      }
      
      return NextResponse.json({
        success: true,
        action,
        message: action === "commit" 
          ? "Credits consumed" 
          : "Credits released",
      });
    }
    
    return NextResponse.json(
      { error: "Invalid request body" },
      { status: 400 }
    );
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Validation failed", details: error.errors },
        { status: 400 }
      );
    }
    
    console.error("[API] Error processing credit operation:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
