import { NextRequest, NextResponse } from "next/server";
import { 
  verifyWebhookSignature, 
  handleWebhookEvent,
  isEventProcessed,
} from "@/payments/stripe";

const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET!;

/**
 * POST /api/webhooks/stripe
 * 
 * Handles incoming Stripe webhook events.
 * 
 * Security considerations:
 * - Signature verification prevents spoofed events
 * - Idempotency handling prevents double-processing
 * - Raw body parsing required for signature verification
 * 
 * CRITICAL: This endpoint handles real money - errors can cause:
 * - Double charges (if we process twice)
 * - Lost revenue (if we miss subscription updates)
 * - Customer disputes (if we don't handle refunds)
 */
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Get raw body for signature verification
    const rawBody = await request.text();
    const signature = request.headers.get("stripe-signature");
    
    if (!signature) {
      console.error("[WEBHOOK] Missing stripe-signature header");
      return NextResponse.json(
        { error: "Missing signature" },
        { status: 400 }
      );
    }
    
    // Verify webhook signature (CRITICAL for security)
    const event = verifyWebhookSignature(rawBody, signature, STRIPE_WEBHOOK_SECRET);
    
    if (!event) {
      console.error("[WEBHOOK] Invalid signature");
      return NextResponse.json(
        { error: "Invalid signature" },
        { status: 401 }
      );
    }
    
    // Quick idempotency check before processing
    if (isEventProcessed(event.id)) {
      return NextResponse.json({
        received: true,
        eventId: event.id,
        status: "already_processed",
      });
    }
    
    // Process the event
    const result = await handleWebhookEvent(event);
    
    const elapsed = Date.now() - startTime;
    console.log(`[WEBHOOK] ${event.type} processed in ${elapsed}ms`);
    
    if (!result.success) {
      // Return 500 to trigger Stripe retry
      return NextResponse.json(
        { 
          error: result.error,
          eventId: event.id,
          eventType: event.type,
        },
        { status: 500 }
      );
    }
    
    return NextResponse.json({
      received: true,
      eventId: result.eventId,
      eventType: result.eventType,
      action: result.action,
    });
    
  } catch (error) {
    console.error("[WEBHOOK] Unexpected error:", error);
    // Return 500 to trigger Stripe retry
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

/**
 * GET /api/webhooks/stripe
 * Health check for webhook endpoint
 */
export async function GET() {
  return NextResponse.json({
    status: "healthy",
    endpoint: "/api/webhooks/stripe",
    note: "POST requests from Stripe only",
  });
}
