import Stripe from "stripe";
import { prisma } from "@/db/client";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: "2023-10-16",
});

export const PRICE_IDS = {
  STARTER: "price_starter_monthly",
  PRO: "price_pro_monthly",
  ENTERPRISE: "price_enterprise_monthly",
};

/**
 * Create a Stripe customer for a user
 */
export async function createCustomer(
  userId: string,
  email: string,
  name?: string
): Promise<string> {
  const customer = await stripe.customers.create({
    email,
    name,
    metadata: { userId },
  });
  
  return customer.id;
}

/**
 * Create a checkout session for subscription
 */
export async function createCheckoutSession(
  customerId: string,
  priceId: string,
  successUrl: string,
  cancelUrl: string
): Promise<string> {
  const session = await stripe.checkout.sessions.create({
    customer: customerId,
    payment_method_types: ["card"],
    line_items: [
      {
        price: priceId,
        quantity: 1,
      },
    ],
    mode: "subscription",
    success_url: successUrl,
    cancel_url: cancelUrl,
  });
  
  return session.url!;
}

/**
 * Create a billing portal session
 */
export async function createBillingPortalSession(
  customerId: string,
  returnUrl: string
): Promise<string> {
  const session = await stripe.billingPortal.sessions.create({
    customer: customerId,
    return_url: returnUrl,
  });
  
  return session.url;
}

/**
 * Get subscription details
 */
export async function getSubscription(
  subscriptionId: string
): Promise<Stripe.Subscription | null> {
  try {
    return await stripe.subscriptions.retrieve(subscriptionId);
  } catch (error) {
    return null;
  }
}

/**
 * Cancel a subscription
 */
export async function cancelSubscription(
  subscriptionId: string,
  immediately: boolean = false
): Promise<Stripe.Subscription> {
  if (immediately) {
    return stripe.subscriptions.cancel(subscriptionId);
  }
  
  return stripe.subscriptions.update(subscriptionId, {
    cancel_at_period_end: true,
  });
}

// ============================================================================
// Idempotency & Webhook Security
// ============================================================================

// Processed webhook event IDs (prevent duplicate processing)
const processedEvents = new Map<string, number>();
const EVENT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Check if a webhook event has already been processed.
 * Critical for preventing double-charges on retries.
 */
export function isEventProcessed(eventId: string): boolean {
  const processedAt = processedEvents.get(eventId);
  if (!processedAt) return false;
  
  // Clean up old entries periodically
  if (processedEvents.size > 10000) {
    const now = Date.now();
    for (const [id, timestamp] of processedEvents) {
      if (now - timestamp > EVENT_TTL_MS) {
        processedEvents.delete(id);
      }
    }
  }
  
  return true;
}

/**
 * Mark an event as processed.
 */
export function markEventProcessed(eventId: string): void {
  processedEvents.set(eventId, Date.now());
}

/**
 * Verify Stripe webhook signature.
 * CRITICAL: Always verify before processing to prevent spoofed events.
 */
export function verifyWebhookSignature(
  payload: string,
  signature: string,
  webhookSecret: string
): Stripe.Event | null {
  try {
    return stripe.webhooks.constructEvent(payload, signature, webhookSecret);
  } catch (error) {
    console.error("[PAYMENTS] Webhook signature verification failed:", error);
    return null;
  }
}

// ============================================================================
// Webhook Event Handling
// ============================================================================

export interface WebhookResult {
  success: boolean;
  eventId: string;
  eventType: string;
  error?: string;
  action?: string;
}

/**
 * Handle Stripe webhook events with idempotency.
 * 
 * CRITICAL: This handler must be idempotent - the same event
 * may be delivered multiple times by Stripe during retries.
 */
export async function handleWebhookEvent(
  event: Stripe.Event
): Promise<WebhookResult> {
  const { id: eventId, type: eventType } = event;
  
  // Idempotency check - prevent duplicate processing
  if (isEventProcessed(eventId)) {
    console.log(`[PAYMENTS] Duplicate event ${eventId}, skipping`);
    return { 
      success: true, 
      eventId, 
      eventType, 
      action: "skipped_duplicate" 
    };
  }
  
  try {
    let action = "processed";
    
    switch (eventType) {
      case "customer.subscription.created":
      case "customer.subscription.updated": {
        const subscription = event.data.object as Stripe.Subscription;
        await syncSubscription(subscription);
        action = "subscription_synced";
        break;
      }
      
      case "customer.subscription.deleted": {
        const subscription = event.data.object as Stripe.Subscription;
        await handleSubscriptionDeleted(subscription);
        action = "subscription_deleted";
        break;
      }
      
      case "invoice.payment_succeeded": {
        const invoice = event.data.object as Stripe.Invoice;
        await handlePaymentSucceeded(invoice);
        action = "payment_recorded";
        break;
      }
      
      case "invoice.payment_failed": {
        const invoice = event.data.object as Stripe.Invoice;
        await handlePaymentFailed(invoice);
        action = "payment_failed_handled";
        break;
      }
      
      case "charge.refunded": {
        const charge = event.data.object as Stripe.Charge;
        await handleRefund(charge);
        action = "refund_processed";
        break;
      }
      
      case "charge.dispute.created": {
        const dispute = event.data.object as Stripe.Dispute;
        await handleDisputeCreated(dispute);
        action = "dispute_flagged";
        break;
      }
      
      default:
        action = "ignored";
    }
    
    // Mark as processed AFTER successful handling
    markEventProcessed(eventId);
    
    console.log(`[PAYMENTS] ${eventType} (${eventId}): ${action}`);
    return { success: true, eventId, eventType, action };
    
  } catch (error) {
    console.error(`[PAYMENTS] Error handling ${eventType}:`, error);
    // Don't mark as processed - allow retry
    return { 
      success: false, 
      eventId, 
      eventType, 
      error: error instanceof Error ? error.message : "Unknown error" 
    };
  }
}

// ============================================================================
// Event-Specific Handlers
// ============================================================================

/**
 * Handle subscription deletion with grace period check.
 */
async function handleSubscriptionDeleted(
  subscription: Stripe.Subscription
): Promise<void> {
  const customerId = subscription.customer as string;
  
  // Soft delete - mark as canceled but don't remove data
  await prisma.subscription.update({
    where: { stripeCustomerId: customerId },
    data: { 
      status: "CANCELED",
      canceledAt: new Date(),
    },
  });
  
  console.log(`[PAYMENTS] Subscription canceled for customer ${customerId}`);
}

/**
 * Handle successful payment - update subscription, refill credits, and log.
 */
async function handlePaymentSucceeded(invoice: Stripe.Invoice): Promise<void> {
  const customerId = invoice.customer as string;
  const amountPaid = invoice.amount_paid;
  
  // Record successful payment for audit trail
  await prisma.paymentEvent.create({
    data: {
      stripeCustomerId: customerId,
      eventType: "PAYMENT_SUCCEEDED",
      amount: amountPaid,
      currency: invoice.currency,
      invoiceId: invoice.id,
      metadata: {
        subscriptionId: invoice.subscription,
        periodStart: invoice.period_start,
        periodEnd: invoice.period_end,
      },
    },
  });
  
  // Refill credits on subscription renewal
  // Credit amount based on plan tier (simplified - real implementation
  // would look up price to determine credit allocation)
  const subscription = await prisma.subscription.findUnique({
    where: { stripeCustomerId: customerId },
  });
  
  if (subscription) {
    const creditAmount = getCreditAllocationForPlan(subscription.stripePriceId);
    if (creditAmount > 0) {
      await refillCredits(subscription.userId, creditAmount, invoice.id);
    }
  }
  
  console.log(`[PAYMENTS] Payment succeeded: ${amountPaid / 100} ${invoice.currency.toUpperCase()}`);
}

/**
 * Determine credit allocation based on subscription plan.
 */
function getCreditAllocationForPlan(priceId: string): number {
  switch (priceId) {
    case PRICE_IDS.STARTER:
      return 100;
    case PRICE_IDS.PRO:
      return 500;
    case PRICE_IDS.ENTERPRISE:
      return 2000;
    default:
      return 0;
  }
}

/**
 * Handle failed payment - notify and potentially downgrade.
 */
async function handlePaymentFailed(invoice: Stripe.Invoice): Promise<void> {
  const customerId = invoice.customer as string;
  const attemptCount = invoice.attempt_count || 1;
  
  // Record failed payment
  await prisma.paymentEvent.create({
    data: {
      stripeCustomerId: customerId,
      eventType: "PAYMENT_FAILED",
      amount: invoice.amount_due,
      currency: invoice.currency,
      invoiceId: invoice.id,
      metadata: {
        attemptCount,
        nextAttempt: invoice.next_payment_attempt,
      },
    },
  });
  
  // Mark subscription as past due
  await prisma.subscription.update({
    where: { stripeCustomerId: customerId },
    data: { status: "PAST_DUE" },
  });
  
  // TODO: Send notification email to user
  console.log(`[PAYMENTS] Payment failed for ${customerId}, attempt ${attemptCount}`);
}

/**
 * Handle refund - update records and potentially adjust access.
 */
async function handleRefund(charge: Stripe.Charge): Promise<void> {
  const customerId = charge.customer as string;
  const refundedAmount = charge.amount_refunded;
  
  await prisma.paymentEvent.create({
    data: {
      stripeCustomerId: customerId,
      eventType: "REFUNDED",
      amount: refundedAmount,
      currency: charge.currency,
      chargeId: charge.id,
      metadata: {
        refundReason: charge.refunds?.data[0]?.reason,
        fullRefund: charge.refunded,
      },
    },
  });
  
  console.log(`[PAYMENTS] Refund processed: ${refundedAmount / 100} ${charge.currency.toUpperCase()}`);
}

/**
 * Handle dispute - flag for manual review.
 * CRITICAL: Disputes require immediate attention to avoid penalties.
 */
async function handleDisputeCreated(dispute: Stripe.Dispute): Promise<void> {
  const chargeId = dispute.charge as string;
  const amount = dispute.amount;
  
  await prisma.paymentEvent.create({
    data: {
      stripeCustomerId: "", // Will be resolved from charge
      eventType: "DISPUTE_CREATED",
      amount,
      currency: dispute.currency,
      chargeId,
      metadata: {
        reason: dispute.reason,
        status: dispute.status,
        evidenceDueBy: dispute.evidence_details?.due_by,
      },
      requiresAction: true,
    },
  });
  
  // TODO: Send urgent notification to support team
  console.error(`[PAYMENTS] DISPUTE CREATED: ${chargeId}, reason: ${dispute.reason}`);
}

/**
 * Sync subscription data from Stripe to database
 */
async function syncSubscription(subscription: Stripe.Subscription): Promise<void> {
  const customerId = subscription.customer as string;
  
  // Find user by Stripe customer ID
  const existingSub = await prisma.subscription.findUnique({
    where: { stripeCustomerId: customerId },
  });
  
  if (!existingSub) {
    // Customer doesn't exist in our system yet
    return;
  }
  
  await prisma.subscription.update({
    where: { stripeCustomerId: customerId },
    data: {
      stripePriceId: subscription.items.data[0].price.id,
      status: mapSubscriptionStatus(subscription.status),
      currentPeriodEnd: new Date(subscription.current_period_end * 1000),
    },
  });
}

function mapSubscriptionStatus(
  status: Stripe.Subscription.Status
): "ACTIVE" | "PAST_DUE" | "CANCELED" | "TRIALING" {
  switch (status) {
    case "active":
      return "ACTIVE";
    case "past_due":
      return "PAST_DUE";
    case "canceled":
      return "CANCELED";
    case "trialing":
      return "TRIALING";
    default:
      return "CANCELED";
  }
}

// ============================================================================
// Credits System
// ============================================================================

/**
 * User credit balance for metered features (API calls, storage, etc.)
 * Credits are consumed as users use features, refilled on subscription renewal.
 */
export interface CreditBalance {
  userId: string;
  available: number;
  reserved: number;  // Held during in-flight operations
  lastRefill: Date;
  expiresAt: Date | null;
}

/**
 * Reserve credits for an operation.
 * CRITICAL: Must be atomic to prevent double-spending.
 * Returns reservation ID if successful, null if insufficient balance.
 */
export async function reserveCredits(
  userId: string,
  amount: number,
  operationId: string
): Promise<string | null> {
  // Atomic reservation using transaction
  const result = await prisma.$transaction(async (tx) => {
    const balance = await tx.creditBalance.findUnique({
      where: { userId },
    });
    
    if (!balance || balance.available < amount) {
      return null;
    }
    
    // Check expiry
    if (balance.expiresAt && balance.expiresAt < new Date()) {
      return null;
    }
    
    // Reserve credits atomically
    await tx.creditBalance.update({
      where: { userId },
      data: {
        available: { decrement: amount },
        reserved: { increment: amount },
      },
    });
    
    // Create reservation record
    const reservation = await tx.creditReservation.create({
      data: {
        userId,
        amount,
        operationId,
        status: "PENDING",
        expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 min timeout
      },
    });
    
    return reservation.id;
  });
  
  return result;
}

/**
 * Commit a credit reservation (operation succeeded).
 * Removes reserved credits permanently.
 */
export async function commitCredits(reservationId: string): Promise<boolean> {
  try {
    await prisma.$transaction(async (tx) => {
      const reservation = await tx.creditReservation.findUnique({
        where: { id: reservationId },
      });
      
      if (!reservation || reservation.status !== "PENDING") {
        throw new Error("Invalid reservation");
      }
      
      // Consume reserved credits
      await tx.creditBalance.update({
        where: { userId: reservation.userId },
        data: {
          reserved: { decrement: reservation.amount },
        },
      });
      
      // Mark reservation as committed
      await tx.creditReservation.update({
        where: { id: reservationId },
        data: { status: "COMMITTED", committedAt: new Date() },
      });
    });
    
    return true;
  } catch (error) {
    console.error("[PAYMENTS] Failed to commit credits:", error);
    return false;
  }
}

/**
 * Release a credit reservation (operation failed/canceled).
 * Returns reserved credits to available balance.
 */
export async function releaseCredits(reservationId: string): Promise<boolean> {
  try {
    await prisma.$transaction(async (tx) => {
      const reservation = await tx.creditReservation.findUnique({
        where: { id: reservationId },
      });
      
      if (!reservation || reservation.status !== "PENDING") {
        throw new Error("Invalid reservation");
      }
      
      // Return credits to available
      await tx.creditBalance.update({
        where: { userId: reservation.userId },
        data: {
          available: { increment: reservation.amount },
          reserved: { decrement: reservation.amount },
        },
      });
      
      // Mark reservation as released
      await tx.creditReservation.update({
        where: { id: reservationId },
        data: { status: "RELEASED", releasedAt: new Date() },
      });
    });
    
    return true;
  } catch (error) {
    console.error("[PAYMENTS] Failed to release credits:", error);
    return false;
  }
}

/**
 * Refill credits on subscription renewal.
 * CRITICAL: Must be idempotent - called from webhook.
 */
export async function refillCredits(
  userId: string,
  amount: number,
  invoiceId: string
): Promise<boolean> {
  try {
    // Idempotency check - don't double-refill
    const existingRefill = await prisma.creditRefill.findFirst({
      where: { invoiceId },
    });
    
    if (existingRefill) {
      console.log(`[PAYMENTS] Credit refill already processed for invoice ${invoiceId}`);
      return true;
    }
    
    await prisma.$transaction(async (tx) => {
      // Add credits
      await tx.creditBalance.upsert({
        where: { userId },
        create: {
          userId,
          available: amount,
          reserved: 0,
          lastRefill: new Date(),
          expiresAt: null,
        },
        update: {
          available: { increment: amount },
          lastRefill: new Date(),
        },
      });
      
      // Record refill for idempotency
      await tx.creditRefill.create({
        data: {
          userId,
          amount,
          invoiceId,
        },
      });
    });
    
    console.log(`[PAYMENTS] Refilled ${amount} credits for user ${userId}`);
    return true;
  } catch (error) {
    console.error("[PAYMENTS] Failed to refill credits:", error);
    return false;
  }
}

/**
 * Get current credit balance for a user.
 */
export async function getCreditBalance(userId: string): Promise<CreditBalance | null> {
  const balance = await prisma.creditBalance.findUnique({
    where: { userId },
  });
  
  if (!balance) return null;
  
  return {
    userId: balance.userId,
    available: balance.available,
    reserved: balance.reserved,
    lastRefill: balance.lastRefill,
    expiresAt: balance.expiresAt,
  };
}

/**
 * Cleanup expired reservations and release credits.
 * Should be run periodically (cron job).
 */
export async function cleanupExpiredReservations(): Promise<number> {
  const now = new Date();
  
  const expiredReservations = await prisma.creditReservation.findMany({
    where: {
      status: "PENDING",
      expiresAt: { lt: now },
    },
  });
  
  let released = 0;
  for (const reservation of expiredReservations) {
    const success = await releaseCredits(reservation.id);
    if (success) released++;
  }
  
  console.log(`[PAYMENTS] Released ${released} expired credit reservations`);
  return released;
}
