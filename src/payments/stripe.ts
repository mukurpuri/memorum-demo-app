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
 * Handle successful payment - update subscription and log.
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
  
  console.log(`[PAYMENTS] Payment succeeded: ${amountPaid / 100} ${invoice.currency.toUpperCase()}`);
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
// Subscription Management (Upgrades, Downgrades, Prorations)
// ============================================================================

export interface SubscriptionChangeResult {
  success: boolean;
  subscription?: Stripe.Subscription;
  prorationAmount?: number;
  error?: string;
}

export interface UpcomingInvoicePreview {
  amountDue: number;
  currency: string;
  prorationAmount: number;
  nextBillingDate: Date;
  lineItems: {
    description: string;
    amount: number;
  }[];
}

/**
 * Upgrade or downgrade subscription to a different plan
 * 
 * CRITICAL: Handles proration correctly to avoid over/under-charging
 * - Upgrade: Charges prorated amount immediately
 * - Downgrade: Credits remaining time on next invoice
 */
export async function changeSubscriptionPlan(
  subscriptionId: string,
  newPriceId: string,
  prorationBehavior: "create_prorations" | "none" | "always_invoice" = "create_prorations"
): Promise<SubscriptionChangeResult> {
  try {
    const subscription = await stripe.subscriptions.retrieve(subscriptionId);
    const currentPriceId = subscription.items.data[0].price.id;
    
    if (currentPriceId === newPriceId) {
      return { success: false, error: "Already on this plan" };
    }
    
    const updatedSubscription = await stripe.subscriptions.update(subscriptionId, {
      items: [{
        id: subscription.items.data[0].id,
        price: newPriceId,
      }],
      proration_behavior: prorationBehavior,
    });
    
    // Calculate proration amount from latest invoice
    const invoices = await stripe.invoices.list({
      subscription: subscriptionId,
      limit: 1,
    });
    
    const prorationAmount = invoices.data[0]?.amount_due || 0;
    
    console.log(`[PAYMENTS] Subscription ${subscriptionId} changed from ${currentPriceId} to ${newPriceId}`);
    
    return {
      success: true,
      subscription: updatedSubscription,
      prorationAmount,
    };
  } catch (error) {
    console.error("[PAYMENTS] Failed to change subscription:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

/**
 * Preview what a subscription change would cost
 * Use before confirming upgrade/downgrade to show user the proration
 */
export async function previewSubscriptionChange(
  customerId: string,
  subscriptionId: string,
  newPriceId: string
): Promise<UpcomingInvoicePreview | null> {
  try {
    const subscription = await stripe.subscriptions.retrieve(subscriptionId);
    
    const upcomingInvoice = await stripe.invoices.retrieveUpcoming({
      customer: customerId,
      subscription: subscriptionId,
      subscription_items: [{
        id: subscription.items.data[0].id,
        price: newPriceId,
      }],
      subscription_proration_behavior: "create_prorations",
    });
    
    // Calculate proration from line items
    let prorationAmount = 0;
    const lineItems: { description: string; amount: number }[] = [];
    
    for (const line of upcomingInvoice.lines.data) {
      lineItems.push({
        description: line.description || "Subscription",
        amount: line.amount,
      });
      
      if (line.proration) {
        prorationAmount += line.amount;
      }
    }
    
    return {
      amountDue: upcomingInvoice.amount_due,
      currency: upcomingInvoice.currency,
      prorationAmount,
      nextBillingDate: new Date(upcomingInvoice.period_end * 1000),
      lineItems,
    };
  } catch (error) {
    console.error("[PAYMENTS] Failed to preview subscription change:", error);
    return null;
  }
}

/**
 * Apply a coupon/discount to an existing subscription
 */
export async function applySubscriptionDiscount(
  subscriptionId: string,
  couponId: string
): Promise<SubscriptionChangeResult> {
  try {
    const subscription = await stripe.subscriptions.update(subscriptionId, {
      coupon: couponId,
    });
    
    console.log(`[PAYMENTS] Coupon ${couponId} applied to subscription ${subscriptionId}`);
    
    return { success: true, subscription };
  } catch (error) {
    console.error("[PAYMENTS] Failed to apply coupon:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

/**
 * Pause a subscription (keep it active but don't charge)
 * Useful for temporary account holds
 */
export async function pauseSubscription(
  subscriptionId: string,
  resumeDate?: Date
): Promise<SubscriptionChangeResult> {
  try {
    const pauseConfig: Stripe.SubscriptionUpdateParams.PauseCollection = {
      behavior: resumeDate ? "void" : "mark_uncollectible",
    };
    
    if (resumeDate) {
      pauseConfig.resumes_at = Math.floor(resumeDate.getTime() / 1000);
    }
    
    const subscription = await stripe.subscriptions.update(subscriptionId, {
      pause_collection: pauseConfig,
    });
    
    console.log(`[PAYMENTS] Subscription ${subscriptionId} paused`);
    
    return { success: true, subscription };
  } catch (error) {
    console.error("[PAYMENTS] Failed to pause subscription:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

/**
 * Resume a paused subscription
 */
export async function resumeSubscription(
  subscriptionId: string
): Promise<SubscriptionChangeResult> {
  try {
    const subscription = await stripe.subscriptions.update(subscriptionId, {
      pause_collection: "",
    });
    
    console.log(`[PAYMENTS] Subscription ${subscriptionId} resumed`);
    
    return { success: true, subscription };
  } catch (error) {
    console.error("[PAYMENTS] Failed to resume subscription:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

/**
 * Add a one-time charge to a subscription's next invoice
 * Useful for add-ons, overage charges, etc.
 */
export async function addInvoiceItem(
  customerId: string,
  amount: number,
  description: string,
  subscriptionId?: string
): Promise<Stripe.InvoiceItem | null> {
  try {
    const invoiceItem = await stripe.invoiceItems.create({
      customer: customerId,
      amount,
      currency: "usd",
      description,
      subscription: subscriptionId,
    });
    
    console.log(`[PAYMENTS] Invoice item added: ${description} ($${amount / 100})`);
    
    return invoiceItem;
  } catch (error) {
    console.error("[PAYMENTS] Failed to add invoice item:", error);
    return null;
  }
}

/**
 * Get subscription usage and billing summary
 */
export async function getSubscriptionSummary(subscriptionId: string): Promise<{
  status: string;
  currentPlan: string;
  currentPeriodEnd: Date;
  cancelAtPeriodEnd: boolean;
  upcomingInvoiceAmount: number | null;
} | null> {
  try {
    const subscription = await stripe.subscriptions.retrieve(subscriptionId, {
      expand: ["latest_invoice"],
    });
    
    let upcomingInvoiceAmount: number | null = null;
    try {
      const upcoming = await stripe.invoices.retrieveUpcoming({
        subscription: subscriptionId,
      });
      upcomingInvoiceAmount = upcoming.amount_due;
    } catch {
      // No upcoming invoice (subscription ending)
    }
    
    return {
      status: subscription.status,
      currentPlan: subscription.items.data[0].price.id,
      currentPeriodEnd: new Date(subscription.current_period_end * 1000),
      cancelAtPeriodEnd: subscription.cancel_at_period_end,
      upcomingInvoiceAmount,
    };
  } catch (error) {
    console.error("[PAYMENTS] Failed to get subscription summary:", error);
    return null;
  }
}
