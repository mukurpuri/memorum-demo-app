# Demo PR Guide

This guide shows you how to create PRs that will trigger different Memorum analysis scenarios.

## Setup

1. Create a new GitHub repo (e.g., `your-username/acme-demo`)
2. Push this project to the repo
3. Install Memorum GitHub App on the repo
4. Create branches and PRs as described below

---

## PR Scenarios

### PR 1: AUTH_FLOW_CHANGE (Elevated Risk) ⚠️

**Branch:** `feature/jwt-refresh-tokens`

**Files to modify:**

1. `src/auth/session.ts` - Add refresh token rotation
2. `src/auth/middleware.ts` - Add token validation
3. `src/api/auth/login/route.ts` - Update login response

**Changes to make in `src/auth/session.ts`:**

Add this function at the end:

```typescript
/**
 * Rotate refresh token on each use (security best practice)
 * Prevents token replay attacks
 */
export async function rotateRefreshToken(oldToken: string): Promise<{
  accessToken: string;
  refreshToken: string;
} | null> {
  const result = await refreshSession(oldToken);
  if (!result) return null;
  
  // Log rotation for audit trail
  console.log(`[AUTH] Refresh token rotated at ${new Date().toISOString()}`);
  
  return result;
}

/**
 * Revoke all tokens for a user (forced logout everywhere)
 * Use after password change or security incident
 */
export async function revokeAllTokens(userId: string): Promise<number> {
  const result = await prisma.session.deleteMany({
    where: { userId },
  });
  
  console.log(`[AUTH] Revoked ${result.count} sessions for user ${userId}`);
  
  return result.count;
}
```

**Expected Memorum Analysis:**
- Category: AUTH_FLOW_CHANGE
- Risk: Elevated — auth layer
- Layers: auth, api
- Review Gate: "auth change detected. Verify session handling and permissions."

---

### PR 2: DATA_MODEL_CHANGE (Elevated Risk) ⚠️

**Branch:** `feature/user-preferences`

**Files to modify:**

1. `prisma/schema.prisma` - Add UserPreferences model

**Changes to make in `prisma/schema.prisma`:**

Add this model:

```prisma
model UserPreferences {
  id                String   @id @default(cuid())
  userId            String   @unique
  theme             String   @default("light")
  emailNotifications Boolean @default(true)
  weeklyDigest      Boolean  @default(true)
  timezone          String   @default("UTC")
  language          String   @default("en")
  createdAt         DateTime @default(now())
  updatedAt         DateTime @updatedAt
  
  user              User     @relation(fields: [userId], references: [id], onDelete: Cascade)
}
```

Also add to User model:
```prisma
preferences   UserPreferences?
```

**Expected Memorum Analysis:**
- Category: DATA_MODEL_CHANGE
- Risk: Elevated — db layer
- Layers: db
- Review Gate: "database change detected. Verify migration rollback and data integrity."

---

### PR 3: PAYMENTS Change (Elevated Risk) ⚠️

**Branch:** `feature/subscription-tiers`

**Files to modify:**

1. `src/payments/stripe.ts` - Add new pricing tiers

**Changes to make in `src/payments/stripe.ts`:**

Add these functions:

```typescript
/**
 * Upgrade subscription to a higher tier
 */
export async function upgradeSubscription(
  subscriptionId: string,
  newPriceId: string
): Promise<Stripe.Subscription> {
  const subscription = await stripe.subscriptions.retrieve(subscriptionId);
  
  return stripe.subscriptions.update(subscriptionId, {
    items: [{
      id: subscription.items.data[0].id,
      price: newPriceId,
    }],
    proration_behavior: "create_prorations",
  });
}

/**
 * Apply a discount coupon to subscription
 */
export async function applyCoupon(
  subscriptionId: string,
  couponId: string
): Promise<Stripe.Subscription> {
  return stripe.subscriptions.update(subscriptionId, {
    coupon: couponId,
  });
}

/**
 * Get upcoming invoice preview
 */
export async function getUpcomingInvoice(
  customerId: string
): Promise<Stripe.Invoice> {
  return stripe.invoices.retrieveUpcoming({
    customer: customerId,
  });
}
```

**Expected Memorum Analysis:**
- Category: API_CHANGE (or payments-related)
- Risk: Elevated — payments layer
- Layers: payments
- Review Gate: "payments change detected. Verify transaction safety and idempotency."

---

### PR 4: API_CHANGE (Medium Risk)

**Branch:** `feature/team-endpoints`

**Files to modify:**

1. `src/api/teams/route.ts` (create new file)
2. `src/api/teams/[id]/route.ts` (create new file)

**Create `src/api/teams/route.ts`:**

```typescript
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/db/client";
import { authMiddleware, unauthorizedResponse } from "@/auth/middleware";
import { z } from "zod";

const CreateTeamSchema = z.object({
  name: z.string().min(1).max(100),
  slug: z.string().min(1).max(50).regex(/^[a-z0-9-]+$/),
});

export async function GET(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);
  
  const teams = await prisma.team.findMany({
    where: {
      members: { some: { userId: auth.user!.userId } },
    },
    include: { members: true },
  });
  
  return NextResponse.json({ teams });
}

export async function POST(request: NextRequest) {
  const auth = await authMiddleware(request);
  if (!auth.authorized) return unauthorizedResponse(auth.error!);
  
  const body = await request.json();
  const parsed = CreateTeamSchema.safeParse(body);
  
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }
  
  const team = await prisma.team.create({
    data: {
      ...parsed.data,
      members: {
        create: { userId: auth.user!.userId, role: "OWNER" },
      },
    },
  });
  
  return NextResponse.json({ team }, { status: 201 });
}
```

**Expected Memorum Analysis:**
- Category: API_CHANGE
- Risk: Medium — Cross-layer change
- Layers: api, db
- Review focus: route behavior, error handling, backwards compat

---

### PR 5: UI_CHANGE (Low Risk)

**Branch:** `feature/button-variants`

**Files to modify:**

1. `src/components/Button.tsx` - Add new variants
2. `src/components/Card.tsx` - Add hover effects

**Changes to make in `src/components/Button.tsx`:**

Add new variant:

```typescript
// Add to variantStyles object:
outline: "border-2 border-blue-600 text-blue-600 hover:bg-blue-50 focus:ring-blue-500",
```

**Expected Memorum Analysis:**
- Category: UI_CHANGE
- Risk: Low — UI-only change
- Layers: ui
- No Review Gate (low risk)

---

### PR 6: TEST_ONLY (Filtered - Low WSS)

**Branch:** `test/password-coverage`

**Files to modify:**

1. `src/auth/__tests__/password.test.ts` - Add more test cases

**Add more tests:**

```typescript
describe("edge cases", () => {
  it("should handle empty password", () => {
    const result = validatePasswordStrength("");
    expect(result.valid).toBe(false);
  });
  
  it("should handle unicode characters", async () => {
    const password = "SecurePass123!🔒";
    const hash = await hashPassword(password);
    const valid = await verifyPassword(password, hash);
    expect(valid).toBe(true);
  });
});
```

**Expected Memorum Analysis:**
- Category: TEST_ONLY
- WSS: Below threshold (likely won't trigger AI)
- If it does inject: Low risk, test-only

---

### PR 7: INFRA_CHANGE (Medium Risk)

**Branch:** `infra/docker-optimization`

**Files to modify:**

1. `Dockerfile` - Optimize build

**Changes to make in `Dockerfile`:**

Add caching layer:

```dockerfile
# Add after "FROM base AS deps"
# Enable BuildKit cache for faster rebuilds
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline
```

**Expected Memorum Analysis:**
- Category: INFRA_CHANGE
- Risk: Medium — infra change
- Layers: infra
- Review focus: deployment, env config, rollback

---

### PR 8: Multi-Layer Change (Medium Risk)

**Branch:** `feature/rate-limiting`

**Files to modify:**

1. `src/api/auth/login/route.ts` - Add rate limit check
2. `src/utils/rateLimit.ts` (create new file)
3. `src/config/env.ts` - Add rate limit config

**This touches api + utils + config = 3 layers**

**Expected Memorum Analysis:**
- Category: API_CHANGE
- Risk: Medium — Cross-layer change (api, utils, config)
- Layers: api, utils, config
- Multi-layer bonus in WSS

---

## PR Creation Order (Recommended)

For the demo, create and merge PRs in this order:

1. **PR 2: DATA_MODEL_CHANGE** - Merge first (db schema)
2. **PR 1: AUTH_FLOW_CHANGE** - Merge second (shows elevated risk)
3. **PR 3: PAYMENTS** - Merge third (another elevated risk)
4. **PR 4: API_CHANGE** - Merge fourth (medium risk)
5. **PR 5: UI_CHANGE** - Leave OPEN (show low risk in drafts)
6. **PR 6: TEST_ONLY** - Leave OPEN (show WSS filtering)

This gives you:
- 4 merged intents for file search demo
- 2 open PRs in the dashboard
- Mix of risk levels to show

---

## Demo Script Integration

When demoing:

1. **Show PR 1 (auth)** - Point out Review Gate alert
2. **Search `src/auth/`** - Show 2 merged intents (PR 1 + PR 2 touched related areas)
3. **Show dashboard** - 4 merged, 2 open PRs
4. **Show PR 6** - Explain WSS filtering ("We don't waste AI on test-only changes")

---

## Quick Commands

```bash
# Create all branches at once
git checkout -b feature/jwt-refresh-tokens
git checkout main
git checkout -b feature/user-preferences
git checkout main
git checkout -b feature/subscription-tiers
git checkout main
git checkout -b feature/team-endpoints
git checkout main
git checkout -b feature/button-variants
git checkout main
git checkout -b test/password-coverage
git checkout main
```

Good luck with the demo!
