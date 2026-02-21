import { NextRequest, NextResponse } from 'next/server';
import { Redis } from 'ioredis';
import { RateLimiter, RateLimitConfig, RateLimitResult, createRateLimiter, RateLimitPreset } from './rate-limiter';
import { env } from '../config/env';
import { auditLog } from '../audit/logger';

let redisClient: Redis | null = null;

function getRedis(): Redis {
  if (!redisClient) {
    redisClient = new Redis(env.REDIS_URL, {
      maxRetriesPerRequest: 3,
      retryDelayOnFailover: 100,
      enableReadyCheck: true,
      lazyConnect: true,
    });
  }
  return redisClient;
}

export interface RateLimitMiddlewareOptions {
  preset?: RateLimitPreset;
  config?: Partial<RateLimitConfig>;
  keyGenerator?: (req: NextRequest) => string;
  onRateLimited?: (req: NextRequest, result: RateLimitResult) => void;
  skipIf?: (req: NextRequest) => boolean;
  headers?: boolean;
}

const DEFAULT_OPTIONS: RateLimitMiddlewareOptions = {
  preset: 'standard',
  headers: true,
};

function defaultKeyGenerator(req: NextRequest): string {
  const forwarded = req.headers.get('x-forwarded-for');
  const ip = forwarded?.split(',')[0]?.trim() || 'unknown';
  
  const userId = req.headers.get('x-user-id');
  if (userId) {
    return `user:${userId}`;
  }
  
  return `ip:${ip}`;
}

function addRateLimitHeaders(
  response: NextResponse,
  result: RateLimitResult,
  limit: number
): NextResponse {
  response.headers.set('X-RateLimit-Limit', limit.toString());
  response.headers.set('X-RateLimit-Remaining', result.remaining.toString());
  response.headers.set('X-RateLimit-Reset', Math.floor(result.resetAt.getTime() / 1000).toString());
  
  if (!result.allowed && result.retryAfter) {
    response.headers.set('Retry-After', result.retryAfter.toString());
  }
  
  return response;
}

export function createRateLimitMiddleware(options: RateLimitMiddlewareOptions = {}) {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const keyGenerator = opts.keyGenerator || defaultKeyGenerator;
  
  const rateLimiter = createRateLimiter(
    getRedis(),
    opts.preset || 'standard',
    { keyPrefix: 'rl:api:', ...opts.config }
  );

  return async function rateLimitMiddleware(
    req: NextRequest,
    handler: () => Promise<NextResponse>
  ): Promise<NextResponse> {
    if (opts.skipIf?.(req)) {
      return handler();
    }

    const identifier = keyGenerator(req);
    const result = await rateLimiter.consume(identifier);

    if (!result.allowed) {
      await auditLog({
        action: 'RATE_LIMIT_EXCEEDED',
        resource: req.nextUrl.pathname,
        metadata: {
          identifier,
          blocked: result.blocked,
          retryAfter: result.retryAfter,
        },
      });

      opts.onRateLimited?.(req, result);

      const response = NextResponse.json(
        {
          error: 'Too Many Requests',
          message: result.blocked 
            ? 'You have been temporarily blocked due to excessive requests'
            : 'Rate limit exceeded. Please try again later.',
          retryAfter: result.retryAfter,
        },
        { status: 429 }
      );

      if (opts.headers) {
        const limit = opts.config?.maxRequests || 100;
        addRateLimitHeaders(response, result, limit);
      }

      return response;
    }

    const response = await handler();

    if (opts.headers) {
      const limit = opts.config?.maxRequests || 100;
      addRateLimitHeaders(response, result, limit);
    }

    return response;
  };
}

export const authRateLimiter = createRateLimitMiddleware({
  preset: 'auth',
  keyGenerator: (req) => {
    const body = req.headers.get('x-auth-email') || '';
    const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
    return `auth:${body || ip}`;
  },
  onRateLimited: async (req, result) => {
    await auditLog({
      action: 'AUTH_RATE_LIMIT_EXCEEDED',
      resource: 'authentication',
      severity: 'warning',
      metadata: {
        ip: req.headers.get('x-forwarded-for'),
        blocked: result.blocked,
      },
    });
  },
});

export const apiRateLimiter = createRateLimitMiddleware({
  preset: 'api',
  headers: true,
});

export const strictRateLimiter = createRateLimitMiddleware({
  preset: 'strict',
  headers: true,
  onRateLimited: async (req, result) => {
    await auditLog({
      action: 'STRICT_RATE_LIMIT_EXCEEDED',
      resource: req.nextUrl.pathname,
      severity: 'critical',
      metadata: {
        blocked: result.blocked,
        retryAfter: result.retryAfter,
      },
    });
  },
});

export async function closeRateLimitConnection(): Promise<void> {
  if (redisClient) {
    await redisClient.quit();
    redisClient = null;
  }
}
