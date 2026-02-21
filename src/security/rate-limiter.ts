import { Redis } from 'ioredis';

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  keyPrefix: string;
  blockDuration?: number;
  skipFailedRequests?: boolean;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
  retryAfter?: number;
  blocked?: boolean;
}

export interface RateLimitInfo {
  identifier: string;
  currentCount: number;
  limit: number;
  windowStart: Date;
  windowEnd: Date;
}

const DEFAULT_CONFIG: Partial<RateLimitConfig> = {
  windowMs: 60000,
  maxRequests: 100,
  keyPrefix: 'rl:',
  blockDuration: 300000,
  skipFailedRequests: false,
};

export class RateLimiter {
  private redis: Redis;
  private config: RateLimitConfig;
  private blockedKeys: Map<string, number> = new Map();

  constructor(redis: Redis, config: Partial<RateLimitConfig> = {}) {
    this.redis = redis;
    this.config = { ...DEFAULT_CONFIG, ...config } as RateLimitConfig;
  }

  async check(identifier: string): Promise<RateLimitResult> {
    const key = this.buildKey(identifier);
    const blockKey = this.buildBlockKey(identifier);
    const now = Date.now();

    const isBlocked = await this.isBlocked(blockKey);
    if (isBlocked) {
      const ttl = await this.redis.pttl(blockKey);
      return {
        allowed: false,
        remaining: 0,
        resetAt: new Date(now + ttl),
        retryAfter: Math.ceil(ttl / 1000),
        blocked: true,
      };
    }

    const windowStart = now - this.config.windowMs;
    
    await this.redis.zremrangebyscore(key, 0, windowStart);
    
    const currentCount = await this.redis.zcard(key);
    
    if (currentCount >= this.config.maxRequests) {
      if (this.config.blockDuration) {
        await this.block(blockKey);
      }
      
      const oldestEntry = await this.redis.zrange(key, 0, 0, 'WITHSCORES');
      const resetAt = oldestEntry.length > 1 
        ? new Date(parseInt(oldestEntry[1]) + this.config.windowMs)
        : new Date(now + this.config.windowMs);
      
      return {
        allowed: false,
        remaining: 0,
        resetAt,
        retryAfter: Math.ceil((resetAt.getTime() - now) / 1000),
      };
    }

    return {
      allowed: true,
      remaining: this.config.maxRequests - currentCount - 1,
      resetAt: new Date(now + this.config.windowMs),
    };
  }

  async consume(identifier: string): Promise<RateLimitResult> {
    const result = await this.check(identifier);
    
    if (!result.allowed) {
      return result;
    }

    const key = this.buildKey(identifier);
    const now = Date.now();
    const uniqueId = `${now}:${Math.random().toString(36).substr(2, 9)}`;
    
    await this.redis.zadd(key, now, uniqueId);
    await this.redis.pexpire(key, this.config.windowMs);

    return {
      ...result,
      remaining: result.remaining,
    };
  }

  async reset(identifier: string): Promise<void> {
    const key = this.buildKey(identifier);
    const blockKey = this.buildBlockKey(identifier);
    
    await Promise.all([
      this.redis.del(key),
      this.redis.del(blockKey),
    ]);
    
    this.blockedKeys.delete(identifier);
  }

  async getInfo(identifier: string): Promise<RateLimitInfo> {
    const key = this.buildKey(identifier);
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    
    await this.redis.zremrangebyscore(key, 0, windowStart);
    const currentCount = await this.redis.zcard(key);
    
    return {
      identifier,
      currentCount,
      limit: this.config.maxRequests,
      windowStart: new Date(windowStart),
      windowEnd: new Date(now),
    };
  }

  private buildKey(identifier: string): string {
    return `${this.config.keyPrefix}window:${identifier}`;
  }

  private buildBlockKey(identifier: string): string {
    return `${this.config.keyPrefix}block:${identifier}`;
  }

  private async isBlocked(blockKey: string): Promise<boolean> {
    const exists = await this.redis.exists(blockKey);
    return exists === 1;
  }

  private async block(blockKey: string): Promise<void> {
    if (this.config.blockDuration) {
      await this.redis.set(blockKey, '1', 'PX', this.config.blockDuration);
    }
  }
}

export const RATE_LIMIT_PRESETS = {
  strict: {
    windowMs: 60000,
    maxRequests: 10,
    blockDuration: 600000,
  },
  standard: {
    windowMs: 60000,
    maxRequests: 100,
    blockDuration: 300000,
  },
  relaxed: {
    windowMs: 60000,
    maxRequests: 1000,
    blockDuration: 60000,
  },
  auth: {
    windowMs: 900000,
    maxRequests: 5,
    blockDuration: 3600000,
  },
  api: {
    windowMs: 60000,
    maxRequests: 60,
    blockDuration: 120000,
  },
} as const;

export type RateLimitPreset = keyof typeof RATE_LIMIT_PRESETS;

export function createRateLimiter(
  redis: Redis,
  preset: RateLimitPreset,
  overrides: Partial<RateLimitConfig> = {}
): RateLimiter {
  return new RateLimiter(redis, {
    ...RATE_LIMIT_PRESETS[preset],
    ...overrides,
  });
}
