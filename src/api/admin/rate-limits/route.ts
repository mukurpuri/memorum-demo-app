import { NextRequest, NextResponse } from 'next/server';
import { Redis } from 'ioredis';
import { env } from '../../../config/env';
import { requireAuth, requireRole } from '../../../auth/middleware';
import { auditLog } from '../../../audit/logger';
import { RateLimiter, RATE_LIMIT_PRESETS } from '../../../security/rate-limiter';

let redis: Redis | null = null;

function getRedis(): Redis {
  if (!redis) {
    redis = new Redis(env.REDIS_URL);
  }
  return redis;
}

export async function GET(req: NextRequest) {
  const authResult = await requireAuth(req);
  if (!authResult.authenticated) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const roleResult = await requireRole(req, ['admin', 'superadmin']);
  if (!roleResult.authorized) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }

  try {
    const redisClient = getRedis();
    const searchParams = req.nextUrl.searchParams;
    const prefix = searchParams.get('prefix') || 'rl:';
    const limit = parseInt(searchParams.get('limit') || '100', 10);

    const keys = await redisClient.keys(`${prefix}*`);
    const limitedKeys = keys.slice(0, limit);

    const rateLimitData: Array<{
      key: string;
      type: 'window' | 'block';
      identifier: string;
      count?: number;
      ttl: number;
    }> = [];

    for (const key of limitedKeys) {
      const ttl = await redisClient.pttl(key);
      const isBlock = key.includes(':block:');
      const isWindow = key.includes(':window:');

      if (isWindow) {
        const count = await redisClient.zcard(key);
        const identifier = key.split(':window:')[1];
        rateLimitData.push({
          key,
          type: 'window',
          identifier,
          count,
          ttl,
        });
      } else if (isBlock) {
        const identifier = key.split(':block:')[1];
        rateLimitData.push({
          key,
          type: 'block',
          identifier,
          ttl,
        });
      }
    }

    await auditLog({
      action: 'RATE_LIMIT_LIST_VIEWED',
      userId: authResult.userId,
      resource: 'rate-limits',
      metadata: {
        totalKeys: keys.length,
        returned: rateLimitData.length,
      },
    });

    return NextResponse.json({
      success: true,
      data: {
        rateLimits: rateLimitData,
        total: keys.length,
        presets: RATE_LIMIT_PRESETS,
      },
    });
  } catch (error) {
    console.error('Failed to fetch rate limits:', error);
    return NextResponse.json(
      { error: 'Failed to fetch rate limits' },
      { status: 500 }
    );
  }
}

export async function DELETE(req: NextRequest) {
  const authResult = await requireAuth(req);
  if (!authResult.authenticated) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const roleResult = await requireRole(req, ['superadmin']);
  if (!roleResult.authorized) {
    return NextResponse.json({ error: 'Forbidden - Superadmin required' }, { status: 403 });
  }

  try {
    const body = await req.json();
    const { identifier, type } = body as { identifier: string; type?: 'window' | 'block' | 'all' };

    if (!identifier) {
      return NextResponse.json(
        { error: 'Identifier is required' },
        { status: 400 }
      );
    }

    const redisClient = getRedis();
    const keysToDelete: string[] = [];

    if (type === 'window' || type === 'all' || !type) {
      keysToDelete.push(`rl:api:window:${identifier}`);
    }
    if (type === 'block' || type === 'all') {
      keysToDelete.push(`rl:api:block:${identifier}`);
    }

    const deletedCount = await redisClient.del(...keysToDelete);

    await auditLog({
      action: 'RATE_LIMIT_RESET',
      userId: authResult.userId,
      resource: 'rate-limits',
      severity: 'warning',
      metadata: {
        identifier,
        type: type || 'window',
        keysDeleted: deletedCount,
      },
    });

    return NextResponse.json({
      success: true,
      message: `Rate limit reset for ${identifier}`,
      deletedKeys: deletedCount,
    });
  } catch (error) {
    console.error('Failed to reset rate limit:', error);
    return NextResponse.json(
      { error: 'Failed to reset rate limit' },
      { status: 500 }
    );
  }
}

export async function POST(req: NextRequest) {
  const authResult = await requireAuth(req);
  if (!authResult.authenticated) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const roleResult = await requireRole(req, ['superadmin']);
  if (!roleResult.authorized) {
    return NextResponse.json({ error: 'Forbidden - Superadmin required' }, { status: 403 });
  }

  try {
    const body = await req.json();
    const { identifier, action, duration } = body as {
      identifier: string;
      action: 'block' | 'unblock';
      duration?: number;
    };

    if (!identifier || !action) {
      return NextResponse.json(
        { error: 'Identifier and action are required' },
        { status: 400 }
      );
    }

    const redisClient = getRedis();
    const blockKey = `rl:api:block:${identifier}`;

    if (action === 'block') {
      const blockDuration = duration || 3600000;
      await redisClient.set(blockKey, '1', 'PX', blockDuration);

      await auditLog({
        action: 'RATE_LIMIT_MANUAL_BLOCK',
        userId: authResult.userId,
        resource: 'rate-limits',
        severity: 'critical',
        metadata: {
          identifier,
          duration: blockDuration,
        },
      });

      return NextResponse.json({
        success: true,
        message: `Blocked ${identifier} for ${blockDuration}ms`,
      });
    } else if (action === 'unblock') {
      await redisClient.del(blockKey);

      await auditLog({
        action: 'RATE_LIMIT_MANUAL_UNBLOCK',
        userId: authResult.userId,
        resource: 'rate-limits',
        severity: 'warning',
        metadata: {
          identifier,
        },
      });

      return NextResponse.json({
        success: true,
        message: `Unblocked ${identifier}`,
      });
    }

    return NextResponse.json(
      { error: 'Invalid action. Use "block" or "unblock"' },
      { status: 400 }
    );
  } catch (error) {
    console.error('Failed to manage rate limit:', error);
    return NextResponse.json(
      { error: 'Failed to manage rate limit' },
      { status: 500 }
    );
  }
}
