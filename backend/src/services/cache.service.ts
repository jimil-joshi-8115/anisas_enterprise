import { redisClient } from '../config/redis';
import { logger } from '../utils/logger';

const localCache = new Map<string, { value: any; expiresAt: number }>();

export class CacheService {
  public static async get<T>(key: string): Promise<T | null> {
    try {
      if (redisClient && redisClient.status === 'ready') {
        const val = await redisClient.get(key);
        if (val) return JSON.parse(val) as T;
      }
    } catch (e) {
      logger.debug(`Redis cache fetch error: ${(e as Error).message}`);
    }

    // In-Memory Fallback
    const cached = localCache.get(key);
    if (cached) {
      if (Date.now() < cached.expiresAt) {
        return cached.value as T;
      }
      localCache.delete(key);
    }
    return null;
  }

  public static async set(key: string, value: any, ttlSeconds: number = 3600): Promise<void> {
    try {
      if (redisClient && redisClient.status === 'ready') {
        await redisClient.set(key, JSON.stringify(value), 'EX', ttlSeconds);
      }
    } catch (e) {
      logger.debug(`Redis cache set error: ${(e as Error).message}`);
    }

    localCache.set(key, {
      value,
      expiresAt: Date.now() + ttlSeconds * 1000
    });
  }
}
