import Redis from 'ioredis';
import { env } from './env';
import { logger } from '../utils/logger';

let redisClient: Redis | null = null;

try {
  redisClient = new Redis(env.REDIS_URL, {
    maxRetriesPerRequest: null,
    enableOfflineQueue: false,
    retryStrategy(times) {
      if (times > 3) {
        logger.warn('Redis connection limit reached. Operating with fallback memory queue/cache.');
        return null;
      }
      return Math.min(times * 100, 2000);
    }
  });

  redisClient.on('error', (err) => {
    logger.warn(`Redis Error: ${err.message}. Using fallback in-memory caching.`);
  });
} catch (e) {
  logger.warn('Redis initialization skipped. Operating in fallback in-memory mode.');
}

export { redisClient };
