import { Queue } from 'bullmq';
import { env } from '../config/env';
import { redisClient } from '../config/redis';
import { logger } from '../utils/logger';

let asnQueue: Queue | null = null;

try {
  if (redisClient && redisClient.status === 'ready') {
    asnQueue = new Queue('asn-scans', {
      connection: redisClient as any
    });
  }
} catch (e) {
  logger.warn('BullMQ Redis Queue disabled. Using synchronous async fallback execution.');
}

export { asnQueue };
