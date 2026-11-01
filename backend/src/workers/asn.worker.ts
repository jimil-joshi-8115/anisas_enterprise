import { Worker, Job } from 'bullmq';
import { redisClient } from '../config/redis';
import { ASNService } from '../services/asn.service';
import { logger } from '../utils/logger';

if (redisClient && redisClient.status === 'ready') {
  const worker = new Worker('asn-scans', async (job: Job) => {
    const { scanId, targetIp } = job.data;
    logger.info(`Processing background BullMQ job ${job.id} for IP: ${targetIp}`);
    return await ASNService.executeScan(scanId, targetIp);
  }, {
    connection: redisClient as any
  });

  worker.on('completed', (job) => {
    logger.info(`Scan job ${job.id} completed successfully.`);
  });

  worker.on('failed', (job, err) => {
    logger.error(`Scan job ${job?.id} failed: ${err.message}`);
  });
}
