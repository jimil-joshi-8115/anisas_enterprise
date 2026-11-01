import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger';

export const prisma = new PrismaClient();

// In-Memory store fallback for live development when postgres is offline
export const memoryStore = {
  scans: new Map<string, any>(),
  history: [] as any[]
};
