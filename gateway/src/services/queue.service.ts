import { config } from '../config';
import { getRedis } from '../redis';

export interface ScanJob {
  scanId: string;
  userId: string;
  type: 'url' | 'email';
  payload: Record<string, unknown>;
}

/**
 * Publishes a scan job to the Redis Stream. The Python worker reads it through a
 * consumer group, so several workers can share the load and unacknowledged jobs
 * are never lost.
 */
export async function enqueueScan(job: ScanJob): Promise<string> {
  const id = await getRedis().call(
    'XADD',
    config.JOBS_STREAM,
    'MAXLEN',
    '~',
    '10000',
    '*',
    'scanId',
    job.scanId,
    'userId',
    job.userId,
    'type',
    job.type,
    'payload',
    JSON.stringify(job.payload),
    'attempt',
    '1',
    'enqueuedAt',
    new Date().toISOString(),
  );
  return String(id);
}
