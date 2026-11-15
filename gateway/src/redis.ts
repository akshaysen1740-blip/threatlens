import Redis from 'ioredis';
import { config } from './config';
import { logger } from './logger';

let client: Redis | null = null;

/** Shared connection for normal (non-blocking) commands such as XADD and PING. */
export function getRedis(): Redis {
  if (!client) {
    client = createRedisConnection('main');
  }
  return client;
}

/**
 * Blocking commands (XREADGROUP ... BLOCK) hold the connection while they wait,
 * so the stream consumer gets its own dedicated connection.
 */
export function createRedisConnection(name: string): Redis {
  const conn = new Redis(config.REDIS_URL, { maxRetriesPerRequest: null });
  conn.on('error', (err) => logger.error({ err, connection: name }, 'Redis error'));
  return conn;
}

/** Creates a consumer group (and the stream) if it does not exist yet. */
export async function ensureConsumerGroup(conn: Redis, stream: string, group: string): Promise<void> {
  try {
    await conn.call('XGROUP', 'CREATE', stream, group, '0', 'MKSTREAM');
    logger.info({ stream, group }, 'Created consumer group');
  } catch (err) {
    if (!(err instanceof Error) || !err.message.includes('BUSYGROUP')) throw err;
  }
}

export async function closeRedis(): Promise<void> {
  if (client) {
    await client.quit();
    client = null;
  }
}
