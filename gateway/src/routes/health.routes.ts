import { Router } from 'express';
import { isDbReady } from '../db';
import { getRedis } from '../redis';

export const healthRouter = Router();

/** Liveness: the process is up. */
healthRouter.get('/live', (_req, res) => {
  res.json({ status: 'ok' });
});

/** Readiness: dependencies are reachable, so the service can take traffic. */
healthRouter.get('/ready', async (_req, res) => {
  const mongo = isDbReady();
  let redis = false;
  try {
    const timeout = new Promise<never>((_, reject) => setTimeout(() => reject(new Error('timeout')), 2000));
    redis = (await Promise.race([getRedis().ping(), timeout])) === 'PONG';
  } catch {
    redis = false;
  }
  const ready = mongo && redis;
  res.status(ready ? 200 : 503).json({ status: ready ? 'ready' : 'not_ready', checks: { mongo, redis } });
});
