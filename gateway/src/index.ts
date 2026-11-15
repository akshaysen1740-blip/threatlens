import http from 'http';
import { createApp } from './app';
import { config, usingDevSecrets } from './config';
import { connectDb, disconnectDb } from './db';
import { logger } from './logger';
import { closeRedis, getRedis } from './redis';
import { ScanEventsListener } from './services/eventsListener';
import { failTimedOutScans } from './services/scanUpdate.service';
import { closeSocket, initSocket } from './socket';

const SWEEP_INTERVAL_MS = 30_000;

async function main() {
  if (usingDevSecrets) {
    logger.warn('Using default development JWT secrets. Set JWT_ACCESS_SECRET and JWT_REFRESH_SECRET for production.');
  }

  await connectDb();
  await getRedis().ping();
  logger.info('Connected to Redis');

  const app = createApp();
  const server = http.createServer(app);
  initSocket(server);

  const listener = new ScanEventsListener();
  await listener.start();

  const sweeper = setInterval(() => {
    failTimedOutScans().catch((err) => logger.error({ err }, 'Timeout sweeper failed'));
  }, SWEEP_INTERVAL_MS);

  server.listen(config.PORT, () => {
    logger.info(`ThreatLens gateway listening on http://localhost:${config.PORT} (docs at /docs)`);
  });

  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ signal }, 'Shutting down gracefully');

    // Force exit if cleanup hangs
    setTimeout(() => process.exit(1), 10_000).unref();

    clearInterval(sweeper);
    await listener.stop();
    await closeSocket(); // also closes the HTTP server
    await disconnectDb();
    await closeRedis();
    logger.info('Shutdown complete');
    process.exit(0);
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

main().catch((err) => {
  logger.fatal({ err }, 'Failed to start gateway');
  process.exit(1);
});
