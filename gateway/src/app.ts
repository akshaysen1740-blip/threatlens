import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import { pinoHttp } from 'pino-http';
import swaggerUi from 'swagger-ui-express';
import { config } from './config';
import { openApiSpec } from './docs/openapi';
import { logger } from './logger';
import { errorHandler, notFoundHandler } from './middleware/errorHandler';
import { apiLimiter, authLimiter } from './middleware/rateLimit';
import { authRouter } from './routes/auth.routes';
import { healthRouter } from './routes/health.routes';
import { scanRouter } from './routes/scan.routes';

export function createApp() {
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  // Swagger UI needs a relaxed Content-Security-Policy, so it gets its own Helmet config
  app.get('/docs.json', (_req, res) => {
    res.json(openApiSpec);
  });
  app.use('/docs', helmet({ contentSecurityPolicy: false }), swaggerUi.serve, swaggerUi.setup(openApiSpec));

  app.use(helmet());
  app.use(cors({ origin: config.CORS_ORIGIN === '*' ? '*' : config.CORS_ORIGIN.split(',') }));
  app.use(express.json({ limit: '300kb' }));
  app.use(
    pinoHttp({
      logger,
      autoLogging: { ignore: (req) => (req.url ?? '').startsWith('/health') },
    }),
  );

  app.get('/', (_req, res) => {
    res.json({ name: 'ThreatLens API', docs: '/docs' });
  });
  app.use('/health', healthRouter);
  app.use('/api', apiLimiter);
  app.use('/api/auth', authLimiter, authRouter);
  app.use('/api/scans', scanRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
