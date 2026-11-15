import 'dotenv/config';
import { z } from 'zod';

const DEV_ACCESS_SECRET = 'dev-access-secret-change-me-in-production';
const DEV_REFRESH_SECRET = 'dev-refresh-secret-change-me-in-production';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  LOG_LEVEL: z.string().default('info'),

  MONGO_URI: z.string().default('mongodb://localhost:27017/threatlens'),
  REDIS_URL: z.string().default('redis://localhost:6379'),

  JWT_ACCESS_SECRET: z.string().min(16).default(DEV_ACCESS_SECRET),
  JWT_REFRESH_SECRET: z.string().min(16).default(DEV_REFRESH_SECRET),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(900),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().positive().default(7),

  CORS_ORIGIN: z.string().default('*'),

  JOBS_STREAM: z.string().default('scan:jobs'),
  EVENTS_STREAM: z.string().default('scan:events'),
  EVENTS_GROUP: z.string().default('gateway'),
  SCAN_TIMEOUT_MS: z.coerce.number().int().positive().default(120_000),
});

const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
  // eslint-disable-next-line no-console
  console.error('Invalid environment configuration', parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const config = parsed.data;

export const usingDevSecrets =
  config.JWT_ACCESS_SECRET === DEV_ACCESS_SECRET || config.JWT_REFRESH_SECRET === DEV_REFRESH_SECRET;
