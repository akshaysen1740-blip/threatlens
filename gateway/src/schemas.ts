import { z } from 'zod';

export const credentialsSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(128)
    .regex(/[A-Za-z]/, 'Password must contain a letter')
    .regex(/[0-9]/, 'Password must contain a number'),
});

export const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email(),
  password: z.string().min(1).max(128),
});

export const refreshSchema = z.object({
  refreshToken: z.string().min(10),
});

const HAS_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

/** Accepts "example.com" or "https://example.com/path" and normalizes to a full http(s) URL. */
export const scanUrlSchema = z
  .string()
  .trim()
  .min(4)
  .max(2048)
  .transform((value) => (HAS_SCHEME.test(value) ? value : `http://${value}`))
  .refine((value) => {
    try {
      const url = new URL(value);
      return ['http:', 'https:'].includes(url.protocol) && url.hostname.includes('.');
    } catch {
      return false;
    }
  }, 'Must be a valid http(s) URL or domain');

export const createScanSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('url'), url: scanUrlSchema }),
  z.object({
    type: z.literal('email'),
    rawEmail: z
      .string()
      .min(20, 'Paste the full raw email including headers')
      .max(200_000, 'Email is too large (max 200 KB)'),
  }),
]);

export type CreateScanInput = z.infer<typeof createScanSchema>;

export const listScansQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(50).default(20),
  status: z.enum(['queued', 'scanning', 'done', 'failed']).optional(),
});
