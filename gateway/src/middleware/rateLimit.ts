import rateLimit from 'express-rate-limit';

const options = { standardHeaders: 'draft-7' as const, legacyHeaders: false };

/** General limit for all API routes. */
export const apiLimiter = rateLimit({
  ...options,
  windowMs: 15 * 60 * 1000,
  limit: 300,
  message: { error: { message: 'Too many requests, please try again later.' } },
});

/** Stricter limit for login/register to slow down brute-force attacks. */
export const authLimiter = rateLimit({
  ...options,
  windowMs: 15 * 60 * 1000,
  limit: 20,
  message: { error: { message: 'Too many authentication attempts, please try again later.' } },
});

/** Limits how fast a client can submit new scans. */
export const scanLimiter = rateLimit({
  ...options,
  windowMs: 60 * 1000,
  limit: 20,
  message: { error: { message: 'Scan rate limit reached, please slow down.' } },
});
