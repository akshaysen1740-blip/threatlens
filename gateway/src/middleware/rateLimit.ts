import rateLimit from 'express-rate-limit';

const options = { standardHeaders: 'draft-7' as const, legacyHeaders: false };

export const apiLimiter = rateLimit({
  ...options,
  windowMs: 15 * 60 * 1000,
  limit: 300,
  message: { error: { message: 'Too many requests, please try again later.' } },
});

export const authLimiter = rateLimit({
  ...options,
  windowMs: 15 * 60 * 1000,
  limit: 20,
  message: { error: { message: 'Too many authentication attempts, please try again later.' } },
});

export const scanLimiter = rateLimit({
  ...options,
  windowMs: 60 * 1000,
  limit: 20,
  keyGenerator: (req) => (req.user ? `user:${req.user.id}` : `ip:${req.ip}`),
  message: { error: { message: 'Scan rate limit reached, please slow down.' } },
});
