import { RequestHandler } from 'express';
import { ZodTypeAny } from 'zod';
import { AppError } from '../utils/errors';

export const validateBody =
  (schema: ZodTypeAny): RequestHandler =>
  (req, _res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      return next(new AppError(400, 'Validation failed', result.error.flatten()));
    }
    req.body = result.data;
    next();
  };
