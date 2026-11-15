import { ErrorRequestHandler, RequestHandler } from 'express';
import { logger } from '../logger';
import { AppError } from '../utils/errors';

export const notFoundHandler: RequestHandler = (req, res) => {
  res.status(404).json({ error: { message: `Route ${req.method} ${req.path} not found` } });
};

export const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
  if (err instanceof AppError) {
    res.status(err.statusCode).json({ error: { message: err.message, details: err.details } });
    return;
  }
  if (err?.type === 'entity.too.large') {
    res.status(413).json({ error: { message: 'Request body too large' } });
    return;
  }
  if (err?.type === 'entity.parse.failed') {
    res.status(400).json({ error: { message: 'Invalid JSON body' } });
    return;
  }
  logger.error({ err }, 'Unhandled error');
  res.status(500).json({ error: { message: 'Internal server error' } });
};
