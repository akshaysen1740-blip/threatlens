import { RequestHandler } from 'express';
import { AuthUser, verifyAccessToken } from '../services/token.service';

declare module 'express-serve-static-core' {
  interface Request {
    user?: AuthUser;
  }
}

export const requireAuth: RequestHandler = (req, _res, next) => {
  const header = req.headers.authorization ?? '';
  const [scheme, token] = header.split(' ');
  try {
    req.user = verifyAccessToken(scheme === 'Bearer' ? token : undefined);
    next();
  } catch (err) {
    next(err);
  }
};
