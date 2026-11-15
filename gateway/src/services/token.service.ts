import crypto from 'crypto';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { config } from '../config';
import { AppError } from '../utils/errors';

export interface AuthUser {
  id: string;
  email: string;
}

export function signAccessToken(user: AuthUser): string {
  return jwt.sign({ email: user.email, type: 'access' }, config.JWT_ACCESS_SECRET, {
    subject: user.id,
    expiresIn: config.ACCESS_TOKEN_TTL_SECONDS,
  });
}

export function verifyAccessToken(token: string | undefined): AuthUser {
  if (!token) throw new AppError(401, 'Missing access token');
  try {
    const payload = jwt.verify(token, config.JWT_ACCESS_SECRET) as JwtPayload;
    if (payload.type !== 'access' || !payload.sub) throw new Error('Wrong token type');
    return { id: payload.sub, email: String(payload.email) };
  } catch {
    throw new AppError(401, 'Invalid or expired access token');
  }
}

export function signRefreshToken(userId: string, family: string) {
  const jti = crypto.randomUUID();
  const ttlSeconds = config.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60;
  const token = jwt.sign({ family, type: 'refresh' }, config.JWT_REFRESH_SECRET, {
    subject: userId,
    jwtid: jti,
    expiresIn: ttlSeconds,
  });
  return { token, jti, expiresAt: new Date(Date.now() + ttlSeconds * 1000) };
}

export function verifyRefreshToken(token: string) {
  try {
    const payload = jwt.verify(token, config.JWT_REFRESH_SECRET) as JwtPayload;
    if (payload.type !== 'refresh' || !payload.sub || !payload.jti || !payload.family) {
      throw new Error('Malformed refresh token');
    }
    return { userId: payload.sub, jti: payload.jti, family: String(payload.family) };
  } catch {
    throw new AppError(401, 'Invalid or expired refresh token');
  }
}
