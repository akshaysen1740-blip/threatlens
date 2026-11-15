import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { config } from '../config';
import { logger } from '../logger';
import { RefreshToken } from '../models/RefreshToken';
import { User } from '../models/User';
import { AppError } from '../utils/errors';
import { AuthUser, signAccessToken, signRefreshToken, verifyRefreshToken } from './token.service';

const BCRYPT_ROUNDS = 12;

async function issueTokens(user: AuthUser, family: string = crypto.randomUUID()) {
  const accessToken = signAccessToken(user);
  const refresh = signRefreshToken(user.id, family);
  await RefreshToken.create({
    jti: refresh.jti,
    userId: user.id,
    family,
    expiresAt: refresh.expiresAt,
  });
  return {
    user,
    tokenType: 'Bearer',
    accessToken,
    expiresIn: config.ACCESS_TOKEN_TTL_SECONDS,
    refreshToken: refresh.token,
  };
}

export async function register(email: string, password: string) {
  const existing = await User.exists({ email });
  if (existing) throw new AppError(409, 'An account with this email already exists');

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const user = await User.create({ email, passwordHash });
  return issueTokens({ id: user.id, email: user.email });
}

export async function login(email: string, password: string) {
  const user = await User.findOne({ email }).select('+passwordHash');
  // Same message for "no user" and "wrong password" so attackers can't enumerate accounts
  const valid = user ? await bcrypt.compare(password, user.passwordHash) : false;
  if (!user || !valid) throw new AppError(401, 'Invalid email or password');
  return issueTokens({ id: user.id, email: user.email });
}

/**
 * Refresh token rotation: every refresh token can be used exactly once.
 * Using an already-used token means it was probably stolen, so the whole
 * token family is revoked and the user must log in again.
 */
export async function refresh(refreshToken: string) {
  const { userId, jti, family } = verifyRefreshToken(refreshToken);

  // Atomically mark this token as used; null means it was already used or unknown
  const current = await RefreshToken.findOneAndUpdate(
    { jti, revokedAt: null },
    { $set: { revokedAt: new Date() } },
  );

  if (!current) {
    const known = await RefreshToken.exists({ jti });
    if (known) {
      await RefreshToken.updateMany({ family, revokedAt: null }, { $set: { revokedAt: new Date() } });
      logger.warn({ userId, family }, 'Refresh token reuse detected; token family revoked');
      throw new AppError(401, 'Refresh token reuse detected. Please log in again.');
    }
    throw new AppError(401, 'Invalid or expired refresh token');
  }

  const user = await User.findById(userId);
  if (!user) throw new AppError(401, 'User no longer exists');
  return issueTokens({ id: user.id, email: user.email }, family);
}

export async function logout(refreshToken: string) {
  try {
    const { jti } = verifyRefreshToken(refreshToken);
    await RefreshToken.updateOne({ jti, revokedAt: null }, { $set: { revokedAt: new Date() } });
  } catch {
    // Logging out with an invalid token is a no-op
  }
}
