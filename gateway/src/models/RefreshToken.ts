import { Schema, model, Types } from 'mongoose';

/**
 * One document per issued refresh token. Tokens issued from the same login share a
 * "family". If a revoked token is ever used again, the whole family is revoked
 * (refresh token reuse detection).
 */
export interface IRefreshToken {
  jti: string;
  userId: Types.ObjectId;
  family: string;
  expiresAt: Date;
  revokedAt: Date | null;
}

const refreshTokenSchema = new Schema<IRefreshToken>(
  {
    jti: { type: String, required: true, unique: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    family: { type: String, required: true, index: true },
    expiresAt: { type: Date, required: true },
    revokedAt: { type: Date, default: null },
  },
  { timestamps: true },
);

// MongoDB removes expired tokens automatically (TTL index)
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const RefreshToken = model<IRefreshToken>('RefreshToken', refreshTokenSchema);
