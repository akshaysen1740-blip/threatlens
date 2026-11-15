import jwt from 'jsonwebtoken';
import {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
} from '../src/services/token.service';

const user = { id: '65f000000000000000000001', email: 'akshay@example.com' };

describe('token.service', () => {
  it('signs and verifies an access token', () => {
    const token = signAccessToken(user);
    expect(verifyAccessToken(token)).toEqual(user);
  });

  it('rejects a missing access token', () => {
    expect(() => verifyAccessToken(undefined)).toThrow('Missing access token');
  });

  it('rejects a tampered access token', () => {
    const token = signAccessToken(user);
    const tampered = token.slice(0, -2) + (token.endsWith('a') ? 'bb' : 'aa');
    expect(() => verifyAccessToken(tampered)).toThrow('Invalid or expired access token');
  });

  it('rejects a token signed with a different secret', () => {
    const forged = jwt.sign({ type: 'access', email: user.email }, 'attacker-secret-1234567890', {
      subject: user.id,
    });
    expect(() => verifyAccessToken(forged)).toThrow();
  });

  it('does not accept a refresh token as an access token', () => {
    const { token } = signRefreshToken(user.id, 'family-1');
    expect(() => verifyAccessToken(token)).toThrow();
  });

  it('signs and verifies a refresh token with jti and family', () => {
    const { token, jti, expiresAt } = signRefreshToken(user.id, 'family-1');
    const payload = verifyRefreshToken(token);
    expect(payload).toEqual({ userId: user.id, jti, family: 'family-1' });
    expect(expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it('does not accept an access token as a refresh token', () => {
    expect(() => verifyRefreshToken(signAccessToken(user))).toThrow('Invalid or expired refresh token');
  });
});
