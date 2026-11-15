import { createScanSchema, credentialsSchema } from '../src/schemas';

describe('createScanSchema', () => {
  it('accepts a full URL', () => {
    const result = createScanSchema.parse({ type: 'url', url: 'https://example.com/login' });
    expect(result).toEqual({ type: 'url', url: 'https://example.com/login' });
  });

  it('adds http:// to a bare domain', () => {
    const result = createScanSchema.parse({ type: 'url', url: 'example.com' });
    expect(result).toEqual({ type: 'url', url: 'http://example.com' });
  });

  it.each(['javascript:alert(1)', 'ftp://example.com', 'not a url', 'localhost'])('rejects %s', (url) => {
    expect(createScanSchema.safeParse({ type: 'url', url }).success).toBe(false);
  });

  it('accepts a raw email', () => {
    const rawEmail = 'From: a@example.com\nSubject: Hi\n\nHello there, this is a test.';
    expect(createScanSchema.safeParse({ type: 'email', rawEmail }).success).toBe(true);
  });

  it('rejects an unknown scan type', () => {
    expect(createScanSchema.safeParse({ type: 'file', url: 'https://example.com' }).success).toBe(false);
  });
});

describe('credentialsSchema', () => {
  it('normalizes the email', () => {
    const result = credentialsSchema.parse({ email: '  Akshay@Example.COM ', password: 'Passw0rd!' });
    expect(result.email).toBe('akshay@example.com');
  });

  it('rejects weak passwords', () => {
    expect(credentialsSchema.safeParse({ email: 'a@b.com', password: 'short' }).success).toBe(false);
    expect(credentialsSchema.safeParse({ email: 'a@b.com', password: 'onlyletters' }).success).toBe(false);
  });
});
