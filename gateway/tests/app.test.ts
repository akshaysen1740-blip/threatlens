import request from 'supertest';
import { createApp } from '../src/app';

const app = createApp();

describe('HTTP app', () => {
  it('GET /health/live returns ok', async () => {
    const res = await request(app).get('/health/live');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  it('sets security headers', async () => {
    const res = await request(app).get('/health/live');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  it('serves the OpenAPI spec', async () => {
    const res = await request(app).get('/docs.json');
    expect(res.status).toBe(200);
    expect(res.body.openapi).toBe('3.0.3');
  });

  it('rejects scan requests without a token', async () => {
    const res = await request(app).get('/api/scans');
    expect(res.status).toBe(401);
  });

  it('rejects scan requests with an invalid token', async () => {
    const res = await request(app).get('/api/scans').set('Authorization', 'Bearer not-a-real-token');
    expect(res.status).toBe(401);
  });

  it('validates the register body before touching the database', async () => {
    const res = await request(app).post('/api/auth/register').send({ email: 'bad', password: '1' });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toBe('Validation failed');
  });

  it('returns 400 for malformed JSON', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .set('Content-Type', 'application/json')
      .send('{"email": ');
    expect(res.status).toBe(400);
  });

  it('returns 404 for unknown routes', async () => {
    const res = await request(app).get('/api/nope');
    expect(res.status).toBe(404);
  });
});
