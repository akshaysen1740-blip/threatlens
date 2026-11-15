/** OpenAPI 3 specification served at /docs (Swagger UI) and /docs.json. */
const errorResponse = {
  description: 'Error',
  content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
};

const authResponse = {
  description: 'Authenticated',
  content: { 'application/json': { schema: { $ref: '#/components/schemas/AuthResponse' } } },
};

export const openApiSpec = {
  openapi: '3.0.3',
  info: {
    title: 'ThreatLens API',
    version: '1.0.0',
    description:
      'AI-powered phishing and URL threat scanner.\n\n' +
      '1. Register or log in to get an access token.\n' +
      '2. Click **Authorize** and paste the access token.\n' +
      '3. Submit a scan with `POST /api/scans`. It returns `202` immediately with status `queued`.\n' +
      '4. Poll `GET /api/scans/{id}` or listen to the `scan:update` WebSocket event for the result.',
  },
  servers: [{ url: '/' }],
  tags: [{ name: 'Auth' }, { name: 'Scans' }, { name: 'Health' }],
  components: {
    securitySchemes: {
      bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
    },
    schemas: {
      Error: {
        type: 'object',
        properties: {
          error: {
            type: 'object',
            properties: { message: { type: 'string' }, details: { type: 'object' } },
          },
        },
      },
      Credentials: {
        type: 'object',
        required: ['email', 'password'],
        properties: {
          email: { type: 'string', format: 'email', example: 'akshay@example.com' },
          password: { type: 'string', example: 'Str0ngPassw0rd' },
        },
      },
      RefreshRequest: {
        type: 'object',
        required: ['refreshToken'],
        properties: { refreshToken: { type: 'string' } },
      },
      AuthResponse: {
        type: 'object',
        properties: {
          user: { type: 'object', properties: { id: { type: 'string' }, email: { type: 'string' } } },
          tokenType: { type: 'string', example: 'Bearer' },
          accessToken: { type: 'string' },
          expiresIn: { type: 'integer', example: 900 },
          refreshToken: { type: 'string' },
        },
      },
      CreateUrlScan: {
        type: 'object',
        required: ['type', 'url'],
        properties: {
          type: { type: 'string', enum: ['url'] },
          url: { type: 'string', example: 'http://paypa1-secure-login.xyz/verify' },
        },
      },
      CreateEmailScan: {
        type: 'object',
        required: ['type', 'rawEmail'],
        properties: {
          type: { type: 'string', enum: ['email'] },
          rawEmail: {
            type: 'string',
            description: 'Full raw email source (headers + body), e.g. the contents of a .eml file',
          },
        },
      },
      Finding: {
        type: 'object',
        properties: {
          id: { type: 'string', example: 'typosquat_paypal' },
          title: { type: 'string', example: 'Lookalike of a well-known brand' },
          severity: { type: 'string', enum: ['info', 'low', 'medium', 'high', 'critical'] },
          detail: { type: 'string' },
        },
      },
      Scan: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          type: { type: 'string', enum: ['url', 'email'] },
          target: { type: 'string' },
          status: { type: 'string', enum: ['queued', 'scanning', 'done', 'failed'] },
          attempts: { type: 'integer' },
          riskScore: { type: 'integer', nullable: true, minimum: 0, maximum: 100 },
          verdict: { type: 'string', nullable: true, enum: ['safe', 'suspicious', 'malicious'] },
          findings: { type: 'array', items: { $ref: '#/components/schemas/Finding' } },
          explanation: { type: 'string', nullable: true },
          explanationSource: { type: 'string', nullable: true, enum: ['ai', 'rules'] },
          details: { type: 'object', nullable: true },
          error: { type: 'string', nullable: true },
          createdAt: { type: 'string', format: 'date-time' },
          startedAt: { type: 'string', format: 'date-time', nullable: true },
          completedAt: { type: 'string', format: 'date-time', nullable: true },
        },
      },
    },
  },
  paths: {
    '/api/auth/register': {
      post: {
        tags: ['Auth'],
        summary: 'Create an account',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/Credentials' } } },
        },
        responses: { 201: authResponse, 400: errorResponse, 409: errorResponse },
      },
    },
    '/api/auth/login': {
      post: {
        tags: ['Auth'],
        summary: 'Log in',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/Credentials' } } },
        },
        responses: { 200: authResponse, 401: errorResponse },
      },
    },
    '/api/auth/refresh': {
      post: {
        tags: ['Auth'],
        summary: 'Rotate tokens (each refresh token works only once)',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/RefreshRequest' } } },
        },
        responses: { 200: authResponse, 401: errorResponse },
      },
    },
    '/api/auth/logout': {
      post: {
        tags: ['Auth'],
        summary: 'Revoke a refresh token',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/RefreshRequest' } } },
        },
        responses: { 204: { description: 'Logged out' } },
      },
    },
    '/api/auth/me': {
      get: {
        tags: ['Auth'],
        summary: 'Current user',
        security: [{ bearerAuth: [] }],
        responses: { 200: { description: 'Current user' }, 401: errorResponse },
      },
    },
    '/api/scans': {
      post: {
        tags: ['Scans'],
        summary: 'Submit a URL or email for scanning',
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                oneOf: [
                  { $ref: '#/components/schemas/CreateUrlScan' },
                  { $ref: '#/components/schemas/CreateEmailScan' },
                ],
              },
            },
          },
        },
        responses: {
          202: {
            description: 'Scan accepted and queued',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Scan' } } },
          },
          400: errorResponse,
          401: errorResponse,
          429: errorResponse,
          503: errorResponse,
        },
      },
      get: {
        tags: ['Scans'],
        summary: 'List your scans (newest first)',
        security: [{ bearerAuth: [] }],
        parameters: [
          { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 20, maximum: 50 } },
          {
            name: 'status',
            in: 'query',
            schema: { type: 'string', enum: ['queued', 'scanning', 'done', 'failed'] },
          },
        ],
        responses: { 200: { description: 'Paginated scans' }, 401: errorResponse },
      },
    },
    '/api/scans/{id}': {
      get: {
        tags: ['Scans'],
        summary: 'Get one scan',
        security: [{ bearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: {
            description: 'Scan',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Scan' } } },
          },
          401: errorResponse,
          404: errorResponse,
        },
      },
    },
    '/health/live': {
      get: { tags: ['Health'], summary: 'Liveness probe', responses: { 200: { description: 'Alive' } } },
    },
    '/health/ready': {
      get: {
        tags: ['Health'],
        summary: 'Readiness probe (MongoDB + Redis)',
        responses: { 200: { description: 'Ready' }, 503: { description: 'Not ready' } },
      },
    },
  },
};
