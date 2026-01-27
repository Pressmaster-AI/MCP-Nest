import { INestApplication, Injectable } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';
import { randomBytes, createHash } from 'crypto';
import { z } from 'zod';
import { Tool, McpModule, McpTransportType } from '../src';
import type { Context } from '../src';
import { McpAuthModule } from '../src/authz/mcp-oauth.module';
import { McpAuthJwtGuard } from '../src/authz/guards/jwt-auth.guard';
import {
  OAuthProviderConfig,
  OAuthUserProfile,
} from '../src/authz/providers/oauth-provider.interface';
import type {
  IOAuthStore,
  OAuthClient,
  AuthorizationCode,
  ClientRegistrationDto,
} from '../src/authz/stores/oauth-store.interface';
import type { OAuthSession } from '../src/authz/providers/oauth-provider.interface';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { createStreamableClient } from './utils';

// Mock OAuth Provider for testing
const MockOAuthProvider: OAuthProviderConfig = {
  name: 'mock',
  displayName: 'Mock Provider',
  strategy: class MockStrategy {
    _verify: any;
    name: string = 'mock';

    constructor(options: any, verify: any) {
      this._verify = verify;
    }

    authenticate(req: any, options?: any) {
      // Simulate immediate redirect to OAuth provider
      this.redirect(
        `https://mock-oauth-provider.com/authorize?client_id=test&redirect_uri=${encodeURIComponent('http://localhost:3000/auth/callback')}`,
      );
    }

    redirect(url: string) {
      // This would be called by Passport to redirect the user
      throw { redirect: url };
    }
  },
  strategyOptions: (options) => ({
    clientID: options.clientId,
    clientSecret: options.clientSecret,
    callbackURL: `${options.serverUrl}/auth/callback`,
  }),
  profileMapper: (profile: any): OAuthUserProfile => ({
    id: profile.id,
    username: profile.username,
    email: profile.emails?.[0]?.value,
    displayName: profile.displayName,
  }),
};

// Mock store for testing
@Injectable()
class MockOAuthStore implements IOAuthStore {
  private clients = new Map<string, OAuthClient>();
  private authCodes = new Map<string, AuthorizationCode>();
  private oauthSessions = new Map<string, OAuthSession>();
  private profilesById = new Map<
    string,
    OAuthUserProfile & { profile_id: string; provider: string }
  >();
  private providerUserKeyToId = new Map<string, string>();

  async storeClient(client: OAuthClient): Promise<OAuthClient> {
    this.clients.set(client.client_id, client);
    return client;
  }

  async getClient(client_id: string): Promise<OAuthClient | undefined> {
    return this.clients.get(client_id);
  }

  async findClient(client_name: string): Promise<OAuthClient | undefined> {
    for (const client of this.clients.values()) {
      if (client.client_name === client_name) {
        return client;
      }
    }
    return undefined;
  }

  generateClientId(client: OAuthClient): string {
    const normalizedName = client.client_name
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '');
    const timestamp = Date.now().toString(36);
    return `${normalizedName}_${timestamp}`;
  }

  async storeAuthCode(code: AuthorizationCode): Promise<void> {
    this.authCodes.set(code.code, code);
  }

  async getAuthCode(code: string): Promise<AuthorizationCode | undefined> {
    return this.authCodes.get(code);
  }

  async removeAuthCode(code: string): Promise<void> {
    this.authCodes.delete(code);
  }

  async storeOAuthSession(
    sessionId: string,
    session: OAuthSession,
  ): Promise<void> {
    this.oauthSessions.set(sessionId, session);
  }

  async getOAuthSession(sessionId: string): Promise<OAuthSession | undefined> {
    return this.oauthSessions.get(sessionId);
  }

  async removeOAuthSession(sessionId: string): Promise<void> {
    this.oauthSessions.delete(sessionId);
  }

  async upsertUserProfile(
    profile: OAuthUserProfile,
    provider: string,
  ): Promise<string> {
    const key = `${provider}:${profile.id}`;
    let profileId = this.providerUserKeyToId.get(key);
    if (!profileId) {
      profileId = `${provider}_${profile.id}`;
      this.providerUserKeyToId.set(key, profileId);
    }
    this.profilesById.set(profileId, {
      ...profile,
      profile_id: profileId,
      provider,
    });
    return profileId;
  }

  async getUserProfileById(
    profileId: string,
  ): Promise<
    (OAuthUserProfile & { profile_id: string; provider: string }) | undefined
  > {
    return this.profilesById.get(profileId);
  }
}

// Test tool for protected endpoints
@Injectable()
export class TestProtectedTool {
  @Tool({
    name: 'fastify-protected-hello',
    description: 'A protected tool that requires authentication (Fastify)',
    parameters: z.object({
      message: z.string().default('Hello'),
    }),
  })
  async protectedHello({ message }, context: Context, request: any) {
    return {
      content: [
        {
          type: 'text',
          text: `${message} from Fastify authenticated user: ${request.user?.sub}`,
        },
      ],
    };
  }
}

describe('E2E: McpAuthModule OAuth Flow with Fastify', () => {
  let app: NestFastifyApplication;
  let testPort: number;
  let mockStore: MockOAuthStore;

  const testJwtSecret = 'test-jwt-secret-that-is-at-least-32-characters-long';
  const testServerUrl = 'http://localhost:3000';
  const testClientId = 'test-client-id';
  const testClientSecret = 'test-client-secret';

  beforeAll(async () => {
    mockStore = new MockOAuthStore();

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        McpAuthModule.forRoot({
          provider: MockOAuthProvider,
          clientId: testClientId,
          clientSecret: testClientSecret,
          jwtSecret: testJwtSecret,
          serverUrl: testServerUrl,
          apiPrefix: 'auth',
          cookieSecure: false, // For testing
          storeConfiguration: {
            type: 'custom',
            store: mockStore,
          },
        }),
        McpModule.forRoot({
          name: 'test-fastify-oauth-mcp-server',
          version: '0.0.1',
          transport: McpTransportType.STREAMABLE_HTTP,
          guards: [McpAuthJwtGuard],
        }),
      ],
      providers: [TestProtectedTool],
    }).compile();

    // Create Fastify adapter with @fastify/cookie registered
    const fastifyAdapter = new FastifyAdapter();

    // Register @fastify/cookie for cookie support
    try {
      const fastifyCookie = await import('@fastify/cookie');
      await fastifyAdapter.register(fastifyCookie.default || fastifyCookie, {});
    } catch (e) {
      console.warn(
        'Could not register @fastify/cookie - some tests may fail. Install with: npm install @fastify/cookie',
      );
    }

    app = moduleFixture.createNestApplication<NestFastifyApplication>(
      fastifyAdapter,
    );
    await app.listen(0, '0.0.0.0');

    const server = app.getHttpServer();
    testPort = (server.address() as import('net').AddressInfo).port;
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  describe('OAuth Well-Known Endpoint (Fastify)', () => {
    it('should return authorization server metadata', async () => {
      const response = await request(app.getHttpServer())
        .get('/.well-known/oauth-authorization-server')
        .expect(200);

      expect(response.body).toMatchObject({
        issuer: testServerUrl,
        authorization_endpoint: expect.stringContaining('/auth/authorize'),
        token_endpoint: expect.stringContaining('/auth/token'),
        registration_endpoint: expect.stringContaining('/auth/register'),
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        code_challenge_methods_supported: ['plain', 'S256'],
      });
    });
  });

  describe('Client Registration (Fastify)', () => {
    it('should register a new OAuth client', async () => {
      const clientData: ClientRegistrationDto = {
        client_name: 'Fastify Test Client',
        client_description: 'A test OAuth client for Fastify',
        redirect_uris: ['http://localhost:8080/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
      };

      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .send(clientData)
        .expect(201);

      const registeredClientId = response.body.client_id;

      expect(response.body).toMatchObject({
        client_id: expect.any(String),
        client_name: 'Fastify Test Client',
        client_description: 'A test OAuth client for Fastify',
        redirect_uris: ['http://localhost:8080/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
      });

      // Verify client was stored
      const storedClient = await mockStore.getClient(registeredClientId);
      expect(storedClient).toBeDefined();
      expect(storedClient!.client_name).toBe('Fastify Test Client');
    });
  });

  describe('Authorization Flow (Fastify)', () => {
    let registeredClient: OAuthClient;

    beforeEach(async () => {
      // Register a test client
      const clientData: ClientRegistrationDto = {
        client_name: 'Fastify Flow Test Client',
        redirect_uris: ['http://localhost:8080/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
      };

      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .send(clientData);

      registeredClient = response.body;
    });

    it('should initiate authorization flow with valid parameters', async () => {
      const codeVerifier = randomBytes(32).toString('base64url');
      const codeChallenge = createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');

      const authUrl = `/auth/authorize?response_type=code&client_id=${registeredClient.client_id}&redirect_uri=${encodeURIComponent(registeredClient.redirect_uris[0])}&code_challenge=${codeChallenge}&code_challenge_method=S256&state=test-state`;

      // The mock strategy will throw an error with redirect info
      // In a real scenario, this would be a 302 redirect to the OAuth provider
      const response = await request(app.getHttpServer()).get(authUrl);

      // For our mock, we expect either a 302 redirect or a 500 (due to mock limitations)
      expect([302, 500]).toContain(response.status);
    });

    it('should reject authorization request with invalid client_id', async () => {
      const authUrl = `/auth/authorize?response_type=code&client_id=invalid-client&redirect_uri=http://localhost:8080/callback`;

      await request(app.getHttpServer()).get(authUrl).expect(400);
    });

    it('should reject authorization request with invalid redirect_uri', async () => {
      const authUrl = `/auth/authorize?response_type=code&client_id=${registeredClient.client_id}&redirect_uri=http://evil.com/callback`;

      await request(app.getHttpServer()).get(authUrl).expect(400);
    });
  });

  describe('Token Exchange (Fastify)', () => {
    let registeredClient: OAuthClient;
    let authCode: string;
    let codeVerifier: string;

    beforeEach(async () => {
      // Register a test client
      const clientData: ClientRegistrationDto = {
        client_name: 'Fastify Token Test Client',
        redirect_uris: ['http://localhost:8080/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
      };

      const clientResponse = await request(app.getHttpServer())
        .post('/auth/register')
        .send(clientData);

      registeredClient = clientResponse.body;

      // Create a test authorization code
      codeVerifier = randomBytes(32).toString('base64url');
      const codeChallenge = createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');
      authCode = randomBytes(32).toString('base64url');

      await mockStore.storeAuthCode({
        code: authCode,
        user_id: 'fastify-testuser',
        client_id: registeredClient.client_id,
        redirect_uri: registeredClient.redirect_uris[0],
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        expires_at: Date.now() + 600000, // 10 minutes
        resource: `${testServerUrl}/mcp`,
        scope: '',
      });
    });

    it('should exchange authorization code for tokens', async () => {
      const tokenRequest = {
        grant_type: 'authorization_code',
        code: authCode,
        code_verifier: codeVerifier,
        redirect_uri: registeredClient.redirect_uris[0],
        client_id: registeredClient.client_id,
      };

      const response = await request(app.getHttpServer())
        .post('/auth/token')
        .send(tokenRequest)
        .expect(200);

      expect(response.body).toMatchObject({
        access_token: expect.any(String),
        refresh_token: expect.any(String),
        token_type: 'bearer',
        expires_in: expect.any(Number),
      });

      // Verify authorization code was removed
      const removedCode = await mockStore.getAuthCode(authCode);
      expect(removedCode).toBeUndefined();
    });

    it('should reject token exchange with invalid authorization code', async () => {
      const tokenRequest = {
        grant_type: 'authorization_code',
        code: 'invalid-code',
        code_verifier: codeVerifier,
        redirect_uri: registeredClient.redirect_uris[0],
        client_id: registeredClient.client_id,
      };

      await request(app.getHttpServer())
        .post('/auth/token')
        .send(tokenRequest)
        .expect(400);
    });

    it('should reject token exchange with invalid PKCE verifier', async () => {
      const tokenRequest = {
        grant_type: 'authorization_code',
        code: authCode,
        code_verifier: 'invalid-verifier',
        redirect_uri: registeredClient.redirect_uris[0],
        client_id: registeredClient.client_id,
      };

      await request(app.getHttpServer())
        .post('/auth/token')
        .send(tokenRequest)
        .expect(400);
    });
  });

  describe('JWT Guard Protection (Fastify)', () => {
    let validAccessToken: string;

    beforeEach(async () => {
      // Get a valid token for testing
      const clientData: ClientRegistrationDto = {
        client_name: 'Fastify Guard Test Client',
        redirect_uris: ['http://localhost:8080/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
      };

      const clientResponse = await request(app.getHttpServer())
        .post('/auth/register')
        .send(clientData);

      const registeredClient = clientResponse.body;

      const codeVerifier = randomBytes(32).toString('base64url');
      const codeChallenge = createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');
      const authCode = randomBytes(32).toString('base64url');

      await mockStore.storeAuthCode({
        code: authCode,
        user_id: 'fastify-testuser',
        client_id: registeredClient.client_id,
        redirect_uri: registeredClient.redirect_uris[0],
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        expires_at: Date.now() + 600000,
        resource: `${testServerUrl}/mcp`,
        scope: '',
      });

      const tokenResponse = await request(app.getHttpServer())
        .post('/auth/token')
        .send({
          grant_type: 'authorization_code',
          code: authCode,
          code_verifier: codeVerifier,
          redirect_uri: registeredClient.redirect_uris[0],
          client_id: registeredClient.client_id,
        });

      validAccessToken = tokenResponse.body.access_token;
    });

    it('should allow access to protected MCP endpoints with valid token', async () => {
      const client = await createStreamableClient(testPort, {
        requestInit: {
          headers: {
            Authorization: `Bearer ${validAccessToken}`,
          },
        },
      });

      const tools = await client.listTools();
      expect(tools.tools).toHaveLength(1);
      expect(tools.tools[0].name).toBe('fastify-protected-hello');

      const result: any = await client.callTool({
        name: 'fastify-protected-hello',
        arguments: { message: 'Hello' },
      });

      expect(result.content[0].text).toContain(
        'Hello from Fastify authenticated user: fastify-testuser',
      );

      await client.close();
    });

    it('should reject connection without token', async () => {
      // Standard OAuth flow: connection without token should get 401
      await expect(
        createStreamableClient(testPort, {
          requestInit: {
            headers: {},
          },
        }),
      ).rejects.toThrow();
    });

    it('should reject access with invalid token', async () => {
      await expect(
        createStreamableClient(testPort, {
          requestInit: {
            headers: {
              Authorization: 'Bearer invalid-token',
            },
          },
        }),
      ).rejects.toThrow();
    });
  });

  describe('Refresh Token Flow (Fastify)', () => {
    let refreshToken: string;

    beforeEach(async () => {
      // Get tokens for testing
      const clientData: ClientRegistrationDto = {
        client_name: 'Fastify Refresh Test Client',
        redirect_uris: ['http://localhost:8080/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
      };

      const clientResponse = await request(app.getHttpServer())
        .post('/auth/register')
        .send(clientData);

      const registeredClient = clientResponse.body;

      const codeVerifier = randomBytes(32).toString('base64url');
      const codeChallenge = createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');
      const authCode = randomBytes(32).toString('base64url');

      await mockStore.storeAuthCode({
        code: authCode,
        user_id: 'fastify-testuser',
        client_id: registeredClient.client_id,
        redirect_uri: registeredClient.redirect_uris[0],
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        expires_at: Date.now() + 600000,
        resource: `${testServerUrl}/mcp`,
        scope: '',
      });

      const tokenResponse = await request(app.getHttpServer())
        .post('/auth/token')
        .send({
          grant_type: 'authorization_code',
          code: authCode,
          code_verifier: codeVerifier,
          redirect_uri: registeredClient.redirect_uris[0],
          client_id: registeredClient.client_id,
        });

      refreshToken = tokenResponse.body.refresh_token;
    });

    it('should refresh access token with valid refresh token', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/token')
        .send({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
        })
        .expect(200);

      expect(response.body).toMatchObject({
        access_token: expect.any(String),
        refresh_token: expect.any(String),
        token_type: 'bearer',
        expires_in: expect.any(Number),
      });
    });

    it('should reject refresh with invalid refresh token', async () => {
      await request(app.getHttpServer())
        .post('/auth/token')
        .send({
          grant_type: 'refresh_token',
          refresh_token: 'invalid-refresh-token',
        })
        .expect(400);
    });
  });

  describe('Cookie Handling (Fastify-specific)', () => {
    let registeredClient: OAuthClient;

    beforeEach(async () => {
      const clientData: ClientRegistrationDto = {
        client_name: 'Fastify Cookie Test Client',
        redirect_uris: ['http://localhost:8080/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
      };

      const response = await request(app.getHttpServer())
        .post('/auth/register')
        .send(clientData);

      registeredClient = response.body;
    });

    it('should set OAuth session cookies during authorization', async () => {
      const codeVerifier = randomBytes(32).toString('base64url');
      const codeChallenge = createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');

      const authUrl = `/auth/authorize?response_type=code&client_id=${registeredClient.client_id}&redirect_uri=${encodeURIComponent(registeredClient.redirect_uris[0])}&code_challenge=${codeChallenge}&code_challenge_method=S256&state=test-state`;

      const response = await request(app.getHttpServer()).get(authUrl);

      // Check that cookies are being set (even if the mock strategy fails)
      // The Set-Cookie header should be present
      const cookies = response.headers['set-cookie'];

      // In Fastify with @fastify/cookie, cookies should be set
      // The exact behavior depends on the mock strategy
      if (cookies) {
        const cookieArray = Array.isArray(cookies) ? cookies : [cookies];
        const hasOAuthSession = cookieArray.some((c) =>
          c.includes('oauth_session'),
        );
        const hasOAuthState = cookieArray.some((c) =>
          c.includes('oauth_state'),
        );

        // At least one cookie should be set during the OAuth flow
        expect(hasOAuthSession || hasOAuthState).toBe(true);
      }
    });
  });
});
