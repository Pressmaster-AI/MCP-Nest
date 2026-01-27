import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Header,
  HttpCode,
  Inject,
  Logger,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import { createHash, randomBytes } from 'crypto';
import passport from 'passport';
import { HttpAdapterFactory } from '../mcp/adapters/http-adapter.factory';
import type { HttpResponse } from '../mcp/interfaces/http-adapter.interface';
import { normalizeEndpoint } from '../mcp/utils/normalize-endpoint';
import type {
  OAuthEndpointConfiguration,
  OAuthModuleOptions,
  OAuthSession,
  OAuthUserProfile,
} from './providers/oauth-provider.interface';
import { ClientService } from './services/client.service';
import { JwtTokenService, TokenPair } from './services/jwt-token.service';
import { OAuthStrategyService } from './services/oauth-strategy.service';
import type { IOAuthStore } from './stores/oauth-store.interface';

/**
 * Platform-agnostic OAuth callback request interface
 */
interface OAuthCallbackRequest {
  user?: {
    profile: OAuthUserProfile;
    accessToken: string;
    provider: string;
  };
  headers: Record<string, string | string[] | undefined>;
  cookies?: Record<string, string | undefined>;
  [key: string]: any;
}

/**
 * Platform-agnostic request interface with raw body support
 */
interface RequestWithRawBody {
  headers: Record<string, string | string[] | undefined>;
  body?: any;
  rawBody?: Buffer;
  textBody?: string;
  cookies?: Record<string, string | undefined>;
  [key: string]: any;
}

export function createMcpOAuthController(
  endpoints: OAuthEndpointConfiguration = {},
  options?: {
    disableWellKnownProtectedResourceMetadata?: boolean;
    disableWellKnownAuthorizationServerMetadata?: boolean;
  },
  authModuleId?: string,
) {
  // Optional decorator helpers
  const OptionalGet = (
    path: string | string[] | undefined,
    enabled: boolean,
  ): MethodDecorator => {
    return enabled && path
      ? (Get as unknown as (p?: any) => MethodDecorator)(path)
      : ((() => {}) as unknown as MethodDecorator);
  };
  const OptionalHeader = (
    name: string,
    value: string,
    enabled: boolean,
  ): MethodDecorator => {
    return enabled
      ? (Header as unknown as (n: string, v: string) => MethodDecorator)(
          name,
          value,
        )
      : ((() => {}) as unknown as MethodDecorator);
  };

  @Controller()
  class McpOAuthController {
    readonly logger = new Logger(McpOAuthController.name);
    readonly serverUrl: string;
    readonly isProduction: boolean;
    readonly options: OAuthModuleOptions;
    readonly strategyName: string;

    constructor(
      @Inject(
        authModuleId
          ? `OAUTH_MODULE_OPTIONS_${authModuleId}`
          : 'OAUTH_MODULE_OPTIONS',
      )
      options: OAuthModuleOptions,
      @Inject(authModuleId ? `IOAuthStore_${authModuleId}` : 'IOAuthStore')
      readonly store: IOAuthStore,
      readonly jwtTokenService: JwtTokenService,
      readonly clientService: ClientService,
      readonly oauthStrategyService: OAuthStrategyService,
    ) {
      this.serverUrl = options.serverUrl;
      this.isProduction = options.cookieSecure;
      this.options = options;
      this.strategyName = oauthStrategyService.getStrategyName();
    }

    /**
     * Utility function to parse form-encoded or JSON bodies
     * Handles both string (raw form data) and object bodies
     */
    parseRequestBody(body: any, req?: RequestWithRawBody): Record<string, any> {
      // If body is already a parsed object with properties, return it
      if (body && typeof body === 'object' && Object.keys(body).length > 0) {
        return body;
      }

      // If body is a string (raw form data), parse it
      if (typeof body === 'string' && body.length > 0) {
        const params = new URLSearchParams(body);
        const parsedBody: Record<string, any> = {};
        for (const [key, value] of params.entries()) {
          parsedBody[key] = value;
        }
        return parsedBody;
      }

      // Check if we have a text body stored on the request (from our middleware)
      if (req?.textBody) {
        const params = new URLSearchParams(req.textBody);
        const parsedBody: Record<string, any> = {};
        for (const [key, value] of params.entries()) {
          parsedBody[key] = value;
        }
        return parsedBody;
      }

      // Check if we have a raw body buffer stored on the request
      if (req?.rawBody) {
        const bodyString = req.rawBody.toString('utf-8');
        if (bodyString) {
          const params = new URLSearchParams(bodyString);
          const parsedBody: Record<string, any> = {};
          for (const [key, value] of params.entries()) {
            parsedBody[key] = value;
          }
          return parsedBody;
        }
      }

      // Return empty object if no valid body
      return {};
    }

    /**
     * Platform-agnostic method to capture raw body for form-encoded requests
     * This is needed when bodyParser is disabled in the main app
     * Works with both Express and Fastify
     */
    async captureRawBodyAsync(req: RequestWithRawBody): Promise<void> {
      const contentType = Array.isArray(req.headers['content-type'])
        ? req.headers['content-type'][0]
        : req.headers['content-type'];

      if (!contentType?.includes('application/x-www-form-urlencoded')) {
        return;
      }

      // Check if we already have the body parsed (Fastify or Express with body-parser)
      if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
        return;
      }

      // Check for Fastify raw body (from fastify-raw-body plugin)
      if (req.rawBody) {
        const bodyString = req.rawBody.toString('utf-8');
        if (bodyString) {
          req.textBody = bodyString;
          const params = new URLSearchParams(bodyString);
          const parsedBody: any = {};
          for (const [key, value] of params.entries()) {
            parsedBody[key] = value;
          }
          req.body = parsedBody;
        }
        return;
      }

      // Get the raw request object (works for both Express and Fastify)
      const rawReq = req.raw || req;

      // Check if the stream is readable
      if (typeof rawReq.on !== 'function') {
        return;
      }

      return new Promise<void>((resolve, reject) => {
        let rawBody = '';

        rawReq.on('data', (chunk: Buffer) => {
          rawBody += chunk.toString('utf-8');
        });

        rawReq.on('end', () => {
          req.textBody = rawBody;
          // Also parse and set it as body for NestJS
          if (rawBody) {
            const params = new URLSearchParams(rawBody);
            const parsedBody: any = {};
            for (const [key, value] of params.entries()) {
              parsedBody[key] = value;
            }
            req.body = parsedBody;
          }
          resolve();
        });

        rawReq.on('error', (err: Error) => {
          this.logger.error('Error reading request body:', err);
          reject(err);
        });
      });
    }

    @OptionalGet(
      endpoints.wellKnownProtectedResourceMetadata,
      !options?.disableWellKnownProtectedResourceMetadata,
    )
    @OptionalHeader(
      'content-type',
      'application/json',
      !options?.disableWellKnownProtectedResourceMetadata,
    )
    getProtectedResourceMetadata() {
      // The issuer URL of your authorization server.
      const authorizationServerIssuer = this.options.jwtIssuer;

      // The canonical URI of the MCP server resource itself.
      const resourceIdentifier = this.options.resource;

      const metadata = {
        /**
         * REQUIRED by MCP Spec.
         * A list of authorization server issuer URLs that can issue tokens for this resource.
         */
        authorization_servers: [authorizationServerIssuer],

        /**
         * RECOMMENDED by RFC 9728.
         * The identifier for this resource server.
         */
        resource: resourceIdentifier,

        /**
         * RECOMMENDED by RFC 9728.
         * A list of scopes that this resource server understands.
         */
        scopes_supported:
          this.options.protectedResourceMetadata.scopesSupported,

        /**
         * RECOMMENDED by RFC 9728.
         * A list of methods clients can use to present the access token.
         */
        bearer_methods_supported:
          this.options.protectedResourceMetadata.bearerMethodsSupported,

        /**
         * OPTIONAL but helpful custom metadata.
         * Declares which version of the MCP spec this server supports.
         */
        mcp_versions_supported:
          this.options.protectedResourceMetadata.mcpVersionsSupported,
      };

      return metadata;
    }

    // OAuth endpoints
    @OptionalGet(
      endpoints.wellKnownAuthorizationServerMetadata,
      !options?.disableWellKnownAuthorizationServerMetadata,
    )
    @OptionalHeader(
      'content-type',
      'application/json',
      !options?.disableWellKnownAuthorizationServerMetadata,
    )
    getAuthorizationServerMetadata() {
      return {
        issuer: this.serverUrl,
        authorization_endpoint: normalizeEndpoint(
          `${this.serverUrl}/${endpoints.authorize}`,
        ),
        token_endpoint: normalizeEndpoint(
          `${this.serverUrl}/${endpoints.token}`,
        ),
        registration_endpoint: normalizeEndpoint(
          `${this.serverUrl}/${endpoints.register}`,
        ),
        response_types_supported:
          this.options.authorizationServerMetadata.responseTypesSupported,
        response_modes_supported:
          this.options.authorizationServerMetadata.responseModesSupported,
        grant_types_supported:
          this.options.authorizationServerMetadata.grantTypesSupported,
        token_endpoint_auth_methods_supported:
          this.options.authorizationServerMetadata
            .tokenEndpointAuthMethodsSupported,
        scopes_supported:
          this.options.authorizationServerMetadata.scopesSupported,
        revocation_endpoint: normalizeEndpoint(
          `${this.serverUrl}/${endpoints?.revoke}`,
        ),
        code_challenge_methods_supported:
          this.options.authorizationServerMetadata
            .codeChallengeMethodsSupported,
      };
    }

    @Post(endpoints.register)
    async registerClient(@Body() registrationDto: any) {
      return await this.clientService.registerClient(registrationDto);
    }

    @Get(endpoints.authorize)
    async authorize(
      @Query() query: any,
      @Req() req: any,
      @Res() res: any,
    ) {
      const {
        response_type,
        client_id,
        redirect_uri,
        code_challenge,
        code_challenge_method,
        state,
        scope,
      } = query;
      const resource = this.options.resource;
      if (response_type !== 'code') {
        throw new BadRequestException('Only response_type=code is supported');
      }

      if (!client_id) {
        throw new BadRequestException('Missing required parameters');
      }

      // Validate client and redirect URI
      const client = await this.clientService.getClient(client_id);
      if (!client) {
        throw new BadRequestException('Invalid client_id');
      }

      const validRedirect = await this.clientService.validateRedirectUri(
        client_id,
        redirect_uri,
      );
      if (!validRedirect) {
        throw new BadRequestException('Invalid redirect_uri');
      }

      // Create OAuth session
      const sessionId = randomBytes(32).toString('base64url');
      const sessionState = randomBytes(32).toString('base64url');

      const oauthSession: OAuthSession = {
        sessionId,
        state: sessionState,
        clientId: client_id,
        redirectUri: redirect_uri,
        codeChallenge: code_challenge,
        codeChallengeMethod: code_challenge_method || 'plain',
        oauthState: state,
        scope: scope,
        resource,
        expiresAt: Date.now() + this.options.oauthSessionExpiresIn,
      };

      await this.store.storeOAuthSession(sessionId, oauthSession);

      // Use adapter for platform-agnostic cookie operations
      const adapter = HttpAdapterFactory.getAdapter(req, res);
      const adaptedReq = adapter.adaptRequest(req);
      const adaptedRes = adapter.adaptResponse(res);

      // Set session cookie
      adaptedRes.setCookie?.('oauth_session', sessionId, {
        httpOnly: true,
        secure: this.isProduction,
        maxAge: this.options.oauthSessionExpiresIn,
        path: '/',
      });

      // Store state for passport
      adaptedRes.setCookie?.('oauth_state', sessionState, {
        httpOnly: true,
        secure: this.isProduction,
        maxAge: this.options.oauthSessionExpiresIn,
        path: '/',
      });

      // Get raw request/response for Passport.js (which expects raw objects)
      const rawReq = adaptedReq.raw || req;
      const rawRes = adaptedRes.raw || res;

      // Redirect to the provider's auth endpoint using Promise wrapper
      // This avoids the Express-specific next() middleware pattern
      return new Promise<void>((resolve, reject) => {
        passport.authenticate(this.strategyName, {
          state: adaptedReq.getCookie?.('oauth_state') || adaptedReq.cookies?.oauth_state,
        })(rawReq, rawRes, (err?: any) => {
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        });
      });
    }

    @Get(endpoints.callback)
    async handleProviderCallback(
      @Req() req: OAuthCallbackRequest,
      @Res() res: any,
    ) {
      // Use adapter for platform-agnostic operations
      const adapter = HttpAdapterFactory.getAdapter(req, res);
      const adaptedReq = adapter.adaptRequest(req);
      const adaptedRes = adapter.adaptResponse(res);

      // Get raw request/response for Passport.js
      const rawReq = adaptedReq.raw || req;
      const rawRes = adaptedRes.raw || res;

      // Use Promise wrapper for Passport authentication
      // This avoids the Express-specific next() middleware pattern
      return new Promise<void>((resolve, reject) => {
        passport.authenticate(
          this.strategyName,
          { session: false },
          async (err: any, user: any) => {
            try {
              if (err) {
                this.logger.error('OAuth callback error:', err);
                reject(new BadRequestException('Authentication failed'));
                return;
              }

              if (!user) {
                reject(new BadRequestException('Authentication failed'));
                return;
              }

              // Attach user to the original request for downstream processing
              req.user = user;
              // Also attach cookies from adapted request for platform-agnostic access
              req.cookies = adaptedReq.cookies;

              await this.processAuthenticationSuccess(req, res, adaptedRes);
              resolve();
            } catch (error) {
              reject(error);
            }
          },
        )(rawReq, rawRes, (err?: any) => {
          if (err) {
            reject(err);
          }
        });
      });
    }

    async processAuthenticationSuccess(
      req: OAuthCallbackRequest,
      res: any,
      adaptedRes?: HttpResponse,
    ) {
      const user = req.user;
      if (!user) {
        throw new BadRequestException('Authentication failed');
      }

      // Use adapted response if provided, otherwise create one
      const httpResponse = adaptedRes || HttpAdapterFactory.getAdapter(req, res).adaptResponse(res);

      const sessionId = req.cookies?.oauth_session;
      if (!sessionId) {
        throw new BadRequestException('Missing OAuth session');
      }

      const session = await this.store.getOAuthSession(sessionId);
      if (!session) {
        throw new BadRequestException('Invalid or expired OAuth session');
      }

      // Verify state
      const stateFromCookie = req.cookies?.oauth_state;
      if (session.state !== stateFromCookie) {
        throw new BadRequestException('Invalid state parameter');
      }

      // Generate JWT for UI access
      const jwt = this.jwtTokenService.generateUserToken(
        user.profile.username,
        user.profile,
      );

      // Set JWT token as cookie for UI endpoints (platform-agnostic)
      httpResponse.setCookie?.('auth_token', jwt, {
        httpOnly: true,
        secure: this.isProduction,
        maxAge: this.options.cookieMaxAge,
        path: '/',
      });

      // Clear temporary cookies (platform-agnostic)
      // Path must match the path used when setting the cookies
      httpResponse.clearCookie?.('oauth_session', { path: '/' });
      httpResponse.clearCookie?.('oauth_state', { path: '/' });

      // Persist user profile and get stable profile_id
      const user_profile_id = await this.store.upsertUserProfile(
        user.profile,
        user.provider,
      );

      // Generate authorization code
      const authCode = randomBytes(32).toString('base64url');

      // Store the auth code
      await this.store.storeAuthCode({
        code: authCode,
        user_id: user.profile.username,
        client_id: session.clientId!,
        redirect_uri: session.redirectUri!,
        code_challenge: session.codeChallenge!,
        code_challenge_method: session.codeChallengeMethod!,
        expires_at: Date.now() + this.options.authCodeExpiresIn,
        resource: session.resource,
        scope: session.scope,
        user_profile_id,
      });

      // Build redirect URL with authorization code
      const redirectUrl = new URL(session.redirectUri!);
      redirectUrl.searchParams.set('code', authCode);
      if (session.oauthState) {
        redirectUrl.searchParams.set('state', session.oauthState);
      }

      // Clean up session
      await this.store.removeOAuthSession(sessionId);

      // Redirect using platform-agnostic method
      httpResponse.redirect?.(redirectUrl.toString());
    }

    @Post(endpoints.token)
    @Header('content-type', 'application/json')
    @Header('Cache-Control', 'no-store')
    @Header('Pragma', 'no-cache')
    @HttpCode(200)
    async exchangeToken(
      @Body() body: any,
      @Req() req: RequestWithRawBody,
      @Res({ passthrough: true }) res: any,
    ): Promise<TokenPair> {
      // Get content type in a platform-agnostic way
      const contentType = Array.isArray(req.headers['content-type'])
        ? req.headers['content-type'][0]
        : req.headers['content-type'];

      const isFormUrlEncoded = contentType?.includes(
        'application/x-www-form-urlencoded',
      );
      const isBodyEmpty =
        !body ||
        (typeof body === 'object' &&
          Object.keys(body as Record<string, unknown>).length === 0);

      // Apply platform-agnostic raw body capture if needed
      if (isFormUrlEncoded && isBodyEmpty) {
        await this.captureRawBodyAsync(req);
      }

      // Body is already parsed, process directly
      const parsedBody = this.parseRequestBody(req.body || body, req);
      return this.processTokenExchange(parsedBody, req);
    }

    async processTokenExchange(
      parsedBody: Record<string, any>,
      req: RequestWithRawBody,
    ): Promise<TokenPair> {
      const { grant_type, code, code_verifier, redirect_uri, refresh_token } =
        parsedBody;

      // Add debugging to help identify issues
      if (!grant_type) {
        this.logger.error('Missing grant_type in request body:', {
          parsedBodyKeys: Object.keys(parsedBody),
          contentType: req.headers['content-type'],
          textBody: req.textBody,
          parsedBody,
        });
        throw new BadRequestException('Missing grant_type parameter');
      }

      switch (grant_type) {
        case 'authorization_code': {
          // Extract client credentials based on authentication method
          const clientCredentials = this.extractClientCredentials(
            req,
            parsedBody,
          );
          return await this.handleAuthorizationCodeGrant(
            typeof code === 'string' ? code : String(code ?? ''),
            typeof code_verifier === 'string'
              ? code_verifier
              : String(code_verifier ?? ''),
            typeof redirect_uri === 'string'
              ? redirect_uri
              : String(redirect_uri ?? ''),
            clientCredentials,
          );
        }
        case 'refresh_token': {
          // For refresh tokens, try to extract client credentials, but allow fallback to token-based extraction
          let clientCredentials: { client_id: string; client_secret?: string };
          try {
            clientCredentials = this.extractClientCredentials(req, parsedBody);
          } catch {
            // If we can't extract credentials, we'll try to get them from the refresh token
            clientCredentials = { client_id: '' }; // Will be filled from token
          }
          return await this.handleRefreshTokenGrant(
            typeof refresh_token === 'string'
              ? refresh_token
              : String(refresh_token ?? ''),
            clientCredentials,
          );
        }
        default:
          throw new BadRequestException(
            `Unsupported grant_type: ${grant_type}`,
          );
      }
    }

    /**
     * Extract client credentials from request based on authentication method
     */
    extractClientCredentials(
      req: RequestWithRawBody,
      body: any,
    ): { client_id: string; client_secret?: string } {
      // Parse the body using the shared utility function
      const parsedBody = this.parseRequestBody(body, req);

      // Try client_secret_basic first (Authorization header)
      // Handle both string and array headers (Fastify may return arrays)
      const authHeaderRaw = req.headers?.authorization;
      const authHeader = Array.isArray(authHeaderRaw)
        ? authHeaderRaw[0]
        : authHeaderRaw;

      if (authHeader && authHeader.startsWith('Basic ')) {
        const credentials = Buffer.from(authHeader.slice(6), 'base64').toString(
          'utf-8',
        );
        const [client_id, client_secret] = credentials.split(':', 2);
        if (client_id) {
          return { client_id, client_secret };
        }
      }

      // Try client_secret_post (body parameters)
      if (parsedBody.client_id) {
        return {
          client_id: parsedBody.client_id,
          client_secret: parsedBody.client_secret,
        };
      }

      throw new BadRequestException('Missing client credentials');
    }

    /**
     * Validate client authentication based on the client's configured method
     */
    validateClientAuthentication(
      client: any,
      clientCredentials: { client_id: string; client_secret?: string },
    ): void {
      if (!client) {
        throw new BadRequestException('Invalid client_id');
      }

      const { token_endpoint_auth_method } = client;

      switch (token_endpoint_auth_method) {
        case 'client_secret_basic':
        case 'client_secret_post':
          if (!clientCredentials.client_secret) {
            throw new BadRequestException(
              'Client secret required for this authentication method',
            );
          }
          if (client.client_secret !== clientCredentials.client_secret) {
            throw new BadRequestException('Invalid client credentials');
          }
          break;

        case 'none':
          // Public client - no secret required
          if (clientCredentials.client_secret) {
            throw new BadRequestException(
              'Client secret not allowed for public clients',
            );
          }
          break;

        default:
          throw new BadRequestException(
            `Unsupported authentication method: ${token_endpoint_auth_method}`,
          );
      }
    }

    async handleAuthorizationCodeGrant(
      code: string,
      code_verifier: string,
      _redirect_uri: string,
      clientCredentials: { client_id: string; client_secret?: string },
    ): Promise<TokenPair> {
      this.logger.debug('handleAuthorizationCodeGrant - Params:', {
        code,
        client_id: clientCredentials.client_id,
      });

      // Get and validate the authorization code
      const authCode = await this.store.getAuthCode(code);
      if (!authCode) {
        this.logger.error(
          'handleAuthorizationCodeGrant - Invalid authorization code:',
          code,
        );
        throw new BadRequestException('Invalid authorization code');
      }
      if (authCode.expires_at < Date.now()) {
        await this.store.removeAuthCode(code);
        this.logger.error(
          'handleAuthorizationCodeGrant - Authorization code expired:',
          code,
        );
        throw new BadRequestException('Authorization code has expired');
      }
      if (authCode.client_id !== clientCredentials.client_id) {
        this.logger.error(
          'handleAuthorizationCodeGrant - Client ID mismatch:',
          { expected: authCode.client_id, got: clientCredentials.client_id },
        );
        throw new BadRequestException('Client ID mismatch');
      }

      // Get client and validate authentication
      const client = await this.clientService.getClient(
        clientCredentials.client_id,
      );
      this.validateClientAuthentication(client, clientCredentials);
      if (authCode.code_challenge) {
        const isValid = this.validatePKCE(
          code_verifier,
          authCode.code_challenge,
          authCode.code_challenge_method,
        );
        if (!isValid) {
          this.logger.error(
            'handleAuthorizationCodeGrant - Invalid PKCE verification',
          );
          throw new BadRequestException('Invalid PKCE verification');
        }
      }
      if (!authCode.resource) {
        this.logger.error(
          'handleAuthorizationCodeGrant - No resource associated with code',
        );
        throw new BadRequestException(
          'Authorization code is not associated with a resource',
        );
      }

      let userData: Record<string, unknown> | undefined = undefined;
      if (authCode.user_profile_id) {
        try {
          const profile = await this.store.getUserProfileById(
            authCode.user_profile_id,
          );
          if (profile) {
            // Avoid circular/large raw payloads if present
            userData = { ...profile };
          }
        } catch (e) {
          this.logger.warn('Failed to load user profile for token payload', e);
        }
      }

      const tokens = this.jwtTokenService.generateTokenPair(
        authCode.user_id,
        clientCredentials.client_id,
        authCode.scope,
        authCode.resource,
        {
          user_profile_id: authCode.user_profile_id,
          user_data: userData,
        },
      );
      await this.store.removeAuthCode(code);
      this.logger.debug(
        'handleAuthorizationCodeGrant - Token pair generated for user:',
        authCode.user_id,
      );
      return tokens;
    }

    async handleRefreshTokenGrant(
      refresh_token: string,
      clientCredentials: { client_id: string; client_secret?: string },
    ): Promise<TokenPair> {
      // Verify the refresh token first to get client_id from token if not provided
      const payload = this.jwtTokenService.validateToken(refresh_token);
      if (!payload || payload.type !== 'refresh') {
        throw new BadRequestException('Invalid or expired refresh token');
      }

      // Use client_id from token if not provided in credentials
      const clientId = clientCredentials.client_id || payload.client_id;
      if (!clientId) {
        throw new BadRequestException('Unable to determine client_id');
      }

      // Get client and validate authentication
      const client = await this.clientService.getClient(clientId);

      // For refresh token grants, we can be more lenient with client authentication
      // if the token already contains the client_id and the client is public
      if (client?.token_endpoint_auth_method !== 'none') {
        this.validateClientAuthentication(client, {
          ...clientCredentials,
          client_id: clientId,
        });
      }

      // Verify the refresh token belongs to the client
      if (payload.client_id !== clientId) {
        throw new BadRequestException(
          'Invalid refresh token or token does not belong to this client',
        );
      }

      let newTokens: TokenPair | null = null;
      try {
        const payload = this.jwtTokenService.validateToken(refresh_token);
        if (!payload || payload.type !== 'refresh') {
          throw new BadRequestException('Invalid or expired refresh token');
        }

        let userData: Record<string, unknown> | undefined = undefined;
        if (payload.user_profile_id) {
          try {
            const profile = await this.store.getUserProfileById(
              payload.user_profile_id,
            );
            if (profile) userData = { ...profile };
          } catch (e) {
            this.logger.warn(
              'Failed to load user profile for refreshed token payload',
              e,
            );
          }
        }

        newTokens = this.jwtTokenService.generateTokenPair(
          payload.sub,
          clientId,
          payload.scope,
          payload.resource,
          {
            user_profile_id: payload.user_profile_id,
            user_data: userData,
          },
        );
      } catch (e) {
        this.logger.warn(
          'Refresh flow failed using enriched path, fallback',
          e,
        );
        newTokens = this.jwtTokenService.refreshAccessToken(refresh_token);
      }

      if (!newTokens) throw new BadRequestException('Failed to refresh token');
      return newTokens;
    }

    validatePKCE(
      code_verifier: string,
      code_challenge: string,
      method: string,
    ): boolean {
      if (method === 'plain') {
        return code_verifier === code_challenge;
      } else if (method === 'S256') {
        const hash = createHash('sha256')
          .update(code_verifier)
          .digest('base64url');
        return hash === code_challenge;
      }
      return false;
    }
  }

  return McpOAuthController;
}
