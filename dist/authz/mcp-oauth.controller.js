"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createMcpOAuthController = createMcpOAuthController;
const common_1 = require("@nestjs/common");
const crypto_1 = require("crypto");
const passport_1 = __importDefault(require("passport"));
const http_adapter_factory_1 = require("../mcp/adapters/http-adapter.factory");
const normalize_endpoint_1 = require("../mcp/utils/normalize-endpoint");
const client_service_1 = require("./services/client.service");
const jwt_token_service_1 = require("./services/jwt-token.service");
const oauth_strategy_service_1 = require("./services/oauth-strategy.service");
function createMcpOAuthController(endpoints = {}, options, authModuleId) {
    var McpOAuthController_1;
    const OptionalGet = (path, enabled) => {
        return enabled && path
            ? common_1.Get(path)
            : (() => { });
    };
    const OptionalHeader = (name, value, enabled) => {
        return enabled
            ? common_1.Header(name, value)
            : (() => { });
    };
    let McpOAuthController = McpOAuthController_1 = class McpOAuthController {
        constructor(options, store, jwtTokenService, clientService, oauthStrategyService) {
            this.store = store;
            this.jwtTokenService = jwtTokenService;
            this.clientService = clientService;
            this.oauthStrategyService = oauthStrategyService;
            this.logger = new common_1.Logger(McpOAuthController_1.name);
            this.serverUrl = options.serverUrl;
            this.isProduction = options.cookieSecure;
            this.options = options;
            this.strategyName = oauthStrategyService.getStrategyName();
        }
        parseRequestBody(body, req) {
            if (body && typeof body === 'object' && Object.keys(body).length > 0) {
                return body;
            }
            if (typeof body === 'string' && body.length > 0) {
                const params = new URLSearchParams(body);
                const parsedBody = {};
                for (const [key, value] of params.entries()) {
                    parsedBody[key] = value;
                }
                return parsedBody;
            }
            if (req?.textBody) {
                const params = new URLSearchParams(req.textBody);
                const parsedBody = {};
                for (const [key, value] of params.entries()) {
                    parsedBody[key] = value;
                }
                return parsedBody;
            }
            if (req?.rawBody) {
                const bodyString = req.rawBody.toString('utf-8');
                if (bodyString) {
                    const params = new URLSearchParams(bodyString);
                    const parsedBody = {};
                    for (const [key, value] of params.entries()) {
                        parsedBody[key] = value;
                    }
                    return parsedBody;
                }
            }
            return {};
        }
        async captureRawBodyAsync(req) {
            const contentType = Array.isArray(req.headers['content-type'])
                ? req.headers['content-type'][0]
                : req.headers['content-type'];
            if (!contentType?.includes('application/x-www-form-urlencoded')) {
                return;
            }
            if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
                return;
            }
            if (req.rawBody) {
                const bodyString = req.rawBody.toString('utf-8');
                if (bodyString) {
                    req.textBody = bodyString;
                    const params = new URLSearchParams(bodyString);
                    const parsedBody = {};
                    for (const [key, value] of params.entries()) {
                        parsedBody[key] = value;
                    }
                    req.body = parsedBody;
                }
                return;
            }
            const rawReq = req.raw || req;
            if (typeof rawReq.on !== 'function') {
                return;
            }
            return new Promise((resolve, reject) => {
                let rawBody = '';
                rawReq.on('data', (chunk) => {
                    rawBody += chunk.toString('utf-8');
                });
                rawReq.on('end', () => {
                    req.textBody = rawBody;
                    if (rawBody) {
                        const params = new URLSearchParams(rawBody);
                        const parsedBody = {};
                        for (const [key, value] of params.entries()) {
                            parsedBody[key] = value;
                        }
                        req.body = parsedBody;
                    }
                    resolve();
                });
                rawReq.on('error', (err) => {
                    this.logger.error('Error reading request body:', err);
                    reject(err);
                });
            });
        }
        getProtectedResourceMetadata() {
            const authorizationServerIssuer = this.options.jwtIssuer;
            const resourceIdentifier = this.options.resource;
            const metadata = {
                authorization_servers: [authorizationServerIssuer],
                resource: resourceIdentifier,
                scopes_supported: this.options.protectedResourceMetadata.scopesSupported,
                bearer_methods_supported: this.options.protectedResourceMetadata.bearerMethodsSupported,
                mcp_versions_supported: this.options.protectedResourceMetadata.mcpVersionsSupported,
            };
            return metadata;
        }
        getAuthorizationServerMetadata() {
            return {
                issuer: this.serverUrl,
                authorization_endpoint: (0, normalize_endpoint_1.normalizeEndpoint)(`${this.serverUrl}/${endpoints.authorize}`),
                token_endpoint: (0, normalize_endpoint_1.normalizeEndpoint)(`${this.serverUrl}/${endpoints.token}`),
                registration_endpoint: (0, normalize_endpoint_1.normalizeEndpoint)(`${this.serverUrl}/${endpoints.register}`),
                response_types_supported: this.options.authorizationServerMetadata.responseTypesSupported,
                response_modes_supported: this.options.authorizationServerMetadata.responseModesSupported,
                grant_types_supported: this.options.authorizationServerMetadata.grantTypesSupported,
                token_endpoint_auth_methods_supported: this.options.authorizationServerMetadata
                    .tokenEndpointAuthMethodsSupported,
                scopes_supported: this.options.authorizationServerMetadata.scopesSupported,
                revocation_endpoint: (0, normalize_endpoint_1.normalizeEndpoint)(`${this.serverUrl}/${endpoints?.revoke}`),
                code_challenge_methods_supported: this.options.authorizationServerMetadata
                    .codeChallengeMethodsSupported,
            };
        }
        async registerClient(registrationDto) {
            return await this.clientService.registerClient(registrationDto);
        }
        async authorize(query, req, res) {
            const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state, scope, } = query;
            const resource = this.options.resource;
            if (response_type !== 'code') {
                throw new common_1.BadRequestException('Only response_type=code is supported');
            }
            if (!client_id) {
                throw new common_1.BadRequestException('Missing required parameters');
            }
            const client = await this.clientService.getClient(client_id);
            if (!client) {
                throw new common_1.BadRequestException('Invalid client_id');
            }
            const validRedirect = await this.clientService.validateRedirectUri(client_id, redirect_uri);
            if (!validRedirect) {
                throw new common_1.BadRequestException('Invalid redirect_uri');
            }
            const sessionId = (0, crypto_1.randomBytes)(32).toString('base64url');
            const sessionState = (0, crypto_1.randomBytes)(32).toString('base64url');
            const oauthSession = {
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
            const adapter = http_adapter_factory_1.HttpAdapterFactory.getAdapter(req, res);
            const adaptedReq = adapter.adaptRequest(req);
            const adaptedRes = adapter.adaptResponse(res);
            adaptedRes.setCookie?.('oauth_session', sessionId, {
                httpOnly: true,
                secure: this.isProduction,
                maxAge: this.options.oauthSessionExpiresIn,
                path: '/',
            });
            adaptedRes.setCookie?.('oauth_state', sessionState, {
                httpOnly: true,
                secure: this.isProduction,
                maxAge: this.options.oauthSessionExpiresIn,
                path: '/',
            });
            const rawReq = adaptedReq.raw || req;
            const rawRes = adaptedRes.raw || res;
            return new Promise((resolve, reject) => {
                passport_1.default.authenticate(this.strategyName, {
                    state: adaptedReq.getCookie?.('oauth_state') || adaptedReq.cookies?.oauth_state,
                })(rawReq, rawRes, (err) => {
                    if (err) {
                        reject(err);
                    }
                    else {
                        resolve();
                    }
                });
            });
        }
        async handleProviderCallback(req, res) {
            const adapter = http_adapter_factory_1.HttpAdapterFactory.getAdapter(req, res);
            const adaptedReq = adapter.adaptRequest(req);
            const adaptedRes = adapter.adaptResponse(res);
            const rawReq = adaptedReq.raw || req;
            const rawRes = adaptedRes.raw || res;
            return new Promise((resolve, reject) => {
                passport_1.default.authenticate(this.strategyName, { session: false }, async (err, user) => {
                    try {
                        if (err) {
                            this.logger.error('OAuth callback error:', err);
                            reject(new common_1.BadRequestException('Authentication failed'));
                            return;
                        }
                        if (!user) {
                            reject(new common_1.BadRequestException('Authentication failed'));
                            return;
                        }
                        req.user = user;
                        req.cookies = adaptedReq.cookies;
                        await this.processAuthenticationSuccess(req, res, adaptedRes);
                        resolve();
                    }
                    catch (error) {
                        reject(error);
                    }
                })(rawReq, rawRes, (err) => {
                    if (err) {
                        reject(err);
                    }
                });
            });
        }
        async processAuthenticationSuccess(req, res, adaptedRes) {
            const user = req.user;
            if (!user) {
                throw new common_1.BadRequestException('Authentication failed');
            }
            const httpResponse = adaptedRes || http_adapter_factory_1.HttpAdapterFactory.getAdapter(req, res).adaptResponse(res);
            const sessionId = req.cookies?.oauth_session;
            if (!sessionId) {
                throw new common_1.BadRequestException('Missing OAuth session');
            }
            const session = await this.store.getOAuthSession(sessionId);
            if (!session) {
                throw new common_1.BadRequestException('Invalid or expired OAuth session');
            }
            const stateFromCookie = req.cookies?.oauth_state;
            if (session.state !== stateFromCookie) {
                throw new common_1.BadRequestException('Invalid state parameter');
            }
            const jwt = this.jwtTokenService.generateUserToken(user.profile.username, user.profile);
            httpResponse.setCookie?.('auth_token', jwt, {
                httpOnly: true,
                secure: this.isProduction,
                maxAge: this.options.cookieMaxAge,
                path: '/',
            });
            httpResponse.clearCookie?.('oauth_session', { path: '/' });
            httpResponse.clearCookie?.('oauth_state', { path: '/' });
            const user_profile_id = await this.store.upsertUserProfile(user.profile, user.provider);
            const authCode = (0, crypto_1.randomBytes)(32).toString('base64url');
            await this.store.storeAuthCode({
                code: authCode,
                user_id: user.profile.username,
                client_id: session.clientId,
                redirect_uri: session.redirectUri,
                code_challenge: session.codeChallenge,
                code_challenge_method: session.codeChallengeMethod,
                expires_at: Date.now() + this.options.authCodeExpiresIn,
                resource: session.resource,
                scope: session.scope,
                user_profile_id,
            });
            const redirectUrl = new URL(session.redirectUri);
            redirectUrl.searchParams.set('code', authCode);
            if (session.oauthState) {
                redirectUrl.searchParams.set('state', session.oauthState);
            }
            await this.store.removeOAuthSession(sessionId);
            httpResponse.redirect?.(redirectUrl.toString());
        }
        async exchangeToken(body, req, res) {
            const contentType = Array.isArray(req.headers['content-type'])
                ? req.headers['content-type'][0]
                : req.headers['content-type'];
            const isFormUrlEncoded = contentType?.includes('application/x-www-form-urlencoded');
            const isBodyEmpty = !body ||
                (typeof body === 'object' &&
                    Object.keys(body).length === 0);
            if (isFormUrlEncoded && isBodyEmpty) {
                await this.captureRawBodyAsync(req);
            }
            const parsedBody = this.parseRequestBody(req.body || body, req);
            return this.processTokenExchange(parsedBody, req);
        }
        async processTokenExchange(parsedBody, req) {
            const { grant_type, code, code_verifier, redirect_uri, refresh_token } = parsedBody;
            if (!grant_type) {
                this.logger.error('Missing grant_type in request body:', {
                    parsedBodyKeys: Object.keys(parsedBody),
                    contentType: req.headers['content-type'],
                    textBody: req.textBody,
                    parsedBody,
                });
                throw new common_1.BadRequestException('Missing grant_type parameter');
            }
            switch (grant_type) {
                case 'authorization_code': {
                    const clientCredentials = this.extractClientCredentials(req, parsedBody);
                    return await this.handleAuthorizationCodeGrant(typeof code === 'string' ? code : String(code ?? ''), typeof code_verifier === 'string'
                        ? code_verifier
                        : String(code_verifier ?? ''), typeof redirect_uri === 'string'
                        ? redirect_uri
                        : String(redirect_uri ?? ''), clientCredentials);
                }
                case 'refresh_token': {
                    let clientCredentials;
                    try {
                        clientCredentials = this.extractClientCredentials(req, parsedBody);
                    }
                    catch {
                        clientCredentials = { client_id: '' };
                    }
                    return await this.handleRefreshTokenGrant(typeof refresh_token === 'string'
                        ? refresh_token
                        : String(refresh_token ?? ''), clientCredentials);
                }
                default:
                    throw new common_1.BadRequestException(`Unsupported grant_type: ${grant_type}`);
            }
        }
        extractClientCredentials(req, body) {
            const parsedBody = this.parseRequestBody(body, req);
            const authHeaderRaw = req.headers?.authorization;
            const authHeader = Array.isArray(authHeaderRaw)
                ? authHeaderRaw[0]
                : authHeaderRaw;
            if (authHeader && authHeader.startsWith('Basic ')) {
                const credentials = Buffer.from(authHeader.slice(6), 'base64').toString('utf-8');
                const [client_id, client_secret] = credentials.split(':', 2);
                if (client_id) {
                    return { client_id, client_secret };
                }
            }
            if (parsedBody.client_id) {
                return {
                    client_id: parsedBody.client_id,
                    client_secret: parsedBody.client_secret,
                };
            }
            throw new common_1.BadRequestException('Missing client credentials');
        }
        validateClientAuthentication(client, clientCredentials) {
            if (!client) {
                throw new common_1.BadRequestException('Invalid client_id');
            }
            const { token_endpoint_auth_method } = client;
            switch (token_endpoint_auth_method) {
                case 'client_secret_basic':
                case 'client_secret_post':
                    if (!clientCredentials.client_secret) {
                        throw new common_1.BadRequestException('Client secret required for this authentication method');
                    }
                    if (client.client_secret !== clientCredentials.client_secret) {
                        throw new common_1.BadRequestException('Invalid client credentials');
                    }
                    break;
                case 'none':
                    if (clientCredentials.client_secret) {
                        throw new common_1.BadRequestException('Client secret not allowed for public clients');
                    }
                    break;
                default:
                    throw new common_1.BadRequestException(`Unsupported authentication method: ${token_endpoint_auth_method}`);
            }
        }
        async handleAuthorizationCodeGrant(code, code_verifier, _redirect_uri, clientCredentials) {
            this.logger.debug('handleAuthorizationCodeGrant - Params:', {
                code,
                client_id: clientCredentials.client_id,
            });
            const authCode = await this.store.getAuthCode(code);
            if (!authCode) {
                this.logger.error('handleAuthorizationCodeGrant - Invalid authorization code:', code);
                throw new common_1.BadRequestException('Invalid authorization code');
            }
            if (authCode.expires_at < Date.now()) {
                await this.store.removeAuthCode(code);
                this.logger.error('handleAuthorizationCodeGrant - Authorization code expired:', code);
                throw new common_1.BadRequestException('Authorization code has expired');
            }
            if (authCode.client_id !== clientCredentials.client_id) {
                this.logger.error('handleAuthorizationCodeGrant - Client ID mismatch:', { expected: authCode.client_id, got: clientCredentials.client_id });
                throw new common_1.BadRequestException('Client ID mismatch');
            }
            const client = await this.clientService.getClient(clientCredentials.client_id);
            this.validateClientAuthentication(client, clientCredentials);
            if (authCode.code_challenge) {
                const isValid = this.validatePKCE(code_verifier, authCode.code_challenge, authCode.code_challenge_method);
                if (!isValid) {
                    this.logger.error('handleAuthorizationCodeGrant - Invalid PKCE verification');
                    throw new common_1.BadRequestException('Invalid PKCE verification');
                }
            }
            if (!authCode.resource) {
                this.logger.error('handleAuthorizationCodeGrant - No resource associated with code');
                throw new common_1.BadRequestException('Authorization code is not associated with a resource');
            }
            let userData = undefined;
            if (authCode.user_profile_id) {
                try {
                    const profile = await this.store.getUserProfileById(authCode.user_profile_id);
                    if (profile) {
                        userData = { ...profile };
                    }
                }
                catch (e) {
                    this.logger.warn('Failed to load user profile for token payload', e);
                }
            }
            const tokens = this.jwtTokenService.generateTokenPair(authCode.user_id, clientCredentials.client_id, authCode.scope, authCode.resource, {
                user_profile_id: authCode.user_profile_id,
                user_data: userData,
            });
            await this.store.removeAuthCode(code);
            this.logger.debug('handleAuthorizationCodeGrant - Token pair generated for user:', authCode.user_id);
            return tokens;
        }
        async handleRefreshTokenGrant(refresh_token, clientCredentials) {
            const payload = this.jwtTokenService.validateToken(refresh_token);
            if (!payload || payload.type !== 'refresh') {
                throw new common_1.BadRequestException('Invalid or expired refresh token');
            }
            const clientId = clientCredentials.client_id || payload.client_id;
            if (!clientId) {
                throw new common_1.BadRequestException('Unable to determine client_id');
            }
            const client = await this.clientService.getClient(clientId);
            if (client?.token_endpoint_auth_method !== 'none') {
                this.validateClientAuthentication(client, {
                    ...clientCredentials,
                    client_id: clientId,
                });
            }
            if (payload.client_id !== clientId) {
                throw new common_1.BadRequestException('Invalid refresh token or token does not belong to this client');
            }
            let newTokens = null;
            try {
                const payload = this.jwtTokenService.validateToken(refresh_token);
                if (!payload || payload.type !== 'refresh') {
                    throw new common_1.BadRequestException('Invalid or expired refresh token');
                }
                let userData = undefined;
                if (payload.user_profile_id) {
                    try {
                        const profile = await this.store.getUserProfileById(payload.user_profile_id);
                        if (profile)
                            userData = { ...profile };
                    }
                    catch (e) {
                        this.logger.warn('Failed to load user profile for refreshed token payload', e);
                    }
                }
                newTokens = this.jwtTokenService.generateTokenPair(payload.sub, clientId, payload.scope, payload.resource, {
                    user_profile_id: payload.user_profile_id,
                    user_data: userData,
                });
            }
            catch (e) {
                this.logger.warn('Refresh flow failed using enriched path, fallback', e);
                newTokens = this.jwtTokenService.refreshAccessToken(refresh_token);
            }
            if (!newTokens)
                throw new common_1.BadRequestException('Failed to refresh token');
            return newTokens;
        }
        validatePKCE(code_verifier, code_challenge, method) {
            if (method === 'plain') {
                return code_verifier === code_challenge;
            }
            else if (method === 'S256') {
                const hash = (0, crypto_1.createHash)('sha256')
                    .update(code_verifier)
                    .digest('base64url');
                return hash === code_challenge;
            }
            return false;
        }
    };
    __decorate([
        OptionalGet(endpoints.wellKnownProtectedResourceMetadata, !options?.disableWellKnownProtectedResourceMetadata),
        OptionalHeader('content-type', 'application/json', !options?.disableWellKnownProtectedResourceMetadata),
        __metadata("design:type", Function),
        __metadata("design:paramtypes", []),
        __metadata("design:returntype", void 0)
    ], McpOAuthController.prototype, "getProtectedResourceMetadata", null);
    __decorate([
        OptionalGet(endpoints.wellKnownAuthorizationServerMetadata, !options?.disableWellKnownAuthorizationServerMetadata),
        OptionalHeader('content-type', 'application/json', !options?.disableWellKnownAuthorizationServerMetadata),
        __metadata("design:type", Function),
        __metadata("design:paramtypes", []),
        __metadata("design:returntype", void 0)
    ], McpOAuthController.prototype, "getAuthorizationServerMetadata", null);
    __decorate([
        (0, common_1.Post)(endpoints.register),
        __param(0, (0, common_1.Body)()),
        __metadata("design:type", Function),
        __metadata("design:paramtypes", [Object]),
        __metadata("design:returntype", Promise)
    ], McpOAuthController.prototype, "registerClient", null);
    __decorate([
        (0, common_1.Get)(endpoints.authorize),
        __param(0, (0, common_1.Query)()),
        __param(1, (0, common_1.Req)()),
        __param(2, (0, common_1.Res)()),
        __metadata("design:type", Function),
        __metadata("design:paramtypes", [Object, Object, Object]),
        __metadata("design:returntype", Promise)
    ], McpOAuthController.prototype, "authorize", null);
    __decorate([
        (0, common_1.Get)(endpoints.callback),
        __param(0, (0, common_1.Req)()),
        __param(1, (0, common_1.Res)()),
        __metadata("design:type", Function),
        __metadata("design:paramtypes", [Object, Object]),
        __metadata("design:returntype", Promise)
    ], McpOAuthController.prototype, "handleProviderCallback", null);
    __decorate([
        (0, common_1.Post)(endpoints.token),
        (0, common_1.Header)('content-type', 'application/json'),
        (0, common_1.Header)('Cache-Control', 'no-store'),
        (0, common_1.Header)('Pragma', 'no-cache'),
        (0, common_1.HttpCode)(200),
        __param(0, (0, common_1.Body)()),
        __param(1, (0, common_1.Req)()),
        __param(2, (0, common_1.Res)({ passthrough: true })),
        __metadata("design:type", Function),
        __metadata("design:paramtypes", [Object, Object, Object]),
        __metadata("design:returntype", Promise)
    ], McpOAuthController.prototype, "exchangeToken", null);
    McpOAuthController = McpOAuthController_1 = __decorate([
        (0, common_1.Controller)(),
        __param(0, (0, common_1.Inject)(authModuleId
            ? `OAUTH_MODULE_OPTIONS_${authModuleId}`
            : 'OAUTH_MODULE_OPTIONS')),
        __param(1, (0, common_1.Inject)(authModuleId ? `IOAuthStore_${authModuleId}` : 'IOAuthStore')),
        __metadata("design:paramtypes", [Object, Object, jwt_token_service_1.JwtTokenService,
            client_service_1.ClientService,
            oauth_strategy_service_1.OAuthStrategyService])
    ], McpOAuthController);
    return McpOAuthController;
}
//# sourceMappingURL=mcp-oauth.controller.js.map