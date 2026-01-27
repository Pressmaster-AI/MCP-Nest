import type { JwtPayload } from '../services/jwt-token.service';

// Enriched user payload placed on request.user by McpAuthJwtGuard
export type McpUserPayload = JwtPayload & {
  name?: string;
  username?: string;
  email?: string;
  displayName?: string;
  avatarUrl?: string;
};

/**
 * Platform-agnostic request interface with enriched user information
 * Works with both Express and Fastify
 */
export interface McpRequestWithUser {
  headers: Record<string, string | string[] | undefined>;
  user: McpUserPayload;
  body?: any;
  query?: Record<string, any>;
  params?: Record<string, string>;
  cookies?: Record<string, string | undefined>;
  [key: string]: any;
}
