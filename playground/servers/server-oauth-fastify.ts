#!/usr/bin/env node

/**
 * Fastify OAuth MCP Server Example
 *
 * This example demonstrates how to use McpAuthModule with Fastify
 * instead of Express. The key differences from the Express version are:
 *
 * 1. Use FastifyAdapter instead of the default Express
 * 2. Register @fastify/cookie plugin for cookie support
 * 3. Register @fastify/cors plugin for CORS support
 *
 * Required packages:
 * - @nestjs/platform-fastify
 * - @fastify/cookie
 * - @fastify/cors
 */

import { Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import * as dotenv from 'dotenv';
import 'reflect-metadata';
import { GitHubOAuthProvider, McpAuthModule, McpModule } from '../../src';
import { McpAuthJwtGuard } from '../../src/authz/guards/jwt-auth.guard';
import { GreetingPrompt } from '../resources/greeting.prompt';
import { GreetingResource } from '../resources/greeting.resource';
import { GreetingTool } from '../resources/greeting.tool';

dotenv.config();

@Module({
  imports: [
    McpAuthModule.forRoot({
      provider: GitHubOAuthProvider,
      clientId: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
      jwtSecret: process.env.JWT_SECRET!,
      serverUrl: process.env.SERVER_URL || 'http://localhost:3030',
      resource: (process.env.SERVER_URL || 'http://localhost:3030') + '/mcp',
      cookieSecure: process.env.NODE_ENV === 'production',
      apiPrefix: 'auth',
      endpoints: {
        wellKnownAuthorizationServerMetadata:
          '/.well-known/oauth-authorization-server',
        wellKnownProtectedResourceMetadata: [
          '/.well-known/oauth-protected-resource/mcp',
          '/.well-known/oauth-protected-resource',
        ],
      },
      disableEndpoints: {
        wellKnownAuthorizationServerMetadata: false,
        wellKnownProtectedResourceMetadata: false,
      },
    }),

    McpModule.forRoot({
      name: 'fastify-oauth-mcp-server',
      version: '0.0.1',
      allowUnauthenticatedAccess:
        process.env.ALLOW_UNAUTHENTICATED_ACCESS === 'true',
      guards: [McpAuthJwtGuard],
    }),
  ],
  providers: [GreetingResource, GreetingTool, GreetingPrompt, McpAuthJwtGuard],
})
class AppModule {}

async function bootstrap() {
  const port = parseInt(process.env.PORT || '3030', 10);

  try {
    // Import Fastify platform and plugins
    const { FastifyAdapter, NestFastifyApplication } = await import(
      '@nestjs/platform-fastify'
    );
    const fastifyCookie = await import('@fastify/cookie');
    const fastifyCors = await import('@fastify/cors');

    // Create Fastify adapter
    const adapter = new FastifyAdapter();

    // Register @fastify/cookie plugin - REQUIRED for OAuth session management
    await adapter.register(fastifyCookie.default || fastifyCookie, {
      // Optional: configure cookie signing secret
      // secret: process.env.COOKIE_SECRET,
    });

    // Register @fastify/cors plugin
    await adapter.register(fastifyCors.default || fastifyCors, {
      origin: true,
      credentials: true,
    });

    // Create NestJS application with Fastify
    const app = await NestFactory.create<NestFastifyApplication>(
      AppModule,
      adapter,
    );

    await app.listen(port, '0.0.0.0');

    console.log('');
    console.log('🚀 MCP OAuth Server (Fastify) running on http://localhost:' + port);
    console.log('');
    console.log('📡 Endpoints:');
    console.log(`   MCP: http://localhost:${port}/mcp`);
    console.log(`   OAuth Authorize: http://localhost:${port}/auth/authorize`);
    console.log(`   OAuth Token: http://localhost:${port}/auth/token`);
    console.log(`   Client Registration: http://localhost:${port}/auth/register`);
    console.log('');
    console.log('📋 Well-known endpoints:');
    console.log(`   http://localhost:${port}/.well-known/oauth-authorization-server`);
    console.log(`   http://localhost:${port}/.well-known/oauth-protected-resource`);
    console.log('');
    console.log('🔧 Framework: Fastify');
    console.log('');
  } catch (error) {
    console.error('');
    console.error('❌ Failed to start Fastify OAuth server:');
    console.error('');

    if (
      error instanceof Error &&
      error.message.includes('Cannot find module')
    ) {
      console.error('Missing required Fastify packages. Please install:');
      console.error('');
      console.error(
        '  npm install @nestjs/platform-fastify @fastify/cookie @fastify/cors',
      );
      console.error('');
      console.error(
        'Or use the Express version: npm run start:oauth (server-oauth.ts)',
      );
    } else {
      console.error(error);
    }

    process.exit(1);
  }
}

bootstrap().catch((error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
