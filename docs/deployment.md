# Production Deployment Guide

This guide covers deploying `@rekog/mcp-nest` MCP servers to production environments, including Docker, Kubernetes, cloud platforms, and traditional servers.

## Table of Contents

- [Quick Start Deployment](#quick-start-deployment)
- [Environment Configuration](#environment-configuration)
- [Transport Selection for Production](#transport-selection-for-production)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Cloud Platform Deployments](#cloud-platform-deployments)
- [Database Setup](#database-setup)
- [Security Best Practices](#security-best-practices)
- [Scaling Considerations](#scaling-considerations)
- [Monitoring and Health Checks](#monitoring-and-health-checks)
- [Troubleshooting](#troubleshooting)

## Quick Start Deployment

### Railway (One-Click Deploy)

The fastest way to deploy an authenticated MCP server:

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/G6BLGK?referralCode=XAdIhJ)

**Steps:**
1. Create a [GitHub App](https://github.com/settings/applications/new) for authentication
2. Set `Authorization callback URL` to `http://localhost:3000/auth/callback` (temporary)
3. Click the Railway deploy button above
4. Add `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` in Railway
5. After deployment, update the GitHub App callback URL to `https://<your-domain>.up.railway.app/auth/callback`

**Starter Repository:** [rekog-labs/mcp-nest-auth-starter](https://github.com/rekog-labs/mcp-nest-auth-starter)

## Environment Configuration

### Required Environment Variables

```bash
# Server Configuration
NODE_ENV=production
PORT=3030
SERVER_URL=https://your-domain.com

# JWT Configuration (required for authentication)
JWT_SECRET=your-secure-secret-minimum-32-characters-long

# OAuth Provider (GitHub example)
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# Or Google OAuth
# GOOGLE_CLIENT_ID=your_google_client_id
# GOOGLE_CLIENT_SECRET=your_google_client_secret
```

### Optional Environment Variables

```bash
# Database (for TypeORM OAuth store)
DB_TYPE=postgres
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=mcp_user
DB_PASSWORD=secure_password
DB_DATABASE=mcp_oauth

# JWT Token Expiration
JWT_ACCESS_TOKEN_EXPIRES_IN=1d
JWT_REFRESH_TOKEN_EXPIRES_IN=30d

# CORS Configuration
ALLOWED_ORIGINS=https://your-app.com,https://another-app.com

# Logging
LOG_LEVEL=error,warn
```

### Production Server Configuration

```typescript
import { Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import { randomUUID } from 'crypto';
import {
  McpAuthModule,
  McpModule,
  GitHubOAuthProvider,
  McpAuthJwtGuard,
} from '@rekog/mcp-nest';

@Module({
  imports: [
    McpAuthModule.forRoot({
      provider: GitHubOAuthProvider,
      clientId: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
      jwtSecret: process.env.JWT_SECRET!,
      serverUrl: process.env.SERVER_URL || 'https://localhost:3030',
      resource: `${process.env.SERVER_URL}/mcp`,
      apiPrefix: 'auth',
      cookieSecure: process.env.NODE_ENV === 'production',
      // Production database configuration
      storeConfiguration: {
        type: 'typeorm',
        options: {
          type: process.env.DB_TYPE as any || 'postgres',
          host: process.env.DB_HOST,
          port: parseInt(process.env.DB_PORT || '5432'),
          username: process.env.DB_USERNAME,
          password: process.env.DB_PASSWORD,
          database: process.env.DB_DATABASE,
          synchronize: false, // Use migrations in production
          logging: false,
        },
      },
    }),
    McpModule.forRoot({
      name: 'production-mcp-server',
      version: '1.0.0',
      guards: [McpAuthJwtGuard],
      // Production logging - errors and warnings only
      logging: {
        level: ['error', 'warn'],
      },
      // Choose transport based on scaling needs
      streamableHttp: {
        enableJsonResponse: false,
        sessionIdGenerator: () => randomUUID(),
        statelessMode: false, // Set true for horizontal scaling
      },
    }),
  ],
  providers: [McpAuthJwtGuard],
})
class AppModule {}

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  app.use(cookieParser());

  // Production CORS configuration
  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || false,
    credentials: true,
  });

  // Trust proxy for load balancers
  app.set('trust proxy', 1);

  const port = process.env.PORT || 3030;
  await app.listen(port, '0.0.0.0');
  console.log(`MCP Server running on port ${port}`);
}

void bootstrap();
```

## Transport Selection for Production

### Streamable HTTP Stateless (Recommended for Horizontal Scaling)

Best for: Serverless, auto-scaling environments, Kubernetes

```typescript
McpModule.forRoot({
  name: 'mcp-server',
  version: '1.0.0',
  transport: [McpTransportType.STREAMABLE_HTTP],
  streamableHttp: {
    enableJsonResponse: true,
    statelessMode: true, // Each request is independent
  },
})
```

**Advantages:**
- Horizontally scalable without session affinity
- Works with any load balancer
- Suitable for serverless (AWS Lambda, Cloud Functions)
- No shared state between instances

### Streamable HTTP Stateful

Best for: Single-instance or sticky-session deployments

```typescript
McpModule.forRoot({
  name: 'mcp-server',
  version: '1.0.0',
  transport: [McpTransportType.STREAMABLE_HTTP],
  streamableHttp: {
    enableJsonResponse: false,
    sessionIdGenerator: () => randomUUID(),
    statelessMode: false,
  },
})
```

**Requirements:**
- Sticky sessions (session affinity) in load balancer
- Sessions stored in-memory per instance

### SSE Transport

Best for: Real-time streaming, long-running connections

```typescript
McpModule.forRoot({
  name: 'mcp-server',
  version: '1.0.0',
  transport: [McpTransportType.SSE],
  sse: {
    pingEnabled: true,
    pingIntervalMs: 30000, // Keep connections alive
  },
})
```

**Requirements:**
- Sticky sessions required
- Load balancer must support long-lived connections
- Configure appropriate timeouts

## Docker Deployment

### Dockerfile

```dockerfile
# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Production stage
FROM node:20-alpine AS production

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nestjs -u 1001

COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

COPY --from=builder /app/dist ./dist

USER nestjs

ENV NODE_ENV=production
EXPOSE 3030

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3030/health || exit 1

CMD ["node", "dist/main.js"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  mcp-server:
    build: .
    ports:
      - "3030:3030"
    environment:
      - NODE_ENV=production
      - PORT=3030
      - SERVER_URL=https://your-domain.com
      - JWT_SECRET=${JWT_SECRET}
      - GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID}
      - GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET}
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_USERNAME=mcp_user
      - DB_PASSWORD=${DB_PASSWORD}
      - DB_DATABASE=mcp_oauth
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:3030/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=mcp_user
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_DB=mcp_oauth
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U mcp_user -d mcp_oauth"]
      interval: 10s
      timeout: 5s
      retries: 5

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - mcp-server

volumes:
  postgres_data:
```

### Nginx Configuration

```nginx
upstream mcp_backend {
    # For stateless mode - simple load balancing
    least_conn;
    server mcp-server:3030;

    # For stateful mode - use sticky sessions instead:
    # hash $cookie_mcp_session consistent;
    # server mcp-server-1:3030;
    # server mcp-server-2:3030;
}

server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # SSE-specific settings
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;

    location / {
        proxy_pass http://mcp_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://mcp_backend;
        proxy_connect_timeout 5s;
        proxy_read_timeout 5s;
    }
}
```

## Kubernetes Deployment

### Deployment Manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-server
  labels:
    app: mcp-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-server
  template:
    metadata:
      labels:
        app: mcp-server
    spec:
      containers:
        - name: mcp-server
          image: your-registry/mcp-server:latest
          ports:
            - containerPort: 3030
          env:
            - name: NODE_ENV
              value: "production"
            - name: PORT
              value: "3030"
            - name: SERVER_URL
              valueFrom:
                configMapKeyRef:
                  name: mcp-config
                  key: server-url
            - name: JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: mcp-secrets
                  key: jwt-secret
            - name: GITHUB_CLIENT_ID
              valueFrom:
                secretKeyRef:
                  name: mcp-secrets
                  key: github-client-id
            - name: GITHUB_CLIENT_SECRET
              valueFrom:
                secretKeyRef:
                  name: mcp-secrets
                  key: github-client-secret
            - name: DB_HOST
              value: "postgres-service"
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: mcp-secrets
                  key: db-password
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "500m"
          readinessProbe:
            httpGet:
              path: /health
              port: 3030
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /health
              port: 3030
            initialDelaySeconds: 15
            periodSeconds: 20
---
apiVersion: v1
kind: Service
metadata:
  name: mcp-server-service
spec:
  selector:
    app: mcp-server
  ports:
    - protocol: TCP
      port: 80
      targetPort: 3030
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mcp-server-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    # For stateful mode with sticky sessions:
    # nginx.ingress.kubernetes.io/affinity: "cookie"
    # nginx.ingress.kubernetes.io/session-cookie-name: "mcp-route"
    # nginx.ingress.kubernetes.io/session-cookie-expires: "172800"
spec:
  tls:
    - hosts:
        - your-domain.com
      secretName: mcp-tls
  rules:
    - host: your-domain.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: mcp-server-service
                port:
                  number: 80
```

### Secrets and ConfigMap

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mcp-secrets
type: Opaque
stringData:
  jwt-secret: "your-secure-jwt-secret-minimum-32-characters"
  github-client-id: "your-github-client-id"
  github-client-secret: "your-github-client-secret"
  db-password: "your-database-password"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: mcp-config
data:
  server-url: "https://your-domain.com"
```

## Cloud Platform Deployments

### AWS ECS/Fargate

```json
{
  "family": "mcp-server",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "mcp-server",
      "image": "your-ecr-repo/mcp-server:latest",
      "portMappings": [
        {
          "containerPort": 3030,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "NODE_ENV", "value": "production"},
        {"name": "PORT", "value": "3030"}
      ],
      "secrets": [
        {
          "name": "JWT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:mcp/jwt-secret"
        },
        {
          "name": "GITHUB_CLIENT_ID",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:mcp/github-client-id"
        }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "wget --spider -q http://localhost:3030/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/mcp-server",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### Google Cloud Run

```yaml
# cloud-run.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: mcp-server
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/minScale: "1"
        autoscaling.knative.dev/maxScale: "10"
    spec:
      containers:
        - image: gcr.io/YOUR_PROJECT/mcp-server:latest
          ports:
            - containerPort: 3030
          env:
            - name: NODE_ENV
              value: "production"
            - name: SERVER_URL
              value: "https://mcp-server-HASH-uc.a.run.app"
          resources:
            limits:
              memory: "512Mi"
              cpu: "1"
```

Deploy with:
```bash
gcloud run deploy mcp-server \
  --image gcr.io/YOUR_PROJECT/mcp-server:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars "NODE_ENV=production"
```

### Azure Container Apps

```bash
az containerapp create \
  --name mcp-server \
  --resource-group mcp-rg \
  --environment mcp-env \
  --image your-registry.azurecr.io/mcp-server:latest \
  --target-port 3030 \
  --ingress external \
  --min-replicas 1 \
  --max-replicas 10 \
  --env-vars "NODE_ENV=production" \
  --secrets "jwt-secret=your-secret" \
  --env-vars "JWT_SECRET=secretref:jwt-secret"
```

## Database Setup

### PostgreSQL (Recommended)

```sql
-- Create database and user
CREATE DATABASE mcp_oauth;
CREATE USER mcp_user WITH ENCRYPTED PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE mcp_oauth TO mcp_user;

-- Grant schema permissions
\c mcp_oauth
GRANT ALL ON SCHEMA public TO mcp_user;
```

### TypeORM Configuration for Production

```typescript
storeConfiguration: {
  type: 'typeorm',
  options: {
    type: 'postgres',
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || '5432'),
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    // Production settings
    synchronize: false, // Never use synchronize in production
    logging: ['error'], // Only log errors
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
    extra: {
      max: 20, // Connection pool size
      connectionTimeoutMillis: 5000,
      idleTimeoutMillis: 30000,
    },
  },
}
```

### Database Migrations

Create a migration script for production:

```bash
# Generate migration from entities
npx typeorm migration:generate -d src/data-source.ts src/migrations/InitialSchema

# Run migrations
npx typeorm migration:run -d src/data-source.ts
```

## Security Best Practices

### 1. JWT Secret Generation

Generate a cryptographically secure JWT secret:

```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### 2. HTTPS Configuration

Always use HTTPS in production. Configure via reverse proxy (Nginx, Traefik) or cloud load balancer.

### 3. Rate Limiting

Add rate limiting to prevent abuse:

```typescript
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';

@Module({
  imports: [
    ThrottlerModule.forRoot([{
      ttl: 60000, // 1 minute
      limit: 100, // 100 requests per minute
    }]),
    // ... other imports
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
class AppModule {}
```

### 4. Helmet Security Headers

```typescript
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(helmet());
  // ...
}
```

### 5. CORS Configuration

```typescript
app.enableCors({
  origin: (origin, callback) => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
});
```

### 6. Environment Variable Validation

```typescript
import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']),
  PORT: z.string().transform(Number).default('3030'),
  JWT_SECRET: z.string().min(32),
  GITHUB_CLIENT_ID: z.string(),
  GITHUB_CLIENT_SECRET: z.string(),
  SERVER_URL: z.string().url(),
});

const env = envSchema.parse(process.env);
```

## Scaling Considerations

### Horizontal Scaling (Stateless Mode)

For maximum scalability, use stateless mode:

```typescript
McpModule.forRoot({
  streamableHttp: {
    statelessMode: true,
    enableJsonResponse: true,
  },
})
```

**Benefits:**
- Any instance can handle any request
- No session affinity required
- Simple load balancer configuration
- Auto-scaling friendly

### Vertical Scaling (Stateful Mode)

If using stateful mode with sessions:

1. **Enable sticky sessions** in your load balancer
2. Consider session store externalization (Redis) for high availability
3. Monitor memory usage for session data

### Load Balancer Configuration

**For Stateless Mode (Round Robin):**
```nginx
upstream mcp_backend {
    least_conn;
    server mcp-1:3030;
    server mcp-2:3030;
    server mcp-3:3030;
}
```

**For Stateful Mode (Sticky Sessions):**
```nginx
upstream mcp_backend {
    hash $cookie_mcp_session consistent;
    server mcp-1:3030;
    server mcp-2:3030;
    server mcp-3:3030;
}
```

## Monitoring and Health Checks

### Health Check Endpoint

Add a health check endpoint to your server:

```typescript
import { Controller, Get } from '@nestjs/common';

@Controller('health')
export class HealthController {
  @Get()
  check() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    };
  }

  @Get('ready')
  readiness() {
    // Check database connectivity, etc.
    return { status: 'ready' };
  }

  @Get('live')
  liveness() {
    return { status: 'alive' };
  }
}
```

### Metrics to Monitor

- **Request rate** - Requests per second to MCP endpoints
- **Error rate** - 4xx and 5xx responses
- **Response time** - P50, P95, P99 latencies
- **Active connections** - For SSE transport
- **Memory usage** - Especially for stateful sessions
- **Database connections** - Pool utilization

### Logging Configuration

```typescript
McpModule.forRoot({
  logging: {
    level: ['error', 'warn'], // Production: minimal logging
  },
})

// For structured logging, use a custom logger:
import { WinstonModule } from 'nest-winston';
import * as winston from 'winston';

const app = await NestFactory.create(AppModule, {
  logger: WinstonModule.createLogger({
    transports: [
      new winston.transports.Console({
        format: winston.format.json(),
      }),
    ],
  }),
});
```

## Troubleshooting

### Common Issues

**1. OAuth Callback Mismatch**
```
Error: redirect_uri_mismatch
```
Solution: Ensure your OAuth provider's callback URL matches `{SERVER_URL}/{apiPrefix}/callback`

**2. JWT Secret Too Short**
```
Error: JWT secret must be at least 32 characters
```
Solution: Generate a longer secret using `crypto.randomBytes(64).toString('hex')`

**3. CORS Errors**
```
Error: CORS policy blocked
```
Solution: Add the client origin to `ALLOWED_ORIGINS` environment variable

**4. Session Not Persisting (Stateful Mode)**
```
Error: Session not found
```
Solution: Ensure sticky sessions are enabled in your load balancer

**5. Database Connection Timeout**
```
Error: Connection timeout
```
Solution: Check database host/port, increase connection pool size, verify network connectivity

### Debug Mode

Enable verbose logging temporarily:

```typescript
McpModule.forRoot({
  logging: {
    level: ['log', 'error', 'warn', 'debug', 'verbose'],
  },
})
```

### Testing Production Configuration Locally

```bash
# Build production image
docker build -t mcp-server .

# Run with production settings
docker run -p 3030:3030 \
  -e NODE_ENV=production \
  -e JWT_SECRET=test-secret-at-least-32-characters-long \
  -e GITHUB_CLIENT_ID=your-id \
  -e GITHUB_CLIENT_SECRET=your-secret \
  -e SERVER_URL=http://localhost:3030 \
  mcp-server

# Test health endpoint
curl http://localhost:3030/health

# Test MCP endpoint
curl -X POST http://localhost:3030/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

## Related Documentation

- [Built-in Authorization Server](./built-in-authorization-server.md) - OAuth 2.1 configuration
- [Server Examples](./server-examples.md) - Example server configurations
- [External Authorization Server](./external-authorization-server/README.md) - Using external OAuth providers
