// Import types conditionally to avoid hard dependency
interface FastifyRequest {
  url: string;
  method: string;
  headers: Record<string, string | string[]>;
  query: Record<string, any>;
  body: any;
  params: Record<string, string>;
  routeOptions?: any;
  // From @fastify/cookie plugin
  cookies?: Record<string, string>;
}

interface FastifyReply {
  status(code: number): this;
  send(payload: any): Promise<void>;
  header(name: string, value: string | string[]): this;
  sent: boolean;
  raw: any;
  // From @fastify/cookie plugin
  setCookie?(name: string, value: string, options?: any): this;
  clearCookie?(name: string, options?: any): this;
  // Built-in redirect
  redirect(statusCode: number, url: string): this;
  redirect(url: string): this;
}

import {
  CookieOptions,
  HttpAdapter,
  HttpRequest,
  HttpResponse,
} from '../interfaces/http-adapter.interface';

/**
 * Fastify HTTP adapter that implements the generic HTTP interface
 */
export class FastifyHttpAdapter implements HttpAdapter {
  adaptRequest(req: FastifyRequest): HttpRequest {
    const cookies = req.cookies as Record<string, string | undefined> | undefined;
    return {
      url: req.url,
      method: req.method,
      headers: req.headers as Record<string, string | string[] | undefined>,
      query: req.query,
      body: req.body,
      params: req.params,
      get: (name: string) => {
        const value = req.headers[name.toLowerCase()];
        return Array.isArray(value) ? value[0] : value;
      },
      cookies,
      getCookie: (name: string) => cookies?.[name],
      raw: (req as any).raw, // Raw Node.js IncomingMessage for MCP transport
    };
  }

  adaptResponse(res: FastifyReply): HttpResponse {
    return {
      status: (code: number) => {
        res.status(code);
        return this.adaptResponse(res);
      },
      json: (body: any) => {
        void res.send(body);
        return this.adaptResponse(res);
      },
      send: (body: string) => {
        void res.send(body);
        return this.adaptResponse(res);
      },
      write: (chunk: any) => {
        void res.raw.write(chunk);
      },
      setHeader: (name: string, value: string | string[]) => {
        res.header(name, value);
      },
      get headersSent() {
        return res.sent;
      },
      get writable() {
        return !res.sent;
      },
      get closed() {
        return res.sent;
      },
      on: (event: string, listener: (...args: any[]) => void) => {
        res.raw.on(event, listener);
      },
      setCookie: (name: string, value: string, options?: CookieOptions) => {
        // @fastify/cookie provides setCookie method
        if (res.setCookie) {
          res.setCookie(name, value, options);
        }
      },
      clearCookie: (name: string, options?: CookieOptions) => {
        // @fastify/cookie provides clearCookie method
        if (res.clearCookie) {
          res.clearCookie(name, options);
        }
      },
      redirect: (url: string) => {
        res.redirect(302, url);
      },
      raw: res.raw, // Raw Node.js ServerResponse for MCP transport
    };
  }
}
