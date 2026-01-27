import type { Request, Response } from 'express';
import {
  CookieOptions,
  HttpAdapter,
  HttpRequest,
  HttpResponse,
} from '../interfaces/http-adapter.interface';

/**
 * Express HTTP adapter that implements the generic HTTP interface
 */
export class ExpressHttpAdapter implements HttpAdapter {
  adaptRequest(req: Request): HttpRequest {
    // Type assertion for cookies - requires cookie-parser middleware
    const cookies = (req as any).cookies as
      | Record<string, string | undefined>
      | undefined;
    return {
      url: req.url,
      method: req.method,
      headers: req.headers as Record<string, string | string[] | undefined>,
      query: req.query,
      body: req.body,
      params: req.params,
      get: (name: string) => req.get(name),
      cookies,
      getCookie: (name: string) => cookies?.[name],
      raw: req,
    };
  }

  adaptResponse(res: Response): HttpResponse {
    return {
      status: (code: number) => {
        res.status(code);
        return this.adaptResponse(res);
      },
      json: (body: any) => {
        res.json(body);
        return this.adaptResponse(res);
      },
      send: (body: string) => {
        res.send(body);
        return this.adaptResponse(res);
      },
      write: (chunk: any) => res.write(chunk),
      setHeader: (name: string, value: string | string[]) =>
        res.setHeader(name, value),
      get headersSent() {
        return res.headersSent;
      },
      get writable() {
        return res.writable;
      },
      get closed() {
        return res.destroyed || res.writableEnded;
      },
      on: (event: string, listener: (...args: any[]) => void) => {
        res.on(event, listener);
      },
      setCookie: (name: string, value: string, options?: CookieOptions) => {
        res.cookie(name, value, options || {});
      },
      clearCookie: (name: string, options?: CookieOptions) => {
        res.clearCookie(name, options || {});
      },
      redirect: (url: string) => {
        res.redirect(url);
      },
      raw: res,
    };
  }
}
