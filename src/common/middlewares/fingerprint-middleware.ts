import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { createHash } from 'crypto';

export interface FingerprintedRequest extends Request {
    fingerprintId?: string;
}

@Injectable()
export class FingerprintMiddleware implements NestMiddleware {
    private readonly header_name: string = 'x-fingerprint-id';
    use(req: FingerprintedRequest, res: Response, next: NextFunction) {
        const provided: string | string[] | undefined = req.headers[this.header_name];
        const fromClient: string | undefined = Array.isArray(provided) ? provided[0] : provided;
        req.fingerprintId = fromClient?.trim() ? fromClient.trim() : this.buildFallbackFingerprint(req);
        next();
    }

    // Fingerprint Temporal/Auxiliar
    private buildFallbackFingerprint(req: Request): string {
        const ip: string = req.ip ?? req.socket.remoteAddress ?? 'unknown-ip';
        const userAgent: string = req.headers['user-agent'] ?? 'unknown-agent';
        return createHash('sha256').update(`${ip}:${userAgent}`).digest('hex');
    }
}
