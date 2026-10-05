import { ExecutionContext, Injectable } from '@nestjs/common';
import { ThrottlerException, ThrottlerGuard, ThrottlerLimitDetail } from '@nestjs/throttler';
import { FingerprintedRequest } from '../middlewares/fingerprint-middleware';
import { Response } from 'express';

@Injectable()
export class FingerprintThrottlerGuard extends ThrottlerGuard {
    protected async getTracker(req: FingerprintedRequest): Promise<string> {
        return req.fingerprintId ?? req.ip ?? 'unknown';
    }

    protected async addHeaders(response: Response, totalHits: number, timeToBlockExpire: number, throttlerDetail: ThrottlerLimitDetail): Promise<void> {
        const remaining = Math.max(0, throttlerDetail.limit - totalHits);
        response.setHeader('X-RateLimit-Limit', throttlerDetail.limit);
        response.setHeader('X-RateLimit-Remaining', remaining);
        response.setHeader('X-RateLimit-Reset', timeToBlockExpire);
    }

    protected async throwThrottlingException(context: ExecutionContext, throttlerLimitDetail: ThrottlerLimitDetail): Promise<void> {
        throw new ThrottlerException('Demasiadas solicitudes. Has alcanzado el límite permitido.');
    }

    protected async shouldSkip(context: ExecutionContext): Promise<boolean> {
        const req = context.switchToHttp().getRequest<FingerprintedRequest>();
        if (req.headers['x-internal-service']) {
            return true;
        }
        return super.shouldSkip(context);
    }
}
