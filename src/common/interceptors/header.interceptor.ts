import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from "@nestjs/common";
import { Observable } from "rxjs";
import { tap } from 'rxjs/operators';
import { randomUUID } from 'crypto';
import { envs } from "src/config/envs";

@Injectable()
export class HeaderInterceptor implements NestInterceptor {
    intercept(context: ExecutionContext, next: CallHandler<any>): Observable<any> {
        if (context.getType() !== 'http') {
            return next.handle();
        }
        const startTime = performance.now();
        const startMemory = process.memoryUsage().heapUsed;
        const http = context.switchToHttp();
        const request = http.getRequest();
        const response = http.getResponse();
        return next.handle().pipe(
            tap((data) => {
                if (response.headersSent) return;
                // 1. Tiempo de respuesta
                const duration = ((performance.now() - startTime) / 1000).toFixed(3);
                response.setHeader('X-Total-Time', `${duration}s`);
                // 2. Peso de la respuesta
                if (data !== undefined && data !== null) {
                    const bytes = this.getByteSize(data);
                    response.setHeader('X-Total-Size', `${bytes} B`);
                }
                // 3. Cantidad de ítems
                if (!response.getHeader('Content-Disposition')) {
                    if (request.method === 'GET' && !response.getHeader('X-Total-Items')) {
                        if (Array.isArray(data)) {
                            response.setHeader('X-Total-Items', data.length);
                        } else if (typeof data === 'object' && data !== null) {
                            response.setHeader('X-Total-Items', 1);
                        }
                    }
                }
                // 4. Asignar o reutilizar X-Request-ID
                const requestId = request.headers['X-Request-Id'] || randomUUID();
                response.setHeader('X-Request-Id', requestId);
                // 5. Versión del aplicativo
                response.setHeader('X-App-Version', envs.version);
                // 6. Consumo de memoria
                const endMemory = process.memoryUsage().heapUsed;
                const memoryDeltaKb = ((endMemory - startMemory) / 1024).toFixed(2);
                response.setHeader('X-RAM-Memory', `${memoryDeltaKb} KB`);
                return data;
            })
        );
    }

    private getByteSize(data: any): number {
        if (Buffer.isBuffer(data)) {
            return data.length;
        }
        if (typeof data === 'string') {
            return Buffer.byteLength(data, 'utf8');
        }
        if (typeof data === 'object') {
            return Buffer.byteLength(JSON.stringify(data), 'utf8');
        }
        return Buffer.byteLength(String(data), 'utf8');
    }
}
