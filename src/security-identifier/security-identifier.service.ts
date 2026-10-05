import { Injectable, InternalServerErrorException, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { WebDataDto } from '../common/dtos/web-data.dto';
import { request, APIRequestContext, APIResponse } from 'playwright';
import { CertificateInfo, SecretSeverity, RawCertificate, SecurityIdentifierResult } from './dto/security-identifier.dto';
import * as tls from 'tls';

@Injectable()
export class SecurityIdentifierService {
    private readonly logger = new Logger('SECURITY-IDENTIFIER-SERVICE');
    private readonly expiry_warning_days: number = 15;
    private readonly tls_connect_timeout_ms: number = 8000;
    private readonly http_check_timeout_ms: number = 8000;
    private readonly max_redirects: number = 10;
    private readonly browser_like_user_agent: string = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
    constructor() { }

    async getSecurityIdentifier(webDataDto: WebDataDto): Promise<SecurityIdentifierResult> {
        const requestContext: APIRequestContext = await request.newContext({ ignoreHTTPSErrors: true });
        try {
            const [{ finalUrl, httpStatus, unreachable }, httpsRedirectOk] = await Promise.all([
                this.resolveFinalUrl(requestContext, webDataDto.web_url),
                this.checkHttpsRedirect(requestContext, webDataDto.web_url)
            ]);
            const finalUrlObj: URL = new URL(finalUrl);
            const hostname: string = finalUrlObj.hostname;
            const port: number = finalUrlObj.port ? Number(finalUrlObj.port) : 443;
            const rawCert: RawCertificate | null = await this.getRawCertificate(hostname, port);
            const certificate: CertificateInfo | null = this.buildCertificateInfo(rawCert, hostname);
            return {
                url: webDataDto.web_url,
                finalUrl,
                httpStatus,
                unreachable,
                certificate,
                httpsRedirectOk,
                overallRisk: this.computeOverallRisk(certificate, httpsRedirectOk, unreachable),
                summary: this.buildSummaryText(certificate, httpsRedirectOk, unreachable)
            };
        } catch (error: any) {
            this.logger.error(`Error crítico: ${error.stack}`);
            throw new InternalServerErrorException(`Se produjo un error al analizar la seguridad: ${error}`);
        }
        finally {
            await requestContext.dispose();
        }
    }

    private async resolveFinalUrl(requestContext: APIRequestContext, url: string): Promise<{ finalUrl: string; httpStatus: number | null; unreachable: boolean }> {
        try {
            const response: APIResponse<any> = await requestContext.get(url, {
                timeout: this.http_check_timeout_ms,
                maxRedirects: this.max_redirects,
                failOnStatusCode: false
            });
            return { finalUrl: response.url(), httpStatus: response.status(), unreachable: false };
        } catch (error: any) {
            this.logger.warn(`No se pudo obtener respuesta HTTP de ${url}: ${error.message}`);
            return { finalUrl: url, httpStatus: null, unreachable: true };
        }
    }

    private getRawCertificate(hostname: string, port: number): Promise<RawCertificate | null> {
        return new Promise((resolve) => {
            let settled: boolean = false;
            const finish = (value: RawCertificate | null) => {
                if (settled) return;
                settled = true;
                resolve(value);
            };
            const socket: tls.TLSSocket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: this.tls_connect_timeout_ms },
                () => {
                    try {
                        const cert: tls.DetailedPeerCertificate = socket.getPeerCertificate(true);
                        const protocol: string | null = socket.getProtocol();
                        if (!cert || Object.keys(cert).length === 0) {
                            finish(null);
                        } else {
                            const issuerCN: string = this.flattenCertField(cert.issuer?.CN);
                            const issuerO: string = this.flattenCertField(cert.issuer?.O);
                            finish({
                                issuer: issuerCN || issuerO,
                                subject: this.flattenCertField(cert.subject?.CN),
                                protocol,
                                validFrom: new Date(cert.valid_from),
                                validTo: new Date(cert.valid_to),
                                subjectAltNames: this.parseSubjectAltName(cert.subjectaltname)
                            });
                        }
                    } catch (error: any) {
                        this.logger.warn(`No se pudo leer el certificado de ${hostname}: ${error}`);
                        finish(null);
                    } finally {
                        socket.end();
                    }
                },
            );
            socket.on('timeout', () => { socket.destroy(); finish(null); });
            socket.on('error', (error) => {
                this.logger.warn(`Error de conexión TLS a ${hostname}: ${error.message}`);
                finish(null);
            });
        });
    }

    private flattenCertField(value: string | string[] | undefined): string {
        if (Array.isArray(value)) return value.join(', ');
        return value ?? '';
    }

    private parseSubjectAltName(san?: string): string[] {
        if (!san) return [];
        return san.split(',').map((s) => s.trim()).filter((s) => s.startsWith('DNS:')).map((s) => s.slice(4));
    }

    private buildCertificateInfo(raw: { issuer: string; subject: string; protocol: string | null; validFrom: Date; validTo: Date; subjectAltNames: string[] } | null, hostname: string): CertificateInfo | null {
        if (!raw) return null;
        const now: number = Date.now();
        const validToMs: number = raw.validTo.getTime();
        const namesToCheck: string[] = raw.subjectAltNames.length > 0 ? raw.subjectAltNames : [raw.subject];
        return {
            issuer: raw.issuer,
            subjectName: raw.subject,
            subjectAltNames: raw.subjectAltNames,
            protocol: raw.protocol ?? '',
            validFrom: raw.validFrom.toISOString(),
            validTo: raw.validTo.toISOString(),
            daysUntilExpiry: Math.floor((validToMs - now) / 86_400_000),
            isExpired: validToMs < now,
            isSelfSigned: !!raw.issuer && !!raw.subject && raw.issuer.trim().toLowerCase() === raw.subject.trim().toLowerCase(),
            hostnameMismatch: !namesToCheck.some((name) => this.matchesHostname(name, hostname)),
            isWeakProtocol: /TLSv1(\.0|\.1)?$|SSL/i.test(raw.protocol ?? '')
        };
    }

    private matchesHostname(certName: string, hostname: string): boolean {
        if (!certName) return false;
        const cn: string = certName.toLowerCase();
        const host: string = hostname.toLowerCase();
        if (cn.startsWith('*.')) {
            const suffix: string = cn.slice(1);
            return host.endsWith(suffix) && host.split('.').length === cn.split('.').length;
        }
        return cn === host;
    }

    private async checkHttpsRedirect(requestContext: APIRequestContext, originalUrl: string): Promise<boolean | null> {
        const url: URL = new URL(originalUrl);
        if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
        url.protocol = 'http:';
        if (url.port === '443') url.port = '';
        try {
            const response: APIResponse<any> = await requestContext.get(url.toString(), {
                timeout: this.http_check_timeout_ms,
                maxRedirects: this.max_redirects,
                failOnStatusCode: false
            });
            return response.url().startsWith('https://');
        } catch (error: any) {
            this.logger.warn(`No se pudo verificar la redirección HTTP->HTTPS: ${error}`);
            return null;
        }
    }

    private computeOverallRisk(certificate: CertificateInfo | null, httpsRedirectOk: boolean | null, unreachable: boolean): SecretSeverity {
        const severities: SecretSeverity[] = [];
        if (certificate) {
            if (certificate.isExpired) severities.push(SecretSeverity.CRITICAL);
            else if (certificate.daysUntilExpiry <= this.expiry_warning_days) severities.push(SecretSeverity.HIGH);
            if (certificate.isSelfSigned) severities.push(SecretSeverity.HIGH);
            if (certificate.hostnameMismatch) severities.push(SecretSeverity.HIGH);
            if (certificate.isWeakProtocol) severities.push(SecretSeverity.MEDIUM);
        }
        if (httpsRedirectOk === false) severities.push(SecretSeverity.HIGH);
        if (unreachable) severities.push(SecretSeverity.MEDIUM);
        return severities.length === 0 ? SecretSeverity.LOW : Math.max(...severities);
    }

    private buildSummaryText(certificate: CertificateInfo | null, httpsRedirectOk: boolean | null, unreachable: boolean): string {
        const parts: string[] = [];
        if (unreachable) parts.push('El sitio no respondió a la solicitud HTTP (timeout o posible bloqueo anti-bot)');
        if (!certificate) parts.push('No se pudieron obtener detalles del certificado TLS');
        if (certificate?.isExpired) parts.push('El certificado TLS está vencido');
        else if (certificate && certificate.daysUntilExpiry <= this.expiry_warning_days) parts.push(`El certificado vence en ${certificate.daysUntilExpiry} día(s)`);
        if (certificate?.isSelfSigned) parts.push('El certificado parece autofirmado');
        if (certificate?.hostnameMismatch) parts.push('El certificado no coincide con el dominio (CN)');
        if (certificate?.isWeakProtocol) parts.push(`Protocolo TLS débil (${certificate.protocol})`);
        if (httpsRedirectOk === false) parts.push('No redirige de HTTP a HTTPS');
        return parts.length === 0 ? 'No se detectaron problemas evidentes en el certificado TLS.' : parts.join(', ') + '.';
    }
}
