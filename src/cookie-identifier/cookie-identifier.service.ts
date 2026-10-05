import { Injectable, InternalServerErrorException, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { WebDataDto } from '../common/dtos/web-data.dto';
import { chromium, Browser, Cookie, Page, BrowserContext } from 'playwright';
import { CookieAnalysisResponse, CookieDomainScope, CookieIdentifierResult, CookieRiskLevel, CookieSameSite, CookieSummary, CookieValueExposure } from '../cookie-identifier/dto/cookie-identifier.interface';

@Injectable()
export class CookieIdentifierService implements OnModuleInit, OnModuleDestroy {
    private readonly logger = new Logger('COOKIE-IDENTIFIER-SERVICE');
    private static readonly sensitive_name_patterns: RegExp[] = [
        /session/i, /token/i, /auth/i, /jwt/i, /csrf/i, /xsrf/i,
        /secret/i, /api[_-]?key/i, /password/i, /pwd/i,
        /account/i, /uid/i, /user[_-]?id/i, /remember/i,
    ];
    private static readonly secure_prefixes: string[] = ['__Secure-', '__Host-'];
    private static readonly ad_tech_suffixes: string[] = [
        'doubleclick.net', 'google-analytics.com', 'googlesyndication.com',
        'googletagmanager.com', 'adsrvr.org', 'rubiconproject.com',
        'scorecardresearch.com', 'hs-scripts.com', 'hs-analytics.net',
        'hs-banner.com', 'hsforms.com', 'clarity.ms', 'pinterest.com',
        'ct.pinterest.com', 'tiktok.com', 'linkedin.com', 'facebook.com',
        'connect.facebook.net', 'amazon-adsystem.com', 'applovin.com',
        'creativecdn.com', 'groovinads.com', 't.co', 'twitter.com', 'x.com',
        'youtube.com', 'liadm.com', 'disqus.com', 'adsystem.com',
    ];
    private static readonly jwt_pattern: RegExp = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
    private browser!: Browser;
    constructor() { }

    async onModuleInit() {
        this.browser = await chromium.launch({ headless: true });
    }

    async onModuleDestroy() {
        if (this.browser) {
            await this.browser.close();
        }
    }

    async getCookieIdentifier(webDataDto: WebDataDto): Promise<CookieIdentifierResult> {
        const context: BrowserContext = await this.browser.newContext({ ignoreHTTPSErrors: true });
        const page: Page = await context.newPage();
        try {
            await page.route('**/*.{png,jpg,jpeg,gif,svg,woff,woff2,css}', (route) => route.abort());
            const response = await page.goto(webDataDto.web_url, { waitUntil: 'domcontentloaded', timeout: 15000 });
            if (!response) {
                throw new Error('El servidor no devolvió una respuesta válida');
            }
            await page.waitForTimeout(1500);
            const html: string = await page.content();
            const requestedHost: string = new URL(webDataDto.web_url).hostname;
            const cookies: Cookie[] = await context.cookies();
            const nameCounts: Map<string, number> = new Map<string, number>();
            cookies.forEach((c) => nameCounts.set(c.name, (nameCounts.get(c.name) ?? 0) + 1));
            const analyzed: CookieAnalysisResponse[] = cookies.map((cookie) => {
                const isDuplicateName: boolean = (nameCounts.get(cookie.name) ?? 0) > 1;
                return this.analyzeCookie(cookie, requestedHost, html, isDuplicateName);
            });
            const summary: CookieSummary = this.buildSummary(analyzed);
            return { cookies: analyzed, summary };
        } catch (error: any) {
            this.logger.error(`Error crítico: ${error.stack}`);
            throw new InternalServerErrorException(`Se produjo un error al consultar las cookies de la web: ${error}`);
        }
        finally {
            await page.close();
            await context.close();
        }
    }

    private analyzeCookie(cookie: Cookie, requestedHost: string, html: string, isDuplicateName: boolean): CookieAnalysisResponse {
        const findings: string[] = [];
        // --- SESIÓN / EXPIRACIÓN ---
        const session: boolean = cookie.expires === -1 || cookie.expires === undefined;
        const expiresInDays: number = session ? 0 : Math.max(0, Math.round((cookie.expires * 1000 - Date.now()) / 86_400_000));
        if (!session && expiresInDays !== 0 && expiresInDays > 365) {
            findings.push(`Cookie persistente con expiración muy larga (${expiresInDays} días).`);
        }
        // --- PREFIJOS DE SEGURIDAD (__Secure-, __Host-) ---
        const hasSecurePrefix: boolean = CookieIdentifierService.secure_prefixes.some((p) => cookie.name.startsWith(p));
        if (cookie.name.startsWith('__Host-') && (cookie.path !== '/' || cookie.domain.startsWith('.'))) {
            findings.push('Cookie con prefijo __Host- que no cumple sus restricciones (requiere path=/ y sin Domain).');
        }
        if (hasSecurePrefix && !cookie.secure) {
            findings.push('Cookie con prefijo __Secure-/__Host- pero sin el flag Secure activo (violación del prefijo).');
        }
        // --- ALCANCE DE DOMINIO ---
        const domainScope: CookieDomainScope = cookie.domain.startsWith('.') ? 'broad' : 'host';
        if (domainScope === 'broad') {
            findings.push(`Alcance de dominio amplio (${cookie.domain}): visible en todos los subdominios.`);
        }
        // --- COOKIES DE TERCEROS ---
        const normalizedDomain: string = cookie.domain.replace(/^\./, '');
        const thirdParty: boolean = !(requestedHost === normalizedDomain || requestedHost.endsWith(`.${normalizedDomain}`));
        const partitioned: boolean = Boolean((cookie as any).partitionKey);
        if (thirdParty && partitioned) {
            findings.push(`Cookie de tercero particionada (CHIPS, ${cookie.domain}): el navegador aísla su estado por sitio de nivel superior, lo que reduce (no elimina) el riesgo de tracking cruzado.`);
        } else if (thirdParty) {
            findings.push(`Cookie de tercero sin particionar (${cookie.domain}): no pertenece al dominio consultado y su estado no está aislado por sitio.`);
        }
        const knownAdTech: boolean = this.isAdTechDomain(normalizedDomain);
        if (knownAdTech) {
            findings.push(`Dominio asociado a un proveedor de publicidad/analítica conocido (${cookie.domain}).`);
        }
        // --- COOKIES DUPLICADAS ---
        if (isDuplicateName) {
            findings.push(`Existe más de una cookie llamada "${cookie.name}" en el sitio, con distinto domain/path: riesgo de shadowing o de resolución ambigua por parte del navegador.`);
        }
        // --- FLAGS BÁSICOS ---
        if (!cookie.secure) {
            findings.push('Sin flag Secure: puede transmitirse por HTTP sin cifrar.');
        }
        if (!cookie.httpOnly) {
            findings.push('Sin flag HttpOnly: accesible desde JavaScript (riesgo ante XSS/robo de sesión).');
        }
        const sameSite: CookieSameSite = this.normalizeSameSite(cookie.sameSite);
        if (sameSite === 'None' && !cookie.secure) {
            findings.push('SameSite=None sin Secure: configuración inválida, el navegador puede rechazarla o exponerla a CSRF.');
        }
        if (sameSite === 'Unspecified') {
            findings.push('SameSite no especificado explícitamente; el navegador aplica un valor por defecto no garantizado.');
        }
        // --- NOMBRE SENSIBLE ---
        const looksSensitiveByName: boolean = CookieIdentifierService.sensitive_name_patterns.some((re) => re.test(cookie.name));
        // --- FORMATO/EXPOSICIÓN DEL VALOR ---
        const valueExposure: CookieValueExposure = this.classifyValue(cookie.value);
        if (valueExposure === 'json') {
            findings.push('El valor es un objeto JSON (plano o URL-encoded) legible: expone datos/estructura interna de la aplicación al cliente.');
        }
        if (valueExposure === 'plaintext_like') {
            findings.push('El valor parece texto plano legible: posible dato sensible sin cifrar ni firmar.');
        }
        if (valueExposure === 'jwt' && !cookie.httpOnly) {
            findings.push('Token JWT accesible desde JavaScript: un XSS podría robar el token completo.');
        }
        if (valueExposure === 'empty' && looksSensitiveByName) {
            findings.push('Cookie con nombre sensible pero valor vacío; revisar si se setea correctamente.');
        }
        // --- REFLEJO EN EL HTML: POSIBLE FUGA/INYECCIÓN ---
        const comparableValue: string = this.stripWrappingQuotes(cookie.value);
        const decodedValue: string = this.tryDecodeUri(comparableValue);
        const reflectedInHtml: boolean = comparableValue.length > 3 && (html.includes(comparableValue) || (decodedValue !== comparableValue && html.includes(decodedValue)));
        if (reflectedInHtml) {
            findings.push('El valor de la cookie se refleja tal cual en el HTML de la página: posible fuga de información o vector de inyección si no se está escapando al renderizar.');
        }
        if (looksSensitiveByName && !cookie.secure) {
            findings.push('Cookie con nombre sensible transmitida sin flag Secure.');
        }
        if (looksSensitiveByName && !cookie.httpOnly) {
            findings.push('Cookie con nombre sensible accesible vía JavaScript (sin HttpOnly).');
        }
        const riskLevel: CookieRiskLevel = this.calculateRisk({
            secure: cookie.secure,
            httpOnly: cookie.httpOnly,
            sameSite,
            thirdParty,
            partitioned,
            looksSensitiveByName,
            valueExposure,
            reflectedInHtml,
            isDuplicateName
        });
        return {
            name: cookie.name,
            domain: cookie.domain,
            path: cookie.path,
            secure: cookie.secure,
            httpOnly: cookie.httpOnly,
            sameSite,
            session,
            expiresInDays,
            hasSecurePrefix,
            domainScope,
            thirdParty,
            partitioned,
            knownAdTech,
            duplicateName: isDuplicateName,
            looksSensitiveByName,
            valueExposure,
            reflectedInHtml,
            riskLevel,
            findings
        };
    }

    private normalizeSameSite(value: Cookie['sameSite'] | undefined): CookieSameSite {
        if (value === 'Strict' || value === 'Lax' || value === 'None') return value;
        return 'Unspecified';
    }

    private isAdTechDomain(normalizedDomain: string): boolean {
        return CookieIdentifierService.ad_tech_suffixes.some(
            (suffix) => normalizedDomain === suffix || normalizedDomain.endsWith(`.${suffix}`),
        );
    }

    private classifyValue(rawValue: string): CookieValueExposure {
        if (!rawValue) return 'empty';
        const value: string = this.stripWrappingQuotes(rawValue);
        if (CookieIdentifierService.jwt_pattern.test(value)) return 'jwt';
        if (this.looksLikeJson(value)) return 'json';
        const decoded: string = this.tryDecodeUri(value);
        if (decoded !== value && this.looksLikeJson(decoded)) return 'json';
        const target: string = decoded !== value ? decoded : value;
        const looksLikePlaintext: boolean =
            /\s/.test(target) ||
            /@.+\..+/.test(target) ||
            (/^[a-zA-Z0-9._%+-]+=[^;]+$/.test(target) && target.length < 60) ||
            (/^[\x20-\x7E]+$/.test(target) && target.length < 24 && !/^[A-Za-z0-9+/_=-]{16,}$/.test(target));
        if (looksLikePlaintext) return 'plaintext_like';
        return 'opaque';
    }

    private stripWrappingQuotes(value: string): string {
        if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
            return value.slice(1, -1);
        }
        return value;
    }

    private tryDecodeUri(value: string): string {
        try {
            const decoded: string = decodeURIComponent(value);
            return decoded;
        } catch {
            return value;
        }
    }

    private looksLikeJson(value: string): boolean {
        const trimmed: string = value.trim();
        if (!(trimmed.startsWith('{') && trimmed.endsWith('}')) && !(trimmed.startsWith('[') && trimmed.endsWith(']'))) {
            return false;
        }
        try {
            const parsed: any = JSON.parse(trimmed);
            return typeof parsed === 'object' && parsed !== null;
        } catch {
            return false;
        }
    }

    private calculateRisk(params: {
        secure: boolean;
        httpOnly: boolean;
        sameSite: CookieSameSite;
        thirdParty: boolean;
        partitioned: boolean;
        looksSensitiveByName: boolean;
        valueExposure: CookieValueExposure;
        reflectedInHtml: boolean;
        isDuplicateName: boolean;
    }): CookieRiskLevel {
        let score: number = 0;
        if (!params.secure) score += 2;
        if (!params.httpOnly) score += 2;
        if (params.sameSite === 'None' && !params.secure) score += 2;
        if (params.sameSite === 'Unspecified') score += 1;
        if (params.thirdParty && !params.partitioned) score += 1;
        if (params.reflectedInHtml) score += 3;
        if (params.valueExposure === 'plaintext_like') score += 2;
        if (params.valueExposure === 'json') score += 1;
        if (params.looksSensitiveByName) score += 1;
        if (params.looksSensitiveByName && (!params.secure || !params.httpOnly)) score += 2;
        if (params.isDuplicateName) score += 1;
        if (score >= 10) return CookieRiskLevel.CRITICAL;
        if (score >= 7) return CookieRiskLevel.HIGH;
        if (score >= 4) return CookieRiskLevel.MEDIUM;
        return CookieRiskLevel.LOW;
    }

    private buildSummary(cookies: CookieAnalysisResponse[]): CookieSummary {
        const total: number = cookies.length;
        let secureCount: number = 0;
        let httpOnlyCount: number = 0;
        let thirdPartyCount: number = 0;
        let partitionedCount: number = 0;
        let adTechCount: number = 0;
        let sessionCount: number = 0;
        let highOrCriticalCount: number = 0;
        let overallRiskNumeric: number = CookieRiskLevel.LOW as number;
        for (const cookie of cookies) {
            if (cookie.secure) secureCount++;
            if (cookie.httpOnly) httpOnlyCount++;
            if (cookie.thirdParty) thirdPartyCount++;
            if (cookie.partitioned) partitionedCount++;
            if (cookie.knownAdTech) adTechCount++;
            if (cookie.session) sessionCount++;
            if (cookie.riskLevel === CookieRiskLevel.HIGH || cookie.riskLevel === CookieRiskLevel.CRITICAL) {
                highOrCriticalCount++;
            }
            overallRiskNumeric = Math.max(overallRiskNumeric, cookie.riskLevel as number);
        }
        return {
            total,
            secureCount,
            httpOnlyCount,
            thirdPartyCount,
            partitionedCount,
            adTechCount,
            sessionCount,
            persistentCount: total - sessionCount,
            highOrCriticalCount,
            overallRisk: overallRiskNumeric as CookieRiskLevel,
        };
    }
}
