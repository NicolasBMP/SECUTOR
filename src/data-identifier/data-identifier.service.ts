import { Injectable, InternalServerErrorException, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { WebDataDto } from '../common/dtos/web-data.dto';
import { chromium, Browser, Page, BrowserContext, APIResponse } from 'playwright';
import { getDomain } from 'tldts';
import { DataIdentifierResult, ExposedPathFinding, ExposedSourceMapFinding, ScriptIntegrityFinding, ScriptsIntegritySummary, SecretFinding, SecretSeverity } from './dto/data-identifier.interface';

@Injectable()
export class DataIdentifierService implements OnModuleInit, OnModuleDestroy {
    private readonly logger = new Logger('DATA-IDENTIFIER-SERVICE');
    private readonly max_scripts_to_scan: number = 120;
    private readonly max_script_bytes: number = 8_000_000;
    private readonly max_total_script_bytes: number = 80_000_000;
    private readonly script_fetch_batch_size: number = 12;
    private readonly max_script_fetch_time_ms: number = 20_000;
    private readonly public_context_markers: string[] = [
        'maps.googleapis.com', 'recaptcha', 'firebaseapp.com', 'firebaseio.com',
        'bugsnag.com', 'sentry.io', 'mparticle', 'segment.com', 'amplitude.com',
        'mixpanel.com', 'hotjar.com', 'intercom.io', 'launchdarkly.com',
        'googletagmanager.com', 'google-analytics.com', 'doubleclick.net'
    ];
    private readonly secret_patterns: { name: string; regex: RegExp; severity: SecretSeverity }[] = [
        { name: 'Clave privada (PEM)', regex: /-----BEGIN ((?:RSA|EC|DSA|OPENSSH) )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\s]{60,}?-----END \1?PRIVATE KEY-----/g, severity: SecretSeverity.CRITICAL },
        { name: 'Cadena de conexión con credenciales (DB)', regex: /(mongodb(\+srv)?|postgres(ql)?|mysql):\/\/[^\s'"<>]+:[^\s'"<>]+@[^\s'"<>]+/gi, severity: SecretSeverity.CRITICAL },
        { name: 'Credenciales embebidas en URL (user:pass@host)', regex: /https?:\/\/[^\s'"<>/:]+:[^\s'"<>/@]+@[^\s'"<>]+/gi, severity: SecretSeverity.HIGH },
        { name: 'AWS Access Key ID', regex: /AKIA[0-9A-Z]{16}/g, severity: SecretSeverity.HIGH },
        { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g, severity: SecretSeverity.MEDIUM },
        { name: 'Stripe Secret/Restricted Key', regex: /(sk|rk)_(live|test)_[0-9a-zA-Z]{20,}/g, severity: SecretSeverity.HIGH },
        { name: 'GitHub Token', regex: /(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}|github_pat_[0-9A-Za-z_]{80,}/g, severity: SecretSeverity.HIGH },
        { name: 'Slack Token', regex: /xox[baprs]-[0-9A-Za-z-]{10,}/g, severity: SecretSeverity.HIGH },
        { name: 'SendGrid API Key', regex: /SG\.[0-9A-Za-z\-_]{20,}\.[0-9A-Za-z\-_]{20,}/g, severity: SecretSeverity.HIGH },
        { name: 'npm Token', regex: /npm_[0-9A-Za-z]{30,}/g, severity: SecretSeverity.HIGH },
        { name: 'Azure Storage Connection String', regex: /DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{20,};?/gi, severity: SecretSeverity.CRITICAL },
        { name: 'Bearer Token hardcodeado', regex: /["']?Authorization["']?\s*:\s*["']Bearer\s+[A-Za-z0-9\-_.]{20,}["']/gi, severity: SecretSeverity.HIGH },
        { name: 'Basic Auth hardcodeado', regex: /["']?Authorization["']?\s*:\s*["']Basic\s+[A-Za-z0-9+/=]{16,}["']/gi, severity: SecretSeverity.HIGH },
        { name: 'Slack Webhook URL', regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g, severity: SecretSeverity.MEDIUM },
        { name: 'Twilio Account SID/Key', regex: /\b(AC|SK)[0-9a-fA-F]{32}\b/g, severity: SecretSeverity.MEDIUM },
        { name: 'Mailgun API Key', regex: /key-[0-9a-zA-Z]{32}/g, severity: SecretSeverity.MEDIUM },
        { name: 'Facebook/Meta Access Token', regex: /\bEAA[A-Za-z0-9]{20,}\b/g, severity: SecretSeverity.MEDIUM },
        { name: 'Posible secreto en variable (heurística)', regex: /(api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]([0-9a-zA-Z\-_]{16,})['"]/gi, severity: SecretSeverity.MEDIUM },
        { name: 'JWT expuesto (no cifrado, solo codificado)', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, severity: SecretSeverity.LOW },
        { name: 'Firebase Realtime Database URL', regex: /https:\/\/[a-z0-9-]+\.firebaseio\.com/g, severity: SecretSeverity.LOW },
        { name: 'Dirección IP privada/interna expuesta', regex: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g, severity: SecretSeverity.LOW }
    ];
    private readonly sensitive_paths: { path: string; signature: RegExp; description: string; severity: SecretSeverity }[] = [
        { path: '/.git/HEAD', signature: /ref:\s*refs\//, description: 'Repositorio .git expuesto: puede filtrar todo el código fuente e historial.', severity: SecretSeverity.CRITICAL },
        { path: '/.git/config', signature: /\[core\]/, description: 'Configuración de .git expuesta.', severity: SecretSeverity.CRITICAL },
        { path: '/.git/logs/HEAD', signature: /\b[0-9a-f]{40}\b/, description: 'Log de referencias de .git expuesto: mismo riesgo que .git/HEAD.', severity: SecretSeverity.CRITICAL },
        { path: '/.env', signature: /^[A-Z0-9_]+\s*=/m, description: 'Archivo .env expuesto: suele contener credenciales y claves de API.', severity: SecretSeverity.CRITICAL },
        { path: '/.env.production', signature: /^[A-Z0-9_]+\s*=/m, description: 'Archivo .env.production expuesto.', severity: SecretSeverity.CRITICAL },
        { path: '/.env.local', signature: /^[A-Z0-9_]+\s*=/m, description: 'Archivo .env.local expuesto.', severity: SecretSeverity.CRITICAL },
        { path: '/.aws/credentials', signature: /aws_access_key_id/i, description: 'Credenciales de AWS expuestas.', severity: SecretSeverity.CRITICAL },
        { path: '/backup.sql', signature: /INSERT INTO|CREATE TABLE/i, description: 'Dump de base de datos expuesto.', severity: SecretSeverity.CRITICAL },
        { path: '/web.config', signature: /<connectionStrings>|<appSettings>/, description: 'web.config de IIS/.NET expuesto: históricamente uno de los leaks más comunes en .NET, suele traer connectionStrings en texto plano.', severity: SecretSeverity.CRITICAL },
        { path: '/appsettings.json', signature: /"ConnectionStrings"|"Logging"\s*:\s*\{/, description: 'appsettings.json de .NET expuesto: puede incluir cadenas de conexión y claves.', severity: SecretSeverity.HIGH },
        { path: '/appsettings.Development.json', signature: /"ConnectionStrings"|"Logging"\s*:\s*\{/, description: 'appsettings.Development.json expuesto: build de desarrollo con configuración interna.', severity: SecretSeverity.HIGH },
        { path: '/docker-compose.yml', signature: /services:\s*\r?\n/, description: 'docker-compose.yml expuesto: puede revelar topología interna y variables de entorno con credenciales.', severity: SecretSeverity.HIGH },
        { path: '/wp-config.php.bak', signature: /DB_PASSWORD|<\?php/, description: 'Backup de configuración de WordPress expuesto.', severity: SecretSeverity.HIGH },
        { path: '/config.json', signature: /"(password|secret|apiKey|api_key)"/i, description: 'Archivo de configuración con posibles credenciales expuesto.', severity: SecretSeverity.HIGH },
        { path: '/.htpasswd', signature: /^[^:\s]+:\$(apr1|2y|1)\$/m, description: 'Archivo .htpasswd expuesto: hashes de credenciales de acceso básico.', severity: SecretSeverity.HIGH }
    ];
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

    async getDataIdentifier(webDataDto: WebDataDto): Promise<DataIdentifierResult> {
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
            const origin: string = new URL(webDataDto.web_url).origin;
            const { findings: scriptsIntegrityFindings, summary: scriptsIntegrity } = this.analyzeResourceIntegrity(html, webDataDto.web_url);
            const scriptUrls: string[] = this.extractFirstPartyScriptUrls(html, webDataDto.web_url);
            const [fetchScriptsResult, exposedPaths] = await Promise.all([
                this.fetchScripts(context, scriptUrls),
                this.checkExposedPaths(context, origin, html)
            ]);
            const { scriptsContent, scannedCount, skippedCount, skippedByByteCapCount, skippedByTimeoutCount } = fetchScriptsResult;
            const htmlFindings: SecretFinding[] = this.scanForSecrets(html, 'html');
            const scriptFindings: SecretFinding[] = scriptsContent.flatMap(({ url, content }) => this.scanForSecrets(content, url));
            const secrets: SecretFinding[] = [...htmlFindings, ...scriptFindings];
            const exposedSourceMaps: ExposedSourceMapFinding[] = await this.checkExposedSourceMaps(context, scriptsContent);
            return {
                secrets,
                exposedPaths,
                exposedSourceMaps,
                scriptsIntegrity,
                scriptsIntegrityFindings,
                scannedSources: {
                    scriptsFound: scriptUrls.length,
                    scriptsScanned: scannedCount,
                    scriptsSkipped: skippedCount,
                    skippedByByteCap: skippedByByteCapCount,
                    skippedByTimeout: skippedByTimeoutCount
                },
                overallRisk: this.computeOverallRisk(secrets, exposedPaths, exposedSourceMaps),
                summary: this.buildSummaryText(secrets, exposedPaths, exposedSourceMaps)
            };
        } catch (error: any) {
            this.logger.error(`Error crítico: ${error.stack}`);
            throw new InternalServerErrorException(`Se produjo un error al analizar posibles fugas de datos: ${error}`);
        }
        finally {
            await page.close();
            await context.close();
        }
    }

    private looksLikeFirstPartyAssetDomain(scriptHostname: string, pageRegistrableDomain: string): boolean {
        const pageMainLabel: string = pageRegistrableDomain.split('.')[0];
        if (pageMainLabel.length < 4) return false;
        const scriptMainLabel: string = this.getRegistrableDomain(scriptHostname).split('.')[0];
        return scriptMainLabel !== pageMainLabel && scriptMainLabel.includes(pageMainLabel);
    }

    private extractFirstPartyScriptUrls(html: string, pageUrl: string): string[] {
        const pageHostname: string = new URL(pageUrl).hostname;
        const pageRegistrableDomain: string = this.getRegistrableDomain(pageHostname);
        const urls: Set<string> = new Set<string>();
        const scriptSrcRegex: RegExp = /<script[^>]+src=["']([^"']+)["']/gi;
        let match: RegExpExecArray | null;
        while ((match = scriptSrcRegex.exec(html)) !== null) {
            try {
                const resolved: URL = new URL(match[1], pageUrl);
                if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') continue;
                const isSameSite: boolean = this.getRegistrableDomain(resolved.hostname) === pageRegistrableDomain;
                const isFirstPartyAsset: boolean = this.looksLikeFirstPartyAssetDomain(resolved.hostname, pageRegistrableDomain);
                if (isSameSite || isFirstPartyAsset) {
                    urls.add(resolved.toString());
                }
            } catch {
                // URL inválida (data:, blob:, etc.)
            }
        }
        return Array.from(urls);
    }

    private getRegistrableDomain(hostname: string): string {
        return getDomain(hostname) ?? hostname;
    }

    private async fetchScripts(context: BrowserContext, urls: string[]): Promise<{ scriptsContent: { url: string; content: string }[]; scannedCount: number; skippedCount: number, skippedByByteCapCount: number, skippedByTimeoutCount: number }> {
        const startTime = Date.now();
        const toScan: string[] = urls.slice(0, this.max_scripts_to_scan);
        const skippedByCount: number = Math.max(0, urls.length - toScan.length);
        const scriptsContent: { url: string; content: string }[] = [];
        let totalBytes: number = 0;
        let skippedByByteCapCount: number = 0;
        let skippedByTimeoutCount: number = 0;
        for (let i = 0; i < toScan.length; i += this.script_fetch_batch_size) {
            if (totalBytes >= this.max_total_script_bytes) {
                skippedByByteCapCount += toScan.length - i;
                break;
            }
            if (Date.now() - startTime >= this.max_script_fetch_time_ms) {
                skippedByTimeoutCount += toScan.length - i;
                break;
            }
            const batch: string[] = toScan.slice(i, i + this.script_fetch_batch_size);
            const results = await Promise.all(
                batch.map(async (url) => {
                    try {
                        const res: APIResponse<any> = await context.request.get(url, { timeout: 8000, failOnStatusCode: false });
                        if (!res.ok()) return null;
                        const body: string = await res.text();
                        return { url, content: body.slice(0, this.max_script_bytes) };
                    } catch (error: any) {
                        this.logger.warn(`No se pudo descargar script ${url}: ${error}`);
                        return null;
                    }
                })
            );
            for (const r of results) {
                if (r) {
                    scriptsContent.push(r);
                    totalBytes += r.content.length;
                }
            }
        }
        return { scriptsContent, scannedCount: scriptsContent.length, skippedCount: skippedByCount + skippedByByteCapCount + skippedByTimeoutCount, skippedByByteCapCount, skippedByTimeoutCount };
    }

    private isKnownPublicClientContext(content: string, matchIndex: number): boolean {
        const start: number = Math.max(0, matchIndex - 200);
        const end: number = Math.min(content.length, matchIndex + 200);
        const windowText: string = content.slice(start, end).toLowerCase();
        return this.public_context_markers.some((marker) => windowText.includes(marker));
    }

    private scanForSecrets(content: string, source: string): SecretFinding[] {
        const findings: SecretFinding[] = [];
        for (const pattern of this.secret_patterns) {
            let matches: RegExpExecArray[] = Array.from(content.matchAll(pattern.regex));
            if (pattern.name === 'Posible secreto en variable (heurística)') {
                matches = matches.filter((m) => !/^[A-Z0-9_]+$/.test(m[2] ?? ''));
            }
            if (matches.length === 0) continue;
            const publicCount: number = pattern.severity !== SecretSeverity.CRITICAL ? matches.filter((m) => this.isKnownPublicClientContext(content, m.index ?? 0)).length : 0;
            findings.push({
                type: pattern.name,
                severity: publicCount === matches.length ? SecretSeverity.LOW : pattern.severity,
                source,
                message: publicCount > 0 ? `${publicCount}/${matches.length} coincidencia(s) aparecen junto a un servicio público conocido (Maps, Firebase, GA, Sentry, etc.); probablemente sea una clave publicable y no un secreto sensible.` : '',
                matchPreview: this.maskSecret(matches[0][0]),
                occurrences: matches.length
            });
        }
        return findings;
    }

    private maskSecret(value: string): string {
        if (value.length <= 8) return '*'.repeat(value.length);
        return `${value.slice(0, 4)}${'*'.repeat(Math.max(4, value.length - 8))}${value.slice(-4)}`;
    }

    private async checkExposedPaths(context: BrowserContext, origin: string, baselineHtml: string): Promise<ExposedPathFinding[]> {
        const results = await Promise.all(
            this.sensitive_paths.map(async (candidate) => {
                try {
                    const url: string = `${origin}${candidate.path}`;
                    const res: APIResponse = await context.request.get(url, { timeout: 6000, failOnStatusCode: false });
                    if (!res.ok()) return null;
                    const body: string = await res.text();
                    if (body === baselineHtml || !candidate.signature.test(body)) return null;
                    return { path: candidate.path, url, severity: candidate.severity, description: candidate.description };
                } catch (error: any) {
                    return null;
                }
            }),
        );
        return results.filter((r): r is ExposedPathFinding => r !== null);
    }

    private async checkExposedSourceMaps(context: BrowserContext, scriptsContent: { url: string; content: string }[]): Promise<ExposedSourceMapFinding[]> {
        const candidates = scriptsContent
            .map(({ url, content }) => ({ scriptUrl: url, mapUrl: this.extractSourceMapUrl(content, url) }))
            .filter((c): c is { scriptUrl: string; mapUrl: string } => c.mapUrl !== null);
        const results = await Promise.all(
            candidates.map(async ({ scriptUrl, mapUrl }) => {
                try {
                    const res = await context.request.get(mapUrl, { timeout: 6000, failOnStatusCode: false });
                    if (!res.ok()) return null;
                    const body = await res.text();
                    if (!/"sources"\s*:|"mappings"\s*:/.test(body)) return null;
                    return { scriptUrl, mapUrl, severity: SecretSeverity.MEDIUM };
                } catch {
                    return null;
                }
            }),
        );
        return results.filter((r): r is ExposedSourceMapFinding => r !== null);
    }

    private extractSourceMapUrl(scriptContent: string, scriptUrl: string): string | null {
        const tail: string = scriptContent.slice(-2000);
        const match: RegExpExecArray | null = /\/\/[#@]\s*sourceMappingURL=([^\s]+)/.exec(tail);
        if (!match) return null;
        try {
            return new URL(match[1], scriptUrl).toString();
        } catch {
            return null;
        }
    }

    private analyzeResourceIntegrity(html: string, pageUrl: string): { findings: ScriptIntegrityFinding[]; summary: ScriptsIntegritySummary } {
        const pageHostname: string = new URL(pageUrl).hostname;
        const pageRegistrableDomain: string = this.getRegistrableDomain(pageHostname);
        const tags = this.extractIntegrityCandidateTags(html);
        const seen: Set<string> = new Set<string>();
        const findings: ScriptIntegrityFinding[] = [];
        let totalResources: number = 0;
        let crossOriginResources: number = 0;
        let withIntegrity: number = 0;
        let crossOriginWithoutIntegrity: number = 0;
        for (const { tag, raw } of tags) {
            const rawUrl: string | null = this.extractTagAttribute(raw, tag === 'script' ? 'src' : 'href');
            if (!rawUrl) continue;
            let resolved: URL;
            try {
                resolved = new URL(rawUrl, pageUrl);
            } catch {
                continue; // data:, blob:, mailto:, etc.
            }
            if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') continue;
            const dedupeKey: string = `${tag}:${resolved.toString()}`;
            if (seen.has(dedupeKey)) continue;
            seen.add(dedupeKey);
            const isCrossOrigin: boolean = this.getRegistrableDomain(resolved.hostname) !== pageRegistrableDomain;
            const integrityValue: string | null = this.extractTagAttribute(raw, 'integrity');
            const hasIntegrity: boolean = !!integrityValue && integrityValue.trim().length > 0;
            const hasCrossoriginAttribute: boolean = this.hasTagAttribute(raw, 'crossorigin');
            totalResources++;
            if (isCrossOrigin) crossOriginResources++;
            if (hasIntegrity) withIntegrity++;
            if (!isCrossOrigin) continue; // SRI aporta poco valor en recursos same-site; no se reporta como finding
            const resourceLabel: string = tag === 'script' ? 'script' : 'hoja de estilos';
            if (!hasIntegrity) {
                crossOriginWithoutIntegrity++;
                findings.push({
                    tag,
                    url: resolved.toString(),
                    crossOrigin: true,
                    hasIntegrity: false,
                    hasCrossoriginAttribute,
                    integrityIssue: 'missing',
                    severity: SecretSeverity.MEDIUM,
                    description: `${tag === 'script' ? 'Script' : 'Hoja de estilos'} de otro origen (${resolved.hostname}) cargado sin atributo integrity: si ese origen es comprometido o secuestrado (CDN, DNS), el ${resourceLabel} se ejecutaría/aplicaría en el sitio sin ninguna verificación de que su contenido no fue alterado.`,
                });
            } else if (!this.isValidIntegrityValue(integrityValue!)) {
                findings.push({
                    tag,
                    url: resolved.toString(),
                    crossOrigin: true,
                    hasIntegrity: true,
                    hasCrossoriginAttribute,
                    integrityIssue: 'malformed',
                    severity: SecretSeverity.LOW,
                    description: `El atributo integrity de este ${resourceLabel} tiene un valor con formato no reconocido (se esperaba uno o más hashes sha256-/sha384-/sha512- en base64); revisar cómo se generó.`,
                });
            } else if (!hasCrossoriginAttribute) {
                findings.push({
                    tag,
                    url: resolved.toString(),
                    crossOrigin: true,
                    hasIntegrity: true,
                    hasCrossoriginAttribute: false,
                    integrityIssue: 'missing_crossorigin',
                    severity: SecretSeverity.MEDIUM,
                    description: `Tiene integrity pero le falta el atributo crossorigin: al ser un recurso de otro origen, sin crossorigin el navegador no puede validar el hash correctamente y la protección de SRI queda sin efecto real, aunque el atributo esté presente.`,
                });
            }
        }
        const integrityCoverageRatio: number = crossOriginResources === 0 ? 1 : (crossOriginResources - crossOriginWithoutIntegrity) / crossOriginResources;
        return {
            findings,
            summary: { totalResources, crossOriginResources, withIntegrity, crossOriginWithoutIntegrity, integrityCoverageRatio },
        };
    }

    private extractIntegrityCandidateTags(html: string): { tag: 'script' | 'link'; raw: string }[] {
        const tags: { tag: 'script' | 'link'; raw: string }[] = [];
        const scriptTagRegex: RegExp = /<script\b[^>]*>/gi;
        const linkTagRegex: RegExp = /<link\b[^>]*>/gi;
        let match: RegExpExecArray | null;
        while ((match = scriptTagRegex.exec(html)) !== null) {
            if (/\bsrc\s*=/i.test(match[0])) tags.push({ tag: 'script', raw: match[0] });
        }
        while ((match = linkTagRegex.exec(html)) !== null) {
            if (/\brel\s*=\s*["']?[^"'>]*\bstylesheet\b/i.test(match[0]) && /\bhref\s*=/i.test(match[0])) {
                tags.push({ tag: 'link', raw: match[0] });
            }
        }
        return tags;
    }

    private extractTagAttribute(tagHtml: string, attr: string): string | null {
        const regex: RegExp = new RegExp(`\\b${attr}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i');
        const match: RegExpExecArray | null = regex.exec(tagHtml);
        if (!match) return null;
        return match[1] ?? match[2] ?? match[3] ?? '';
    }

    private hasTagAttribute(tagHtml: string, attr: string): boolean {
        return new RegExp(`\\b${attr}\\b`, 'i').test(tagHtml);
    }

    private isValidIntegrityValue(value: string): boolean {
        const entries: string[] = value.trim().split(/\s+/).filter(Boolean);
        if (entries.length === 0) return false;
        return entries.every((entry) => /^sha(256|384|512)-[A-Za-z0-9+/]+=*$/.test(entry));
    }

    private computeOverallRisk(secrets: SecretFinding[], exposedPaths: ExposedPathFinding[], exposedSourceMaps: ExposedSourceMapFinding[]): SecretSeverity {
        const severities: SecretSeverity[] = [
            ...secrets.map((s) => s.severity),
            ...exposedPaths.map((p) => p.severity),
            ...exposedSourceMaps.map((m) => m.severity),
        ];
        return severities.length === 0 ? SecretSeverity.LOW : Math.max(...severities);
    }

    private buildSummaryText(secrets: SecretFinding[], exposedPaths: ExposedPathFinding[], exposedSourceMaps: ExposedSourceMapFinding[]): string {
        if (secrets.length === 0 && exposedPaths.length === 0 && exposedSourceMaps.length === 0) {
            return 'No se detectaron fugas de datos evidentes con los patrones analizados.';
        }
        const parts: string[] = [];
        if (secrets.length > 0) parts.push(`${secrets.length} patrón(es) de secreto detectado(s)`);
        if (exposedPaths.length > 0) parts.push(`${exposedPaths.length} ruta(s) sensible(s) expuesta(s)`);
        if (exposedSourceMaps.length > 0) parts.push(`${exposedSourceMaps.length} source map(s) expuesto(s)`);
        return parts.join(', ') + '.';
    }
}
