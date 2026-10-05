import { Injectable, InternalServerErrorException, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { WebDataDto } from 'src/common/dtos/web-data.dto';
import { chromium, Browser, Page, BrowserContext } from 'playwright';
import { getInitialHeadersResponse, HeaderEvaluationResult, HeaderEvaluator, HeaderIdentifierResponse, HeaderIdentifierTypeResponse, HeaderSummaryIdentifierResponse, RateLimitDetectionResult, RateLimitHeaderKind, RateLimitHeaderMatch } from './dto/header-identifier.interface';

@Injectable()
export class HeaderIdentifierService implements OnModuleInit, OnModuleDestroy {
    private readonly logger = new Logger('HEADER-IDENTIFIER-SERVICE');
    private readonly recommended_absence_penalty_ratio: number = 0.5;
    private static readonly domain_regex: RegExp = /^((https?|wss?):\/\/)?(\*\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?(\/.*)?$/;
    private static readonly version_regex: RegExp = /\d+\.\d+/;
    private static readonly nonce_hash_regex: RegExp = /^'(nonce-|sha256-|sha384-|sha512-)/i;
    private static readonly six_months_seconds: number = 15552000;
    private static readonly one_year_seconds: number = 31536000;
    // --- RATE LIMIT / THROTTLING ---
    // Red de cobertura para cualquier variante no listada
    private static readonly rate_limit_header_pattern: RegExp = /(rate[-_]?limit|retry[-_]?after|throttl|\bquota\b)/i;
    private static readonly known_rate_limit_headers: Record<string, RateLimitHeaderKind> = {
        // Borrador IETF "RateLimit Fields for HTTP"
        'ratelimit': 'standard',
        'ratelimit-limit': 'standard',
        'ratelimit-remaining': 'standard',
        'ratelimit-reset': 'standard',
        'ratelimit-policy': 'standard',
        // Convención heredada, todavía la más común en APIs (GitHub, Twitter/X, etc.)
        'x-ratelimit-limit': 'legacy',
        'x-ratelimit-remaining': 'legacy',
        'x-ratelimit-reset': 'legacy',
        'x-ratelimit-used': 'legacy',
        'x-ratelimit-resource': 'legacy',
        'x-rate-limit-limit': 'legacy',
        'x-rate-limit-remaining': 'legacy',
        'x-rate-limit-reset': 'legacy',
        // Estándar HTTP (RFC 9110)
        'retry-after': 'retry-after',
        // Variantes propias de proveedores puntuales
        'x-shopify-shop-api-call-limit': 'vendor'
    };
    private readonly evaluators: Record<string, HeaderEvaluator> = {
        'content-security-policy': (val, _, weight) => this.evaluateCSP(val, weight),
        'strict-transport-security': (val, _, weight) => this.evaluateHSTS(val, weight),
        'x-frame-options': (val, _, weight) => this.evaluateXFrameOptions(val, weight),
        'referrer-policy': (val, _, weight) => this.evaluateReferrerPolicy(val, weight),
        'permissions-policy': (val, _, weight) => this.evaluatePermissionsPolicy(val, weight),
        'cross-origin-opener-policy': (val, _, weight) => this.evaluateCOOP(val, weight),
        'cross-origin-resource-policy': (val, _, weight) => this.evaluateCORP(val, weight),
        'cross-origin-embedder-policy': (val, _, weight) => this.evaluateCOEP(val, weight),
        'x-permitted-cross-domain-policies': (val, _, weight) => this.evaluateCrossDomainPolicies(val, weight),
        'cache-control': (val, _, weight) => this.evaluateCacheControl(val, weight),
        'access-control-allow-origin': (_, raw, weight) => this.evaluateCORS(raw, weight),
        'x-xss-protection': (val, _, weight) => this.evaluateXSSProtection(val, weight),
        server: (val, _, weight) => this.evaluateServerInfo(val, weight),
        'x-powered-by': (val, _, weight) => this.evaluateServerInfo(val, weight),
    };
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

    async getHeaderIdentifier(webDataDto: WebDataDto): Promise<HeaderIdentifierResponse> {
        const context: BrowserContext = await this.browser.newContext({ ignoreHTTPSErrors: true });
        const page: Page = await context.newPage();
        try {
            await page.route('**/*', (route) => {
                const resourceType: string = route.request().resourceType();
                if (resourceType === 'document') {
                    route.continue();
                } else {
                    route.abort();
                }
            });
            const response = await page.goto(webDataDto.web_url, { waitUntil: 'domcontentloaded', timeout: 15000 });
            if (!response) {
                throw new Error('El servidor no devolvió una respuesta válida');
            }
            const rawHeaders: Record<string, string> = response.headers();
            const headers: HeaderSummaryIdentifierResponse[] = this.analyzeHeaders(rawHeaders);
            const score: number = this.calculateScore(headers);
            const grade: string = this.getGrade(score);
            const rateLimit: RateLimitDetectionResult = this.detectRateLimitSignals(rawHeaders);
            return { headers, score, grade, rateLimit };
        } catch (error: any) {
            this.logger.error(`Error crítico: ${error.stack}`);
            throw new InternalServerErrorException(`Se produjo un error al consultar las cabeceras de la web: ${error}`);
        } finally {
            await page.close();
            await context.close();
        }
    }

    private analyzeHeaders(rawHeaders: Record<string, string>): HeaderSummaryIdentifierResponse[] {
        return getInitialHeadersResponse().map((header) => {
            const headerNameLower: string = header.name.toLowerCase();
            const value: string = rawHeaders[headerNameLower];
            let exist: boolean = value !== undefined;
            let weightValue: number = header.weigth;
            let finding: string = '';
            if (exist) {
                const evaluator: HeaderEvaluator = this.evaluators[headerNameLower];
                if (evaluator) {
                    const result: HeaderEvaluationResult = evaluator(value, rawHeaders, weightValue);
                    finding = result.finding;
                    weightValue = result.weightValue;
                    if (result.exist !== undefined) exist = result.exist;
                }
            }
            const isMandatory: boolean = header.type === HeaderIdentifierTypeResponse.MANDATORY;
            const isRecommended: boolean = header.type === HeaderIdentifierTypeResponse.RECOMMENDED;
            const absenceFloor: number = isMandatory ? -header.weigth : (isRecommended ? -(header.weigth * this.recommended_absence_penalty_ratio) : 0);
            if (!exist) {
                weightValue = absenceFloor;
            } else if (isMandatory || isRecommended) {
                weightValue = Math.max(weightValue, absenceFloor);
            }
            return {
                ...header,
                exist,
                value: value ?? '',
                finding,
                weigth: weightValue,
            };
        });
    }

    // --- EVALUADORES INDIVIDUALES ---
    private evaluateCSP(value: string, weightValue: number): HeaderEvaluationResult {
        let finding: string = '';
        const cspMap: Map<string, string[]> = this.parseCSP(value);
        const defaultSrc: string[] | undefined = cspMap.get('default-src');
        if (!defaultSrc || defaultSrc.length === 0 || defaultSrc.includes('*') || !defaultSrc.every(this.isValidDomain)) {
            finding = 'La directiva default-src no está definida, está vacía, permite cualquier origen (*) o contiene valores con formato inválido, dejando sin una política base restrictiva al resto de directivas de CSP.';
            weightValue -= 2;
        }
        const objectSrcExplicit: boolean = cspMap.has('object-src');
        const objectSrc: string[] | undefined = cspMap.get('object-src') ?? defaultSrc;
        if (!objectSrc || objectSrc.includes('*') || !objectSrc.every(this.isValidDomain)) {
            finding = 'La directiva object-src (o default-src como respaldo) permite cualquier origen (*) o contiene valores inválidos, facilitando la carga de plugins/objetos embebidos (Flash, Java) desde orígenes no confiables.';
            weightValue -= 2;
        } else if (objectSrcExplicit && !objectSrc.includes("'none'")) {
            finding = "La directiva object-src está definida explícitamente pero no la restringe con 'none'; se recomienda bloquear por completo los objetos embebidos si no son necesarios.";
            weightValue -= 1;
        }
        const imgSrc: string[] | undefined = cspMap.get('img-src') ?? defaultSrc;
        if (!imgSrc || imgSrc.includes('*') || !imgSrc.every(this.isValidDomain)) {
            finding = 'La directiva img-src (o default-src) permite cualquier origen (*) o contiene valores inválidos, permitiendo cargar imágenes desde cualquier dominio (posible vector de tracking/exfiltración vía beacons).';
            weightValue -= 2;
        }
        const connectSrc: string[] | undefined = cspMap.get('connect-src') ?? defaultSrc;
        if (!connectSrc || connectSrc.includes('*') || !connectSrc.every(this.isValidDomain)) {
            finding = 'La directiva connect-src (o default-src) permite cualquier origen (*) o contiene valores inválidos, lo que podría permitir la exfiltración de datos hacia dominios arbitrarios vía fetch/XHR/WebSocket.';
            weightValue -= 2;
        }
        const fontSrc: string[] | undefined = cspMap.get('font-src') ?? defaultSrc;
        if (!fontSrc || fontSrc.includes('*') || !fontSrc.every(this.isValidDomain)) {
            finding = 'La directiva font-src (o default-src) permite cualquier origen (*) o contiene valores inválidos, ampliando innecesariamente la superficie de orígenes confiables.';
            weightValue -= 2;
        }
        const frameAncestors: string[] | undefined = cspMap.get('frame-ancestors');
        if (!frameAncestors || frameAncestors.length === 0 || frameAncestors.includes('*')) {
            finding = 'La directiva frame-ancestors no está definida o permite cualquier origen (*), dejando el sitio expuesto a ataques de clickjacking al poder ser embebido en un iframe desde cualquier dominio.';
            weightValue -= 2;
        } else {
            const hasNoneOrSelf: boolean = frameAncestors.includes("'none'") || frameAncestors.includes("'self'");
            if (!hasNoneOrSelf && !frameAncestors.every(this.isValidDomain)) {
                finding = "La directiva frame-ancestors no incluye 'none' ni 'self' y contiene orígenes con formato inválido, dificultando verificar quién puede embeber el sitio en un iframe.";
                weightValue -= 2;
            }
        }
        const styleResult: HeaderEvaluationResult = this.evaluateStyleSrc(cspMap, defaultSrc, weightValue);
        weightValue = styleResult.weightValue;
        if (styleResult.finding) finding = styleResult.finding;
        const scriptResult: HeaderEvaluationResult = this.evaluateScriptSrc(cspMap, defaultSrc, weightValue);
        weightValue = scriptResult.weightValue;
        if (scriptResult.finding) finding = scriptResult.finding;
        return { finding, weightValue };
    }

    private evaluateStyleSrc(cspMap: Map<string, string[]>, defaultSrc: string[] | undefined, weightValue: number): HeaderEvaluationResult {
        let finding: string = '';
        const styleSrc: string[] | undefined = cspMap.get('style-src') ?? defaultSrc;
        if (!styleSrc || styleSrc.length === 0 || styleSrc.includes('*')) {
            finding = 'La directiva style-src (o default-src) no está definida, está vacía o permite cualquier origen (*), permitiendo cargar hojas de estilo desde cualquier dominio.';
            return { finding, weightValue: weightValue - 2 };
        }
        const hasSelfStyle: boolean = styleSrc.includes("'self'");
        const hasNoneStyle: boolean = styleSrc.includes("'none'");
        const hasUnsafeInlineStyle: boolean = styleSrc.includes("'unsafe-inline'");
        const hasNonceOrHashStyle: boolean = styleSrc.some((val) => HeaderIdentifierService.nonce_hash_regex.test(val));
        const externalStyleOrigins: string[] = styleSrc.filter((val) => !val.startsWith("'") || !val.endsWith("'"));
        const hasValidExternalStyleOrigins: boolean = externalStyleOrigins.length > 0 && externalStyleOrigins.every(this.isValidDomain);
        if (hasUnsafeInlineStyle && !hasNonceOrHashStyle) {
            finding = "La directiva style-src permite 'unsafe-inline' sin usar nonce ni hash, habilitando la inyección de estilos arbitrarios (CSS injection), que puede usarse para exfiltrar datos o alterar la apariencia de la página.";
            weightValue -= 2;
        } else if (!hasSelfStyle && !hasNoneStyle && !hasNonceOrHashStyle && !hasValidExternalStyleOrigins) {
            finding = "La directiva style-src no restringe el origen de los estilos a 'self', 'none', un nonce/hash ni a dominios externos válidos.";
            weightValue -= 2;
        } else if (externalStyleOrigins.length > 0 && !externalStyleOrigins.every(this.isValidDomain)) {
            finding = 'La directiva style-src incluye orígenes externos con formato inválido, lo que puede indicar una configuración incorrecta de la política.';
            weightValue -= 2;
        }
        return { finding, weightValue };
    }

    private evaluateScriptSrc(cspMap: Map<string, string[]>, defaultSrc: string[] | undefined, weightValue: number): HeaderEvaluationResult {
        let finding: string = '';
        const scriptSrc: string[] | undefined = cspMap.get('script-src') ?? defaultSrc;
        if (!scriptSrc || scriptSrc.length === 0 || scriptSrc.includes('*')) {
            finding = 'La directiva script-src (o default-src) no está definida, está vacía o permite cualquier origen (*), permitiendo cargar y ejecutar scripts desde cualquier dominio: la protección de CSP contra XSS queda prácticamente anulada.';
            return { finding, weightValue: weightValue - 2 };
        }
        const hasSelfScript: boolean = scriptSrc.includes("'self'");
        const hasNoneScript: boolean = scriptSrc.includes("'none'");
        const hasUnsafeInlineScript: boolean = scriptSrc.includes("'unsafe-inline'");
        const hasUnsafeEvalScript: boolean = scriptSrc.includes("'unsafe-eval'");
        const hasStrictDynamic: boolean = scriptSrc.includes("'strict-dynamic'");
        const hasNonceOrHashScript: boolean = scriptSrc.some((val) => HeaderIdentifierService.nonce_hash_regex.test(val));
        const externalScriptOrigins: string[] = scriptSrc.filter((val) => !val.startsWith("'") || !val.endsWith("'"));
        const hasValidExternalScriptOrigins: boolean = externalScriptOrigins.length > 0 && externalScriptOrigins.every(this.isValidDomain);
        if (hasUnsafeEvalScript) {
            finding = "La directiva script-src permite 'unsafe-eval', habilitando la ejecución de código dinámico (eval, new Function, setTimeout con string), un vector frecuente para escalar un XSS a ejecución arbitraria de código.";
            weightValue -= 2;
        } else if (hasUnsafeInlineScript && !hasNonceOrHashScript && !hasStrictDynamic) {
            finding = "La directiva script-src permite 'unsafe-inline' sin nonce, hash ni 'strict-dynamic', lo que anula gran parte de la protección de CSP contra ataques XSS mediante scripts inline.";
            weightValue -= 2;
        } else if (!hasSelfScript && !hasNoneScript && !hasNonceOrHashScript && !hasStrictDynamic && !hasValidExternalScriptOrigins) {
            finding = "La directiva script-src no restringe el origen de los scripts a 'self', 'none', un nonce/hash, 'strict-dynamic' ni a dominios externos válidos.";
            weightValue -= 2;
        } else if (externalScriptOrigins.length > 0 && !externalScriptOrigins.every(this.isValidDomain)) {
            finding = 'La directiva script-src incluye orígenes externos con formato inválido, lo que puede indicar una configuración incorrecta de la política.';
            weightValue -= 2;
        }
        return { finding, weightValue };
    }

    private evaluateHSTS(value: string, weightValue: number): HeaderEvaluationResult {
        let finding: string = '';
        const stsDirectives: string[] = value.split(';').map((d) => d.trim().toLowerCase()).filter(Boolean);
        const maxAgeDirective: string | undefined = stsDirectives.find((d) => d.startsWith('max-age='));
        const maxAgeValue: number = maxAgeDirective ? parseInt(maxAgeDirective.split('=')[1], 10) : NaN;
        const hasIncludeSubDomains: boolean = stsDirectives.includes('includesubdomains');
        const hasPreload: boolean = stsDirectives.includes('preload');
        if (isNaN(maxAgeValue) || maxAgeValue < HeaderIdentifierService.six_months_seconds) {
            finding = 'El atributo max-age no está definido o es menor a 6 meses (15552000 segundos), un periodo insuficiente para forzar HTTPS de manera consistente y proteger contra ataques de downgrade/SSL stripping.';
            weightValue -= 4;
        } else if (maxAgeValue < HeaderIdentifierService.one_year_seconds) {
            finding = 'El atributo max-age es menor a 1 año (31536000 segundos); se recomienda un valor de al menos un año para maximizar la ventana de protección HTTPS.';
            weightValue -= 2;
        }
        if (!hasIncludeSubDomains) {
            finding = 'No incluye la directiva includeSubDomains, por lo que los subdominios del sitio no quedan cubiertos por la política HSTS y podrían seguir siendo accedidos por HTTP.';
            weightValue -= 2;
        }
        if (!hasPreload) {
            finding = 'No incluye la directiva preload; al no estar precargado en las listas HSTS de los navegadores, la primera visita al sitio sigue siendo vulnerable a un ataque de downgrade a HTTP.';
            weightValue -= 1;
        }
        return { finding, weightValue };
    }

    private evaluateXFrameOptions(value: string, weightValue: number): HeaderEvaluationResult {
        if (value.includes('ALLOW-FROM')) {
            return {
                finding: 'Usa la directiva obsoleta ALLOW-FROM, que los navegadores modernos ya no soportan, por lo que en la práctica no ofrece protección real contra clickjacking.',
                weightValue: weightValue - 2,
            };
        }
        return { finding: '', weightValue };
    }

    private evaluateReferrerPolicy(value: string, weightValue: number): HeaderEvaluationResult {
        let finding: string = '';
        const referrerCandidates: string[] = value.split(',').map((v) => v.trim().toLowerCase()).filter(Boolean);
        const strongReferrerValues: string[] = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin'];
        const weakReferrerValues: string[] = ['origin', 'origin-when-cross-origin', 'no-referrer-when-downgrade'];
        const normalizedReferrer: string = referrerCandidates[referrerCandidates.length - 1] ?? '';
        if (normalizedReferrer === 'unsafe-url') {
            finding = 'La política unsafe-url envía la URL completa (incluyendo rutas y parámetros potencialmente sensibles) como referrer en todas las solicitudes, incluso hacia orígenes distintos y sin cifrar.';
            weightValue -= 2;
        } else if (weakReferrerValues.includes(normalizedReferrer) || !strongReferrerValues.includes(normalizedReferrer)) {
            finding = `El valor configurado ('${normalizedReferrer || 'no reconocido'}') expone más información de la recomendada en solicitudes entre orígenes; se sugiere usar 'strict-origin-when-cross-origin' o 'no-referrer'.`;
            weightValue -= 1;
        }
        return { finding, weightValue };
    }

    private evaluatePermissionsPolicy(value: string, weightValue: number): HeaderEvaluationResult {
        const directives: string[] = value.split(',').map((d) => d.trim());
        let wildcardCount: number = 0;
        for (const directive of directives) {
            const parts: string[] = directive.split('=');
            if (parts.length === 2) {
                const allowList: string = parts[1].trim();
                if (allowList === '*' || allowList === '(*)') wildcardCount++;
            }
        }
        if (wildcardCount > 0) {
            return {
                finding: `Se detectaron ${wildcardCount} directiva(s) que permiten el uso de funciones sensibles del navegador (cámara, micrófono, geolocalización, etc.) desde cualquier origen (*), lo que amplía innecesariamente quién puede invocarlas.`,
                weightValue: weightValue - wildcardCount * 0.5,
            };
        }
        return { finding: '', weightValue };
    }

    private evaluateCOOP(value: string, weightValue: number): HeaderEvaluationResult {
        if (value === 'same-origin-allow-popups') {
            return {
                finding: "El valor 'same-origin-allow-popups' mantiene la referencia hacia ventanas emergentes de otros orígenes, reduciendo el aislamiento frente a ataques de canal lateral tipo Spectre y a manipulación desde ventanas externas.",
                weightValue: weightValue - 2,
            };
        }
        if (value === 'unsafe-none') {
            return {
                finding: "El valor 'unsafe-none' desactiva por completo el aislamiento de origen cruzado (COOP), dejando la página expuesta a ataques de canal lateral (Spectre) y a manipulación desde ventanas de otros orígenes.",
                weightValue: weightValue - 4,
            };
        }
        return { finding: '', weightValue };
    }

    private evaluateCORP(value: string, weightValue: number): HeaderEvaluationResult {
        if (value === 'same-site') {
            return {
                finding: "El valor 'same-site' permite que cualquier subdominio del sitio cargue este recurso; en entornos con subdominios no totalmente confiables esto amplía la superficie de exposición.",
                weightValue: weightValue - 1,
            };
        }
        if (value === 'cross-origin') {
            return {
                finding: "El valor 'cross-origin' permite que cualquier sitio externo cargue este recurso sin restricciones, facilitando ataques de canal lateral (Spectre) y el abuso del recurso (hotlinking, filtración de datos).",
                weightValue: weightValue - 2,
            };
        }
        return { finding: '', weightValue };
    }

    private evaluateCOEP(value: string, weightValue: number): HeaderEvaluationResult {
        if (value === 'credentialless') {
            return {
                finding: "El valor 'credentialless' es más flexible que 'require-corp' y permite cargar recursos de terceros sin enviarles credenciales; ofrece aislamiento algo más débil si no se administra junto con COOP.",
                weightValue: weightValue - 1,
            };
        }
        if (value === 'unsafe-none') {
            return {
                finding: "El valor 'unsafe-none' desactiva la política de aislamiento (COEP), permitiendo cargar recursos de otros orígenes sin restricción y reduciendo la protección frente a ataques de canal lateral.",
                weightValue: weightValue - 2,
            };
        }
        return { finding: '', weightValue };
    }

    private evaluateCrossDomainPolicies(value: string, weightValue: number): HeaderEvaluationResult {
        if (value === 'master-only' || value === 'by-content-type') {
            return {
                finding: `El valor '${value}' aún permite cierto acceso entre dominios para clientes Flash/PDF; si no se necesita compatibilidad con estos, se recomienda usar 'none'.`,
                weightValue: weightValue - 1,
            };
        }
        if (value === 'all') {
            return {
                finding: "El valor 'all' permite el acceso entre dominios sin restricciones a través de políticas de Flash/PDF; aunque son clientes obsoletos, siguen siendo una superficie de ataque explotable.",
                weightValue: weightValue - 2,
            };
        }
        return { finding: '', weightValue };
    }

    private evaluateCacheControl(value: string, weightValue: number): HeaderEvaluationResult {
        let finding: string = '';
        const cacheDirectives: string[] = value.split(',').map((d) => d.trim().toLowerCase());
        const hasNoStore: boolean = cacheDirectives.includes('no-store');
        const hasNoCache: boolean = cacheDirectives.includes('no-cache');
        const hasMustRevalidate: boolean = cacheDirectives.includes('must-revalidate');
        const hasPrivate: boolean = cacheDirectives.includes('private');
        const hasPublic: boolean = cacheDirectives.includes('public');
        if (hasNoStore) {
            // no-store es la configuración óptima, sin penalización
        } else if (hasNoCache && (hasMustRevalidate || hasPrivate)) {
            finding = `Usa 'no-cache' junto con '${hasMustRevalidate ? 'must-revalidate' : 'private'}' en lugar de 'no-store'; el navegador aún puede guardar una copia local de la respuesta aunque deba revalidarla, lo cual no es ideal si la respuesta contiene datos sensibles.`;
            weightValue -= 1;
        } else {
            finding = "No incluye 'no-store' ni una combinación segura de 'no-cache' con 'must-revalidate'/'private', por lo que la respuesta podría quedar almacenada en el navegador o en proxies intermedios.";
            weightValue -= 2;
        }
        if (hasPublic) {
            finding = "Incluye la directiva 'public', permitiendo que la respuesta se almacene en cachés compartidas (proxies, CDNs); riesgoso si la respuesta contiene datos sensibles o personalizados por usuario.";
            weightValue -= 1;
        }
        return { finding, weightValue };
    }

    private evaluateCORS(rawHeaders: Record<string, string>, weightValue: number): HeaderEvaluationResult {
        const allowOrigin: string = rawHeaders['access-control-allow-origin'];
        const allowCredentials: string = rawHeaders['access-control-allow-credentials']?.toLowerCase();
        const isWildcardOrigin: boolean = allowOrigin === '*';
        const hasCredentialsTrue: boolean = allowCredentials === 'true';
        const isCorsMisconfigured: boolean = isWildcardOrigin || hasCredentialsTrue;
        if (isCorsMisconfigured) {
            return {
                finding: `Configuración de CORS insegura: ${isWildcardOrigin ? 'el origen permitido es un comodín (Access-Control-Allow-Origin: *)' : 'el origen permitido es específico'} ${hasCredentialsTrue ? 'y además se habilita el envío de credenciales (Access-Control-Allow-Credentials: true)' : ''}. Esta combinación puede permitir que un sitio malicioso lea respuestas con datos de sesión del usuario.`,
                weightValue: weightValue - 5,
            };
        }
        if (!isWildcardOrigin) {
            return { finding: '', weightValue, exist: false };
        }
        return { finding: '', weightValue };
    }

    private evaluateXSSProtection(value: string, weightValue: number): HeaderEvaluationResult {
        if (value.trim() !== '0') {
            return {
                finding: "El valor debería ser '0' para desactivar el filtro XSS heredado del navegador: en navegadores modernos este filtro está obsoleto y en ciertos casos históricos llegó a introducir vulnerabilidades propias (filtrado usado como canal lateral de información).",
                weightValue: weightValue - 1,
            };
        }
        return { finding: '', weightValue };
    }

    private evaluateServerInfo(value: string, weightValue: number): HeaderEvaluationResult {
        const hasVersionNumber: boolean = HeaderIdentifierService.version_regex.test(value);
        if (hasVersionNumber) {
            return {
                finding: `El header revela el software del servidor ('${value}') sin número de versión; sigue siendo una fuga de información sobre la infraestructura que facilita reconocimiento a un atacante.`,
                weightValue: - 1,
            };
        }
        return { finding: '', weightValue };
    }

    // --- RATE LIMIT / THROTTLING ---
    private detectRateLimitSignals(rawHeaders: Record<string, string>): RateLimitDetectionResult {
        const matches: RateLimitHeaderMatch[] = [];
        for (const [name, value] of Object.entries(rawHeaders)) {
            const lower: string = name.toLowerCase();
            const knownKind: RateLimitHeaderKind | undefined = HeaderIdentifierService.known_rate_limit_headers[lower];
            if (knownKind) {
                matches.push({ name: lower, value, kind: knownKind });
                continue;
            }
            if (HeaderIdentifierService.rate_limit_header_pattern.test(lower)) {
                matches.push({ name: lower, value, kind: 'vendor' });
            }
        }
        const present: boolean = matches.length > 0;
        const finding: string = present ? this.buildRateLimitFinding(matches) : 'No se detectaron cabeceras de rate limiting (RateLimit-*, X-RateLimit-*, Retry-After, X-Rate-Limit-*, cabeceras con "throttle"/"quota" en el nombre, etc.) en esta respuesta. Esto NO confirma que el sitio carezca de protección contra abuso: muchos WAF/CDN limitan tráfico sin exponer cabeceras informativas, y el rate limiting suele mostrarse en endpoints de API/login, no en la página principal.';
        return { present, matchedHeaders: matches, finding };
    }

    private buildRateLimitFinding(matches: RateLimitHeaderMatch[]): string {
        const names: string = matches.map((m) => m.name).join(', ');
        const retryAfter: RateLimitHeaderMatch | undefined = matches.find((m) => m.kind === 'retry-after');
        const standardOrLegacy: RateLimitHeaderMatch[] = matches.filter((m) => m.kind === 'standard' || m.kind === 'legacy');
        let extra: string = '';
        if (retryAfter) {
            extra += ` Incluye "Retry-After: ${retryAfter.value}", que indica cuánto debe esperar el cliente antes de reintentar (típico de respuestas 429/503).`;
        }
        if (standardOrLegacy.length > 0) {
            extra += ` Se pueden leer valores concretos de cuota: ${standardOrLegacy.map((m) => `${m.name}=${m.value}`).join(', ')}.`;
        }
        return `Se detectaron cabeceras de límite de tasa/tráfico: ${names}.${extra} Es una señal pasiva (sin generar tráfico real) de que el sitio, su API o su CDN/WAF aplican algún control de rate limiting.`;
    }

    // --- HELPERS ---
    private parseCSP(value: string): Map<string, string[]> {
        const cspMap: Map<string, string[]> = new Map<string, string[]>();
        value.split(';').forEach((part) => {
            const trimmed: string = part.trim();
            if (trimmed) {
                const [name, ...valList]: string[] = trimmed.split(/\s+/);
                if (name) {
                    cspMap.set(name.toLowerCase(), valList.map((v) => v.trim()));
                }
            }
        });
        return cspMap;
    }

    private isValidDomain = (domain: string): boolean => {
        if (domain === '*') return false;
        if (domain.startsWith("'") && domain.endsWith("'")) return true;
        if (['https:', 'http:', 'data:', 'blob:', 'ws:', 'wss:'].includes(domain)) return true;
        return HeaderIdentifierService.domain_regex.test(domain);
    };

    private calculateScore(headers: HeaderSummaryIdentifierResponse[]): number {
        const raw: number = headers.reduce((total, header) => total + header.weigth, 0);
        return Math.max(0, Math.min(100, raw));
    }

    private getGrade(score: number): string {
        if (score >= 90) return 'A';
        if (score >= 80) return 'B';
        if (score >= 65) return 'C';
        if (score >= 50) return 'D';
        return 'F';
    }
}
