import { Injectable, InternalServerErrorException, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { WebDataDto } from '../common/dtos/web-data.dto';
import { chromium, Browser, Page, BrowserContext } from 'playwright';
import { ContentIdentifierResult, InsecureFormFinding, InsecureFormIssue, MixedContentFinding, MixedContentKind, ScannedContentInfo, SecretSeverity, TabnabbingFinding } from './dto/content-identifier.interface';

@Injectable()
export class ContentIdentifierService implements OnModuleInit, OnModuleDestroy {
    private readonly logger = new Logger('CONTENT-IDENTIFIER-SERVICE');
    private readonly max_html_bytes = 10_000_000;
    private readonly resource_tag_patterns: { tag: string; source: string; kind: MixedContentKind }[] = [
        { tag: 'script', source: String.raw`<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>`, kind: 'active' },
        { tag: 'link[stylesheet]', source: String.raw`<link\b(?=[^>]*\brel\s*=\s*["']?[^"'>]*stylesheet)[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>`, kind: 'active' },
        { tag: 'iframe', source: String.raw`<iframe\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>`, kind: 'active' },
        { tag: 'embed', source: String.raw`<embed\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>`, kind: 'active' },
        { tag: 'object', source: String.raw`<object\b[^>]*\bdata\s*=\s*["']([^"']+)["'][^>]*>`, kind: 'active' },
        { tag: 'css-url', source: String.raw`url\(\s*["']?(http:\/\/[^"')]+)["']?\s*\)`, kind: 'active' },
        { tag: 'img', source: String.raw`<img\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>`, kind: 'passive' },
        { tag: 'audio', source: String.raw`<audio\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>`, kind: 'passive' },
        { tag: 'video', source: String.raw`<video\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>`, kind: 'passive' },
        { tag: 'source', source: String.raw`<source\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>`, kind: 'passive' },
    ];
    private readonly srcset_tag_regex: RegExp = /<(img|source)\b[^>]*\bsrcset\s*=\s*["']([^"']+)["'][^>]*>/gi;
    private readonly form_block_regex: RegExp = /<form\b[^>]*>[\s\S]*?<\/form>/gi;
    private readonly form_action_regex: RegExp = /\baction\s*=\s*["']([^"']*)["']/i;
    private readonly form_method_regex: RegExp = /\bmethod\s*=\s*["']([^"']*)["']/i;
    private readonly form_password_regex: RegExp = /<input\b[^>]*\btype\s*=\s*["']?password["']?[^>]*>/i;
    private readonly blank_link_regex: RegExp = /<a\b[^>]*\btarget\s*=\s*["']?_blank["']?[^>]*>([\s\S]*?)<\/a>/gi;
    private readonly rel_attr_regex: RegExp = /\brel\s*=\s*["']([^"']*)["']/i;
    private readonly href_attr_regex: RegExp = /\bhref\s*=\s*["']([^"']*)["']/i;
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

    async getContentIdentifier(webDataDto: WebDataDto): Promise<ContentIdentifierResult> {
        const context: BrowserContext = await this.browser.newContext({ ignoreHTTPSErrors: true });
        const page: Page = await context.newPage();
        try {
            await page.route('**/*.{png,jpg,jpeg,gif,svg,woff,woff2,css}', (route) => route.abort());
            const response = await page.goto(webDataDto.web_url, { waitUntil: 'domcontentloaded', timeout: 15000 });
            if (!response) {
                throw new Error('El servidor no devolvió una respuesta válida');
            }
            await page.waitForTimeout(1500);
            const html: string = (await page.content()).slice(0, this.max_html_bytes);
            const finalUrl: string = page.url();
            const pageIsHttps: boolean = finalUrl.startsWith('https://');
            const insecureForms: InsecureFormFinding[] = this.scanInsecureForms(html, finalUrl);
            const mixedContent: MixedContentFinding[] = pageIsHttps ? this.scanMixedContent(html, finalUrl) : [];
            const tabnabbing: TabnabbingFinding[] = this.scanTabnabbing(html);
            const scannedContent: ScannedContentInfo = {
                pageIsHttps,
                formsScanned: (html.match(this.form_block_regex) ?? []).length,
                linksWithBlankTargetScanned: (html.match(this.blank_link_regex) ?? []).length,
                resourceTagsScanned: this.countResourceTags(html),
            };
            return {
                insecureForms,
                mixedContent,
                tabnabbing,
                scannedContent,
                overallRisk: this.computeOverallRisk(insecureForms, mixedContent, tabnabbing, pageIsHttps),
                summary: this.buildSummaryText(insecureForms, mixedContent, tabnabbing, pageIsHttps),
            };
        } catch (error: any) {
            this.logger.error(`Error crítico: ${error.stack}`);
            throw new InternalServerErrorException(`Se produjo un error al analizar el contenido de la página: ${error}`);
        }
        finally {
            await page.close();
            await context.close();
        }
    }

    // --- FORMULARIOS INSEGUROS ---
    private scanInsecureForms(html: string, pageUrl: string): InsecureFormFinding[] {
        const findings: InsecureFormFinding[] = [];
        const formBlocks: string[] = html.match(this.form_block_regex) ?? [];
        for (const block of formBlocks) {
            if (!this.form_password_regex.test(block)) continue;
            const actionMatch: RegExpMatchArray | null = block.match(this.form_action_regex);
            const rawAction: string | undefined = actionMatch?.[1]?.trim();
            const resolved: URL | null = this.resolveFormAction(rawAction, pageUrl);
            const methodMatch: RegExpMatchArray | null = block.match(this.form_method_regex);
            const method: string = (methodMatch?.[1]?.trim().toLowerCase() || 'get');
            const issues: InsecureFormIssue[] = [];
            if (resolved && resolved.protocol === 'http:') issues.push('http-transport');
            if (method === 'get') issues.push('get-method');
            if (issues.length === 0) continue;
            const severity: SecretSeverity = issues.includes('http-transport') ? SecretSeverity.CRITICAL : SecretSeverity.HIGH;
            const descriptionParts: string[] = [];
            if (issues.includes('http-transport')) {
                descriptionParts.push(`El envío va por HTTP sin cifrar (${resolved!.toString()}): cualquiera en la misma red (Wi-Fi público, proxy intermedio, ISP) puede interceptar la contraseña en texto plano`);
            }
            if (issues.includes('get-method')) {
                descriptionParts.push(`Usa method="get", por lo que la contraseña viaja como parte de la URL: queda registrada en el historial del navegador, en logs de acceso del servidor/proxy, y se filtra vía el header Referer a cualquier recurso de terceros que la página cargue después — esto ocurre incluso si el envío va por HTTPS`);
            }
            findings.push({
                formAction: rawAction || '(mismo origen de la página)',
                method,
                hasPasswordField: true,
                issues,
                severity,
                description: `Formulario con campo de contraseña donde ${descriptionParts.join('; además, ')}.`,
            });
        }
        return findings;
    }

    private resolveFormAction(rawAction: string | undefined, pageUrl: string): URL | null {
        if (!rawAction || rawAction === '#') {
            try { return new URL(pageUrl); } catch { return null; }
        }
        if (/^(javascript|mailto|tel):/i.test(rawAction)) return null;
        try {
            return new URL(rawAction, pageUrl);
        } catch {
            return null;
        }
    }

    // --- MIXED CONTENT ---
    private scanMixedContent(html: string, pageUrl: string): MixedContentFinding[] {
        const findings: MixedContentFinding[] = [];
        const seen: Set<string> = new Set<string>();
        for (const pattern of this.resource_tag_patterns) {
            const regex: RegExp = new RegExp(pattern.source, 'gi');
            let match: RegExpExecArray | null;
            while ((match = regex.exec(html)) !== null) {
                this.pushMixedContentIfInsecure(findings, seen, pattern.tag, match[1], pattern.kind, pageUrl);
            }
        }
        const srcsetRegex: RegExp = new RegExp(this.srcset_tag_regex.source, 'gi');
        let srcsetMatch: RegExpExecArray | null;
        while ((srcsetMatch = srcsetRegex.exec(html)) !== null) {
            const tagName: string = srcsetMatch[1].toLowerCase();
            const urls: string[] = this.parseSrcsetUrls(srcsetMatch[2]);
            for (const rawUrl of urls) {
                this.pushMixedContentIfInsecure(findings, seen, `${tagName}[srcset]`, rawUrl, 'passive', pageUrl);
            }
        }
        return findings;
    }

    private parseSrcsetUrls(srcsetValue: string): string[] {
        return srcsetValue.split(',').map((candidate) => candidate.trim().split(/\s+/)[0]).filter((url): url is string => !!url);
    }

    private pushMixedContentIfInsecure(findings: MixedContentFinding[], seen: Set<string>, tag: string, rawUrl: string | undefined, kind: MixedContentKind, pageUrl: string): void {
        if (!rawUrl || /^(data|blob|mailto|tel|javascript):/i.test(rawUrl)) return;
        let resolved: URL;
        try {
            resolved = new URL(rawUrl, pageUrl);
        } catch {
            return;
        }
        if (resolved.protocol !== 'http:') return;
        const dedupeKey: string = `${tag}:${resolved.toString()}`;
        if (seen.has(dedupeKey)) return;
        seen.add(dedupeKey);
        findings.push({
            tag,
            url: resolved.toString(),
            kind,
            severity: kind === 'active' ? SecretSeverity.HIGH : SecretSeverity.LOW,
            description: kind === 'active'
                ? `Recurso activo (${tag}) cargado por HTTP en una página HTTPS: ${resolved.toString()}. Los navegadores modernos lo bloquean por defecto, pero si llega a ejecutarse es un vector directo para que un atacante en la red inyecte código, ya que el candado de HTTPS no protege este recurso.`
                : `Recurso pasivo (${tag}) cargado por HTTP en una página HTTPS: ${resolved.toString()}. El navegador lo carga igual, pero un atacante en la red puede alterar o espiar ese contenido, y el navegador suele mostrar el candado como "no totalmente seguro".`
        });
    }

    private countResourceTags(html: string): number {
        let total: number = 0;
        for (const pattern of this.resource_tag_patterns) {
            total += (html.match(new RegExp(pattern.source, 'gi')) ?? []).length;
        }
        total += (html.match(this.srcset_tag_regex) ?? []).length;
        return total;
    }

    // --- REVERSE TABNABBING ---
    private scanTabnabbing(html: string): TabnabbingFinding[] {
        const findings: TabnabbingFinding[] = [];
        this.blank_link_regex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = this.blank_link_regex.exec(html)) !== null) {
            const fullTag: string = match[0];
            const innerHtml: string = match[1] ?? '';
            const relMatch: RegExpMatchArray | null = fullTag.match(this.rel_attr_regex);
            const relValues: string[] = (relMatch?.[1] ?? '').toLowerCase().split(/\s+/).filter(Boolean);
            if (relValues.includes('noopener')) continue;
            const hasNoreferrer: boolean = relValues.includes('noreferrer');
            const hrefMatch: RegExpMatchArray | null = fullTag.match(this.href_attr_regex);
            const href: string = hrefMatch?.[1] ?? '(sin href)';
            findings.push({
                href,
                linkText: this.extractLinkText(innerHtml),
                severity: SecretSeverity.MEDIUM,
                description: `Enlace con target="_blank" sin rel="noopener": la página de destino puede acceder a window.opener y redirigir la pestaña original hacia un sitio de phishing sin que el usuario lo note (reverse tabnabbing). Nota: Chrome, Edge y Firefox aplican noopener de forma implícita desde ~2021 para target="_blank" salvo que se use rel="opener" explícitamente, por lo que el riesgo real depende del navegador del visitante; aun así se recomienda declararlo explícitamente${hasNoreferrer ? '' : ', y además falta "noreferrer", por lo que también se filtra la URL de origen (Referer) al sitio de destino'}.`,
            });
        }
        return findings;
    }

    private extractLinkText(innerHtml: string): string | null {
        const text: string = innerHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
        if (!text) return null;
        return text.length > 80 ? `${text.slice(0, 80)}…` : text;
    }

    // --- AGREGACIÓN ---
    private computeOverallRisk(insecureForms: InsecureFormFinding[], mixedContent: MixedContentFinding[], tabnabbing: TabnabbingFinding[], pageIsHttps: boolean): SecretSeverity {
        const severities: SecretSeverity[] = [
            ...insecureForms.map((f) => f.severity),
            ...mixedContent.map((f) => f.severity),
            ...tabnabbing.map((f) => f.severity)
        ];
        if (!pageIsHttps) severities.push(SecretSeverity.HIGH);
        return severities.length === 0 ? SecretSeverity.LOW : Math.max(...severities);
    }

    private buildSummaryText(insecureForms: InsecureFormFinding[], mixedContent: MixedContentFinding[], tabnabbing: TabnabbingFinding[], pageIsHttps: boolean): string {
        const parts: string[] = [];
        if (!pageIsHttps) parts.push('La página se sirve por HTTP, sin cifrado de transporte');
        if (insecureForms.length > 0) {
            const httpTransport: number = insecureForms.filter((f) => f.issues.includes('http-transport')).length;
            const getMethod: number = insecureForms.filter((f) => f.issues.includes('get-method')).length;
            parts.push(`${insecureForms.length} formulario(s) con contraseña con envío inseguro (${httpTransport} por HTTP, ${getMethod} por method="get")`);
        }
        if (mixedContent.length > 0) {
            const active: number = mixedContent.filter((m) => m.kind === 'active').length;
            parts.push(`${mixedContent.length} recurso(s) con mixed content (${active} activo(s), ${mixedContent.length - active} pasivo(s))`);
        }
        if (tabnabbing.length > 0) parts.push(`${tabnabbing.length} enlace(s) target="_blank" sin rel="noopener"`);
        return parts.length === 0 ? 'No se detectaron problemas evidentes de formularios, mixed content o reverse tabnabbing.' : parts.join(', ') + '.';
    }
}
