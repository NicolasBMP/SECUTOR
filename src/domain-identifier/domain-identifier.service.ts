import { Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import { Resolver } from 'dns/promises';
import { getDomain } from 'tldts';
import { WebDataDto } from '../common/dtos/web-data.dto';
import { DkimResult, DkimSelectorResult, DmarcResult, EmailIdentifierResult, EmailSecurityFinding, SecretSeverity, SpfResult } from './dto/domain-identifier.interface';

@Injectable()
export class DomainIdentifierService {
    private readonly logger = new Logger('DOMAIN-IDENTIFIER-SERVICE');
    private readonly common_dkim_selectors: string[] = [
        'google', 'default', 'selector1', 'selector2', // Google Workspace, Microsoft 365
        'k1', 'k2', 'k3', // Mailchimp / Mandrill
        's1', 's2', // SendGrid
        'dkim', 'mail', 'smtp', 'email',
        'mandrill', 'zoho', 'mailjet', 'mailgun', 'mg1',
        'pm', 'amazonses', // Postmark, Amazon SES
        'everlytickey1', 'everlytickey2', // Klaviyo
        'hs1', 'hs2' // HubSpot
    ];
    private readonly dns_timeout_ms: number = 5000;
    private readonly resolver: Resolver;
    constructor() {
        this.resolver = new Resolver();
        this.resolver.setServers(['1.1.1.1', '8.8.8.8']);
    }

    async getDomainIdentifier(webDataDto: WebDataDto): Promise<EmailIdentifierResult> {
        try {
            const hostname: string = new URL(webDataDto.web_url).hostname;
            const domain: string = getDomain(hostname) ?? hostname;
            const [spf, dkim, dmarc] = await Promise.all([
                this.analyzeSpf(domain),
                this.analyzeDkim(domain),
                this.analyzeDmarc(domain)
            ]);
            return {
                domain,
                spf,
                dkim,
                dmarc,
                overallRisk: this.computeOverallRisk(spf, dkim, dmarc),
                summary: this.buildSummaryText(spf, dkim, dmarc)
            };
        } catch (error: any) {
            this.logger.error(`Error crítico: ${error.stack}`);
            throw new InternalServerErrorException(`Se produjo un error al analizar la higiene DNS/email: ${error}`);
        }
    }

    // --- SPF ---
    private async analyzeSpf(domain: string): Promise<SpfResult> {
        const { records: txtRecords, error } = await this.resolveTxtRecords(domain);
        if (error) {
            return {
                found: false, record: null, multipleRecords: false, allMechanism: null, lookupCount: 0,
                checkError: error,
                findings: [{
                    type: 'SPF',
                    severity: SecretSeverity.LOW,
                    description: `No se pudo verificar SPF en ${domain} por un error de resolución DNS (${error}). Este resultado no debe interpretarse como "sin SPF"; reintenta el análisis.`
                }]
            };
        }
        const spfRecords: string[] = txtRecords.filter((r) => /^v=spf1\b/i.test(r.trim()));
        const findings: EmailSecurityFinding[] = [];
        if (spfRecords.length === 0) {
            findings.push({
                type: 'SPF',
                severity: SecretSeverity.HIGH,
                description: `No se encontró un registro SPF (TXT "v=spf1...") en ${domain}. Sin SPF, cualquier servidor puede enviar correo suplantando este dominio y pasar la primera capa de autenticación.`
            });
            return { found: false, record: null, multipleRecords: false, allMechanism: null, lookupCount: 0, findings, checkError: null };
        }
        if (spfRecords.length > 1) {
            findings.push({
                type: 'SPF',
                severity: SecretSeverity.HIGH,
                description: `Se encontraron ${spfRecords.length} registros SPF en el mismo dominio. Según RFC 7208, más de un registro SPF causa un "permerror": los validadores de correo descartan la verificación por completo, como si SPF no existiera.`
            });
        }
        const record: string = spfRecords[0];
        const allMechanism = this.extractAllQualifier(record);
        const lookupCount: number = this.countSpfLookups(record);
        if (allMechanism === '+all') {
            findings.push({
                type: 'SPF',
                severity: SecretSeverity.CRITICAL,
                description: `El registro SPF termina en "+all": autoriza explícitamente a CUALQUIER servidor de internet a enviar correo en nombre de este dominio, anulando por completo la protección de SPF.`
            });
        } else if (allMechanism === null || allMechanism === '?all') {
            findings.push({
                type: 'SPF',
                severity: SecretSeverity.MEDIUM,
                description: allMechanism === null ? 'El registro SPF no termina en un mecanismo "all"; el tratamiento de servidores no listados queda indefinido para muchos validadores.' : 'El registro SPF termina en "?all" (neutral): los servidores no listados no son aceptados ni rechazados explícitamente, ofreciendo poca protección real.'
            });
        } else if (allMechanism === '~all') {
            findings.push({
                type: 'SPF',
                severity: SecretSeverity.LOW,
                description: 'El registro SPF termina en "~all" (softfail): el correo no autorizado se marca como sospechoso pero normalmente no se rechaza. "-all" (hardfail) da una protección más estricta.'
            });
        }
        if (lookupCount > 10) {
            findings.push({
                type: 'SPF',
                severity: SecretSeverity.HIGH,
                description: `El registro SPF dispara aproximadamente ${lookupCount} consultas DNS adicionales (include/a/mx/ptr/exists/redirect), superando el límite de 10 de RFC 7208. Los validadores tratarán esto como "permerror" y descartarán la verificación SPF.`
            });
        } else if (lookupCount >= 8) {
            findings.push({
                type: 'SPF',
                severity: SecretSeverity.LOW,
                description: `El registro SPF ya dispara ${lookupCount} de las 10 consultas DNS permitidas por RFC 7208; está cerca del límite y un "include" adicional podría romper la validación.`
            });
        }
        return { found: true, record, multipleRecords: spfRecords.length > 1, allMechanism, lookupCount, findings, checkError: null };
    }

    private extractAllQualifier(record: string): SpfResult['allMechanism'] {
        const terms: string[] = record.split(/\s+/).filter(Boolean);
        const allTerm: string | undefined = terms.find((t) => /^[+\-~?]?all$/i.test(t));
        if (!allTerm) return null;
        if (/^-all$/i.test(allTerm)) return '-all';
        if (/^~all$/i.test(allTerm)) return '~all';
        if (/^\?all$/i.test(allTerm)) return '?all';
        return '+all';
    }

    private countSpfLookups(record: string): number {
        const terms: string[] = record.split(/\s+/).filter(Boolean);
        let count: number = 0;
        for (const rawTerm of terms) {
            const term: string = rawTerm.replace(/^[+\-~?]/, '');
            if (/^include:/i.test(term)) count++;
            else if (/^redirect=/i.test(term)) count++;
            else if (/^exists:/i.test(term)) count++;
            else if (/^(a|mx)(:|\/|$)/i.test(term)) count++;
            else if (/^ptr(:|$)/i.test(term)) count++;
        }
        return count;
    }

    // --- DMARC ---
    private async analyzeDmarc(domain: string): Promise<DmarcResult> {
        const { records: txtRecords, error } = await this.resolveTxtRecords(`_dmarc.${domain}`);
        if (error) {
            return {
                found: false, record: null, checkError: error, policy: null, subdomainPolicy: null, percentage: null,
                alignment: { dkim: 'relaxed', spf: 'relaxed' }, reportingAddresses: [],
                findings: [{
                    type: 'DMARC',
                    severity: SecretSeverity.LOW,
                    description: `No se pudo verificar DMARC en _dmarc.${domain} por un error de resolución DNS (${error}). Este resultado no debe interpretarse como "sin DMARC"; reintenta el análisis.`
                }]
            };
        }
        const dmarcRecords: string[] = txtRecords.filter((r) => /^v=dmarc1\b/i.test(r.trim()));
        const findings: EmailSecurityFinding[] = [];
        if (dmarcRecords.length === 0) {
            findings.push({
                type: 'DMARC',
                severity: SecretSeverity.HIGH,
                description: `No se encontró un registro DMARC (TXT "v=DMARC1..." en _dmarc.${domain}). Sin DMARC no hay política para el correo que falla SPF/DKIM, ni reportes de intentos de suplantación del dominio.`
            });
            return {
                found: false, record: null, checkError: null, policy: null, subdomainPolicy: null, percentage: null,
                alignment: { dkim: 'relaxed', spf: 'relaxed' }, reportingAddresses: [], findings
            };
        }
        const record: string = dmarcRecords[0];
        const tags: Record<string, string> = this.parseTagValuePairs(record);
        const policy: "none" | "quarantine" | "reject" | null = (tags['p'] as DmarcResult['policy']) ?? null;
        const subdomainPolicy: string | null = tags['sp'] ?? null;
        const percentage: number | null = tags['pct'] !== undefined ? Number(tags['pct']) : null;
        const alignment: DmarcResult['alignment'] = {
            dkim: tags['adkim'] === 's' ? 'strict' : 'relaxed',
            spf: tags['aspf'] === 's' ? 'strict' : 'relaxed'
        };
        const reportingAddresses: string[] = (tags['rua'] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
        if (policy === 'none') {
            findings.push({ type: 'DMARC', severity: SecretSeverity.MEDIUM, description: 'DMARC está configurado pero con política "p=none": el correo que falla autenticación se entrega igual, solo se registra en los reportes. Buen primer paso, pero no bloquea la suplantación activamente.' });
        } else if (policy === 'quarantine') {
            findings.push({ type: 'DMARC', severity: SecretSeverity.LOW, description: 'DMARC está en "p=quarantine": el correo que falla autenticación suele ir a spam en vez de bloquearse. Es una protección intermedia; "p=reject" es la más estricta.' });
        }
        if (percentage !== null && percentage < 100) {
            findings.push({ type: 'DMARC', severity: SecretSeverity.LOW, description: `La política DMARC solo se aplica al ${percentage}% del correo ("pct=${percentage}"); el resto queda sin cubrir.` });
        }
        if (reportingAddresses.length === 0) {
            findings.push({ type: 'DMARC', severity: SecretSeverity.LOW, description: 'El registro DMARC no define "rua" (dirección para reportes agregados): no hay visibilidad de quién envía correo a nombre del dominio ni de intentos de suplantación.' });
        }
        return { found: true, record, checkError: null, policy, subdomainPolicy, percentage, alignment, reportingAddresses, findings };
    }

    private parseTagValuePairs(record: string): Record<string, string> {
        const tags: Record<string, string> = {};
        record.split(';').forEach((part) => {
            const [key, ...rest] = part.trim().split('=');
            if (key && rest.length > 0) tags[key.trim().toLowerCase()] = rest.join('=').trim();
        });
        return tags;
    }

    // --- DKIM ---
    private async analyzeDkim(domain: string): Promise<DkimResult> {
        const selectorsWithErrors: { selector: string; error: string }[] = [];
        const results = await Promise.all(
            this.common_dkim_selectors.map(async (selector): Promise<DkimSelectorResult | null> => {
                const hostname: string = `${selector}._domainkey.${domain}`;
                const { records: txtRecords, error } = await this.resolveTxtRecords(hostname);
                if (error) {
                    selectorsWithErrors.push({ selector, error });
                    return null;
                }
                const record: string | undefined = txtRecords.find((r) => /v=dkim1/i.test(r)) ?? txtRecords[0];
                if (!record) return null;
                const tags: Record<string, string> = this.parseTagValuePairs(record);
                const publicKey: string = tags['p'] ?? '';
                return {
                    selector,
                    found: true,
                    record,
                    hasPublicKey: publicKey.length > 0,
                    keyRevoked: 'p' in tags && publicKey.length === 0
                };
            })
        );
        const selectorsFound: DkimSelectorResult[] = results.filter((r): r is DkimSelectorResult => r !== null);
        const findings: EmailSecurityFinding[] = [];
        if (selectorsWithErrors.length === this.common_dkim_selectors.length) {
            findings.push({
                type: 'DKIM',
                severity: SecretSeverity.LOW,
                description: `No se pudo verificar ninguno de los ${this.common_dkim_selectors.length} selectores DKIM por errores de resolución DNS. Este resultado no debe interpretarse como "sin DKIM"; reintenta el análisis.`
            });
        } else if (selectorsFound.length === 0) {
            findings.push({
                type: 'DKIM',
                severity: SecretSeverity.MEDIUM,
                description: `No se encontró DKIM en ninguno de los ${this.common_dkim_selectors.length} selectores comunes probados. Esto NO confirma que el dominio carezca de DKIM: el selector real puede no estar en esta lista. Si conoces el selector de tu proveedor de correo, verifícalo manualmente.`
            });
        } else {
            const revoked: DkimSelectorResult[] = selectorsFound.filter((s) => s.keyRevoked);
            if (revoked.length > 0) {
                findings.push({
                    type: 'DKIM',
                    severity: SecretSeverity.LOW,
                    description: `El/los selector(es) ${revoked.map((s) => s.selector).join(', ')} tienen la clave pública vacía ("p="), lo que indica una clave revocada. Si ya no se usan no es un problema; si deberían estar activos, el correo firmado con ellos fallará DKIM.`
                });
            }
        }
        return { selectorsChecked: this.common_dkim_selectors, selectorsFound, selectorsWithErrors, findings };
    }

    private async resolveTxtRecords(hostname: string): Promise<{ records: string[]; error: string | null }> {
        try {
            const records: string[][] = await this.withTimeout(
                this.resolver.resolveTxt(hostname),
                this.dns_timeout_ms
            );
            return { records: records.map((chunks) => chunks.join('')), error: null };
        } catch (error: any) {
            const code: string = error.code ?? 'UNKNOWN';
            if (code === 'ENOTFOUND' || code === 'ENODATA') {
                return { records: [], error: null };
            }
            this.logger.warn(`No se pudo resolver TXT de ${hostname}: [${code}] ${error.message}`);
            return { records: [], error: code };
        }
    }

    private withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
        let timer: NodeJS.Timeout;
        const timeout: Promise<T> = new Promise<T>((_, reject) => {
            timer = setTimeout(() => reject(Object.assign(new Error('DNS timeout'), { code: 'ETIMEOUT_CUSTOM' })), ms);
        });
        return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
    }

    private computeOverallRisk(spf: SpfResult, dkim: DkimResult, dmarc: DmarcResult): SecretSeverity {
        const severities: SecretSeverity[] = [...spf.findings, ...dkim.findings, ...dmarc.findings].map((f) => f.severity);
        return severities.length === 0 ? SecretSeverity.LOW : Math.max(...severities);
    }

    private buildSummaryText(spf: SpfResult, dkim: DkimResult, dmarc: DmarcResult): string {
        const spfText: string = spf.checkError ? 'SPF no verificable (error DNS)' : spf.found ? `SPF presente${spf.allMechanism ? ` (${spf.allMechanism})` : ''}` : 'Sin SPF';
        const dkimText: string = dkim.selectorsWithErrors.length === this.common_dkim_selectors.length ? 'DKIM no verificable (error DNS)' : dkim.selectorsFound.length > 0 ? `DKIM encontrado en ${dkim.selectorsFound.length} selector(es)` : 'Sin DKIM en selectores comunes';
        const dmarcText: string = dmarc.checkError ? 'DMARC no verificable (error DNS)' : dmarc.found ? `DMARC presente (p=${dmarc.policy ?? 'desconocido'})` : 'Sin DMARC';
        return [spfText, dkimText, dmarcText].join(', ') + '.';
    }
}
