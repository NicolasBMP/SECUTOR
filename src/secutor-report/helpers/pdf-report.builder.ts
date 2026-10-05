import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { ContentIdentifierResult, CookieIdentifierResult, DataIdentifierResult, EmailIdentifierResult, HeaderIdentifierResponse, SecretSeverity, SecurityIdentifierResult, SecutorReportRequest, VulnerabilityIdentifierResult, WebIdentifierResponse } from '../dto/secutor-report.interface';
import { ScannedContentInfo } from 'src/content-identifier/dto/content-identifier.interface';
import { ScannedSourcesInfo } from 'src/data-identifier/dto/data-identifier.interface';
import { DkimResult, DmarcResult, SpfResult } from 'src/domain-identifier/dto/domain-identifier.interface';
import { HeaderSummaryIdentifierResponse } from 'src/header-identifier/dto/header-identifier.interface';
import { CertificateInfo } from 'src/security-identifier/dto/security-identifier.dto';

const SEVERITY_COLOR: Record<SecretSeverity, [number, number, number]> = {
    [SecretSeverity.LOW]: [46, 160, 67],
    [SecretSeverity.MEDIUM]: [227, 179, 20],
    [SecretSeverity.HIGH]: [230, 126, 34],
    [SecretSeverity.CRITICAL]: [192, 57, 43],
};

const SEVERITY_LABEL: Record<SecretSeverity, string> = {
    [SecretSeverity.LOW]: 'BAJO',
    [SecretSeverity.MEDIUM]: 'MEDIO',
    [SecretSeverity.HIGH]: 'ALTO',
    [SecretSeverity.CRITICAL]: 'CRÍTICO',
};

export class PdfReportBuilder {
    private readonly doc: jsPDF;
    private readonly margin = 14;
    private readonly pageWidth: number;
    private readonly pageHeight: number;
    private cursorY: number;

    constructor(private readonly data: SecutorReportRequest) {
        this.doc = new jsPDF({ unit: 'mm', format: 'a4' });
        this.pageWidth = this.doc.internal.pageSize.getWidth();
        this.pageHeight = this.doc.internal.pageSize.getHeight();
        this.cursorY = this.margin;
    }

    build(): Buffer {
        this.addCoverPage();
        this.addContentSection();
        this.addDataSection();
        this.addEmailSection();
        this.addHeaderSection();
        this.addSecuritySection();
        this.addWebTechSection();
        this.addVulnerabilitySection();
        this.addCookieSection();
        this.addFootersToAllPages();
        return Buffer.from(this.doc.output('arraybuffer'));
    }

    // ============================================================
    // PORTADA
    // ============================================================
    private addCoverPage(): void {
        const targetUrl: string =
            this.data.securityIdentifierResult?.finalUrl ||
            this.data.securityIdentifierResult?.url ||
            this.data.emailIdentifierResult?.domain ||
            'N/D';
        this.doc.setFillColor(24, 38, 54);
        this.doc.rect(0, 0, this.pageWidth, this.pageHeight, 'F');
        this.doc.setTextColor(255, 255, 255);
        this.doc.setFont('helvetica', 'bold');
        this.doc.setFontSize(28);
        this.doc.text('SECUTOR', this.pageWidth / 2, 55, { align: 'center' });
        this.doc.setFont('helvetica', 'normal');
        this.doc.setFontSize(13);
        this.doc.text('Reporte de Seguridad Web', this.pageWidth / 2, 65, { align: 'center' });
        this.doc.setFontSize(11);
        this.doc.text(targetUrl, this.pageWidth / 2, 80, { align: 'center' });
        const generatedAt: string = new Date().toLocaleString('es-ES', { dateStyle: 'long', timeStyle: 'short' });
        this.doc.setFontSize(9);
        this.doc.setTextColor(180, 190, 200);
        this.doc.text(`Generado el ${generatedAt}`, this.pageWidth / 2, 87, { align: 'center' });
        const executiveRisk: SecretSeverity = this.computeExecutiveRisk();
        const [r, g, b]: [number, number, number] = SEVERITY_COLOR[executiveRisk];
        this.doc.setFillColor(r, g, b);
        this.doc.roundedRect(this.pageWidth / 2 - 38, 100, 76, 26, 3, 3, 'F');
        this.doc.setTextColor(255, 255, 255);
        this.doc.setFont('helvetica', 'bold');
        this.doc.setFontSize(11);
        this.doc.text('RIESGO GENERAL', this.pageWidth / 2, 110, { align: 'center' });
        this.doc.setFontSize(16);
        this.doc.text(SEVERITY_LABEL[executiveRisk], this.pageWidth / 2, 120, { align: 'center' });
        const moduleDots: { label: string; color: [number, number, number] }[] = [
            this.buildSeverityDot('Contenido / DOM', this.data.contentIdentifierResult?.overallRisk),
            this.buildSeverityDot('Datos expuestos', this.data.dataIdentifierResult?.overallRisk),
            this.buildSeverityDot('Email (SPF/DKIM/DMARC)', this.data.emailIdentifierResult?.overallRisk),
            this.buildSeverityDot('Certificado TLS', this.data.securityIdentifierResult?.overallRisk),
            this.buildSeverityDot('Vulnerabilidades conocidas', this.data.vulnerabilityIdentifierResult?.overallRisk),
        ];
        const headerScore: number | undefined = this.data.headerIdentifierResponse?.score;
        const header: HeaderIdentifierResponse = this.data.headerIdentifierResponse;
        if (header) {
            if (typeof headerScore === 'number') {
                moduleDots.push({
                    label: `Cabeceras HTTP: ${headerScore}/100 - ${header.grade}`,
                    color: this.getScoreColor(headerScore),
                });
            }
        }
        const gridStartY: number = 142;
        const colWidth: number = (this.pageWidth - this.margin * 2) / 2;
        moduleDots.forEach((m, idx) => {
            const col: number = idx % 2;
            const row: number = Math.floor(idx / 2);
            const x: number = this.margin + col * colWidth;
            const y: number = gridStartY + row * 14;
            const [mr, mg, mb]: [number, number, number] = m.color;
            this.doc.setFillColor(mr, mg, mb);
            this.doc.circle(x + 2, y - 1.3, 1.8, 'F');
            this.doc.setTextColor(230, 235, 240);
            this.doc.setFont('helvetica', 'normal');
            this.doc.setFontSize(9.5);
            this.doc.text(m.label, x + 7, y);
        });
        this.doc.addPage();
        this.cursorY = this.margin;
        this.doc.setTextColor(0, 0, 0);
        this.doc.setFont('helvetica', 'normal');
    }

    private buildSeverityDot(label: string, risk: SecretSeverity | undefined): { label: string; color: [number, number, number] } {
        const resolvedRisk: SecretSeverity = risk ?? SecretSeverity.LOW;
        return { label: `${label}: ${SEVERITY_LABEL[resolvedRisk]}`, color: SEVERITY_COLOR[resolvedRisk] };
    }

    private getScoreColor(score: number): [number, number, number] {
        if (score < 50) return SEVERITY_COLOR[SecretSeverity.CRITICAL];
        if (score < 80) return SEVERITY_COLOR[SecretSeverity.MEDIUM];
        return SEVERITY_COLOR[SecretSeverity.LOW];
    }

    private computeExecutiveRisk(): SecretSeverity {
        const risks: (SecretSeverity | undefined)[] = [
            this.data.contentIdentifierResult?.overallRisk,
            this.data.dataIdentifierResult?.overallRisk,
            this.data.emailIdentifierResult?.overallRisk,
            this.data.securityIdentifierResult?.overallRisk,
            this.data.vulnerabilityIdentifierResult?.overallRisk,
            // AJUSTAR
            (this.data.cookieIdentifierResult?.summary as any)?.overallRisk,
        ];
        const valid: SecretSeverity[] = risks.filter((r): r is SecretSeverity => r !== undefined && r !== null);
        return valid.length === 0 ? SecretSeverity.LOW : Math.max(...valid);
    }

    // ============================================================
    // HELPERS DE LAYOUT
    // ============================================================
    private ensureSpace(neededHeight: number): void {
        if (this.cursorY + neededHeight > this.pageHeight - this.margin) {
            this.doc.addPage();
            this.cursorY = this.margin;
        }
    }

    private addSectionHeader(title: string, risk?: SecretSeverity): void {
        this.ensureSpace(16);
        this.doc.setFillColor(41, 65, 90);
        this.doc.rect(this.margin, this.cursorY, this.pageWidth - this.margin * 2, 10, 'F');
        this.doc.setTextColor(255, 255, 255);
        this.doc.setFont('helvetica', 'bold');
        this.doc.setFontSize(12);
        this.doc.text(title, this.margin + 3, this.cursorY + 7);
        if (risk !== undefined) {
            const label: string = SEVERITY_LABEL[risk];
            const [r, g, b]: [number, number, number] = SEVERITY_COLOR[risk];
            this.doc.setFontSize(8.5);
            const badgeWidth: number = this.doc.getTextWidth(label) + 8;
            const badgeX: number = this.pageWidth - this.margin - badgeWidth - 2;
            this.doc.setFillColor(r, g, b);
            this.doc.roundedRect(badgeX, this.cursorY + 1.5, badgeWidth, 7, 1.5, 1.5, 'F');
            this.doc.setTextColor(255, 255, 255);
            this.doc.text(label, badgeX + badgeWidth / 2, this.cursorY + 6, { align: 'center' });
        }
        this.cursorY += 14;
        this.doc.setTextColor(0, 0, 0);
        this.doc.setFont('helvetica', 'normal');
    }

    private addSubheading(text: string): void {
        this.ensureSpace(8);
        this.doc.setFont('helvetica', 'bold');
        this.doc.setFontSize(10);
        this.doc.setTextColor(41, 65, 90);
        this.doc.text(text, this.margin, this.cursorY);
        this.cursorY += 6;
        this.doc.setTextColor(0, 0, 0);
        this.doc.setFont('helvetica', 'normal');
    }

    private addParagraph(text: string, options?: { fontSize?: number; bold?: boolean }): void {
        if (!text) return;
        const fontSize: number = options?.fontSize ?? 9.5;
        this.doc.setFont('helvetica', options?.bold ? 'bold' : 'normal');
        this.doc.setFontSize(fontSize);
        this.doc.setTextColor(50, 50, 50);
        const maxWidth: number = this.pageWidth - this.margin * 2;
        const lines: string[] = this.doc.splitTextToSize(text, maxWidth);
        const lineHeight: number = fontSize * 0.42;
        this.ensureSpace(lines.length * lineHeight + 4);
        this.doc.text(lines, this.margin, this.cursorY);
        this.cursorY += lines.length * lineHeight + 5;
        this.doc.setTextColor(0, 0, 0);
    }

    private addKeyValueRow(key: string, value: string): void {
        this.ensureSpace(6);
        this.doc.setFont('helvetica', 'bold');
        this.doc.setFontSize(9);
        this.doc.text(`${key}:`, this.margin, this.cursorY);
        this.doc.setFont('helvetica', 'normal');
        this.doc.text(value || 'N/D', this.margin + 48, this.cursorY);
        this.cursorY += 6;
    }

    private addEmptyState(message: string): void {
        this.ensureSpace(10);
        this.doc.setFillColor(230, 245, 233);
        this.doc.roundedRect(this.margin, this.cursorY, this.pageWidth - this.margin * 2, 8, 1, 1, 'F');
        this.doc.setTextColor(39, 110, 58);
        this.doc.setFontSize(9);
        this.doc.text(`\u2713 ${message}`, this.margin + 3, this.cursorY + 5.5);
        this.cursorY += 12;
        this.doc.setTextColor(0, 0, 0);
    }

    private addWarningBox(message: string): void {
        this.ensureSpace(10);
        this.doc.setFillColor(255, 243, 205);
        this.doc.roundedRect(this.margin, this.cursorY, this.pageWidth - this.margin * 2, 8, 1, 1, 'F');
        this.doc.setTextColor(133, 100, 4);
        this.doc.setFontSize(8.5);
        this.doc.text(`\u26a0 ${message}`, this.margin + 3, this.cursorY + 5.5);
        this.cursorY += 12;
        this.doc.setTextColor(0, 0, 0);
    }

    private truncate(text: string | null | undefined, maxLength: number): string {
        if (!text) return '';
        return text.length > maxLength ? `${text.slice(0, maxLength)}…` : text;
    }

    private addSeverityTable(params: { head: string[]; rows: (string | number)[][]; severities: SecretSeverity[]; severityColIndex: number; columnStyles?: Record<number, any>; }): void {
        const { head, rows, severities, severityColIndex, columnStyles } = params;
        autoTable(this.doc, {
            startY: this.cursorY,
            head: [head],
            body: rows,
            theme: 'grid',
            styles: { fontSize: 8, cellPadding: 2, overflow: 'linebreak', valign: 'middle' },
            headStyles: { fillColor: [41, 65, 90], textColor: 255, fontStyle: 'bold', fontSize: 8.5 },
            alternateRowStyles: { fillColor: [245, 247, 250] },
            columnStyles,
            margin: { left: this.margin, right: this.margin },
            didParseCell: (hookData: any) => {
                if (hookData.section === 'body' && hookData.column.index === severityColIndex) {
                    const sev: SecretSeverity | undefined = severities[hookData.row.index];
                    if (sev !== undefined) {
                        const [r, g, b]: [number, number, number] = SEVERITY_COLOR[sev];
                        hookData.cell.styles.fillColor = [r, g, b];
                        hookData.cell.styles.textColor = [255, 255, 255];
                        hookData.cell.styles.fontStyle = 'bold';
                        hookData.cell.styles.halign = 'center';
                    }
                }
            }
        });
        this.cursorY = (this.doc as any).lastAutoTable.finalY + 8;
    }

    private addFindingsList(findings: { type?: string; severity: SecretSeverity; description: string }[]): void {
        if (findings.length === 0) {
            this.addEmptyState('Sin hallazgos en esta categoría.');
            return;
        }
        this.addSeverityTable({
            head: ['Hallazgo', 'Severidad'],
            rows: findings.map((f) => [this.truncate(f.description, 100), SEVERITY_LABEL[f.severity]]),
            severities: findings.map((f) => f.severity),
            severityColIndex: 1,
            columnStyles: { 0: { cellWidth: 140 } }
        });
    }
    yo
    // ============================================================
    // 1. CONTENIDO / DOM
    // ============================================================
    private addContentSection(): void {
        const result: ContentIdentifierResult = this.data.contentIdentifierResult;
        if (!result) return;
        this.addSectionHeader('1. Contenido y DOM de la página', result.overallRisk);
        this.addParagraph(result.summary);
        const info: ScannedContentInfo = result.scannedContent;
        this.addParagraph(
            `Conexión: ${info.pageIsHttps ? 'HTTPS' : 'HTTP (sin cifrado)'} · Formularios analizados: ${info.formsScanned} · ` +
            `Enlaces target="_blank" analizados: ${info.linksWithBlankTargetScanned} · Recursos analizados: ${info.resourceTagsScanned}`,
            { fontSize: 8.5 }
        );
        this.addSubheading('Formularios con envío inseguro');
        if (result.insecureForms.length === 0) {
            this.addEmptyState('No se encontraron formularios con contraseña enviados de forma insegura.');
        } else {
            this.addSeverityTable({
                head: ['Acción', 'Método', 'Problema(s)', 'Severidad'],
                rows: result.insecureForms.map((f) => [this.truncate(f.formAction, 45), f.method.toUpperCase(), f.issues.join(', '), SEVERITY_LABEL[f.severity]]),
                severities: result.insecureForms.map((f) => f.severity),
                severityColIndex: 3,
                columnStyles: { 0: { cellWidth: 70 } }
            });
        }
        this.addSubheading('Mixed content (HTTP dentro de HTTPS)');
        if (result.mixedContent.length === 0) {
            this.addEmptyState('No se detectó contenido mixto.');
        } else {
            this.addSeverityTable({
                head: ['Etiqueta', 'URL', 'Tipo', 'Severidad'],
                rows: result.mixedContent.map((m) => [m.tag, this.truncate(m.url, 50), m.kind === 'active' ? 'Activo' : 'Pasivo', SEVERITY_LABEL[m.severity]]),
                severities: result.mixedContent.map((m) => m.severity),
                severityColIndex: 3,
                columnStyles: { 1: { cellWidth: 75 } }
            });
        }
        this.addSubheading('Enlaces vulnerables a reverse tabnabbing');
        if (result.tabnabbing.length === 0) {
            this.addEmptyState('No se encontraron enlaces target="_blank" sin rel="noopener".');
        } else {
            this.addSeverityTable({
                head: ['Texto del enlace', 'Destino', 'Severidad'],
                rows: result.tabnabbing.map((t) => [t.linkText ?? '(sin texto)', this.truncate(t.href, 55), SEVERITY_LABEL[t.severity]]),
                severities: result.tabnabbing.map((t) => t.severity),
                severityColIndex: 2
            });
        }
    }

    // ============================================================
    // 2. DATOS EXPUESTOS
    // ============================================================
    private addDataSection(): void {
        const result: DataIdentifierResult = this.data.dataIdentifierResult;
        if (!result) return;
        this.addSectionHeader('2. Datos expuestos y secretos', result.overallRisk);
        this.addParagraph(result.summary);
        const info: ScannedSourcesInfo = result.scannedSources;
        this.addParagraph(
            `Scripts encontrados: ${info?.scriptsFound ?? 'N/D'} · Escaneados: ${info?.scriptsScanned ?? 'N/D'} · Omitidos: ${info?.scriptsSkipped ?? 'N/D'}`,
            { fontSize: 8.5 }
        );
        this.addSubheading('Secretos detectados');
        if (result.secrets.length === 0) {
            this.addEmptyState('No se detectaron patrones de secretos.');
        } else {
            this.addSeverityTable({
                head: ['Tipo', 'Origen', 'Vista previa', 'Ocurrencias', 'Severidad'],
                rows: result.secrets.map((s) => [s.type, this.truncate(s.source, 35), s.matchPreview, String(s.occurrences), SEVERITY_LABEL[s.severity]]),
                severities: result.secrets.map((s) => s.severity),
                severityColIndex: 4,
                columnStyles: { 1: { cellWidth: 42 } }
            });
            result.secrets.filter((s) => s.message).forEach((s) => this.addParagraph(`• ${s.type}: ${s.message}`, { fontSize: 8 }));
        }
        this.addSubheading('Rutas sensibles expuestas');
        if (result.exposedPaths.length === 0) {
            this.addEmptyState('No se encontraron rutas sensibles accesibles.');
        } else {
            this.addSeverityTable({
                head: ['Ruta', 'Descripción', 'Severidad'],
                rows: result.exposedPaths.map((p) => [p.path, this.truncate(p.description, 60), SEVERITY_LABEL[p.severity]]),
                severities: result.exposedPaths.map((p) => p.severity),
                severityColIndex: 2,
                columnStyles: { 1: { cellWidth: 95 } }
            });
        }
        this.addSubheading('Source maps expuestos');
        if (result.exposedSourceMaps.length === 0) {
            this.addEmptyState('No se encontraron source maps expuestos.');
        } else {
            this.addSeverityTable({
                head: ['Script', 'Source map', 'Severidad'],
                rows: result.exposedSourceMaps.map((m) => [m.scriptUrl, m.mapUrl, SEVERITY_LABEL[m.severity]]),
                severities: result.exposedSourceMaps.map((m) => m.severity),
                severityColIndex: 2
            });
        }
        this.addSubheading('Integridad de scripts (SRI)');
        const sri: any = result.scriptsIntegrity; // AJUSTAR
        this.addParagraph(
            `Scripts de terceros: ${sri?.thirdPartyScripts ?? 'N/D'} · Con SRI: ${sri?.withIntegrity ?? 'N/D'} · Sin SRI: ${sri?.withoutIntegrity ?? 'N/D'}`,
            { fontSize: 8.5 }
        );
        const sriFindings: any[] = result.scriptsIntegrityFindings ?? [];
        if (sriFindings.length === 0) {
            this.addEmptyState('No se encontraron scripts de terceros sin protección de integridad (SRI).');
        } else {
            this.addSeverityTable({
                head: ['Script', 'Severidad'],
                rows: sriFindings.map((f) => [this.truncate(f.scriptUrl ?? f.url ?? '', 90), SEVERITY_LABEL[f.severity as SecretSeverity]]),
                severities: sriFindings.map((f) => f.severity as SecretSeverity),
                severityColIndex: 1
            });
        }
    }

    // ============================================================
    // 3. EMAIL (SPF / DKIM / DMARC)
    // ============================================================
    private addEmailSection(): void {
        const result: EmailIdentifierResult = this.data.emailIdentifierResult;
        if (!result) return;
        this.addSectionHeader('3. Higiene de correo (SPF / DKIM / DMARC)', result.overallRisk);
        this.addParagraph(`Dominio analizado: ${result.domain}`, { bold: true, fontSize: 9.5 });
        this.addParagraph(result.summary);
        this.addSubheading('SPF');
        if ((result.spf as SpfResult).checkError) {
            this.addWarningBox(`No se pudo verificar SPF (error DNS: ${(result.spf as SpfResult).checkError}). No interpretar como ausencia confirmada.`);
        } else {
            this.addKeyValueRow('Registro encontrado', result.spf.found ? 'Sí' : 'No');
            if (result.spf.record) this.addParagraph(this.truncate(result.spf.record, 110), { fontSize: 8 });
        }
        this.addFindingsList(result.spf.findings);
        this.addSubheading('DKIM');
        const dkimErrors: any[] = (result.dkim as DkimResult).selectorsWithErrors ?? [];
        if (dkimErrors.length > 0 && dkimErrors.length === result.dkim.selectorsChecked.length) {
            this.addWarningBox('No se pudo verificar DKIM en ningún selector por errores de resolución DNS. No interpretar como ausencia confirmada.');
        } else {
            this.addKeyValueRow('Selectores con registro', `${result.dkim.selectorsFound.length} de ${result.dkim.selectorsChecked.length} probados`);
        }
        this.addFindingsList(result.dkim.findings);
        this.addSubheading('DMARC');
        if ((result.dmarc as DmarcResult).checkError) {
            this.addWarningBox(`No se pudo verificar DMARC (error DNS: ${(result.dmarc as DmarcResult).checkError}). No interpretar como ausencia confirmada.`);
        } else {
            this.addKeyValueRow('Registro encontrado', result.dmarc.found ? 'Sí' : 'No');
            if (result.dmarc.policy) this.addKeyValueRow('Política', result.dmarc.policy);
        }
        this.addFindingsList(result.dmarc.findings);
    }

    // ============================================================
    // 4. CABECERAS HTTP
    // ============================================================
    private addHeaderSection(): void {
        const result: HeaderIdentifierResponse = this.data.headerIdentifierResponse;
        if (!result) return;
        this.addSectionHeader(`4. Cabeceras de seguridad HTTP — Puntaje ${result.score}/100 (${result.grade})`);
        const relevant: HeaderSummaryIdentifierResponse[] = result.headers.filter((h) => h.finding || !h.exist);
        this.addSubheading('Cabeceras con hallazgos o ausentes');
        if (relevant.length === 0) {
            this.addEmptyState('Todas las cabeceras evaluadas están presentes y correctamente configuradas.');
        } else {
            autoTable(this.doc, {
                startY: this.cursorY,
                head: [['Cabecera', 'Presente', 'Hallazgo', 'Peso']],
                body: relevant.map((h) => [h.name, h.exist ? 'Sí' : 'No', this.truncate(h.finding || (h.exist ? '—' : 'Ausente'), 75), h.weigth.toFixed(1)]),
                theme: 'grid',
                styles: { fontSize: 7.5, cellPadding: 2, overflow: 'linebreak' },
                headStyles: { fillColor: [41, 65, 90], textColor: 255, fontStyle: 'bold' },
                alternateRowStyles: { fillColor: [245, 247, 250] },
                columnStyles: { 2: { cellWidth: 95 } },
                margin: { left: this.margin, right: this.margin },
                didParseCell: (hookData: any) => {
                    if (hookData.section === 'body' && hookData.column.index === 1) {
                        const present: boolean = hookData.cell.raw === 'Sí';
                        hookData.cell.styles.textColor = present ? [39, 110, 58] : [192, 57, 43];
                        hookData.cell.styles.fontStyle = 'bold';
                    }
                }
            });
            this.cursorY = (this.doc as any).lastAutoTable.finalY + 8;
        }
        this.addSubheading('Rate limiting / throttling');
        this.addParagraph(result.rateLimit.finding, { fontSize: 8.5 });
        if (result.rateLimit.matchedHeaders.length > 0) {
            autoTable(this.doc, {
                startY: this.cursorY,
                head: [['Cabecera', 'Valor', 'Tipo']],
                body: result.rateLimit.matchedHeaders.map((m) => [m.name, this.truncate(m.value, 50), m.kind]),
                theme: 'grid',
                styles: { fontSize: 8, cellPadding: 2 },
                headStyles: { fillColor: [41, 65, 90], textColor: 255, fontStyle: 'bold' },
                margin: { left: this.margin, right: this.margin }
            });
            this.cursorY = (this.doc as any).lastAutoTable.finalY + 8;
        }
    }

    // ============================================================
    // 5. CERTIFICADO TLS
    // ============================================================
    private addSecuritySection(): void {
        const result: SecurityIdentifierResult = this.data.securityIdentifierResult;
        if (!result) return;
        this.addSectionHeader('5. Certificado TLS y transporte', result.overallRisk);
        this.addParagraph(result.summary);
        if (result.unreachable || !result.certificate) {
            this.addWarningBox('No se pudo obtener información del certificado TLS para este sitio.');
        } else {
            const cert: CertificateInfo = result.certificate;
            this.addKeyValueRow('Emisor', cert.issuer);
            this.addKeyValueRow('Sujeto (CN)', cert.subjectName);
            if ((cert as CertificateInfo).subjectAltNames?.length) {
                this.addKeyValueRow('SAN', this.truncate((cert as CertificateInfo).subjectAltNames.join(', '), 90));
            }
            this.addKeyValueRow('Protocolo', cert.protocol);
            this.addKeyValueRow('Válido desde', new Date(cert.validFrom).toLocaleDateString('es-ES'));
            this.addKeyValueRow('Válido hasta', new Date(cert.validTo).toLocaleDateString('es-ES'));
            this.addKeyValueRow('Días para vencer', String(cert.daysUntilExpiry));
            this.addKeyValueRow('Autofirmado', cert.isSelfSigned ? 'Sí' : 'No');
            this.addKeyValueRow('Coincide con el dominio', cert.hostnameMismatch ? 'No' : 'Sí');
        }
        this.addKeyValueRow('Código HTTP', result.httpStatus !== null ? String(result.httpStatus) : 'N/D');
        this.addKeyValueRow('Redirige HTTP→HTTPS', result.httpsRedirectOk === null ? 'No aplica' : result.httpsRedirectOk ? 'Sí' : 'No');
    }

    // ============================================================
    // 6. TECNOLOGÍAS DETECTADAS
    // ============================================================
    private addWebTechSection(): void {
        const technologies: WebIdentifierResponse[] = this.data.webIdentifierResponse;
        if (!technologies || technologies.length === 0) return;
        this.addSectionHeader('6. Tecnologías detectadas');
        autoTable(this.doc, {
            startY: this.cursorY,
            head: [['Tecnología', 'Versión', 'Confianza', 'Categorías']],
            body: technologies.map((t) => [t.name, t.version ?? 'N/D', `${t.confidence}%`, t.categories.map((c) => c.name).join(', ')]),
            theme: 'grid',
            styles: { fontSize: 8, cellPadding: 2, overflow: 'linebreak' },
            headStyles: { fillColor: [41, 65, 90], textColor: 255, fontStyle: 'bold' },
            alternateRowStyles: { fillColor: [245, 247, 250] },
            columnStyles: { 3: { cellWidth: 70 } },
            margin: { left: this.margin, right: this.margin }
        });
        this.cursorY = (this.doc as any).lastAutoTable.finalY + 8;
    }

    // ============================================================
    // 7. VULNERABILIDADES CONOCIDAS (AJUSTAR)
    // ============================================================
    private addVulnerabilitySection(): void {
        const result: VulnerabilityIdentifierResult = this.data.vulnerabilityIdentifierResult;
        if (!result) return;
        this.addSectionHeader('7. Vulnerabilidades conocidas por versión (CVE/GHSA)', result.overallRisk);
        this.addParagraph(result.summary);
        this.addSubheading('Vulnerabilidades encontradas');
        const findings: any[] = result.findings ?? [];
        if (findings.length === 0) {
            this.addEmptyState('No se encontraron vulnerabilidades conocidas para las tecnologías/versiones detectadas.');
        } else {
            this.addSeverityTable({
                head: ['Tecnología', 'ID', 'Versión detectada', 'Corregido en', 'Severidad'],
                rows: findings.map((f) => [
                    f.technology ?? 'N/D',
                    f.vulnerabilityId ?? f.id ?? 'N/D',
                    f.detectedVersion ?? 'N/D',
                    f.fixedVersion ?? '—',
                    SEVERITY_LABEL[f.severity as SecretSeverity],
                ]),
                severities: findings.map((f) => f.severity as SecretSeverity),
                severityColIndex: 4
            });
            findings.forEach((f) => {
                if (f.summary) this.addParagraph(`• ${f.vulnerabilityId ?? f.id}: ${this.truncate(f.summary, 160)}`, { fontSize: 8 });
            });
        }
        this.addSubheading('Tecnologías analizadas');
        const scanned: any[] = result.scannedTechnologies ?? [];
        if (scanned.length === 0) {
            this.addEmptyState('No hay tecnologías con versión suficientemente confiable para analizar.');
        } else {
            autoTable(this.doc, {
                startY: this.cursorY,
                head: [['Tecnología', 'Versión', 'Verificada', 'Motivo si se omitió']],
                body: scanned.map((t) => [t.technology ?? t.name ?? 'N/D', t.version ?? t.detectedVersion ?? 'N/D', t.checked ? 'Sí' : 'No', t.skipReason ?? '—']),
                theme: 'grid',
                styles: { fontSize: 8, cellPadding: 2 },
                headStyles: { fillColor: [41, 65, 90], textColor: 255, fontStyle: 'bold' },
                margin: { left: this.margin, right: this.margin }
            });
            this.cursorY = (this.doc as any).lastAutoTable.finalY + 8;
        }
    }

    // ============================================================
    // 8. COOKIES (AJUSTAR)
    // ============================================================
    private addCookieSection(): void {
        const result: CookieIdentifierResult = this.data.cookieIdentifierResult;
        if (!result) return;
        const overallRisk: SecretSeverity | undefined = (result.summary as any)?.overallRisk;
        this.addSectionHeader('8. Cookies', overallRisk);
        if ((result.summary as any)?.summary) this.addParagraph((result.summary as any).summary);
        const cookies: any[] = result.cookies ?? [];
        if (cookies.length === 0) {
            this.addEmptyState('No se detectaron cookies en la respuesta analizada.');
            return;
        }
        autoTable(this.doc, {
            startY: this.cursorY,
            head: [['Nombre', 'Secure', 'HttpOnly', 'SameSite', 'Severidad']],
            body: cookies.map((c) => [c.name ?? 'N/D', c.secure ? 'Sí' : 'No', c.httpOnly ? 'Sí' : 'No', c.sameSite ?? 'N/D', c.severity !== undefined ? SEVERITY_LABEL[c.severity as SecretSeverity] : 'N/D']),
            theme: 'grid',
            styles: { fontSize: 8, cellPadding: 2 },
            headStyles: { fillColor: [41, 65, 90], textColor: 255, fontStyle: 'bold' },
            margin: { left: this.margin, right: this.margin },
            didParseCell: (hookData: any) => {
                if (hookData.section === 'body' && hookData.column.index === 4) {
                    const cookie: any = cookies[hookData.row.index];
                    if (cookie?.severity !== undefined) {
                        const [r, g, b]: [number, number, number] = SEVERITY_COLOR[cookie.severity as SecretSeverity];
                        hookData.cell.styles.fillColor = [r, g, b];
                        hookData.cell.styles.textColor = [255, 255, 255];
                        hookData.cell.styles.fontStyle = 'bold';
                    }
                }
            }
        });
        this.cursorY = (this.doc as any).lastAutoTable.finalY + 8;
    }

    // ============================================================
    // PIE DE PÁGINA
    // ============================================================
    private addFootersToAllPages(): void {
        const totalPages: number = this.doc.getNumberOfPages();
        for (let i = 2; i <= totalPages; i++) { // página 1 = portada, sin footer
            this.doc.setPage(i);
            this.doc.setFontSize(7.5);
            this.doc.setTextColor(140, 140, 140);
            this.doc.text('Secutor — Reporte de Seguridad Web', this.margin, this.pageHeight - 8);
            this.doc.text(`Página ${i - 1} de ${totalPages - 1}`, this.pageWidth - this.margin, this.pageHeight - 8, { align: 'right' });
        }
    }
}
