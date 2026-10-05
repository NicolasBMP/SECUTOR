import { BadRequestException } from '@nestjs/common';
import { SecretSeverity, SecutorReportRequest } from '../dto/secutor-report.interface';

const REQUIRED_TOP_LEVEL_KEYS: (keyof SecutorReportRequest)[] = [
    'contentIdentifierResult',
    'cookieIdentifierResult',
    'dataIdentifierResult',
    'emailIdentifierResult',
    'headerIdentifierResponse',
    'securityIdentifierResult',
    'webIdentifierResponse',
    'vulnerabilityIdentifierResult',
];
const VALID_SEVERITIES: number[] = [SecretSeverity.LOW, SecretSeverity.MEDIUM, SecretSeverity.HIGH, SecretSeverity.CRITICAL];

function fail(message: string): never {
    throw new BadRequestException(message);
}

function requireArray(value: unknown, path: string): void {
    if (!Array.isArray(value)) fail(`${path} debe ser un arreglo.`);
}

function requireObject(value: unknown, path: string): asserts value is Record<string, unknown> {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${path} debe estar presente y ser un objeto.`);
}

function checkSeverity(value: unknown, path: string): void {
    if (value === undefined || value === null) return;
    if (typeof value !== 'number' || !VALID_SEVERITIES.includes(value)) {
        fail(`${path} tiene un valor inválido (${String(value)}). Debe ser 1 (LOW), 2 (MEDIUM), 3 (HIGH) o 4 (CRITICAL).`);
    }
}

export function validateSecutorReportRequest(body: unknown): asserts body is SecutorReportRequest {
    requireObject(body, 'El cuerpo de la solicitud');
    const payload: Record<string, unknown> = body;
    const missing: string[] = REQUIRED_TOP_LEVEL_KEYS.filter((key) => payload[key] === undefined || payload[key] === null);
    if (missing.length > 0) fail(`Faltan los siguientes módulos en el reporte: ${missing.join(', ')}.`);
    // --- content ---
    const content: Record<string, unknown> = payload.contentIdentifierResult as Record<string, unknown>;
    requireArray(content.insecureForms, 'contentIdentifierResult.insecureForms');
    requireArray(content.mixedContent, 'contentIdentifierResult.mixedContent');
    requireArray(content.tabnabbing, 'contentIdentifierResult.tabnabbing');
    requireObject(content.scannedContent, 'contentIdentifierResult.scannedContent');
    checkSeverity(content.overallRisk, 'contentIdentifierResult.overallRisk');
    // --- data ---
    const data: Record<string, unknown> = payload.dataIdentifierResult as Record<string, unknown>;
    requireArray(data.secrets, 'dataIdentifierResult.secrets');
    requireArray(data.exposedPaths, 'dataIdentifierResult.exposedPaths');
    requireArray(data.exposedSourceMaps, 'dataIdentifierResult.exposedSourceMaps');
    checkSeverity(data.overallRisk, 'dataIdentifierResult.overallRisk');
    // --- email ---
    const email: Record<string, unknown> = payload.emailIdentifierResult as Record<string, unknown>;
    requireObject(email.spf, 'emailIdentifierResult.spf');
    requireObject(email.dkim, 'emailIdentifierResult.dkim');
    requireObject(email.dmarc, 'emailIdentifierResult.dmarc');
    requireArray((email.spf as any).findings, 'emailIdentifierResult.spf.findings');
    requireArray((email.dkim as any).findings, 'emailIdentifierResult.dkim.findings');
    requireArray((email.dkim as any).selectorsChecked, 'emailIdentifierResult.dkim.selectorsChecked');
    requireArray((email.dkim as any).selectorsFound, 'emailIdentifierResult.dkim.selectorsFound');
    requireArray((email.dmarc as any).findings, 'emailIdentifierResult.dmarc.findings');
    checkSeverity(email.overallRisk, 'emailIdentifierResult.overallRisk');
    // --- headers ---
    const header: Record<string, unknown> = payload.headerIdentifierResponse as Record<string, unknown>;
    requireArray(header.headers, 'headerIdentifierResponse.headers');
    requireObject(header.rateLimit, 'headerIdentifierResponse.rateLimit');
    requireArray((header.rateLimit as any).matchedHeaders, 'headerIdentifierResponse.rateLimit.matchedHeaders');
    if (typeof header.score !== 'number' || Number.isNaN(header.score)) {
        fail('headerIdentifierResponse.score debe ser un número.');
    }
    if ((header.score as number) < 0 || (header.score as number) > 100) {
        fail('headerIdentifierResponse.score debe estar entre 0 y 100.');
    }
    if (typeof header.grade !== 'string' || header.grade.length === 0) {
        fail('headerIdentifierResponse.grade debe ser un texto no vacío.');
    }
    // --- security / TLS ---
    const security: Record<string, unknown> = payload.securityIdentifierResult as Record<string, unknown>;
    if (typeof security.url !== 'string' || security.url.length === 0) {
        fail('securityIdentifierResult.url debe ser un texto no vacío.');
    }
    checkSeverity(security.overallRisk, 'securityIdentifierResult.overallRisk');
    // --- tecnologías ---
    requireArray(payload.webIdentifierResponse, 'webIdentifierResponse');
    (payload.webIdentifierResponse as unknown[]).forEach((tech, index) => {
        requireObject(tech, `webIdentifierResponse[${index}]`);
        if (typeof (tech as any).name !== 'string' || (tech as any).name.length === 0) {
            fail(`webIdentifierResponse[${index}].name debe ser un texto no vacío.`);
        }
        requireArray((tech as any).categories, `webIdentifierResponse[${index}].categories`);
    });
    // --- vulnerabilidades ---
    const vuln: Record<string, unknown> = payload.vulnerabilityIdentifierResult as Record<string, unknown>;
    requireArray(vuln.findings, 'vulnerabilityIdentifierResult.findings');
    requireArray(vuln.scannedTechnologies, 'vulnerabilityIdentifierResult.scannedTechnologies');
    checkSeverity(vuln.overallRisk, 'vulnerabilityIdentifierResult.overallRisk');
    // --- cookies ---
    const cookies: Record<string, unknown> = payload.cookieIdentifierResult as Record<string, unknown>;
    requireArray(cookies.cookies, 'cookieIdentifierResult.cookies');
}
