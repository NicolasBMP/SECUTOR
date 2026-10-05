import { InsecureFormFinding, MixedContentFinding, ScannedContentInfo, TabnabbingFinding } from "src/content-identifier/dto/content-identifier.interface";
import { CookieAnalysisResponse, CookieSummary } from "src/cookie-identifier/dto/cookie-identifier.interface";
import { ExposedPathFinding, ExposedSourceMapFinding, ScannedSourcesInfo, ScriptIntegrityFinding, ScriptsIntegritySummary, SecretFinding } from "src/data-identifier/dto/data-identifier.interface";
import { DkimResult, DmarcResult, SpfResult } from "src/domain-identifier/dto/domain-identifier.interface";
import { HeaderSummaryIdentifierResponse, RateLimitDetectionResult } from "src/header-identifier/dto/header-identifier.interface";
import { CertificateInfo } from "src/security-identifier/dto/security-identifier.dto";
import { ScannedTechnologyResult, VulnerabilityFinding } from "src/vulnerability-identifier/dto/vulnerability-identifier.interface";
import { WebIdentifierResponseCategories, WebIdentifierTypeResponse } from "src/web-identifier/dto/web-identifier-response.interface";

export enum SecretSeverity {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4,
}

export interface ContentIdentifierResult {
    insecureForms: InsecureFormFinding[];
    mixedContent: MixedContentFinding[];
    tabnabbing: TabnabbingFinding[];
    scannedContent: ScannedContentInfo;
    overallRisk: SecretSeverity;
    summary: string;
}

export interface CookieIdentifierResult {
    cookies: CookieAnalysisResponse[];
    summary: CookieSummary;
}

export interface DataIdentifierResult {
    secrets: SecretFinding[];
    exposedPaths: ExposedPathFinding[];
    exposedSourceMaps: ExposedSourceMapFinding[];
    scriptsIntegrity: ScriptsIntegritySummary;
    scriptsIntegrityFindings: ScriptIntegrityFinding[];
    scannedSources: ScannedSourcesInfo;
    overallRisk: SecretSeverity;
    summary: string;
}

export interface EmailIdentifierResult {
    domain: string;
    spf: SpfResult;
    dkim: DkimResult;
    dmarc: DmarcResult;
    overallRisk: SecretSeverity;
    summary: string;
}

export interface HeaderIdentifierResponse {
    headers: HeaderSummaryIdentifierResponse[];
    score: number;
    grade: string;
    rateLimit: RateLimitDetectionResult;
}

export interface SecurityIdentifierResult {
    url: string;
    finalUrl: string;
    httpStatus: number | null;
    unreachable: boolean;
    certificate: CertificateInfo | null;
    httpsRedirectOk: boolean | null;
    overallRisk: SecretSeverity;
    summary: string;
}

export interface WebIdentifierResponse {
    name: string;
    type: WebIdentifierTypeResponse;
    confidence: number;
    version: string | null;
    website: string | null;
    categories: WebIdentifierResponseCategories[]
}

export interface VulnerabilityIdentifierResult {
    findings: VulnerabilityFinding[];
    scannedTechnologies: ScannedTechnologyResult[];
    overallRisk: SecretSeverity;
    summary: string;
}

export interface SecutorReportRequest {
    webIdentifierResponse: WebIdentifierResponse[];
    headerIdentifierResponse: HeaderIdentifierResponse;
    cookieIdentifierResult: CookieIdentifierResult;
    dataIdentifierResult: DataIdentifierResult;
    contentIdentifierResult: ContentIdentifierResult;
    securityIdentifierResult: SecurityIdentifierResult;
    emailIdentifierResult: EmailIdentifierResult;
    vulnerabilityIdentifierResult: VulnerabilityIdentifierResult;
}
