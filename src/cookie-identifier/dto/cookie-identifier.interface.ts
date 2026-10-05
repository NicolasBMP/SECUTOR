export type CookieSameSite = 'Strict' | 'Lax' | 'None' | 'Unspecified';
export type CookieDomainScope = 'host' | 'broad';
export type CookieValueExposure = 'empty' | 'jwt' | 'json' | 'opaque' | 'plaintext_like';

export interface CookieIdentifierResult {
    cookies: CookieAnalysisResponse[];
    summary: CookieSummary;
}

export interface CookieAnalysisResponse {
    name: string;
    domain: string;
    path: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite: CookieSameSite;
    session: boolean;
    expiresInDays: number | null;
    hasSecurePrefix: boolean;
    domainScope: CookieDomainScope;
    thirdParty: boolean;
    partitioned: boolean;
    knownAdTech: boolean;
    duplicateName: boolean;
    looksSensitiveByName: boolean;
    valueExposure: CookieValueExposure;
    reflectedInHtml: boolean;
    riskLevel: CookieRiskLevel;
    findings: string[];
}

export interface CookieSummary {
    total: number;
    secureCount: number;
    httpOnlyCount: number;
    thirdPartyCount: number;
    partitionedCount: number;
    adTechCount: number;
    sessionCount: number;
    persistentCount: number;
    highOrCriticalCount: number;
    overallRisk: CookieRiskLevel;
}

export enum CookieRiskLevel {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4,
}
