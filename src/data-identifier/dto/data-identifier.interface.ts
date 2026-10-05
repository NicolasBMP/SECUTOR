export enum SecretSeverity {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4,
}
 
export interface SecretFinding {
    type: string;
    severity: SecretSeverity;
    source: string;
    matchPreview: string;
    occurrences: number;
    message: string;
}
 
export interface ExposedPathFinding {
    path: string;
    url: string;
    severity: SecretSeverity;
    description: string;
}

export interface ExposedSourceMapFinding {
    scriptUrl: string;
    mapUrl: string;
    severity: SecretSeverity;
}
 
export interface ScannedSourcesInfo {
    scriptsFound: number;
    scriptsScanned: number;
    scriptsSkipped: number;
    skippedByByteCap: number;
    skippedByTimeout: number;
}

export interface ScriptIntegrityFinding {
    tag: 'script' | 'link';
    url: string;
    crossOrigin: boolean;
    hasIntegrity: boolean;
    hasCrossoriginAttribute: boolean;
    integrityIssue: 'missing' | 'missing_crossorigin' | 'malformed';
    severity: SecretSeverity;
    description: string;
}

export interface ScriptsIntegritySummary {
    totalResources: number;
    crossOriginResources: number;
    withIntegrity: number;
    crossOriginWithoutIntegrity: number;
    integrityCoverageRatio: number;
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
