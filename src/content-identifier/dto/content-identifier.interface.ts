export enum SecretSeverity {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4,
}

export type InsecureFormIssue = 'http-transport' | 'get-method';

export interface InsecureFormFinding {
    formAction: string;
    method: string;
    hasPasswordField: boolean;
    issues: InsecureFormIssue[];
    severity: SecretSeverity;
    description: string;
}

export type MixedContentKind = 'active' | 'passive';

export interface MixedContentFinding {
    tag: string;
    url: string;
    kind: MixedContentKind;
    severity: SecretSeverity;
    description: string;
}

export interface TabnabbingFinding {
    href: string;
    linkText: string | null;
    severity: SecretSeverity;
    description: string;
}

export interface ScannedContentInfo {
    pageIsHttps: boolean;
    formsScanned: number;
    linksWithBlankTargetScanned: number;
    resourceTagsScanned: number;
}

export interface ContentIdentifierResult {
    insecureForms: InsecureFormFinding[];
    mixedContent: MixedContentFinding[];
    tabnabbing: TabnabbingFinding[];
    scannedContent: ScannedContentInfo;
    overallRisk: SecretSeverity;
    summary: string;
}
