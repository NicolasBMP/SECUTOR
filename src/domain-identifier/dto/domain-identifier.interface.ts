export enum SecretSeverity {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4,
}

export interface EmailSecurityFinding {
    type: 'SPF' | 'DKIM' | 'DMARC';
    severity: SecretSeverity;
    description: string;
}

export interface SpfResult {
    found: boolean;
    record: string | null;
    checkError: string | null;
    multipleRecords: boolean;
    allMechanism: '-all' | '~all' | '?all' | '+all' | null;
    lookupCount: number;
    findings: EmailSecurityFinding[];
}

export interface DkimSelectorResult {
    selector: string;
    found: true;
    record: string;
    hasPublicKey: boolean;
    keyRevoked: boolean;
}

export interface DkimResult {
    selectorsChecked: string[];
    selectorsFound: DkimSelectorResult[];
    selectorsWithErrors: { selector: string; error: string }[];
    findings: EmailSecurityFinding[];
}

export interface DmarcResult {
    found: boolean;
    record: string | null;
    checkError: string | null;
    policy: 'none' | 'quarantine' | 'reject' | null;
    subdomainPolicy: string | null;
    percentage: number | null;
    alignment: { dkim: 'strict' | 'relaxed'; spf: 'strict' | 'relaxed' };
    reportingAddresses: string[];
    findings: EmailSecurityFinding[];
}

export interface EmailIdentifierResult {
    domain: string;
    spf: SpfResult;
    dkim: DkimResult;
    dmarc: DmarcResult;
    overallRisk: SecretSeverity;
    summary: string;
}
