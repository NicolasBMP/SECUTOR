export enum SecretSeverity {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4,
}

export interface CertificateInfo {
    issuer: string;
    subjectName: string;
    protocol: string;
    validFrom: string;
    validTo: string;
    subjectAltNames: string[];
    daysUntilExpiry: number;
    isExpired: boolean;
    isSelfSigned: boolean;
    hostnameMismatch: boolean;
    isWeakProtocol: boolean;
}

export interface RawCertificate {
    issuer: string;
    subject: string;
    protocol: string | null;
    validFrom: Date;
    validTo: Date;
    subjectAltNames: string[];
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
