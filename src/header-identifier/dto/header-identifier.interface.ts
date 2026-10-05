export interface HeaderIdentifierResponse {
  headers: HeaderSummaryIdentifierResponse[];
  score: number;
  grade: string;
  rateLimit: RateLimitDetectionResult;
}

export interface HeaderSummaryIdentifierResponse {
  name: string;
  value: string;
  weigth: number;
  exist: boolean;
  finding: string;
  type: HeaderIdentifierTypeResponse;
}

export interface HeaderEvaluationResult {
  finding: string;
  weightValue: number;
  exist?: boolean;
}

export enum HeaderIdentifierTypeResponse {
  MANDATORY = 1,
  RECOMMENDED = 2,
  HARMFUL = 3,
  DEPRECATED = 4
}

export interface RateLimitHeaderMatch {
  name: string;
  value: string;
  kind: RateLimitHeaderKind;
}

export interface RateLimitDetectionResult {
  present: boolean;
  matchedHeaders: RateLimitHeaderMatch[];
  finding: string;
}

export type HeaderEvaluator = (value: string, rawHeaders: Record<string, string>, currentWeight: number) => HeaderEvaluationResult;
export type RateLimitHeaderKind = 'standard' | 'legacy' | 'retry-after' | 'vendor';

const BASE_HEADERS_CATALOG: Omit<HeaderSummaryIdentifierResponse, 'value' | 'exist' | 'finding'>[] = [
  // 1. MANDATORY
  { name: 'Content-Security-Policy', weigth: 20, type: HeaderIdentifierTypeResponse.MANDATORY },
  { name: 'Strict-Transport-Security', weigth: 15, type: HeaderIdentifierTypeResponse.MANDATORY },
  { name: 'X-Content-Type-Options', weigth: 10, type: HeaderIdentifierTypeResponse.MANDATORY },
  { name: 'X-Frame-Options', weigth: 10, type: HeaderIdentifierTypeResponse.MANDATORY },
  { name: 'Referrer-Policy', weigth: 5, type: HeaderIdentifierTypeResponse.MANDATORY },
  // 2. RECOMMENDED
  { name: 'Permissions-Policy', weigth: 10, type: HeaderIdentifierTypeResponse.RECOMMENDED },
  { name: 'Cross-Origin-Opener-Policy', weigth: 10, type: HeaderIdentifierTypeResponse.RECOMMENDED },
  { name: 'Cross-Origin-Resource-Policy', weigth: 5, type: HeaderIdentifierTypeResponse.RECOMMENDED },
  { name: 'Cross-Origin-Embedder-Policy', weigth: 5, type: HeaderIdentifierTypeResponse.RECOMMENDED },
  { name: 'X-Permitted-Cross-Domain-Policies', weigth: 5, type: HeaderIdentifierTypeResponse.RECOMMENDED },
  { name: 'Cache-Control', weigth: 5, type: HeaderIdentifierTypeResponse.RECOMMENDED },
  // 3. HARMFUL - Minus 5 pts (-5)
  { name: 'Access-Control-Allow-Origin', weigth: -5, type: HeaderIdentifierTypeResponse.HARMFUL },
  { name: 'X-Powered-By', weigth: -5, type: HeaderIdentifierTypeResponse.HARMFUL },
  { name: 'X-AspNet-Version', weigth: -5, type: HeaderIdentifierTypeResponse.HARMFUL },
  { name: 'X-AspNetMvc-Version', weigth: -5, type: HeaderIdentifierTypeResponse.HARMFUL },
  { name: 'X-Debug-Token', weigth: -5, type: HeaderIdentifierTypeResponse.HARMFUL },
  { name: 'X-Backend-Server', weigth: -5, type: HeaderIdentifierTypeResponse.HARMFUL },
  { name: 'X-Generator', weigth: -5, type: HeaderIdentifierTypeResponse.HARMFUL },
  { name: 'Server', weigth: -5, type: HeaderIdentifierTypeResponse.HARMFUL },
  { name: 'Via', weigth: -5, type: HeaderIdentifierTypeResponse.HARMFUL },
  // 4. DEPRECATED - Minus 1 pt (-1)
  { name: 'X-XSS-Protection', weigth: -1, type: HeaderIdentifierTypeResponse.DEPRECATED },
  { name: 'Expect-CT', weigth: -1, type: HeaderIdentifierTypeResponse.DEPRECATED },
  { name: 'Public-Key-Pins', weigth: -1, type: HeaderIdentifierTypeResponse.DEPRECATED },
  { name: 'X-Content-Security-Policy', weigth: -1, type: HeaderIdentifierTypeResponse.DEPRECATED },
  { name: 'X-WebKit-CSP', weigth: -1, type: HeaderIdentifierTypeResponse.DEPRECATED }
];

export function getInitialHeadersResponse(): HeaderSummaryIdentifierResponse[] {
  return BASE_HEADERS_CATALOG.map((header) => ({
    ...header,
    value: '',
    finding: '',
    exist: false
  }));
}
