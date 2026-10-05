export interface WebIdentifierResponse {
    name: string;
    type: WebIdentifierTypeResponse;
    confidence: number;
    version: string | null;
    website: string | null;
    categories: WebIdentifierResponseCategories[]
}

export interface WebIdentifierResponseCategories {
    id: number;
    name: string;
}

export enum WebIdentifierTypeResponse {
    DEVELOPMENT_DATABASE = 1,
    FRAMEWORKS_LIBRARIES = 2,
    SERVER_SECURITY = 3
}