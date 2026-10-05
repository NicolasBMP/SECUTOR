import { BadRequestException } from "@nestjs/common";
 
const private_host_patterns: RegExp[] = [
    /^localhost$/, /^127\./, /^0\.0\.0\.0$/, /^10\./,
    /^172\.(1[6-9]|2\d|3[0-1])\./, /^192\.168\./,
    /^169\.254\./, /^::1$/, /^\[::1\]$/,
];

export function parseAndValidateUrl(rawValue: unknown): URL {
    if (!rawValue || typeof rawValue !== 'string') {
        throw new BadRequestException('El valor enviado debe ser un texto.');
    }
    let parsedUrl: URL;
    try {
        parsedUrl = new URL(rawValue);
    } catch {
        throw new BadRequestException('El valor proporcionado no es una URL válida.');
    }
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        throw new BadRequestException('La URL debe comenzar con http:// o https://');
    }
    const host: string = parsedUrl.hostname.toLowerCase();
    if (private_host_patterns.some((p) => p.test(host))) {
        throw new BadRequestException('No se permite analizar hosts internos o privados.');
    }
    if (parsedUrl.search || parsedUrl.hash) {
        throw new BadRequestException('La URL no debe incluir parámetros de búsqueda ni fragmentos.');
    }
    return parsedUrl;
}
