import { ArgumentMetadata, Injectable, PipeTransform, BadRequestException } from "@nestjs/common";
import { WebDataDto } from "../dtos/web-data.dto";
import { parseAndValidateUrl } from "../helpers/url-validation.helper";
 
@Injectable()
export class ParseDomainPipe implements PipeTransform {
    transform(value: WebDataDto, metadata: ArgumentMetadata) {
        const parsedUrl: URL = parseAndValidateUrl(value?.web_url);
        if (parsedUrl.pathname !== '/' && parsedUrl.pathname !== '') {
            throw new BadRequestException('Este endpoint analiza el dominio completo, envie solo la URL base sin rutas.');
        }
        return {
            ...value,
            web_url: parsedUrl.origin
        };
    }
}
 