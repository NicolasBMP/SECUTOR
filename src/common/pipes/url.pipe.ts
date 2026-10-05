import { ArgumentMetadata, BadRequestException, Injectable, PipeTransform } from "@nestjs/common";
import { WebDataDto } from "../dtos/web-data.dto";
import { parseAndValidateUrl } from "../helpers/url-validation.helper";

@Injectable()
export class ParseUrlPipe implements PipeTransform {
    private static readonly max_path_length: number = 2048;
    transform(value: WebDataDto, metadata: ArgumentMetadata) {
        const parsedUrl: URL = parseAndValidateUrl(value?.web_url);
        if (parsedUrl.pathname.length > ParseUrlPipe.max_path_length) {
            throw new BadRequestException('La ruta de la URL es demasiado larga.');
        }
        return {
            ...value,
            web_url: parsedUrl.origin + parsedUrl.pathname
        };
    }
}
