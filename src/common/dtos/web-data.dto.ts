import { Transform, Type } from "class-transformer";
import { IsNotEmpty, IsString, IsUrl, MinLength } from "class-validator";

export class WebDataDto {
    @Type(() => String)
    @IsString({ message: 'La URL debe ser un texto válido' })
    @IsNotEmpty({ message: 'Debe indicar la URL de la web' })
    @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
    @MinLength(12, { message: 'La URL es demasiado corta (mínimo 12 caracteres)' })
    @IsUrl(
        {
            protocols: ['http', 'https'],
            require_protocol: true,
            require_tld: true,
            allow_query_components: false,
            allow_fragments: false
        },
        { message: 'Debe ingresar una URL válida con protocolo http o https' }
    )
    web_url: string = '';
}
