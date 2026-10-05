import { Body, Controller } from '@nestjs/common';
import { CookieIdentifierService } from './cookie-identifier.service';
import { QueryMethod } from 'src/common/decorators/query-method.decorator';
import { WebDataDto } from '../common/dtos/web-data.dto';
import { ParseUrlPipe } from 'src/common/pipes/url.pipe';
import { CookieIdentifierResult } from './dto/cookie-identifier.interface';

@Controller('v1/cookie-identifier')
export class CookieIdentifierController {
  constructor(private readonly cookieIdentifierService: CookieIdentifierService) { }

  @QueryMethod('/report')
  getCookieIdentifier(@Body(ParseUrlPipe) webDataDto: WebDataDto): Promise<CookieIdentifierResult> {
    return this.cookieIdentifierService.getCookieIdentifier(webDataDto);
  }
}
