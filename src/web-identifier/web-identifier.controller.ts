import { Body, Controller } from '@nestjs/common';
import { WebIdentifierService } from './web-identifier.service';
import { QueryMethod } from 'src/common/decorators/query-method.decorator';
import { WebDataDto } from '../common/dtos/web-data.dto';
import { ParseUrlPipe } from 'src/common/pipes/url.pipe';
import { WebIdentifierResponse } from './dto/web-identifier-response.interface';

@Controller('v1/web-identifier')
export class WebIdentifierController {
  constructor(private readonly webIdentifierService: WebIdentifierService) { }

  @QueryMethod('/report')
  GetWebIdentifier(@Body(ParseUrlPipe) webDataDto: WebDataDto): Promise<WebIdentifierResponse[]> {
    return this.webIdentifierService.getWebIdentifier(webDataDto);
  }
}
