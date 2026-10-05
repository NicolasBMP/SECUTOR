import { Body, Controller } from '@nestjs/common';
import { HeaderIdentifierService } from './header-identifier.service';
import { QueryMethod } from 'src/common/decorators/query-method.decorator';
import { WebDataDto } from '../common/dtos/web-data.dto';
import { ParseUrlPipe } from 'src/common/pipes/url.pipe';
import { HeaderIdentifierResponse } from './dto/header-identifier.interface';

@Controller('v1/header-identifier')
export class HeaderIdentifierController {
  constructor(private readonly headerIdentifierService: HeaderIdentifierService) { }

  @QueryMethod('/report')
  getHeaderIdentifier(@Body(ParseUrlPipe) webDataDto: WebDataDto): Promise<HeaderIdentifierResponse> {
    return this.headerIdentifierService.getHeaderIdentifier(webDataDto);
  }
}
