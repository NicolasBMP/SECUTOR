import { Body, Controller } from '@nestjs/common';
import { ContentIdentifierService } from './content-identifier.service';
import { QueryMethod } from 'src/common/decorators/query-method.decorator';
import { WebDataDto } from '../common/dtos/web-data.dto';
import { ParseUrlPipe } from 'src/common/pipes/url.pipe';
import { ContentIdentifierResult } from './dto/content-identifier.interface';

@Controller('v1/content-identifier')
export class ContentIdentifierController {
  constructor(private readonly contentIdentifierService: ContentIdentifierService) { }

  @QueryMethod('/report')
  getContentIdentifier(@Body(ParseUrlPipe) webDataDto: WebDataDto): Promise<ContentIdentifierResult> {
    return this.contentIdentifierService.getContentIdentifier(webDataDto);
  }
}
