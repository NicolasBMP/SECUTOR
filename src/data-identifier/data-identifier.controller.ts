import { Body, Controller } from '@nestjs/common';
import { DataIdentifierService } from './data-identifier.service';
import { QueryMethod } from 'src/common/decorators/query-method.decorator';
import { WebDataDto } from '../common/dtos/web-data.dto';
import { ParseUrlPipe } from 'src/common/pipes/url.pipe';
import { DataIdentifierResult } from './dto/data-identifier.interface';

@Controller('v1/data-identifier')
export class DataIdentifierController {
  constructor(private readonly dataIdentifierService: DataIdentifierService) { }

  @QueryMethod('/report')
  getDataIdentifier(@Body(ParseUrlPipe) webDataDto: WebDataDto): Promise<DataIdentifierResult> {
    return this.dataIdentifierService.getDataIdentifier(webDataDto);
  }
}
