import { Body, Controller } from '@nestjs/common';
import { DomainIdentifierService } from './domain-identifier.service';
import { QueryMethod } from 'src/common/decorators/query-method.decorator';
import { WebDataDto } from '../common/dtos/web-data.dto';
import { ParseDomainPipe } from 'src/common/pipes/domain.pipe';
import { EmailIdentifierResult } from './dto/domain-identifier.interface';
 
@Controller('v1/domain-identifier')
export class DomainIdentifierController {
  constructor(private readonly domainIdentifierService: DomainIdentifierService) { }
 
  @QueryMethod('/report')
  getDomainIdentifier(@Body(ParseDomainPipe) webDataDto: WebDataDto): Promise<EmailIdentifierResult> {
    return this.domainIdentifierService.getDomainIdentifier(webDataDto);
  }
}
 