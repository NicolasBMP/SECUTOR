import { Body, Controller } from '@nestjs/common';
import { SecurityIdentifierService } from './security-identifier.service';
import { QueryMethod } from 'src/common/decorators/query-method.decorator';
import { WebDataDto } from '../common/dtos/web-data.dto';
import { ParseUrlPipe } from 'src/common/pipes/url.pipe';
import { SecurityIdentifierResult } from './dto/security-identifier.dto';

@Controller('v1/security-identifier')
export class SecurityIdentifierController {
  constructor(private readonly securityIdentifierService: SecurityIdentifierService) { }

  @QueryMethod('/report')
  getSecurityIdentifier(@Body(ParseUrlPipe) webDataDto: WebDataDto): Promise<SecurityIdentifierResult> {
    return this.securityIdentifierService.getSecurityIdentifier(webDataDto);
  }
}
