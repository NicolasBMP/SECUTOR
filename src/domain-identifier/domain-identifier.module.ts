import { Module } from '@nestjs/common';
import { DomainIdentifierService } from './domain-identifier.service';
import { DomainIdentifierController } from './domain-identifier.controller';
 
@Module({
  controllers: [DomainIdentifierController],
  providers: [DomainIdentifierService],
  exports: [DomainIdentifierService]
})
export class DomainIdentifierModule {}
 