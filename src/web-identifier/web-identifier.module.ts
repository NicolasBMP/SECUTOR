import { Module } from '@nestjs/common';
import { WebIdentifierService } from './web-identifier.service';
import { WebIdentifierController } from './web-identifier.controller';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  controllers: [WebIdentifierController],
  providers: [WebIdentifierService],
  exports: [WebIdentifierService]
})
export class WebIdentifierModule {}
