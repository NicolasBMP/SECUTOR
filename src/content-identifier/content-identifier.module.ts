import { Module } from '@nestjs/common';
import { ContentIdentifierService } from './content-identifier.service';
import { ContentIdentifierController } from './content-identifier.controller';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  controllers: [ContentIdentifierController],
  providers: [ContentIdentifierService],
  exports: [ContentIdentifierService]
})
export class ContentIdentifierModule {}
