import { Module } from '@nestjs/common';
import { DataIdentifierService } from './data-identifier.service';
import { DataIdentifierController } from './data-identifier.controller';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  controllers: [DataIdentifierController],
  providers: [DataIdentifierService],
  exports: [DataIdentifierService]
})
export class DataIdentifierModule {}
