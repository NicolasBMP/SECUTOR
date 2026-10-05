import { Module } from '@nestjs/common';
import { SecurityIdentifierService } from './security-identifier.service';
import { SecurityIdentifierController } from './security-identifier.controller';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  controllers: [SecurityIdentifierController],
  providers: [SecurityIdentifierService],
  exports: [SecurityIdentifierService]
})
export class SecurityIdentifierModule {}
