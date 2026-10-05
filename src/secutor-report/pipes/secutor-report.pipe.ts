import { ArgumentMetadata, Injectable, PipeTransform } from '@nestjs/common';
import { SecutorReportRequest } from '../dto/secutor-report.interface';
import { validateSecutorReportRequest } from '../helpers/secutor-report.validator';

@Injectable()
export class SecutorReportValidationPipe implements PipeTransform<unknown, SecutorReportRequest> {
    transform(value: unknown, _metadata: ArgumentMetadata): SecutorReportRequest {
        validateSecutorReportRequest(value);
        return value;
    }
}
