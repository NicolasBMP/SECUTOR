import { RequestMapping, RequestMethod } from '@nestjs/common';

export const QueryMethod = (path: string = '') =>
  RequestMapping({
    path,
    method: 'QUERY' as unknown as RequestMethod,
  });
  