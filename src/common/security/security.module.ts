import { Global, Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { SecurityEventLogService } from './security-event-log.service';
import { SecurityEventBoundaryMiddleware } from './security-event.middleware';

/**
 * Cross-cutting security substrate. `@Global` so the single `SecurityEventLogService` is injectable
 * from every surface that emits a security event (the REST guard, the WS gateway, the MCP mount)
 * without each module importing it, and so the boundary middleware below can resolve it from DI.
 *
 * The boundary middleware is registered here (not in a feature module) because it observes EVERY
 * inbound HTTP request's final status — including the ones the global guards reject before any
 * controller runs — exactly like the request-metrics boundary it mirrors.
 */
@Global()
@Module({
  imports: [ConfigModule],
  providers: [SecurityEventLogService, SecurityEventBoundaryMiddleware],
  exports: [SecurityEventLogService],
})
export class SecurityModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    // '*' resolves against the global prefix, i.e. every /api route — same contract as the
    // request-metrics boundary middleware.
    consumer.apply(SecurityEventBoundaryMiddleware).forRoutes('*');
  }
}
