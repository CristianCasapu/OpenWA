import type { MiddlewareConsumer } from '@nestjs/common';
import type { HttpAdapterHost } from '@nestjs/core';
import { McpModule } from './mcp.module';
import { mountMcpServer } from './mcp.server';
import { KeyRateLimiter } from './mcp-rate-limit';
import type { ToolRegistryService } from '../../core/agent-tools/tool-registry.service';
import type { AuthService } from '../auth/auth.service';
import type { AuditService } from '../audit/audit.service';
import type { SecurityEventLogService } from '../../common/security/security-event-log.service';

// configure() hands everything to mountMcpServer; mocking it keeps this spec about the module's
// wiring (adapter guard, forRoot() option plumbing) rather than the Express mount itself, which
// mcp.server.spec.ts already exercises.
jest.mock('./mcp.server', () => ({
  mountMcpServer: jest.fn(),
}));

const registry = {} as ToolRegistryService;
const authService = {} as AuthService;
const auditService = {} as AuditService;
const securityLog = {} as SecurityEventLogService;
const consumer = {} as MiddlewareConsumer;

function makeModule(httpAdapter: unknown): McpModule {
  return new McpModule(registry, authService, { httpAdapter } as HttpAdapterHost, auditService, securityLog);
}

describe('McpModule', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Reset the module-level options store so one test's forRoot() cannot leak into the next.
    McpModule.forRoot({});
  });

  it('forRoot returns a non-global dynamic module for McpModule', () => {
    const dynamic = McpModule.forRoot({ basePath: '/custom' });
    expect(dynamic.module).toBe(McpModule);
    expect(dynamic.global).toBe(false);
  });

  it('configure throws a named error when the HTTP adapter is not available', () => {
    expect(() => makeModule(undefined).configure(consumer)).toThrow(
      'McpModule: HttpAdapterHost.httpAdapter is not available.',
    );
    expect(mountMcpServer).not.toHaveBeenCalled();
  });

  it('configure mounts the MCP server on the adapter with the forRoot() options', () => {
    const httpAdapter = { getInstance: jest.fn() };
    const serverInfo = { name: 'test-server', version: '9.9.9' };
    McpModule.forRoot({ basePath: '/mcp-test', serverInfo });

    makeModule(httpAdapter).configure(consumer);

    expect(mountMcpServer).toHaveBeenCalledTimes(1);
    const [adapterArg, registryArg, authArg, rateLimiter, ipRateLimiter, options, auditArg, securityArg] =
      jest.mocked(mountMcpServer).mock.calls[0];
    expect(adapterArg).toBe(httpAdapter);
    expect(registryArg).toBe(registry);
    expect(authArg).toBe(authService);
    expect(rateLimiter).toBeInstanceOf(KeyRateLimiter);
    expect(ipRateLimiter).toBeInstanceOf(KeyRateLimiter);
    expect(options).toEqual({ basePath: '/mcp-test', serverInfo });
    expect(auditArg).toBe(auditService);
    expect(securityArg).toBe(securityLog);
  });
});
