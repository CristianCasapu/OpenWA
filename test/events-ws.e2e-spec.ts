// archiver v8 is ESM-only and is pulled in transitively via the @Global StorageModule when
// AppModule boots; stub it so ts-jest (CommonJS) can load the module graph.
jest.mock('archiver', () => ({ TarArchive: jest.fn() }));

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { io, Socket } from 'socket.io-client';
import { AppModule } from './../src/app.module';
import { applyGlobalValidation } from './../src/config/app-validation';
import { AuthService } from './../src/modules/auth/auth.service';
import { ApiKeyRole } from './../src/modules/auth/entities/api-key.entity';

/**
 * Real-wire WebSocket e2e: a genuine socket.io client against the booted gateway.
 *
 * The gateway's unit spec asserts handleMessage's RETURN VALUES — but Nest's IoAdapter only
 * forwards a @SubscribeMessage return value to the wire when the client passed an ack callback or
 * the response carries an `event` key. The dashboard emits ack-less frames carrying `type`, so for
 * its whole life no subscribe ack, pong, or error frame ever reached it while every unit test
 * stayed green (a circular oracle). Only a real client can pin the wire behaviour, so this suite
 * exists specifically to catch that class of regression — above all the FORBIDDEN_SESSION error
 * frame the dashboard's session feed uses to fall back from a '*' subscription for session-scoped
 * keys (without it, their QR flow sits on "generating" forever).
 */
describe('Events gateway over a real socket (e2e)', () => {
  let app: INestApplication;
  let baseUrl: string;
  let adminKey: string;
  let scopedKey: string;
  const sockets: Socket[] = [];

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    applyGlobalValidation(app);
    // listen() (not just init()): the gateway attaches to the app's HTTP server, and a socket.io
    // client needs a real listening port. Port 0 lets the OS pick a free one.
    await app.listen(0);
    const address = app.getHttpServer().address() as { port: number };
    baseUrl = `http://127.0.0.1:${address.port}`;

    const authService = app.get(AuthService);
    adminKey = (await authService.createApiKey({ name: 'e2e-ws-admin', role: ApiKeyRole.ADMIN })).rawKey;
    scopedKey = (
      await authService.createApiKey({
        name: 'e2e-ws-scoped',
        role: ApiKeyRole.OPERATOR,
        allowedSessions: ['sess-a'],
      })
    ).rawKey;
  });

  afterEach(() => {
    for (const socket of sockets.splice(0)) socket.disconnect();
  });

  afterAll(async () => {
    try {
      await app?.close();
    } catch {
      /* ignore teardown-only multi-datasource quirk */
    }
  });

  const connect = (apiKey: string): Promise<Socket> => {
    const socket = io(`${baseUrl}/events`, {
      auth: { apiKey },
      transports: ['websocket'],
      reconnection: false,
    });
    sockets.push(socket);
    return new Promise((resolve, reject) => {
      socket.on('connect', () => resolve(socket));
      socket.on('connect_error', err => reject(err));
    });
  };

  /** The next 'message' frame matching `match`, or a timeout rejection naming what never came. */
  const waitForFrame = (socket: Socket, match: (frame: Record<string, unknown>) => boolean, label: string) =>
    new Promise<Record<string, unknown>>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no '${label}' frame arrived within 5s`)), 5000);
      const onMessage = (frame: Record<string, unknown>) => {
        if (!match(frame)) return;
        clearTimeout(timer);
        socket.off('message', onMessage);
        resolve(frame);
      };
      socket.on('message', onMessage);
    });

  it('delivers the subscribed ack to an ack-less client', async () => {
    const socket = await connect(adminKey);
    const ack = waitForFrame(socket, f => f.type === 'subscribed', 'subscribed');

    socket.emit('message', { type: 'subscribe', sessionId: 'sess-a', events: ['session.status'], requestId: 'r1' });

    expect(await ack).toMatchObject({ type: 'subscribed', sessionId: 'sess-a', requestId: 'r1' });
  });

  it("delivers FORBIDDEN_SESSION when a session-scoped key subscribes to '*' — the scoped-key fallback signal", async () => {
    const socket = await connect(scopedKey);
    const error = waitForFrame(socket, f => f.type === 'error', 'error');

    socket.emit('message', { type: 'subscribe', sessionId: '*', events: ['session.status'], requestId: 'r2' });

    expect(await error).toMatchObject({ type: 'error', code: 'FORBIDDEN_SESSION', requestId: 'r2' });
  });

  it('answers ping with pong', async () => {
    const socket = await connect(adminKey);
    const pong = waitForFrame(socket, f => f.type === 'pong', 'pong');

    socket.emit('message', { type: 'ping', requestId: 'r3' });

    expect(await pong).toMatchObject({ type: 'pong', requestId: 'r3' });
  });
});
