import http from 'http';
import { Server } from 'socket.io';
import { config } from './config';
import { logger } from './logger';
import { verifyAccessToken } from './services/token.service';

let io: Server | null = null;

/**
 * Clients connect with { auth: { token: <accessToken> } } and automatically join
 * a private room for their user, so they only receive their own scan updates.
 */
export function initSocket(server: http.Server): Server {
  io = new Server(server, { cors: { origin: config.CORS_ORIGIN === '*' ? '*' : config.CORS_ORIGIN.split(',') } });

  io.use((socket, next) => {
    try {
      socket.data.user = verifyAccessToken(socket.handshake.auth?.token);
      next();
    } catch {
      next(new Error('Unauthorized'));
    }
  });

  io.on('connection', (socket) => {
    const userId = socket.data.user.id as string;
    socket.join(`user:${userId}`);
    logger.debug({ userId }, 'WebSocket client connected');
  });

  return io;
}

export function emitScanUpdate(userId: string, payload: unknown): void {
  io?.to(`user:${userId}`).emit('scan:update', payload);
}

export async function closeSocket(): Promise<void> {
  if (io) {
    await io.close();
    io = null;
  }
}
