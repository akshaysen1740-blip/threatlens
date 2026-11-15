import os from 'os';
import Redis from 'ioredis';
import { config } from '../config';
import { logger } from '../logger';
import { createRedisConnection, ensureConsumerGroup } from '../redis';
import { sleep } from '../utils/sleep';
import { applyScanEvent, ScanEvent } from './scanUpdate.service';

type StreamEntry = [id: string, fields: string[] | null];
type StreamReply = [stream: string, entries: StreamEntry[]][] | null;

function fieldsToObject(fields: string[]): ScanEvent {
  const obj: Record<string, string> = {};
  for (let i = 0; i < fields.length; i += 2) obj[fields[i]] = fields[i + 1];
  return obj;
}

/**
 * Consumes worker events (scanning / queued / done / failed) from the events stream
 * using a consumer group, then updates MongoDB and notifies clients.
 */
export class ScanEventsListener {
  private readonly conn: Redis;
  private readonly consumer = `${os.hostname()}-${process.pid}`;
  private running = false;
  private loopPromise: Promise<void> | null = null;

  constructor() {
    this.conn = createRedisConnection('events-listener');
  }

  async start(): Promise<void> {
    await ensureConsumerGroup(this.conn, config.EVENTS_STREAM, config.EVENTS_GROUP);
    this.running = true;
    this.loopPromise = this.loop();
    logger.info({ stream: config.EVENTS_STREAM, consumer: this.consumer }, 'Scan events listener started');
  }

  private async loop(): Promise<void> {
    // '0' first re-reads events this consumer received but never acknowledged (e.g. after a crash),
    // then '>' reads only new events.
    let cursor = '0';

    while (this.running) {
      try {
        const reply = (await this.conn.call(
          'XREADGROUP',
          'GROUP',
          config.EVENTS_GROUP,
          this.consumer,
          'COUNT',
          '20',
          'BLOCK',
          '5000',
          'STREAMS',
          config.EVENTS_STREAM,
          cursor,
        )) as StreamReply;

        const entries = reply?.[0]?.[1] ?? [];
        if (cursor === '0' && entries.length === 0) {
          cursor = '>';
          continue;
        }

        for (const [id, fields] of entries) {
          if (fields) {
            try {
              await applyScanEvent(fieldsToObject(fields));
            } catch (err) {
              logger.error({ err, id }, 'Failed to apply scan event');
            }
          }
          await this.conn.call('XACK', config.EVENTS_STREAM, config.EVENTS_GROUP, id);
        }
      } catch (err) {
        if (!this.running) break;
        logger.error({ err }, 'Error reading scan events; retrying in 2s');
        await sleep(2000);
      }
    }
  }

  async stop(): Promise<void> {
    this.running = false;
    this.conn.disconnect(); // interrupts the blocking XREADGROUP
    await this.loopPromise?.catch(() => undefined);
  }
}
