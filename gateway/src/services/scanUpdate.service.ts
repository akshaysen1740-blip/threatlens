import { isValidObjectId } from "mongoose";
import { config } from "../config";
import { logger } from "../logger";
import {
  IScan,
  Scan,
  ScanDocument,
  TERMINAL_STATUSES,
  toScanDto,
} from "../models/Scan";
import { emitScanUpdate } from "../socket";

/** Fields published by the Python worker on the events stream. */
export interface ScanEvent {
  scanId?: string;
  userId?: string;
  status?: string;
  attempt?: string;
  result?: string;
  error?: string;
}

/**
 * Applies a worker event to the scan document. The filter only matches scans that
 * are not finished yet, which makes event handling idempotent: duplicate or late
 * events (for example after a timeout) are simply ignored.
 */
export async function applyScanEvent(
  event: ScanEvent,
): Promise<ScanDocument | null> {
  const { scanId, userId, status } = event;
  if (!scanId || !userId || !status || !isValidObjectId(scanId)) {
    logger.warn({ event }, "Ignoring malformed scan event");
    return null;
  }

  const attempts = Number(event.attempt ?? 1);
  let update: Partial<IScan>;

  switch (status) {
    case "scanning":
      update = { status: "scanning", attempts, startedAt: new Date() };
      break;
    case "queued": // worker re-queued the job for a retry
      update = { status: "queued", attempts, error: event.error ?? null };
      break;
    case "done": {
      let result: Record<string, any>;
      try {
        result = JSON.parse(event.result ?? "{}");
      } catch (err) {
        logger.error({ err, scanId }, "Worker sent an invalid result payload");
        update = {
          status: "failed",
          attempts,
          error: "Invalid result from scanner",
          completedAt: new Date(),
        };
        break;
      }
      update = {
        status: "done",
        attempts,
        riskScore: result.riskScore ?? null,
        verdict: result.verdict ?? null,
        findings: result.findings ?? [],
        explanation: result.explanation ?? null,
        explanationSource: result.explanationSource ?? null,
        details: result.details ?? null,
        error: null,
        completedAt: new Date(),
      };
      break;
    }
    case "failed":
      update = {
        status: "failed",
        attempts,
        error: event.error ?? "Scan failed",
        completedAt: new Date(),
      };
      break;
    default:
      logger.warn({ event }, "Ignoring scan event with unknown status");
      return null;
  }

  const scan = await Scan.findOneAndUpdate(
    { _id: scanId, userId, status: { $nin: TERMINAL_STATUSES } },
    { $set: update },
    { new: true },
  );

  if (scan) {
    emitScanUpdate(userId, toScanDto(scan));
  }
  return scan;
}

/**
 * Safety net: if a scan stays queued/scanning longer than SCAN_TIMEOUT_MS
 * (for example all workers are down), mark it as failed so clients aren't left waiting.
 */
export async function failTimedOutScans(): Promise<number> {
  const cutoff = new Date(Date.now() - config.SCAN_TIMEOUT_MS);
  const stuck = await Scan.find({
    status: { $nin: TERMINAL_STATUSES },
    updatedAt: { $lt: cutoff },
  })
    .select("_id userId")
    .limit(100);

  let count = 0;
  for (const s of stuck) {
    const scan = await Scan.findOneAndUpdate(
      {
        _id: s._id,
        status: { $nin: TERMINAL_STATUSES },
        updatedAt: { $lt: cutoff },
      },
      {
        $set: {
          status: "failed",
          error: "Scan timed out",
          completedAt: new Date(),
        },
      },
      { new: true },
    );
    if (scan) {
      count += 1;
      emitScanUpdate(scan.userId.toString(), toScanDto(scan));
    }
  }
  if (count > 0) logger.warn({ count }, "Marked timed-out scans as failed");
  return count;
}
