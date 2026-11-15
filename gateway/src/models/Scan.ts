import { HydratedDocument, Schema, model, Types } from 'mongoose';

export const SCAN_STATUSES = ['queued', 'scanning', 'done', 'failed'] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];
export const TERMINAL_STATUSES: ScanStatus[] = ['done', 'failed'];

export interface Finding {
  id: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  detail: string;
}

export interface IScan {
  _id: Types.ObjectId;
  userId: Types.ObjectId;
  type: 'url' | 'email';
  target: string;
  input: string;
  status: ScanStatus;
  attempts: number;
  riskScore: number | null;
  verdict: 'safe' | 'suspicious' | 'malicious' | null;
  findings: Finding[];
  explanation: string | null;
  explanationSource: 'ai' | 'rules' | null;
  details: Record<string, unknown> | null;
  error: string | null;
  startedAt: Date | null;
  completedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

const findingSchema = new Schema<Finding>(
  {
    id: String,
    title: String,
    severity: { type: String, enum: ['info', 'low', 'medium', 'high', 'critical'] },
    detail: String,
  },
  { _id: false },
);

const scanSchema = new Schema<IScan>(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['url', 'email'], required: true },
    target: { type: String, required: true },
    input: { type: String, required: true, select: false },
    status: { type: String, enum: SCAN_STATUSES, default: 'queued', index: true },
    attempts: { type: Number, default: 0 },
    riskScore: { type: Number, default: null },
    verdict: { type: String, enum: ['safe', 'suspicious', 'malicious', null], default: null },
    findings: { type: [findingSchema], default: [] },
    explanation: { type: String, default: null },
    explanationSource: { type: String, enum: ['ai', 'rules', null], default: null },
    details: { type: Schema.Types.Mixed, default: null },
    error: { type: String, default: null },
    startedAt: { type: Date, default: null },
    completedAt: { type: Date, default: null },
  },
  { timestamps: true },
);

scanSchema.index({ userId: 1, createdAt: -1 });

export const Scan = model<IScan>('Scan', scanSchema);
export type ScanDocument = HydratedDocument<IScan>;

/** Shape returned by the API and pushed over WebSockets. */
export function toScanDto(scan: ScanDocument) {
  return {
    id: scan.id as string,
    type: scan.type,
    target: scan.target,
    status: scan.status,
    attempts: scan.attempts,
    riskScore: scan.riskScore,
    verdict: scan.verdict,
    findings: scan.findings,
    explanation: scan.explanation,
    explanationSource: scan.explanationSource,
    details: scan.details,
    error: scan.error,
    createdAt: scan.createdAt,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
  };
}
