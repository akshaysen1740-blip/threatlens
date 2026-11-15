import { Router } from 'express';
import { isValidObjectId } from 'mongoose';
import { logger } from '../logger';
import { requireAuth } from '../middleware/auth';
import { scanLimiter } from '../middleware/rateLimit';
import { validateBody } from '../middleware/validate';
import { Scan, toScanDto } from '../models/Scan';
import { CreateScanInput, createScanSchema, listScansQuerySchema } from '../schemas';
import { enqueueScan } from '../services/queue.service';
import { AppError, asyncHandler } from '../utils/errors';

export const scanRouter = Router();
scanRouter.use(requireAuth);

function emailSubject(rawEmail: string): string {
  const match = rawEmail.match(/^Subject:[ \t]*(.+)$/im);
  return match ? match[1].trim().slice(0, 200) : '(no subject)';
}

/** Creates a scan and queues it. Returns 202 immediately; the result arrives asynchronously. */
scanRouter.post(
  '/',
  scanLimiter,
  validateBody(createScanSchema),
  asyncHandler(async (req, res) => {
    const body = req.body as CreateScanInput;
    const userId = req.user!.id;

    const input = body.type === 'url' ? body.url : body.rawEmail;
    const scan = await Scan.create({
      userId,
      type: body.type,
      target: body.type === 'url' ? body.url : emailSubject(body.rawEmail),
      input,
      status: 'queued',
    });

    try {
      await enqueueScan({
        scanId: scan.id,
        userId,
        type: body.type,
        payload: body.type === 'url' ? { url: body.url } : { rawEmail: body.rawEmail },
      });
    } catch (err) {
      logger.error({ err, scanId: scan.id }, 'Failed to enqueue scan');
      scan.status = 'failed';
      scan.error = 'Scan queue unavailable';
      await scan.save();
      throw new AppError(503, 'Scan queue is unavailable, please try again later');
    }

    res.status(202).location(`/api/scans/${scan.id}`).json(toScanDto(scan));
  }),
);

scanRouter.get(
  '/',
  asyncHandler(async (req, res) => {
    const parsed = listScansQuerySchema.safeParse(req.query);
    if (!parsed.success) throw new AppError(400, 'Invalid query parameters', parsed.error.flatten());
    const { page, limit, status } = parsed.data;

    const filter = { userId: req.user!.id, ...(status ? { status } : {}) };
    const [items, total] = await Promise.all([
      Scan.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit),
      Scan.countDocuments(filter),
    ]);

    res.json({ items: items.map(toScanDto), page, limit, total });
  }),
);

scanRouter.get(
  '/:id',
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    // Filtering by userId means users can never read someone else's scan (prevents IDOR)
    const scan = isValidObjectId(id) ? await Scan.findOne({ _id: id, userId: req.user!.id }) : null;
    if (!scan) throw new AppError(404, 'Scan not found');
    res.json(toScanDto(scan));
  }),
);
