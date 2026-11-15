import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { validateBody } from '../middleware/validate';
import { credentialsSchema, loginSchema, refreshSchema } from '../schemas';
import * as authService from '../services/auth.service';
import { asyncHandler } from '../utils/errors';

export const authRouter = Router();

authRouter.post(
  '/register',
  validateBody(credentialsSchema),
  asyncHandler(async (req, res) => {
    const result = await authService.register(req.body.email, req.body.password);
    res.status(201).json(result);
  }),
);

authRouter.post(
  '/login',
  validateBody(loginSchema),
  asyncHandler(async (req, res) => {
    res.json(await authService.login(req.body.email, req.body.password));
  }),
);

authRouter.post(
  '/refresh',
  validateBody(refreshSchema),
  asyncHandler(async (req, res) => {
    res.json(await authService.refresh(req.body.refreshToken));
  }),
);

authRouter.post(
  '/logout',
  validateBody(refreshSchema),
  asyncHandler(async (req, res) => {
    await authService.logout(req.body.refreshToken);
    res.status(204).send();
  }),
);

authRouter.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});
