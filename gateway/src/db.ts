import mongoose from 'mongoose';
import { config } from './config';
import { logger } from './logger';

export async function connectDb(): Promise<void> {
  mongoose.connection.on('disconnected', () => logger.warn('MongoDB disconnected'));
  mongoose.connection.on('reconnected', () => logger.info('MongoDB reconnected'));
  await mongoose.connect(config.MONGO_URI, { serverSelectionTimeoutMS: 10_000 });
  logger.info('Connected to MongoDB');
}

export async function disconnectDb(): Promise<void> {
  await mongoose.disconnect();
}

export const isDbReady = () => mongoose.connection.readyState === 1;
