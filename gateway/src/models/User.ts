import { Schema, model, Types } from 'mongoose';

export interface IUser {
  _id: Types.ObjectId;
  email: string;
  passwordHash: string;
  createdAt: Date;
  updatedAt: Date;
}

const userSchema = new Schema<IUser>(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    // select: false keeps the hash out of every query unless explicitly requested
    passwordHash: { type: String, required: true, select: false },
  },
  { timestamps: true },
);

export const User = model<IUser>('User', userSchema);
