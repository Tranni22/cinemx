// models/User.js
import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  }, { timestamps: true }); // Tự động thêm createdAt và updatedAt

const User = mongoose.model('User', userSchema);
export default User; // Sử dụng export default
