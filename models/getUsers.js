// getUsers.js
import mongoose from 'mongoose';  // Đảm bảo import mongoose
import connectDB from '../config/db.js'; // Đảm bảo đường dẫn đúng
import User from '../models/User.js'; // Đảm bảo đường dẫn đúng

const getUsers = async () => {
  await connectDB(); // Kết nối với MongoDB

  try {
    const users = await User.find(); // Lấy tất cả người dùng từ cơ sở dữ liệu
    console.log('Users:', users);
  } catch (error) {
    console.error('Error fetching users:', error.message);
  } finally {
    mongoose.connection.close(); // Đóng kết nối sau khi lấy dữ liệu
  }
};

// Gọi hàm để thực thi
getUsers();
