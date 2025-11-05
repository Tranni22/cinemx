import mongoose from 'mongoose';
import User from '../models/User.js'; // Đảm bảo đường dẫn đúng

const connectDB = async () => {
    try {
        await mongoose.connect('mongodb://localhost:27017/Userdb');
        console.log('MongoDB connected');
    } catch (error) {
        console.error('MongoDB connection error:', error);
        process.exit(1);
    }
};

const getUsers = async () => {
    try {
        const users = await User.find();
        console.log(users);
    } catch (error) {
        console.error('Error fetching users:', error);
    }
};

// Kết nối và lấy dữ liệu
connectDB().then(getUsers);

// Export connectDB như default export
export default connectDB;
