import express from 'express';
import connectDB from './config/db.js';
import User from './models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import dotenv from 'dotenv';

dotenv.config();
const app = express();

// ========================
// 🛠️ Cấu hình CORS
// ========================
app.use(cors({
  origin: [
    'http://localhost:5173',
    'https://choppily-bluish-maegan.ngrok-free.dev' // Cho phép frontend qua ngrok
  ],
  credentials: true
}));

// ========================
// 🧩 Middleware
// ========================
app.use(express.json()); // Phân tích JSON body

// ========================
// 🗄️ Kết nối Database
// ========================
connectDB();

// ========================
// ⚙️ Cổng server
// ========================
const PORT = process.env.PORT || 5009;

// ========================
// 🔐 Middleware xác thực JWT
// ========================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Không có token, bạn không được phép truy cập" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      const message = err.name === 'TokenExpiredError'
        ? "Token đã hết hạn, vui lòng đăng nhập lại."
        : "Token không hợp lệ";
      return res.status(403).json({ error: message });
    }

    req.user = decoded;
    next();
  });
};

// ========================
// 🧾 Route: Đăng ký
// ========================
app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Vui lòng điền đầy đủ thông tin' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email đã được đăng ký' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      createdAt: new Date()
    });
    await newUser.save();

    res.status(201).json({
      username: newUser.username,
      email: newUser.email,
      createdAt: newUser.createdAt
    });
  } catch (error) {
    console.error('Lỗi đăng ký:', error);
    res.status(500).json({ error: 'Đăng ký thất bại' });
  }
});

// ========================
// 🔑 Route: Đăng nhập
// ========================
app.post('/api/signin', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Vui lòng điền đầy đủ thông tin' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Tài khoản không hợp lệ, vui lòng đăng ký tài khoản mới!' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Email hoặc mật khẩu không đúng!' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '8h' });

    res.json({
      token,
      email: user.email,
      username: user.username,
      createdAt: user.createdAt
    });
  } catch (error) {
    console.error('Lỗi đăng nhập:', error);
    res.status(500).json({ error: 'Lỗi máy chủ' });
  }
});

// ========================
// 🔒 Route: Đổi mật khẩu
// ========================
app.post('/api/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (newPassword.length < 8) {
    return res.status(400).json({ error: "Mật khẩu mới phải có ít nhất 8 ký tự." });
  }

  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "Tài khoản không tồn tại" });
    }

    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: "Mật khẩu hiện tại không đúng" });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.status(200).json({ message: "Mật khẩu đã được thay đổi thành công!" });
  } catch (error) {
    console.error("Lỗi đổi mật khẩu:", error);
    res.status(500).json({ error: "Lỗi máy chủ" });
  }
});

// ========================
// 🚀 Khởi động Server
// ========================
app.listen(PORT, () => {
  console.log(`✅ Server đang chạy tại cổng ${PORT}`);
});