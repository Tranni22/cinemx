import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import chatRoutes from './routes/chat.routes.js';

const app = express();
const PORT = process.env.PORT || 5000;

// 📁 Đảm bảo thư mục uploads tồn tại (nơi lưu ảnh/file người dùng gửi lên)
const uploadsDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log(`📁 Đã tạo thư mục uploads tại: ${uploadsDir}`);
}

app.use(cors({
  origin: true, // cho phép mọi origin gọi vào (đang test trong LAN, không public ra ngoài)
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type']
}));

app.use(express.json());

// 🖼️ Cho phép truy cập file đã upload qua URL dạng: http://<ip>:5000/uploads/tenfile.png
app.use('/uploads', express.static(uploadsDir));

app.use('/api', chatRoutes);

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Đã xảy ra sự cố tại máy chủ!' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Backend vận hành thành công tại: http://localhost:${PORT}`);
  console.log(`🌐 Máy khác trong LAN truy cập qua: http://<IP-LAN-cua-may-nay>:${PORT}`);
});
