import express from 'express';
import multer from 'multer';
import path from 'path';
import crypto from 'crypto';
import {
  createConversation,
  getConversations,
  getMessages,
  sendMessageStream,
  deleteConversation
} from '../controllers/chat.controller.js';

const router = express.Router();

// 📎 Cấu hình multer: lưu file vào thư mục uploads/ với tên ngẫu nhiên (giữ đúng phần đuôi file)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(process.cwd(), 'uploads'));
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${crypto.randomUUID()}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 20 * 1024 * 1024 } // giới hạn 20MB / file
});

router.post('/conversations', createConversation);
router.get('/conversations', getConversations);
router.get('/conversations/:id/messages', getMessages);
// 📎 upload.single('file') -> nhận field tên "file" trong FormData, không có file vẫn chạy bình thường
router.post('/conversations/:id/messages', upload.single('file'), sendMessageStream);
router.delete('/conversations/:id', deleteConversation);

export default router;
