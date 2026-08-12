import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const db = new Database(path.join(__dirname, 'chat.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    summary TEXT DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
  );

  -- 📎 Bảng "hồ sơ" ghi nhớ về user, DÙNG CHUNG cho MỌI phòng chat (khác hẳn conversations.summary
  -- vốn chỉ nhớ trong phạm vi 1 phòng). CHECK (id = 1) ép chỉ có đúng 1 dòng duy nhất tồn tại - app
  -- này không có hệ thống tài khoản/nhiều user nên không cần khoá theo user_id.
  CREATE TABLE IF NOT EXISTS user_profile (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    profile TEXT DEFAULT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Thêm cột summary nếu DB cũ chưa có (an toàn khi chạy lại nhiều lần)
try {
  db.exec(`ALTER TABLE conversations ADD COLUMN summary TEXT DEFAULT NULL;`);
} catch (e) {
  // Cột đã tồn tại rồi thì bỏ qua, không cần báo lỗi
}

export default db;