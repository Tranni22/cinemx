import db from '../db/database.js';
import * as aiService from '../services/ai.service.js';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { verifyHtmlCode } from '../services/verifyCode.js';

const RECENT_MESSAGES_COUNT = 10;
const SUMMARY_THRESHOLD = 20;
const SUMMARY_UPDATE_INTERVAL = 15;

// 📎 Tự động thêm cột lưu thông tin file vào bảng messages nếu chưa có.
// An toàn khi chạy nhiều lần: nếu cột đã tồn tại, lệnh sẽ lỗi và bị bắt (catch) im lặng.
function ensureFileColumns() {
  const columns = [
    'ALTER TABLE messages ADD COLUMN file_url TEXT',
    'ALTER TABLE messages ADD COLUMN file_name TEXT',
    'ALTER TABLE messages ADD COLUMN file_mime TEXT'
  ];
  for (const sql of columns) {
    try {
      db.exec(sql);
    } catch (e) {
      // Cột đã tồn tại từ lần chạy trước -> bỏ qua
    }
  }
}
ensureFileColumns();

// 📎 Trích xuất khối HTML hoàn chỉnh từ câu trả lời của AI (nếu có), để đem đi verify.
// Không tìm thấy thì trả về null -> chỗ gọi nó sẽ tự bỏ qua bước verify.
function extractHtmlDocument(text) {
  if (!text) return null;

  // Ưu tiên tìm code block dạng ```html ... ```
  const fencedMatch = text.match(/```html\s*([\s\S]*?)```/i);
  if (fencedMatch) return fencedMatch[1];

  // Fallback: có thể AI trả HTML thô không bọc trong fence
  const rawMatch = text.match(/<!DOCTYPE html[\s\S]*<\/html>/i);
  if (rawMatch) return rawMatch[0];

  return null;
}

export const createConversation = (req, res) => {
  try {
    const { title } = req.body;
    const id = crypto.randomUUID();
    const conversationTitle = title || 'Cuộc hội thoại mới';

    const stmt = db.prepare('INSERT INTO conversations (id, title) VALUES (?, ?)');
    stmt.run(id, conversationTitle);

    res.status(201).json({ id, title: conversationTitle });
  } catch (error) {
    res.status(500).json({ error: 'Không thể tạo cuộc hội thoại: ' + error.message });
  }
};

export const getConversations = (req, res) => {
  try {
    const stmt = db.prepare('SELECT * FROM conversations ORDER BY created_at DESC');
    const conversations = stmt.all();
    res.json(conversations);
  } catch (error) {
    res.status(500).json({ error: 'Không thể lấy dữ liệu hội thoại: ' + error.message });
  }
};

export const getMessages = (req, res) => {
  try {
    const { id } = req.params;
    const stmt = db.prepare('SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at ASC');
    const messages = stmt.all(id);
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: 'Không thể tải lịch sử tin nhắn: ' + error.message });
  }
};

export const deleteConversation = (req, res) => {
  try {
    const { id } = req.params;
    const stmt = db.prepare('DELETE FROM conversations WHERE id = ?');
    stmt.run(id);
    res.json({ success: true, message: 'Đã xoá cuộc hội thoại thành công' });
  } catch (error) {
    res.status(500).json({ error: 'Không thể xoá cuộc hội thoại: ' + error.message });
  }
};

// 📎 Lấy ảnh AI vừa tạo/sửa GẦN NHẤT trong hội thoại (không tính tin nhắn vừa gửi, đã loại bằng
// excludeMsgId) - dùng khi user gõ tiếp câu sửa ảnh mà KHÔNG đính kèm lại file, để hiểu ngầm là
// "sửa tiếp đúng tấm ảnh vừa thấy" thay vì bắt user phải tải lại ảnh mỗi lần muốn sửa thêm 1 chi tiết.
// Trả về tên file thô (vd "abc.png") hoặc null nếu tin nhắn gần nhất không phải ảnh.
function getLastImageFilename(conversationId, excludeMsgId) {
  const last = db.prepare(
    'SELECT file_url, file_mime FROM messages WHERE conversation_id = ? AND id != ? ORDER BY created_at DESC LIMIT 1'
  ).get(conversationId, excludeMsgId);
  if (last?.file_mime?.startsWith('image/') && last.file_url) {
    return last.file_url.replace(/^\/?(uploads\/)?/, '');
  }
  return null;
}

function buildContext(conversationId, excludeMsgId) {
  const messageCount = db.prepare(
    'SELECT COUNT(*) as count FROM messages WHERE conversation_id = ?'
  ).get(conversationId).count;

  if (messageCount <= SUMMARY_THRESHOLD) {
    const history = db.prepare(
      'SELECT role, content FROM messages WHERE conversation_id = ? AND id != ? ORDER BY created_at ASC'
    ).all(conversationId, excludeMsgId);
    return { context: history, messageCount };
  }

  const conv = db.prepare('SELECT summary FROM conversations WHERE id = ?').get(conversationId);
  const recentMessages = db.prepare(
    'SELECT role, content FROM messages WHERE conversation_id = ? AND id != ? ORDER BY created_at DESC LIMIT ?'
  ).all(conversationId, excludeMsgId, RECENT_MESSAGES_COUNT).reverse();

  const context = conv?.summary
    ? [{ role: 'user', content: `[Bối cảnh cuộc trò chuyện trước đó]: ${conv.summary}` }, ...recentMessages]
    : recentMessages;

  return { context, messageCount };
}

function updateSummaryInBackground(conversationId, messageCount) {
  if (messageCount % SUMMARY_UPDATE_INTERVAL !== 0) return;

  const oldMessages = db.prepare(
    'SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY created_at ASC LIMIT ?'
  ).all(conversationId, messageCount - RECENT_MESSAGES_COUNT);

  const apiKey = aiService.getAvailableKeyForSummary();

  aiService.summarizeHistory(oldMessages, apiKey)
    .then(summary => {
      if (summary) {
        db.prepare('UPDATE conversations SET summary = ? WHERE id = ?').run(summary, conversationId);
        console.log(`📝 Đã cập nhật tóm tắt cho hội thoại ${conversationId}`);
      }
    })
    .catch(err => console.error('⚠️ Lỗi khi tóm tắt lịch sử:', err.message));
}

// 📎 Đọc "hồ sơ" user hiện tại (dùng chung mọi phòng chat) - null nếu chưa từng có gì được ghi.
function getUserProfile() {
  const row = db.prepare('SELECT profile FROM user_profile WHERE id = 1').get();
  return row?.profile || null;
}

// 📎 Ghi đè trực tiếp hồ sơ user - dùng cho lệnh "sửa hồ sơ: ..." gõ tay trong chat (khác với
// updateUserProfileInBackground vốn tự động GỘP dần qua Gemini, cái này ghi đè NGUYÊN VĂN theo ý user).
function setUserProfile(text) {
  db.prepare(`
    INSERT INTO user_profile (id, profile, updated_at) VALUES (1, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(id) DO UPDATE SET profile = excluded.profile, updated_at = CURRENT_TIMESTAMP
  `).run(text);
}

// 📎 Cập nhật hồ sơ user ở NỀN (không chặn response) - dùng chung interval với tóm tắt hội thoại cho
// đơn giản (SUMMARY_UPDATE_INTERVAL). Chỉ ghi DB nếu thực sự có gì thay đổi (Gemini có thể trả về y
// nguyên hồ sơ cũ nếu đoạn chat mới không có thông tin dài hạn nào đáng ghi thêm).
function updateUserProfileInBackground(conversationId, messageCount) {
  if (messageCount % SUMMARY_UPDATE_INTERVAL !== 0) return;

  const recentMessages = db.prepare(
    'SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY created_at DESC LIMIT ?'
  ).all(conversationId, RECENT_MESSAGES_COUNT).reverse();

  const oldProfile = getUserProfile();
  const apiKey = aiService.getAvailableKeyForSummary();

  aiService.updateUserProfile(oldProfile, recentMessages, apiKey)
    .then(newProfile => {
      if (newProfile && newProfile !== oldProfile) {
        db.prepare(`
          INSERT INTO user_profile (id, profile, updated_at) VALUES (1, ?, CURRENT_TIMESTAMP)
          ON CONFLICT(id) DO UPDATE SET profile = excluded.profile, updated_at = CURRENT_TIMESTAMP
        `).run(newProfile);
        console.log('📝 Đã cập nhật hồ sơ user (nhớ xuyên hội thoại).');
      }
    })
    .catch(err => console.error('⚠️ Lỗi khi cập nhật hồ sơ user:', err.message));
}

export const sendMessageStream = async (req, res) => {
  const { id } = req.params;
  const { content, model } = req.body; // model: tên Gemini model user chọn từ dropdown UI (optional)
  const uploadedFile = req.file; // 📎 multer gắn file (nếu có) vào req.file

  const hasText = content && content.trim() !== '';
  const hasFile = !!uploadedFile;

  if (!hasText && !hasFile) {
    return res.status(400).json({ error: 'Cần có nội dung tin nhắn hoặc file đính kèm.' });
  }

  try {
    const conversation = db.prepare('SELECT title FROM conversations WHERE id = ?').get(id);
    if (!conversation) {
      return res.status(404).json({ error: 'Mã hội thoại không tồn tại.' });
    }

    // 📎 Lệnh xem/sửa hồ sơ user gõ tay trong chat - xử lý NGAY, KHÔNG gọi Gemini (nhanh, miễn phí,
    // không tốn quota). Đặt trước mọi nhánh khác để không bị nhầm là chat thường/yêu cầu tạo ảnh.
    const viewProfileMatch = hasText && /^\s*xem\s+h[ồo]\s*s[ơo]\s*$/i.test(content);
    const editProfileMatch = hasText && content.match(/^\s*s[ửu]a\s+h[ồo]\s*s[ơo]\s*:\s*([\s\S]+)/i);

    if (viewProfileMatch || editProfileMatch) {
      const userMsgId = crypto.randomUUID();
      db.prepare(
        'INSERT INTO messages (id, conversation_id, role, content) VALUES (?, ?, ?, ?)'
      ).run(userMsgId, id, 'user', content);

      let replyText;
      if (editProfileMatch) {
        const newProfile = editProfileMatch[1].trim();
        setUserProfile(newProfile);
        replyText = `✅ Đã cập nhật hồ sơ:\n\n${newProfile}`;
      } else {
        const profile = getUserProfile();
        replyText = profile
          ? `📋 Hồ sơ hiện tại đang nhớ về bạn:\n\n${profile}`
          : '📋 Chưa có gì trong hồ sơ cả - cứ chat vài lần (đủ 15 tin nhắn) để mình tự ghi nhớ, hoặc gõ "sửa hồ sơ: <nội dung>" để tự nhập tay.';
      }

      const aiMsgId = crypto.randomUUID();
      db.prepare(
        'INSERT INTO messages (id, conversation_id, role, content) VALUES (?, ?, ?, ?)'
      ).run(aiMsgId, id, 'assistant', replyText);

      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.write(`data: ${JSON.stringify({ chunk: replyText })}\n\n`);
      res.write(`data: [DONE]\n\n`);
      return res.end();
    }

    // 📎 Thông tin file để lưu DB (đường dẫn public) và để gửi cho AI (đường dẫn thật trên disk)
    const fileUrl = uploadedFile ? `/uploads/${uploadedFile.filename}` : null;
    const fileName = uploadedFile ? uploadedFile.originalname : null;
    const fileMime = uploadedFile ? uploadedFile.mimetype : null;

    const userMsgId = crypto.randomUUID();
    db.prepare(
      'INSERT INTO messages (id, conversation_id, role, content, file_url, file_name, file_mime) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(userMsgId, id, 'user', content || '', fileUrl, fileName, fileMime);

    // ✏️ Nhánh SỬA ảnh - dùng regex CHẶT (bắt buộc có "ảnh"/"hình") - ĐÃ REVERT từ classifyImageIntent
    // (Gemini) về lại regex vì hướng Gemini bị lỗi 400 chưa rõ nguyên nhân, còn regex này đã test kỹ.
    const lastImageFilename = uploadedFile ? null : getLastImageFilename(id, userMsgId);
    const isFreshUploadEdit = uploadedFile && aiService.isImageEditRequest(content);
    const isContinuationEdit = !uploadedFile && lastImageFilename && aiService.isImageEditRequest(content);

    if (hasText && (isFreshUploadEdit || isContinuationEdit)) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.write(`data: ${JSON.stringify({ chunk: '✏️ Đang sửa ảnh, chờ chút...' })}\n\n`);

      const targetFilename = uploadedFile ? uploadedFile.filename : lastImageFilename;
      const editedImage = await aiService.editImage(targetFilename, content);

      if (!editedImage) {
        res.write(`data: ${JSON.stringify({ error: 'Không sửa được ảnh. Nguyên nhân phổ biến nhất: chưa cấu hình PUBLIC_BASE_URL trong .env (Pollinations cần fetch ảnh gốc qua 1 URL public - LAN nội bộ không dùng được). Xem log backend để biết chi tiết.' })}\n\n`);
        res.write(`data: [DONE]\n\n`);
        return res.end();
      }

      try {
        const uploadsDir = path.join(process.cwd(), 'uploads');
        if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
        const ext = (editedImage.mimeType.split('/')[1] || 'png').replace(/[^a-z0-9]/gi, '');
        const filename = `${crypto.randomUUID()}.${ext}`;
        fs.writeFileSync(path.join(uploadsDir, filename), Buffer.from(editedImage.data, 'base64'));

        const aiMsgId = crypto.randomUUID();
        db.prepare(
          'INSERT INTO messages (id, conversation_id, role, content, file_url, file_name, file_mime) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).run(aiMsgId, id, 'assistant', '✏️ Đã sửa ảnh theo yêu cầu.', `/uploads/${filename}`, filename, editedImage.mimeType);

        if (conversation.title === 'Cuộc hội thoại mới') {
          const newTitle = content.length > 25 ? content.substring(0, 25) + '...' : content;
          db.prepare('UPDATE conversations SET title = ? WHERE id = ?').run(newTitle, id);
        }
      } catch (saveErr) {
        console.error('💥 Lỗi khi lưu ảnh vừa sửa:', saveErr.message);
        res.write(`data: ${JSON.stringify({ error: 'Sửa ảnh thành công nhưng lưu file thất bại: ' + saveErr.message })}\n\n`);
      }

      res.write(`data: [DONE]\n\n`);
      return res.end();
    }

    // 🎨 Nhánh riêng cho yêu cầu TẠO ẢNH MỚI - dùng regex isImageRequest (đã revert từ classifier).
    // Tách khỏi luồng chat text thường vì dùng model khác hẳn (gemini-3.1-flash-lite-image không có
    // khả năng chat/dùng tool, chỉ sinh ảnh từ prompt).
    if (hasText && !uploadedFile && aiService.isImageRequest(content)) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.write(`data: ${JSON.stringify({ chunk: '🎨 Đang tạo ảnh, chờ chút...' })}\n\n`);

      const image = await aiService.generateImage(content);

      if (!image) {
        res.write(`data: ${JSON.stringify({ error: 'Không tạo được ảnh. Nguyên nhân phổ biến nhất: model tạo ảnh hiện KHÔNG có free tier qua API (cần bật billing cho project Google Cloud). Xem log backend để biết chi tiết.' })}\n\n`);
        res.write(`data: [DONE]\n\n`);
        return res.end();
      }

      try {
        const uploadsDir = path.join(process.cwd(), 'uploads');
        if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
        const ext = (image.mimeType.split('/')[1] || 'png').replace(/[^a-z0-9]/gi, '');
        const filename = `${crypto.randomUUID()}.${ext}`;
        fs.writeFileSync(path.join(uploadsDir, filename), Buffer.from(image.data, 'base64'));

        const aiMsgId = crypto.randomUUID();
        db.prepare(
          'INSERT INTO messages (id, conversation_id, role, content, file_url, file_name, file_mime) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).run(aiMsgId, id, 'assistant', '🎨 Đã tạo ảnh theo yêu cầu.', `/uploads/${filename}`, filename, image.mimeType);

        if (conversation.title === 'Cuộc hội thoại mới') {
          const newTitle = content.length > 25 ? content.substring(0, 25) + '...' : content;
          db.prepare('UPDATE conversations SET title = ? WHERE id = ?').run(newTitle, id);
        }
      } catch (saveErr) {
        console.error('💥 Lỗi khi lưu ảnh vừa tạo:', saveErr.message);
        res.write(`data: ${JSON.stringify({ error: 'Tạo ảnh thành công nhưng lưu file thất bại: ' + saveErr.message })}\n\n`);
      }

      res.write(`data: [DONE]\n\n`);
      return res.end();
    }

    const { context, messageCount } = buildContext(id, userMsgId);

    // 📎 Cho phép gõ "model:tên" ngay trong tin nhắn để chọn model (không cần frontend có dropdown).
    // Ưu tiên `model` gửi từ request body (khi frontend có UI thật) nếu có, tag trong content chỉ là
    // fallback. Dùng cleanContent (đã bỏ tag) làm nội dung THẬT gửi cho Gemini - tin nhắn gốc (còn tag)
    // đã lưu DB từ trước nên vẫn hiển thị nguyên văn trên UI, chỉ phần gửi đi là được làm sạch.
    const { cleanContent, model: tagModel } = aiService.extractChatModelTag(content);
    const chatModel = model || tagModel;

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    let fullAiResponse = '';
    let searchResult = null;

    // 📎 fileInfo truyền cho AI service: cần đường dẫn thật trên disk để đọc nội dung
    const fileInfo = uploadedFile
      ? { path: uploadedFile.path, mimeType: uploadedFile.mimetype, originalName: uploadedFile.originalname }
      : null;

    try {
      const userProfile = getUserProfile();
      const streamResult = await aiService.generateChatStream(context, cleanContent, fileInfo, chatModel, userProfile);
      searchResult = streamResult.searchResult;
      const stream = streamResult.stream;
      let finishReason = null;

      for await (const chunk of stream) {
        const textChunk = chunk.text || '';
        fullAiResponse += textChunk;
        res.write(`data: ${JSON.stringify({ chunk: textChunk })}\n\n`);

        if (chunk.candidates?.[0]?.finishReason) {
          finishReason = chunk.candidates[0].finishReason;
        }
      }

      // Cảnh báo nếu bị cắt ngang do chạm giới hạn token
      if (finishReason === 'MAX_TOKENS') {
        console.warn(`⚠️ Response bị cắt do MAX_TOKENS ở hội thoại ${id}`);
        res.write(`data: ${JSON.stringify({ warning: 'Câu trả lời có thể chưa hoàn chỉnh do quá dài. Gõ "tiếp tục" để AI viết nốt.' })}\n\n`);
      }

    } catch (streamError) {
      console.error('💥 Lỗi ngắt quãng giữa dòng stream:', streamError.message);
      res.write(`data: ${JSON.stringify({ error: 'Dòng stream bị ngắt quãng do sự cố đường truyền.' })}\n\n`);
    }

    // 📎 Nếu AI vừa trả về 1 file HTML hoàn chỉnh, tự chạy thử trong browser ẩn (headless)
    // để bắt lỗi runtime thật. Bọc try/catch riêng: dù bước này lỗi/timeout cũng KHÔNG
    // ảnh hưởng tới việc lưu tin nhắn hay đóng stream bên dưới.
    try {
      const htmlToVerify = extractHtmlDocument(fullAiResponse);
      if (htmlToVerify) {
        const { hasErrors, errors } = await verifyHtmlCode(htmlToVerify);
        if (hasErrors) {
          console.warn(`⚠️ verifyHtmlCode phát hiện lỗi runtime ở hội thoại ${id}:`, errors);
          res.write(`data: ${JSON.stringify({ warning: `⚠️ Đã test thử code vừa sinh, phát hiện lỗi runtime: ${errors[0]}` })}\n\n`);
        }
      }
    } catch (verifyErr) {
      console.error('⚠️ Lỗi khi verify code (bỏ qua, không ảnh hưởng chat):', verifyErr.message);
    }

    // 📎 Với code KHÔNG PHẢI HTML (JS, Python, v.v. - không chạy thật được như HTML trong browser),
    // nhờ Gemini "đọc lại và soát lỗi" 1 lần nữa trước khi coi như xong - rẻ/nhanh hơn chạy thật nhưng
    // KHÔNG chắc chắn bằng (Gemini có thể bỏ sót/báo nhầm). Bọc try/catch riêng, lỗi không ảnh hưởng chat.
    try {
      const codeMatch = fullAiResponse.match(/```(\w+)?\n([\s\S]*?)```/);
      const lang = (codeMatch?.[1] || '').toLowerCase();
      if (codeMatch && lang !== 'html') { // html đã được verifyHtmlCode xử lý riêng ở trên
        const reviewApiKey = aiService.getAvailableKeyForSummary();
        const issues = await aiService.reviewCode(codeMatch[2], lang || null, reviewApiKey);
        if (issues) {
          console.warn(`⚠️ reviewCode phát hiện vấn đề ở hội thoại ${id}:`, issues);
          res.write(`data: ${JSON.stringify({ warning: `🔍 Tự soát lại code, phát hiện:\n${issues}` })}\n\n`);
        }
      }
    } catch (reviewErr) {
      console.error('⚠️ Lỗi khi review code (bỏ qua, không ảnh hưởng chat):', reviewErr.message);
    }

    // 📎 Đối chiếu câu trả lời với chính data tra cứu đã dùng - bắt trường hợp Gemini bịa/nói sai dù có
    // data thật trong tay. CHỈ chạy khi response có trích dẫn [n] (factCheckResponse tự lọc điều kiện
    // này) - tránh tốn thêm 1 lượt gọi cho mọi tin nhắn. Bọc try/catch riêng, lỗi không ảnh hưởng chat.
    try {
      const factCheckApiKey = aiService.getAvailableKeyForSummary();
      const factIssues = await aiService.factCheckResponse(fullAiResponse, searchResult, factCheckApiKey);
      if (factIssues) {
        console.warn(`⚠️ factCheckResponse phát hiện vấn đề ở hội thoại ${id}:`, factIssues);
        res.write(`data: ${JSON.stringify({ warning: `⚠️ Đối chiếu lại với nguồn tra cứu, phát hiện chỗ có thể sai:\n${factIssues}` })}\n\n`);
      }
    } catch (factErr) {
      console.error('⚠️ Lỗi khi fact-check (bỏ qua, không ảnh hưởng chat):', factErr.message);
    }

    if (fullAiResponse) {
      const aiMsgId = crypto.randomUUID();
      db.prepare('INSERT INTO messages (id, conversation_id, role, content) VALUES (?, ?, ?, ?)')
        .run(aiMsgId, id, 'assistant', fullAiResponse);

      if (conversation.title === 'Cuộc hội thoại mới') {
        const titleSource = content || fileName || 'Tệp đính kèm';
        const newTitle = titleSource.length > 25 ? titleSource.substring(0, 25) + '...' : titleSource;
        db.prepare('UPDATE conversations SET title = ? WHERE id = ?').run(newTitle, id);
      }

      updateSummaryInBackground(id, messageCount + 2);
      updateUserProfileInBackground(id, messageCount + 2);
    }

    res.write(`data: [DONE]\n\n`);
    res.end();

  } catch (error) {
    console.error('Lỗi API Stream:', error);
    if (res.headersSent) {
      res.write(`data: ${JSON.stringify({ error: 'Lỗi phát sinh trong tiến trình AI generate dữ liệu.' })}\n\n`);
      res.end();
    } else {
      res.status(500).json({ error: 'Lỗi kết nối API Gemini: ' + error.message });
    }
  }
};
