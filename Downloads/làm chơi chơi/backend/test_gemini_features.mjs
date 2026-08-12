// test_gemini_features.mjs
// Script test ĐỘC LẬP, KHÔNG đụng gì tới agent.js - chỉ kiểm tra 2 tính năng mới chưa từng
// được gọi thật hôm nay: (1) embedContent (dùng cho RAG memory + search_code),
// (2) generateContent với responseMimeType json (dùng cho review_code_for_bugs).
//
// Cách chạy: đặt file này CÙNG THƯ MỤC với .env đang có GEMINI_API_KEY_1..19,
// rồi chạy: node test_gemini_features.mjs

import 'dotenv/config';
import { GoogleGenAI } from '@google/genai';

const API_KEYS = Object.keys(process.env)
  .filter(k => k.startsWith('GEMINI_API_KEY'))
  .map(k => process.env[k])
  .filter(Boolean);

if (API_KEYS.length === 0) {
  console.error('❌ Không tìm thấy GEMINI_API_KEY nào trong .env cùng thư mục với script này.');
  process.exit(1);
}

console.log(`🔑 Tìm thấy ${API_KEYS.length} key, dùng key đầu tiên để test.\n`);
const ai = new GoogleGenAI({ apiKey: API_KEYS[0] });

// ===== TEST 1: embedContent =====
console.log('=== TEST 1: ai.models.embedContent() ===');
try {
  const result = await ai.models.embedContent({
    model: 'gemini-embedding-001',
    contents: 'User thích màu xanh dương và làm việc múi giờ UTC+7',
    config: { outputDimensionality: 768 }
  });
  const values = result?.embeddings?.[0]?.values;
  if (Array.isArray(values) && values.length > 0) {
    console.log(`✅ THÀNH CÔNG - nhận được vector ${values.length} chiều.`);
    console.log(`   5 giá trị đầu: [${values.slice(0, 5).map(v => v.toFixed(4)).join(', ')}...]`);
  } else {
    console.log('❌ THẤT BẠI - gọi được nhưng KHÔNG lấy được mảng values đúng đường dẫn result.embeddings[0].values');
    console.log('   Cấu trúc thật trả về:', JSON.stringify(result, null, 2).slice(0, 500));
  }
} catch (err) {
  console.log('❌ THẤT BẠI - lỗi khi gọi:', err.message);
}

console.log('\n' + '='.repeat(50) + '\n');

// ===== TEST 2: generateContent với responseMimeType json (dùng cho review_code_for_bugs) =====
console.log('=== TEST 2: generateContent responseMimeType json ===');
try {
  const result = await ai.models.generateContent({
    model: 'gemini-3.5-flash-lite',
    contents: 'Trả lời CHÍNH XÁC JSON sau, không thêm chữ gì khác: {"hasIssues": false}',
    config: { responseMimeType: 'application/json' }
  });
  const text = (result.text || '').trim();
  console.log('📄 Text thô trả về:', JSON.stringify(text));
  try {
    const parsed = JSON.parse(text);
    console.log('✅ THÀNH CÔNG - parse JSON trực tiếp OK (không bị dính markdown fence):', parsed);
  } catch (e) {
    const fenceMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
    if (fenceMatch) {
      const parsed2 = JSON.parse(fenceMatch[1].trim());
      console.log('⚠️ THÀNH CÔNG NHƯNG có dính markdown fence (đã tự bóc được, code fallback trong agent.js hoạt động đúng):', parsed2);
    } else {
      console.log('❌ THẤT BẠI - không parse được kể cả sau khi thử bóc fence:', e.message);
    }
  }
} catch (err) {
  console.log('❌ THẤT BẠI - lỗi khi gọi:', err.message);
}

console.log('\n' + '='.repeat(50));
console.log('Xong. Copy TOÀN BỘ output ở trên gửi lại cho Claude.');
