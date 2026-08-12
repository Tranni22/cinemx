// ============================================================
// verifyCode.js — Module ĐỘC LẬP, không import/đụng gì tới agent.js
// Nếu Puppeteer lỗi/crash, hàm này CHỈ trả về { hasErrors: false }
// (coi như "không phát hiện lỗi") chứ không bao giờ throw ra ngoài,
// nên dù cái file này có hỏng, code chat chính của mày vẫn chạy bình thường.
// ============================================================

import puppeteer from 'puppeteer';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import crypto from 'crypto';

const VERIFY_TIMEOUT_MS = 8000; // tối đa 8s cho mỗi lần verify, quá thì bỏ qua

/**
 * Chạy 1 đoạn HTML (có JS bên trong) trong browser headless,
 * bắt console.error + uncaught exception thật sự xảy ra khi chạy.
 *
 * @param {string} htmlCode - toàn bộ nội dung file .html
 * @returns {Promise<{hasErrors: boolean, errors: string[]}>}
 */
export async function verifyHtmlCode(htmlCode) {
  // Guard: input rỗng/không hợp lệ thì bỏ qua luôn, không cố chạy
  if (!htmlCode || typeof htmlCode !== 'string' || htmlCode.trim().length === 0) {
    return { hasErrors: false, errors: [] };
  }

  const tmpPath = path.join(os.tmpdir(), `verify_${crypto.randomUUID()}.html`);
  let browser = null;

  try {
    await fs.writeFile(tmpPath, htmlCode, 'utf-8');

    browser = await puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox'] // an toàn khi chạy trong môi trường hạn chế quyền
    });

    const page = await browser.newPage();
    const errors = [];

    page.on('console', (msg) => {
      if (msg.type() === 'error') errors.push(`[console.error] ${msg.text()}`);
    });
    page.on('pageerror', (err) => {
      errors.push(`[uncaught exception] ${err.message}`);
    });
    page.on('requestfailed', (req) => {
      // Chỉ log request tới file local bị fail, bỏ qua lỗi mạng ngoài (vd CDN chặn vì không có internet)
      if (req.url().startsWith('file://')) {
        errors.push(`[request failed] ${req.url()}`);
      }
    });

    await page.goto(`file://${tmpPath}`, { waitUntil: 'load', timeout: VERIFY_TIMEOUT_MS });

    // Đợi thêm chút để các script chạy setTimeout/event ban đầu kịp bắn lỗi (nếu có)
    await new Promise((resolve) => setTimeout(resolve, 1000));

    return { hasErrors: errors.length > 0, errors };

  } catch (err) {
    // Bất kỳ lỗi nào ở bước verify (timeout, puppeteer chưa cài, v.v...)
    // đều KHÔNG được làm sập luồng chat chính -> log ra rồi coi như bỏ qua.
    console.error('⚠️ verifyHtmlCode lỗi (bỏ qua, không ảnh hưởng chat):', err.message);
    return { hasErrors: false, errors: [] };

  } finally {
    // Dọn dẹp CHẮC CHẮN xảy ra dù thành công hay lỗi
    if (browser) {
      try { await browser.close(); } catch (_) {}
    }
    try { await fs.unlink(tmpPath); } catch (_) {}
  }
}
