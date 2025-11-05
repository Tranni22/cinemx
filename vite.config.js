import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Cho phép tất cả các host (bao gồm ngrok)
    allowedHosts: ['.ngrok-free.app', '.ngrok-free.dev'], 
    
    // Nếu bạn muốn, có thể mở port cố định
    port: 5173,

    // Cho phép truy cập từ bất kỳ IP nào (hữu ích khi test bằng điện thoại hoặc máy khác)
    host: true,
  },
});
