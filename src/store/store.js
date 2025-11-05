import { configureStore } from '@reduxjs/toolkit';
import homeSlice from './homeSlice';
import userSlice from './userSlice'; // Import userSlice

export const store = configureStore({
  reducer: {
    home: homeSlice,
    user: userSlice, // Thêm reducer user
  },
});
