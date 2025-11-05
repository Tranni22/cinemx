import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  user: null, // default state is null
};

const userSlice = createSlice({
  name: 'user',
  initialState,
  reducers: {
    setUser: (state, action) => {
      state.user = action.payload; // Set user data when logged in or signed up
    },
    clearUser: (state) => {
      state.user = null; // Clear user data on logout
    },
  },
});

export const { setUser, clearUser } = userSlice.actions;
export const selectUser = (state) => state.user?.user; // Select the user from state

export default userSlice.reducer;
