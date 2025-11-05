import axios from "axios";

// Đường dẫn cơ bản đến TMDb API
const BASE_URL = 'https://api.themoviedb.org/3';

// Lấy token từ biến môi trường
const TMDB_TOKEN = import.meta.env.VITE_APP_TMDB_TOKEN;

const headers = {
    Authorization: "Bearer " + TMDB_TOKEN,
};

// Hàm lấy dữ liệu từ API
export const fetchDataFromApi = async (url, params) => {
    try {
        const { data } = await axios.get(BASE_URL + url, {
            headers,
            params,
        });
        return data;
    } catch (err) {
        console.log(err);
        return err;
    }
};
