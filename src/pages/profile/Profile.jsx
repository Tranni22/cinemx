import React, { useState } from "react";
import { useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import "./style.scss";

const Profile = () => {
  const navigate = useNavigate();
  const user = useSelector((state) => state.user.user); // Lấy thông tin user từ Redux store

  // State lưu trữ input và thông báo
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [errorMessage, setErrorMessage] = useState("");


  // Chuyển đổi định dạng ngày tháng từ chuỗi ISO
  const formatDate = (dateString) => {
    const options = { year: 'numeric', month: 'long', day: 'numeric' };
    const date = new Date(dateString);
    return date.toLocaleDateString("vi-VN", options); // Hiển thị theo định dạng tiếng Việt
  };

  // Xử lý đổi mật khẩu
  const handleChangePassword = async (e) => {
    e.preventDefault();
    setSuccessMessage(""); // Reset thông báo thành công
    setErrorMessage(""); // Reset thông báo lỗi

    // Kiểm tra nếu mật khẩu mới và xác nhận mật khẩu không khớp
    if (newPassword !== confirmPassword) {
      setErrorMessage("Mật khẩu mới và xác nhận mật khẩu không khớp.");
      return;
    }

    // Kiểm tra mật khẩu mới có đủ 8 ký tự hay không
    if (newPassword.length < 8) {
      setErrorMessage("Mật khẩu mới phải có ít nhất 8 ký tự.");
      return;
    }

    const token = localStorage.getItem("token");
    if (!token) {
      setErrorMessage("Phiên làm việc của bạn đã hết hạn, vui lòng đăng nhập lại.");
      navigate("/Signin"); // Điều hướng người dùng đến trang đăng nhập nếu không có token
      return;
    }

    try {
      const response = await fetch("http://localhost:5009/api/change-password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`, // Gửi token trong header
        },
        body: JSON.stringify({
          currentPassword,
          newPassword,
        }),
      });

      const data = await response.json(); // Lấy dữ liệu phản hồi từ API

      if (!response.ok) {
        throw new Error(data.error || "Có lỗi xảy ra khi thay đổi mật khẩu.");
      }

      // Nếu thành công, hiển thị thông báo thành công
      setSuccessMessage(data.message);  // Thông báo từ API
      setErrorMessage(""); // Reset thông báo lỗi
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (error) {
      setErrorMessage(error.message); // Cập nhật thông báo lỗi
      setSuccessMessage(""); // Reset thông báo thành công
    }
  };

  return (
    <div className="profile-container">
      <h2>Thông Tin Tài Khoản</h2>
      <div className="profile-details">
        <p>
          <strong>Email:</strong> {user?.email}
        </p>
        <p>
          <strong>Tên đăng ký:</strong> {user?.username}
        </p>
        <p>
            <strong>Ngày tạo tài khoản:</strong> {user?.createdAt ? formatDate(user.createdAt) : "Không xác định"}
        </p>
      </div>

      <div className="change-password">
        <h3>Đổi Mật Khẩu</h3>
        <form onSubmit={handleChangePassword}>
          <div className="inputField">
            <label>Mật khẩu hiện tại</label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)} // Sửa lỗi onChange
              required
            />
          </div>
          <div className="inputField">
            <label>Mật khẩu mới</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
            />
          </div>
          <div className="inputField">
            <label>Xác nhận mật khẩu mới</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </div>
          <button type="submit" className="submit-button">
            Cập nhật mật khẩu
          </button>
        </form>

        {/* Thông báo kết quả */}
        {successMessage && <p className="successMessage">{successMessage}</p>}
        {errorMessage && <p className="errorMessage">{errorMessage}</p>}
      </div>
      <button onClick={() => navigate("/")} className="back-button">
        Quay lại Trang Chủ
      </button>
    </div>
  );
};
export default Profile;
