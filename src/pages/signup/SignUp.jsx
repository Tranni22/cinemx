import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useDispatch } from 'react-redux';
import { setUser } from '../../store/userSlice'; // Redux action to set user
import "./style.scss";

const SignUp = () => {
  const [formData, setFormData] = useState({ username: "", email: "", password: "" });
  const [errorMessage, setErrorMessage] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const navigate = useNavigate();
  const dispatch = useDispatch();

  // Cập nhật thông tin người dùng vào Redux sau khi đăng ký thành công
  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage("");
    setSuccessMessage("");
  
    try {
      const response = await fetch("http://localhost:5009/api/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });
  
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Đăng ký không thành công");
      }
  
      const userData = await response.json(); // Dữ liệu người dùng từ API
  
      // Dispatch để cập nhật Redux với dữ liệu người dùng
      dispatch(setUser(userData));
  
      // Lưu thông tin người dùng vào localStorage
      localStorage.setItem("user", JSON.stringify(userData));
  
      // Cập nhật thông báo thành công
      setSuccessMessage("Bạn đã đăng ký thành công!");
  
      // Điều hướng đến trang chủ sau khi đăng ký
      setTimeout(() => {
        navigate("/"); // Điều hướng về trang chủ hoặc trang login
      }, 2000);
    } catch (error) {
      setErrorMessage(error.message);
    }
  };

  useEffect(() => {
    if (successMessage) {
      const successElement = document.querySelector(".successMessage");
      successElement.classList.add("show");
      setTimeout(() => successElement.classList.remove("show"), 3000);
    }
  }, [successMessage]);

  useEffect(() => {
    if (errorMessage) {
      const errorElement = document.querySelector(".alertMessage");
      errorElement.classList.add("show");
      setTimeout(() => errorElement.classList.remove("show"), 3000);
    }
  }, [errorMessage]);

  return (
    <div className="signup-container">
      <div className="signup-box">
        <h2>Đăng Ký</h2>
        <form onSubmit={handleSubmit}>
          <div className="signup-inputField">
            <label>Tên Người Dùng</label>
            <input
              type="text"
              name="username"
              placeholder="Nhập tên của bạn"
              value={formData.username}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
              required
            />
          </div>
          <div className="signup-inputField">
            <label>Email</label>
            <input
              type="email"
              name="email"
              placeholder="Nhập email của bạn"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              required
            />
          </div>
          <div className="signup-inputField">
            <label>Mật khẩu</label>
            <input
              type="password"
              name="password"
              placeholder="Nhập mật khẩu của bạn"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              required
            />
          </div>
          <button type="submit">Đăng Ký</button>
        </form>
      </div>

      {/* Hiển thị thông báo thành công */}
      {successMessage && <div className="successMessage">{successMessage}</div>}

      {/* Hiển thị thông báo lỗi */}
      {errorMessage && <div className="alertMessage">{errorMessage}</div>}
    </div>
  );
};

export default SignUp;
