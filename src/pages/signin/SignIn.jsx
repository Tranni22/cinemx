import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useDispatch } from "react-redux";
import { setUser } from "../../store/userSlice"; // Import action từ userSlice
import "./style.scss";

const SignIn = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const navigate = useNavigate();
  const dispatch = useDispatch();

  const handleSignIn = async (e) => {
    e.preventDefault();
    setSuccessMessage("");
    setErrorMessage("");

    try {
      const response = await fetch("http://localhost:5009/api/signin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        if (errorData.error === "Tài khoản không tồn tại") {
          setErrorMessage("Tài khoản không hợp lệ, vui lòng đăng ký tài khoản mới!");
        } else if (errorData.error === "Sai mật khẩu") {
          setErrorMessage("Email hoặc mật khẩu không đúng!");
        } else {
          setErrorMessage(errorData.error || "Thông tin đăng nhập không hợp lệ");
        }
        return;
      }

      const data = await response.json();
      // Lưu token và thông tin người dùng vào localStorage
      localStorage.setItem("token", data.token);
      localStorage.setItem("user", JSON.stringify({ email: data.email, username: data.username }));
      // Cập nhật Redux store
      dispatch(setUser({ email: data.email, username: data.username }));

      setSuccessMessage("Đăng nhập thành công!");
      setTimeout(() => {
        setSuccessMessage("");
        navigate("/"); // Chuyển hướng sau khi đăng nhập thành công
      }, 2000);
    } catch (error) {
      setErrorMessage("Có lỗi xảy ra, vui lòng thử lại sau!");
    }
  };

  return (
    <div className="signInContainer">
      <div
        className={`messageContainer ${successMessage ? "success" : ""} ${errorMessage ? "error" : ""}`}
        style={{ opacity: successMessage || errorMessage ? 1 : 0 }}
      >
        {successMessage || errorMessage}
      </div>

      <div className="signInBox">
        <h2>Đăng Nhập</h2>
        <form onSubmit={handleSignIn}>
          <div className="inputField">
            <label>Email</label>
            <input
              type="email"
              placeholder="Nhập email của bạn"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div className="inputField">
            <label>Mật Khẩu</label>
            <input
              type="password"
              placeholder="Nhập mật khẩu của bạn"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <button type="submit" className="signInButton">
            Đăng Nhập
          </button>
        </form>
        <p className="registerLink">
          Bạn chưa có tài khoản?{" "}
          <span onClick={() => navigate("/signup")}>Đăng Ký</span>
        </p>
      </div>
    </div>
  );
};
export default SignIn;
