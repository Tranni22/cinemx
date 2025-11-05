import React, { useState, useEffect } from "react";
import { HiOutlineSearch, HiOutlineUser } from "react-icons/hi";
import { SlMenu } from "react-icons/sl";
import { VscChromeClose } from "react-icons/vsc";
import { useNavigate, useLocation } from "react-router-dom";
import { useSelector, useDispatch } from "react-redux";
import { selectUser, clearUser } from "../../store/userSlice"; // Import selectors và actions

import "./style.scss";
import ContentWrapper from "../contentWrapper/ContentWrapper";
import logo from "../../assets/cinemx.png";

const Header = () => {
  const [show, setShow] = useState("top");
  const [lastScrollY, setLastScrollY] = useState(0);
  const [mobileMenu, setMobileMenu] = useState(false);
  const [query, setQuery] = useState("");
  const [showSearch, setShowSearch] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const user = useSelector(selectUser); // Lấy thông tin người dùng từ Redux
  const dispatch = useDispatch();

  const hideHeaderRoutes = ["/signin", "/signup"];
  const shouldHideHeader = hideHeaderRoutes.includes(location.pathname);

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [location]);

  useEffect(() => {
    const controlNavBar = () => {
      if (window.scrollY > 200) {
        if (window.scrollY > lastScrollY && !mobileMenu) {
          setShow("hide");
        } else {
          setShow("show");
        }
        setLastScrollY(window.scrollY);
      } else {
        setShow("top");
      }
    };
    window.addEventListener("scroll", controlNavBar);
    return () => window.removeEventListener("scroll", controlNavBar);
  }, [lastScrollY, mobileMenu]);

  const openSearch = () => {
    setMobileMenu(false);
    setShowSearch(true);
  };

  const handleLogout = () => {
    localStorage.removeItem("token"); // Xóa token khi đăng xuất
    localStorage.removeItem("user");  // Xóa thông tin user trong localStorage
    dispatch(clearUser()); // Cập nhật Redux
    navigate("/signin");
  };

  const openMobileMenu = () => {
    setMobileMenu(true);
    setShowSearch(false);
  };

  const searchQueryHandler = (event) => {
    if (event.key === "Enter" && query.length > 0) {
      navigate(`/search/${query}`);
      setTimeout(() => setShowSearch(false), 1000);
    }
  };

  const navigationHandler = (type) => {
    navigate(`/explore/${type}`);
    setMobileMenu(false);
  };

  const signInHandler = () => {
    navigate("/signin");
  };

  if (shouldHideHeader) {
    return null;
  }

  return (
    <header className={`header ${mobileMenu ? "mobileView" : ""} ${show}`}>
      <ContentWrapper>
        <div className="logo" onClick={() => navigate("/")}>
          <img src={logo} alt="Cinemx Logo" />
        </div>
        <ul className="menuItems">
          <li className="menuItem">
            <HiOutlineSearch onClick={openSearch} />
          </li>
          {user ? (
            <li className="menuItem">
              <span>Xin chào, {user.username}</span> {/* Hiển thị tên người dùng */}
              <ul className="dropdownMenu">
                <li onClick={() => navigate("/profile")}>Thông tin tài khoản</li>
                <li onClick={handleLogout}>Đăng xuất</li>
              </ul>
            </li>
          ) : (
            <li className="menuItem" onClick={signInHandler}>
              <HiOutlineUser />
            </li>
          )}
          <li className="menuItem" onClick={() => navigationHandler("movie")}>
            Phim
          </li>
          <li className="menuItem" onClick={() => navigationHandler("tv")}>
            Chương trình TV
          </li>
        </ul>
      </ContentWrapper>
      {showSearch && (
        <div className="searchBar">
          <ContentWrapper>
            <div className="searchInput">
              <input
                type="text"
                placeholder="Search for movie or TV show.."
                onChange={(e) => setQuery(e.target.value)}
                onKeyUp={searchQueryHandler}
              />
              <VscChromeClose onClick={() => setShowSearch(false)} />
            </div>
          </ContentWrapper>
        </div>
      )}
    </header>
  );
};
export default Header;
