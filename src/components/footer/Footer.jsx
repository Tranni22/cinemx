import React from "react";
import {
    FaFacebookF,
    FaInstagram,
    FaTwitter,
    FaLinkedin,
} from "react-icons/fa";

import ContentWrapper from "../contentWrapper/ContentWrapper";

import "./style.scss";

const Footer = () => {
    return (
        <footer className="footer">
            <ContentWrapper>
                <ul className="menuItems">
                    <li className="menuItem">Điều khoản sử dụng</li>
                    <li className="menuItem">Chính sách bảo mật</li>
                    <li className="menuItem">Giới thiệu</li>
                    <li className="menuItem">Blog</li>
                    <li className="menuItem">Câu hỏi thường gặp</li>
                </ul>
                <div className="infoText">
                Trang web xem phim của chúng tôi mang đến trải nghiệm giải trí tuyệt vời
                với hàng ngàn bộ phim đa thể loại. Từ bom tấn Hollywood đến những bộ phim 
                độc lập đầy cảm xúc, tất cả đều được cập nhật liên tục với chất lượng hình ảnh 
                sắc nét và âm thanh sống động. Đăng nhập ngay để khám phá kho phim phong phú 
                và tận hưởng những giây phút thư giãn cùng gia đình và bạn bè.
                </div>
                <div className="socialIcons">
                    <span className="icon">
                        <FaFacebookF />
                    </span>
                    <span className="icon">
                        <FaInstagram />
                    </span>
                    <span className="icon">
                        <FaTwitter />
                    </span>
                    <span className="icon">
                        <FaLinkedin />
                    </span>
                </div>
            </ContentWrapper>
        </footer>
    );
};
export default Footer;