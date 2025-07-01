# 🔐 Secure File Transfer System

## 🎯 Giới thiệu bài toán

Hệ thống này được xây dựng để mô phỏng quy trình **gửi và nhận file an toàn** trong môi trường mạng hạn chế băng thông.  
Bài toán đặt ra:  
- Một giảng viên cần gửi file `assignment.txt` đến hệ thống chấm điểm.  
- Để tiết kiệm băng thông, file được **chia thành 3 phần nhỏ**.  
- Mỗi phần phải được **mã hóa**, **ký số**, và kèm **hash kiểm tra toàn vẹn**.  
- Bên nhận sẽ kiểm tra chữ ký và hash trước khi giải mã và ghép file.  
- Nếu dữ liệu hợp lệ, hệ thống trả về **ACK**, nếu không, trả về **NACK**.  

Quy trình đảm bảo:
- **Bảo mật** dữ liệu (mã hóa DES)
- **Xác thực** nguồn gửi (RSA ký số)
- **Toàn vẹn** nội dung (SHA-512)

---

## 🛠️ Kỹ thuật và công nghệ sử dụng

| Thành phần | Công nghệ |
|------------|-----------|
| Ngôn ngữ lập trình | Python |
| Framework web | Flask |
| Mã hóa đối xứng | DES |
| Mã hóa khóa phiên | RSA 1024-bit (PKCS#1 v1.5) |
| Ký số | RSA + SHA-512 |
| Hàm băm | SHA-512 |
| Frontend | HTML, Jinja2 templates |
| Trao đổi dữ liệu | JSON |

---

## ✨ Các chức năng chính

1. **Đăng ký, đăng nhập người dùng**
   - Tạo tài khoản, xác thực người dùng.
2. **Handshake**
   - Gửi và nhận tín hiệu sẵn sàng ("Hello!" / "Ready!").
3. **Trao đổi và mã hóa khóa phiên**
   - Tạo SessionKey
   - Mã hóa SessionKey bằng RSA
4. **Chia file thành 3 phần**
   - Mỗi phần được:
     - Mã hóa bằng DES
     - Hash SHA-512
     - Ký số RSA
   - Mỗi phần gửi kèm:
     ```json
     {
       "iv": "<Base64>",
       "cipher": "<Base64>",
       "hash": "<Hex>",
       "sig": "<Signature>"
     }
     ```
5. **Kiểm tra toàn vẹn và chữ ký**
   - Bên nhận xác minh hash và chữ ký từng phần.
6. **Giải mã và ghép file**
   - Khi hợp lệ, giải mã và ghép thành `assignment.txt`.
7. **Phản hồi kết quả**
   - Trả về ACK hoặc NACK.
8. **Quản lý file**
   - Lịch sử upload / download.
   - Danh sách file đã nhận.
9. **Giao diện quản trị**
   - Quản lý người dùng và file từ dashboard.

---

## 🖥️ Giao diện và hoạt động

### Trang chính

- **Trang đăng ký và đăng nhập**
  
  <img src="Screenshot 2025-07-01 165121.png" alt="Main App Interface" width="800">


- **Dashboard**
  
  <img src="Screenshot 2025-07-01 165202.png" alt="Main App Interface" width="800">

- **Trang upload file**
  
  <img src="Screenshot 2025-07-01 165225.png" alt="Main App Interface" width="800">

- **Trang lịch sử giao dịch**
  
  <img src="Screenshot 2025-07-01 165310.png" alt="Main App Interface" width="800">

- **Quản lý khóa**
  
  <img src="Screenshot 2025-07-01 165415.png" alt="Main App Interface" width="800">


