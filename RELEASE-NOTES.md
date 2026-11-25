# Zalo iOS 26.11.02.1 — Mod (v26.11.02.1-mod)

Bản mod đầu tiên cho Zalo 26.11.02.1 (build 261102804), cài qua TrollStore.

## Tính năng — 4 công tắc trong Cài đặt → Tài khoản và Bảo mật → Tool (mặc định đều BẬT)

1. **Ẩn đã xem / đang gõ / đã nhận** — người khác không thấy bạn đã xem, đang gõ hay đã nhận tin nhắn.
2. **Hỏi trước khi gọi** — hiện bảng xác nhận trước khi thực hiện cuộc gọi (1-1, nhóm, gọi số điện thoại).
3. **Hỏi trước khi gửi ảnh** — hiện bảng xác nhận trước khi gửi ảnh/video trong trình sửa.
4. **Chống thu hồi** — tin nhắn bị thu hồi vẫn hiển thị như bình thường.

Tắt một công tắc là trở về hành vi gốc của Zalo cho mục đó ngay, không cần khởi động lại.

## Lưu ý

- Bản này chưa từng chạy trên máy thật — hãy thử trên tài khoản phụ trước nếu có thể. Không có hứa hẹn "không crash tuyệt đối".
- Hỏi trước khi gửi ảnh chỉ chặn ở trình sửa ảnh/video; ảnh gửi nhanh không qua trình sửa sẽ không hiện bảng xác nhận.
- Chỉ dùng cho Zalo 26.11.02.1. Zalo cập nhật bản mới là các hook phải kiểm tra lại.

## Kiểm tra file

- `ZaloTool-26.11.02.1.ipa` — kiểm tra SHA-256 với file `.sha256` kèm theo trước khi cài.
- IPA gốc (stock, chưa mod) có SHA-256 `3ea5625c…590864`; binary chính Zalo không bị sửa trong bản mod này.
