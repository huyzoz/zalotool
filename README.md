# ZaloTool — Mod cho Zalo iOS 26.11.02.1

Mod cho Zalo iOS **26.11.02.1** (build 261102804), cài qua TrollStore trên iPhone không jailbreak (đã nhắm tới iPhone 7 Plus, iOS 15.8.8).

Repo: **huyzoz/zalotool** — repo public duy nhất, build + release trực tiếp trên GitHub Actions của repo này. Repo chỉ chứa source + script + workflow; file IPA gốc và framework được tải từ Google Drive trong lúc build (có kiểm tra SHA-256).

## 4 tính năng (bật/tắt trong app)

Mở Zalo → **Cài đặt → Tài khoản và Bảo mật → Tool** (dòng đầu tiên). Trang Tool có 4 công tắc, **mặc định đều BẬT**. Tắt một mục là trở về hành vi gốc của Zalo cho mục đó ngay, không cần khởi động lại.

| # | Tính năng | Hành vi |
|---|---|---|
| 1 | Ẩn đã xem / đang gõ / đã nhận | Người khác không thấy bạn đã xem, đang gõ hay đã nhận tin nhắn |
| 2 | Hỏi trước khi gọi | Hiện bảng xác nhận trước khi thực hiện cuộc gọi (1-1, nhóm, gọi số) |
| 3 | Hỏi trước khi gửi ảnh | Hiện bảng xác nhận trước khi gửi ảnh/video trong trình sửa |
| 4 | Chống thu hồi | Tin nhắn bị thu hồi vẫn hiển thị như bình thường |

## Cài đặt

1. Tải `ZaloTool-26.11.02.1.ipa` từ [release v26.11.02.1-mod](../../releases/tag/v26.11.02.1-mod), kiểm tra SHA-256 với file `.sha256` kèm theo.
2. Cài qua TrollStore.
3. Mở Zalo, vào Cài đặt → Tài khoản và Bảo mật → Tool để bật/tắt tính năng.

## Giới hạn — đọc trước khi cài

- **Chưa có hứa hẹn "không crash tuyệt đối".** Bản mod này chưa từng chạy trên máy thật; lần chạy đầu tiên trên iPhone 7 Plus là phép thử quyết định. Hãy thử trên tài khoản phụ trước nếu có thể.
- **Hỏi trước khi gửi ảnh chỉ chặn ở trình sửa ảnh/video.** Ảnh gửi nhanh (quick-send) hoặc gửi từ các đường không qua trình sửa sẽ **không** hiện bảng xác nhận — đó là giới hạn thiết kế đã biết.
- **"Phễu duy nhất" chưa được chứng minh lúc chạy.** Phân tích tĩnh cho thấy mọi cuộc gọi đi đều qua `VoipFlowManager`, nhưng chỉ test trên máy thật mới khẳng định được không có đường gọi nào lọt.
- **Đường seen phụ.** Nếu đã xem vẫn lọt sau khi bật mục 1, các selector phụ (`sendSeenServerPARQueue`, `retrySendSeenList`…) là ứng viên bổ sung cho bản sau.
- **Bản này chỉ dùng cho Zalo 26.11.02.1.** Zalo cập nhật lên bản mới là các hook phải kiểm tra lại (tên class/selector có thể đổi).

## Vì sao bản cũ crash, và bản này làm khác

Bản mod cũ (Zalo 261002) crash ngay khi bấm icon, trước cả khi hiện giao diện. Nguyên nhân khả nghi nhất: cả 4 binary bị chạm đều mang **cùng một CodeDirectory mẫu** (ident `com.icraze.gtatracker`, 805 slots) — hash trang không khớp code thật nên kernel kill process khi fault-in một trang của bất kỳ binary nào bị tiêm.

Bản này khắc phục bằng cách ký lại **tất cả** binary bị chạm bằng `ldid -S` (tính lại hash trang thật cho từng binary), rồi kiểm tra bằng script rằng không có hai binary nào còn chung một CodeDirectory. Bước `ldid` trong workflow là **bắt buộc** — fail là fail cả job, không "best-effort".

## Build

Chạy workflow `build-zalotool` (workflow_dispatch) trên repo. Workflow tự: build `ZaloTool.dylib` (arm64, iOS 15.0), tải IPA gốc + framework từ Drive (kiểm SHA-256), verify hook table với IPA gốc, tiêm weak-load vào `BackupProtoLib` (không chạm binary chính Zalo), ký lại bằng `ldid -S`, đóng gói và publish release `v26.11.02.1-mod`.
