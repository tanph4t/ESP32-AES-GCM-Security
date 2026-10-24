# Bộ nhớ xử lý lệnh ON/OFF — protocol 2

Firmware gửi `memory` trong ACK của từng lệnh có mã 16 HEX. Web lưu mẫu
trong cùng bản ghi lệnh (`measurements.command_memory_json`), chỉ sau ACK
đặt GPIO thành công, đúng mã, lệnh và chế độ. Các bản ghi v1 cũ giữ nguyên;
chúng không có `stack_peak` và được đếm riêng, không trộn vào thống kê stack.
Không có số đo thì hiển thị `—`, không tự điền 0.

## Vì sao phải đo thêm stack

Đường xử lý lệnh dùng `mbedtls_gcm_context` và buffer `decrypted` như biến
cục bộ trên stack; nhánh này không gọi `malloc`/`calloc`. Vì vậy phép đo
heap cho kết quả 0 byte ở cả hai chế độ — đúng, nhưng không trả lời được
AES tốn bao nhiêu RAM. Protocol 1 chỉ có heap và watermark stack tích lũy,
nên không dùng để kết luận chi phí RAM. Protocol 2 đo trực tiếp độ sâu stack
mà từng lệnh sử dụng.

## Mốc và đơn vị

- Bắt đầu: vào `process_mqtt_payload()`, sau khi MQTT ráp đủ và HEX đã được
  giải mã (AES bật); trước xử lý nội dung payload.
- Kết thúc: kiểm tra xong ON/OFF và mã lệnh; trước khi đưa vào hàng đợi phần
  cứng. Không gồm chờ GPIO, tạo/gửi ACK hoặc dọn buffer sau khi đưa lệnh đi.
- AES bật có init → setkey → auth_decrypt → free, kiểm tra timestamp và phân
  tích lệnh. AES tắt phân tích lệnh bản rõ.
- `stack_peak`: số byte stack bị dùng dưới mốc SP lúc bắt đầu, gồm khung hàm
  của cửa sổ đo, buffer `decrypted[129]` (chỉ nhánh AES), ngữ cảnh GCM và
  các khung hàm mbedtls. Không gồm stack của ISR, tác vụ khác, bộ nhớ tĩnh
  hay heap. Đây là số byte đã dùng, không phải "stack còn trống".
- `context_bytes`: `sizeof(mbedtls_gcm_context)` của bản build, 392 byte,
  nằm trong `stack_peak`; không cộng thêm lần nữa để tránh tính trùng.
- `heap_peak`: tổng byte của các khối cấp phát mới đang tồn tại đồng thời
  cao nhất, theo alloc/free hook, trong tác vụ MQTT ở cửa sổ trên.
- `heap_retained`: các khối được cấp phát trong cửa sổ còn tồn tại khi đóng
  cửa sổ. Khác 0 chưa đủ kết luận rò rỉ: thư viện có thể giữ dữ liệu dùng lại.
- `allocations`: số cấp phát thành công được theo dõi trong cửa sổ.
- `heap_before/after`: heap trống 8-bit toàn hệ thống, có thể chịu tác động
  của tác vụ khác; hiệu hai giá trị không phải heap riêng của AES.
- `stack_free_min`: `uxTaskGetStackHighWaterMark(NULL)`, ESP-IDF trả byte,
  đọc sau khi kết thúc. Vì mỗi lệnh tô lại vùng stack chưa dùng, giá trị này
  không còn là watermark tích lũy từ khi tạo tác vụ như v1; chỉ dùng để
  tham khảo, không dùng thay `stack_peak`.

## Cách đo stack

`command_memory.c` lấy SP hiện tại, đọc stack trống còn lại và tô vùng stack
chưa dùng ngay dưới SP bằng byte 0xA5 (byte fill của FreeRTOS). Vùng tô dài
tối đa 2.048 byte, chừa 64 byte sát SP và 64 byte ở đáy để không chạm khung
hàm đang chạy, canary hay vùng dự trữ của tác vụ. Kích thước vùng lấy từ
`uxTaskGetStackHighWaterMark`, nên đáy vùng luôn nằm trong stack của tác vụ.

Khi lệnh xử lý xong, hàm quét từ đáy vùng lên: byte đầu tiên khác 0xA5 là
địa chỉ bị ghi sâu nhất. `stack_peak = SP_lúc_đầu − địa_chỉ_sâu_nhất`, nên
luôn cộng thêm khoảng 64 byte biên; hằng số này giống nhau ở hai chế độ nên
không ảnh hưởng chênh lệch. Nếu
vùng tô bị dùng hết (byte đáy đã bị ghi) hoặc không có byte nào bị ghi, mẫu
bị đánh dấu `valid=false` thay vì báo một đỉnh bị đánh giá thấp.

Byte 0xA5 trùng với byte fill FreeRTOS dùng khi tạo tác vụ, nên cách này
không phá cơ chế phát hiện tràn stack. Phép tô/quét chỉ chạy trong tác vụ
MQTT, không cấp phát, không ghi log. Chi phí khoảng vài microsecond cho mỗi
lệnh, nằm trong `execution_us` của cả hai chế độ nên không tạo chênh lệch
riêng cho AES.

Giới hạn: chỉ đo phần stack nằm dưới mốc SP lúc bắt đầu; các khung hàm đã
có sẵn phía trên không được tính. Cửa sổ 2.048 byte đủ cho đường xử lý hiện
tại (stack trống khoảng 3,6 KB), nhưng nếu một thay đổi sau này dùng nhiều
stack hơn, mẫu sẽ thành `valid=false` để tránh kết luận sai.

## So sánh và sử dụng

Nạp firmware mới, khởi động lại web, Ctrl+F5. Gửi ON/OFF bằng web ở cả hai
chế độ. Khối “Bộ nhớ xử lý lệnh · ESP32” nằm dưới các số đo trên trang điều
khiển. Bảng nhóm riêng ON/AES bật, ON/AES tắt, OFF/AES bật, OFF/AES tắt;
chênh lệch stack là trung bình `stack_peak` AES bật trừ AES tắt cho cùng lệnh.

Kết luận hợp lệ từ dữ liệu v2:

- Heap cấp phát đỉnh 0 byte ở cả hai chế độ: đường xử lý không cấp phát động.
- `stack_peak` ON trừ OFF là phần stack tăng thêm khi bật AES-GCM trong cùng
  điều kiện chạy; phần lớn là ngữ cảnh 392 byte cộng khung hàm mbedtls.
- Đây là RAM vận hành của đường xử lý lệnh, không phải tổng RAM tĩnh của
  firmware, không phải RAM phía PC và không phải bộ nhớ flash của mã mbedtls.

Mẫu v1 không có `stack_peak`, chỉ dùng cho thống kê heap. Muốn báo cáo chi
phí RAM của AES phải nạp firmware protocol 2 và đo lại cả hai chế độ; không
suy `stack_peak` từ dữ liệu v1.

CSV riêng `/api/command-memory.csv` chứa từng mẫu, trạng thái hợp lệ, mã
lệnh, chế độ và các giá trị (cột `stack_peak` trống với mẫu v1). Các lệnh
trong lượt đo năng lượng cũng được ghi nếu có ACK phù hợp. Không dùng lệnh
thất bại, thiếu ACK, thiếu số đo, sai phiên bản hoặc vùng stack bị tràn để
tính trung bình.

Bộ đo tăng RAM tĩnh (32 slot, trạng thái/owner, biến cửa sổ stack), kích
thước mỗi phần tử hàng đợi phần cứng và ACK, thêm thời gian hook/tô quét
stack/chụp heap. Không lấy số đo tốc độ/năng lượng của firmware cũ so với
firmware mới. Hai chế độ cần cùng firmware, cùng tải mạng và lặp lại đủ lần.
Đỉnh heap/stack của lệnh đầu có thể khác các lệnh sau do khởi tạo lười của
thư viện/log.

Tài liệu API chính thức: https://docs.espressif.com/projects/esp-idf/en/v5.5.5/esp32/api-reference/system/heap_debug.html

Đã kiểm tra build và kiểm thử web; số stack thực trên bo cần được xác nhận
sau khi nạp firmware, không suy ra từ dữ liệu giả lập trong unit test.
