# Bộ nhớ xử lý lệnh ON/OFF — protocol 1

Firmware mới gửi `memory` trong ACK của từng lệnh có mã 16 HEX. Web lưu mẫu
trong cùng bản ghi lệnh (`measurements.command_memory_json`), chỉ sau ACK
đặt GPIO thành công, đúng mã, lệnh và chế độ. Các bản ghi cũ giữ nguyên;
không có số đo thì hiển thị `—`, không tự điền 0.

## Mốc và đơn vị

- Bắt đầu: vào `process_mqtt_payload()`, sau khi MQTT ráp đủ và HEX đã được
  giải mã (AES bật); trước xử lý nội dung payload.
- Kết thúc: kiểm tra xong ON/OFF và mã lệnh; trước khi đưa vào hàng đợi phần
  cứng. Không gồm chờ GPIO, tạo/gửi ACK hoặc dọn buffer sau khi đưa lệnh đi.
- AES bật có init → setkey → auth_decrypt → free, kiểm tra timestamp, log
  ứng dụng và phân tích lệnh. AES tắt phân tích lệnh bản rõ.
- `heap_peak`: tổng byte của các khối cấp phát mới đang tồn tại đồng thời
  cao nhất, theo alloc/free hook, trong tác vụ MQTT ở cửa sổ trên.
- `heap_retained`: các khối được cấp phát trong cửa sổ còn tồn tại khi đóng
  cửa sổ. Khác 0 chưa đủ kết luận rò rỉ: thư viện có thể giữ dữ liệu dùng lại.
- `allocations`: số cấp phát thành công được theo dõi trong cửa sổ.
- `heap_before/after`: heap trống 8-bit toàn hệ thống, có thể chịu tác động
  của tác vụ khác; hiệu hai giá trị không phải heap riêng của AES.
- `context_bytes`: sizeof(mbedtls_gcm_context) của bản build, nằm trên stack
  trong hàm giải mã; 0 ở chế độ bản rõ. Không bao gồm toàn bộ stack của chuỗi
  lời gọi hoặc heap do thư viện cấp phát.
- `stack_free_min`: uxTaskGetStackHighWaterMark(NULL), ESP-IDF trả byte;
  mức stack trống thấp nhất từ khi tạo tác vụ MQTT. Đây không phải số đo
  đỉnh stack độc lập từng lệnh, không dùng để trừ AES bật/tắt.

## Cách theo dõi

Bật `CONFIG_HEAP_USE_HOOKS=y` trong sdkconfig và sdkconfig.defaults. Hai hook
ở `command_memory.c` chỉ xử lý task đang đo, bỏ qua ISR và task khác. Hook
không ghi log, cấp phát bộ nhớ hoặc khóa. Theo dõi tối đa 32 khối cùng lúc;
tràn bảng làm mẫu invalid. Slot được dùng lại sau free. Kích thước là byte
do hook cấp phát báo, không cộng header/phân mảnh của allocator.

Cửa sổ đồng bộ hiện tại chỉ dùng malloc/calloc/free; không chuyển quyền sở
hữu khối nhớ sang task khác. ESP-IDF 5.5.5 không cung cấp old pointer trong
alloc hook của realloc: không dùng bộ đo này cho luồng có realloc hoặc
cross-task free. In-place realloc phát hiện được sẽ làm mẫu invalid. Nếu
thay đổi luồng xử lý về sau phải rà lại điều kiện này.

Không dùng heap trống thấp nhất từ boot để tính đỉnh của lệnh. Heap đỉnh 0
là kết quả hợp lệ khi không có cấp phát động: phần xử lý vẫn dùng stack,
bộ nhớ tĩnh và các buffer đã có sẵn. Không cộng sizeof context và high-water
stack để gọi là “tổng RAM AES”. Phép đo này đánh giá heap cấp phát khi xử lý
lệnh có/không có AES, không đo toàn bộ RAM riêng của thuật toán hoặc RAM PC.

## So sánh và sử dụng

Nạp firmware mới, khởi động lại web, Ctrl+F5. Gửi ON/OFF bằng web ở cả hai
chế độ. Khối “Bộ nhớ xử lý lệnh · ESP32” nằm dưới các số đo trên trang điều
khiển. Bảng nhóm riêng ON/AES bật, ON/AES tắt, OFF/AES bật, OFF/AES tắt;
chênh lệch là trung bình heap đỉnh AES bật trừ AES tắt cho cùng lệnh.

CSV riêng `/api/command-memory.csv` chứa từng mẫu, trạng thái hợp lệ, mã
lệnh, chế độ và các giá trị. Các lệnh trong lượt đo năng lượng cũng được
ghi nếu có ACK phù hợp. Không dùng lệnh thất bại, thiếu ACK, thiếu số đo,
sai phiên bản hoặc tràn bảng để tính trung bình.

Bộ đo tăng RAM tĩnh (32 slot + trạng thái/owner), kích thước mỗi phần tử
hàng đợi phần cứng và ACK, thêm thời gian hook/chụp heap/quét watermark.
Không lấy số đo tốc độ/năng lượng của firmware cũ so với firmware mới.
Hai chế độ cần cùng firmware, cùng tải mạng và lặp lại đủ lần. Đỉnh heap
của lệnh đầu có thể khác các lệnh sau do khởi tạo lười của thư viện/log.

Tài liệu API chính thức: https://docs.espressif.com/projects/esp-idf/en/v5.5.5/esp32/api-reference/system/heap_debug.html

Đã kiểm tra build và kiểm thử web; kết quả heap thực trên bo cần được xác
nhận sau khi nạp firmware, không suy ra từ dữ liệu giả lập trong unit test.
