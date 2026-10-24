# ESP32-AES-IoT-Security
Source code hệ thống điều khiển IoT an toàn (End-to-End Encryption) và đánh giá hiệu năng thuật toán mã hóa AES trên nền tảng ESP32.
# Chuyển dự án sang AES-128-GCM

Bản sửa ngày 05/10/2026, dựa trên toàn bộ crypto_app.c và crypto_app.h An dán trong tin nhắn mới nhất. Đây là hai file thay thế trong thư mục `AES_GCM/main/` của dự án hiện có, không phải một dự án ESP-IDF độc lập.

## 1. Các thay đổi

- `AES_KEY_SIZE`: từ 32 byte thành 16 byte; chỉ định nghĩa tại `crypto_app.h`.
- Hai mảng khóa trong `test_crypto_engine()` và `process_mqtt_payload()`: giữ 16 byte đầu của khóa thử nghiệm cũ, từ `0x01` đến `0x10`.
- Hai lệnh `mbedtls_gcm_setkey(..., AES_KEY_SIZE * 8)` giờ truyền 128 bit.
- Thêm chú thích A–D mô tả các phép biến đổi AES thực hiện trong mbedTLS/backend AES.
- Thêm `stdbool.h` trực tiếp để khai báo `bool`, sửa tên thuật toán trong hai log và làm rõ một số chú thích.

Các nhánh xử lý lệnh, timestamp, giới hạn độ dài, đo thời gian, bật/tắt AES-GCM và lời gọi `hardware_set_state()` được giữ nguyên. Các file MQTT, Wi-Fi, phần cứng, CA và CMake không cần đổi do việc chuyển độ dài khóa.

## 2. Cấu trúc AES-128

AES-128 có khóa 128 bit, khối 128 bit và 10 vòng. KeyExpansion tạo 11 khóa vòng, mỗi khóa 16 byte.

- **A. Substitute Bytes Transformation / SubBytes.** Thay từng byte State theo S-box AES; đây là phép thế phi tuyến.
- **B. ShiftRows.** Dịch vòng trái các hàng 0, 1, 2, 3 lần lượt 0, 1, 2, 3 byte.
- **C. MixColumns.** Trộn các byte trong mỗi cột bằng phép nhân ma trận cố định trên GF(2^8). Vòng cuối không thực hiện bước này.
- **D. AddRoundKey.** XOR State với khóa vòng tương ứng.

Trình tự: AddRoundKey ban đầu; vòng 1–9 thực hiện A → B → C → D; vòng 10 thực hiện A → B → D.

Đây là cấu trúc bên trong AES. GCM bổ sung bộ đếm, GHASH, AAD và Authentication Tag. mbedTLS thực thi toàn bộ; không cần và không được chèn thêm một lượt SubBytes/ShiftRows/MixColumns/AddRoundKey lên payload trước hoặc sau lệnh GCM. GCM dùng phép AES mã hóa thuận ở cả hai chiều.

## 3. Đồng bộ khóa Python bắt buộc

Trong `web_server.py`, thay toàn bộ định nghĩa `AES_KEY` cũ bằng đoạn sau. Giữ nguyên các route, giao diện và hàm đóng gói của bản web mới nhất.

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY = bytes([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
])
assert len(AES_KEY) == 16
aesgcm = AESGCM(AES_KEY)
```

Nếu `generator.py` cũng tự tạo gói tin, đặt cùng khóa 16 byte tại đó. Đây vẫn là khóa thử nghiệm cố định trong mã nguồn, không phải một khóa bí mật mới được cấp phát.

Không thay Nonce 12 byte, Tag 16 byte, AAD timestamp 8 byte little-endian hoặc thứ tự:

```text
Nonce(12) + Tag(16) + Timestamp/AAD(8) + Ciphertext
```

Độ dài payload `ON` vẫn là 38 byte = 76 ký tự HEX; `OFF` vẫn là 39 byte = 78 ký tự HEX. Độ dài khóa không được cộng vào payload.

Các gói AES-256 cũ không xác thực được bằng khóa AES-128. Sau khi cập nhật cả hai đầu, tạo gói mới để kiểm thử; không lấy gói HEX cũ làm mẫu hợp lệ.

## 4. Cài vào dự án và chạy lại

1. Chép `main/crypto_app.c` và `main/crypto_app.h` từ gói này vào `GCM/AES_GCM/main/`.
2. Đổi khóa Python theo mục 3 và khởi động lại web.
3. Mở ESP-IDF Terminal tại `GCM/AES_GCM/`, chạy:

```bash
idf.py -B build-perf -DSDKCONFIG=sdkconfig.perf build flash monitor
```

Lệnh này dùng cấu hình đo; xem mục **Build trên máy hiện tại** để biết lý do và
cách kiểm tra.

4. Khi `ENABLE_AES_GCM=1`: gửi gói mã hóa mới từ web; xác nhận ON/OFF và hành vi auto-lock/ACK của module phần cứng hiện có. MQTT.fx gửi ON/OFF thuần phải bị từ chối.
5. Để chạy đối chứng: đổi `ENABLE_AES_GCM` thành 0, build/flash lại; gửi trực tiếp ON/OFF từ MQTT.fx. Đây là công tắc lúc biên dịch, không phải công tắc đổi thuật toán tức thời trên web. TLS vẫn hoạt động như cấu hình hiện có.

## 5. Kiểm chứng bản sửa

Đã biên dịch riêng module C trên máy tính bằng GCC, liên kết mbedTLS 2.28.8 thực; thay GPIO, bộ định thời ESP và RNG bằng adapter chỉ dùng trong kiểm thử. Đã kiểm tra cả hai chế độ AES bật/tắt. Các adapter không nằm trong mã giao cho ESP32.

Các nhóm kiểm tra đã đạt:

1. Định nghĩa độ dài khóa duy nhất và hai mảng khóa đều đủ đúng 16 byte.
2. Đối chiếu mã thực thi với bản An dán: chỉ thay khóa và tên thuật toán trong log, giữ nguyên logic xử lý.
3. Vector AES-128-GCM với khóa zero 16 byte, IV zero 12 byte, plaintext zero 16 byte, AAD rỗng: ciphertext `0388dace60b6a392f328c2b971b2fe78`, tag `ab6e47d42cec13bdf53a67b21257bddf`.
4. Mã hóa/giải mã C–Python cho dữ liệu 2, 3, 16, 64, 92, 128 byte ở API mật mã.
5. Thay đổi ciphertext, tag, AAD hoặc nonce làm xác thực thất bại; bộ đệm đầu ra được xóa.
6. Gói dùng khóa AES-256 cũ bị từ chối bởi AES-128.
7. Gói ON/OFF từ Python qua `process_mqtt_payload()` gọi đúng trạng thái GPIO mô phỏng; giữ độ dài HEX 76/78.
8. Các kiểm tra kích thước và gói hết hạn hiện có tiếp tục hoạt động trong host test.
9. Khi tắt AES, ON/OFF thuần vẫn được nhận trong host test.

Chưa build toàn bộ dự án bằng ESP-IDF v5.5.x, chưa flash thiết bị, chưa kiểm thử MQTT/TLS, relay, còi, auto-lock và ACK vật lý trong môi trường này. Kết quả host không phải số liệu hiệu năng của ESP32. Nonce cố định chỉ được dùng trong adapter để đối chiếu vector; firmware vẫn gọi `esp_fill_random()` như bản gốc.

## 6. Giới hạn kế thừa cần ghi đúng trong báo cáo

Đổi AES-256 sang AES-128 không tự sửa cơ chế chống replay hoặc các lỗi ứng dụng. Theo đúng phạm vi chỉ đổi thuật toán, bản này giữ nguyên các điểm sau:

- Cửa sổ timestamp ±10 giây chưa chặn một gói hợp lệ bị phát lại ngay trong cửa sổ đó; fallback đặt giờ từ gói tin vẫn nằm trước xác thực.
- Phép so sánh ON/OFF dùng `strncmp()` hiện có được giữ nguyên; chưa bổ sung kiểm tra chính xác độ dài lệnh.
- Trong `mqtt_app.c` An dán, bộ đệm nhị phân 128 byte gồm 36 byte overhead, nên ciphertext thực tế qua MQTT tối đa là 92 byte. Giới hạn 128 byte trong crypto không tăng giới hạn tầng MQTT. Các test API mật mã 128 byte không chứng minh MQTT nhận được payload này.

## Tài liệu thuật toán

- NIST FIPS 197: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
- NIST SP 800-38D: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
- mbedTLS GCM API: https://mbed-tls.readthedocs.io/projects/api/en/v3.6.3/api/file/gcm_8h/
# Dữ liệu ESP32 cần gửi để dashboard có số đo thật

Web hỗ trợ giao thức hiện có và thêm một topic đọc telemetry. Không cần thay payload điều khiển AES để đọc được số đo.

## Trạng thái: đã tương thích với hardware_control.c

Topic `device/esp32/status`, JSON, retain=false:

```json
{"status":"UNLOCKED","message":"Cửa đã mở (Tự khóa sau 3s)"}
```

```json
{"status":"LOCKED","message":"Cửa đã đóng an toàn"}
```

Khi firmware gọi `mqtt_app_publish_status()`, web nhận và lưu lịch sử. ALARM được hiển thị thành cảnh báo; AUTH_FAIL và REPLAY_REJECT cũng được hỗ trợ nếu firmware phát các trạng thái này. Không tự suy ra loại lỗi từ một ALARM chung.

## Số đo: topic device/esp32/telemetry

Gửi JSON, retain=false; có thể gửi mỗi 2–5 giây từ task bình thường. Các trường độc lập và không bắt buộc có đủ. **Chỉ gửi trường đã thực sự đo được**; bỏ trường chưa có, không điền số 0 thay cho chưa đo.

| Trường | Kiểu | Đơn vị / ý nghĩa |
|---|---|---|
| voltage_v | số | Điện áp đo bằng INA219, V |
| current_ma | số | Dòng điện đo bằng INA219, mA |
| power_w | số | Công suất đo/tính từ số đo thật, W |
| heap_free_bytes | số | Heap trống trên ESP32, byte |
| decrypt_us | số | Thời gian giải mã/xác thực ESP32 đã đo, µs |
| pir | boolean | true có chuyển động; false không có |
| aes_enabled | boolean | Giá trị chế độ nhận của firmware |
| relay_on | boolean | Trạng thái relay do ESP32 quản lý |

Ví dụ cấu trúc **minh họa, không phải số đo của thiết bị An**:

```json
{"voltage_v":12.05,"current_ma":145.0,"power_w":1.747,"heap_free_bytes":145200,"decrypt_us":82,"pir":false,"aes_enabled":true,"relay_on":false}
```

### Bước tích hợp tối thiểu trong firmware hiện tại

1. Khai báo hàm publish chung trong `mqtt_app.h`, triển khai tại `mqtt_app.c`, dùng client đã kết nối để gửi JSON tới topic telemetry. Có thể dùng `esp_mqtt_client_enqueue()` để đưa bản tin vào outbox từ task gửi số đo.
2. Lấy heap bằng API ESP-IDF, lấy PIR/INA219 qua driver đã tích hợp; lưu `end_time - start_time` ở chỗ đo giải mã vào biến/snapshot được bảo vệ phù hợp.
3. Đóng JSON bằng cJSON hoặc snprintf có kiểm tra độ dài. Những trường chưa có driver phải bỏ khỏi JSON.
4. Gửi từ một task telemetry; không chờ mạng trong callback software timer auto-lock. Web không thể tự đọc chân GPIO hay INA219 qua MQTT nếu firmware chưa publish.
5. Với `aes_enabled`, gửi giá trị boolean từ `ENABLE_AES_GCM`; đây là báo cáo chế độ, không phải nhận lệnh đổi chế độ từ web.

Phần nguồn firmware mới nhất đã cung cấp chưa có driver đọc INA219/PIR hoặc topic telemetry. Bản giao này triển khai phía web và hợp đồng dữ liệu; không giả lập các số đo để che phần firmware còn thiếu. Đèn phụ trợ cũng cần một định dạng lệnh phân biệt Relay 1/Relay 2 trước khi cho phép điều khiển riêng.

## Cách đọc kết quả

- ACK/status báo trạng thái logic của relay, chưa xác nhận vị trí cửa/chốt bằng cảm biến vật lý.
- Web ghi giờ nhận MQTT (UTC+7); không đồng nhất thời điểm này với thời điểm GPIO thay đổi.
- Lệnh từ web dùng `ON:<16HEX>` / `OFF:<16HEX>` và ACK khớp `command_id`; RTT được lưu riêng. Ô thời gian thực thi dùng số đo trên ESP32 như mô tả bên dưới.
- Thời gian trong `crypto_app.c` hiện bao quanh cả hàm aes_gcm_decrypt (khởi tạo, setkey, xác thực/giải mã, free); phải ghi đúng phạm vi khi công bố số liệu.


### Thời gian thực thi lệnh trên ESP32

Web hiển thị thời gian ESP32 nhận đủ bản tin MQTT → đặt GPIO relay thành công,
đơn vị ms. Firmware lấy hai mốc bằng `esp_timer_get_time()`, giữ mốc nhận trong
hàng đợi phần cứng và gửi `execution_us` trong ACK khớp `command_id`. Số đo bao
gồm HEX-decode, giải mã/xác thực khi AES bật, kiểm tra lệnh và chờ hàng đợi;
không gồm truyền mạng, mã hóa Python hay chuyển động cơ khí của chốt.

Cần build/flash firmware mới và khởi động lại web. ACK của firmware cũ không có
`execution_us` vẫn xác nhận trạng thái nhưng web báo thiếu số đo, không dùng RTT
thay thế. SQLite tự thêm cột `execution_ms`; số RTT cũ giữ trong `rtt_ms`, không
trộn vào thống kê thực thi mới. CSV xuất cả hai cột.

Kiểm thử web: `python -m unittest discover -s tests -v` từ thư mục `AES_GCM`.


### Build trên máy hiện tại

Công cụ ESP-IDF nằm tại `C:/Espressif/frameworks/esp-idf-v5.5.5`. Dùng thư mục
build riêng (`build-perf`) để tránh cache cũ trỏ tới `D:/GCM/AES_GCM` hoặc
`D:/Espressif`.

**Bắt buộc dùng cấu hình đo.** Số liệu trong báo cáo được lấy từ
`sdkconfig.perf`: CPU 240 MHz, biên dịch PERF (`-O2`), log mức WARN, heap hooks
bật, MQTT poll 10 ms. `main/command_memory.c` báo lỗi biên dịch nếu thiếu
`CONFIG_HEAP_USE_HOOKS`, nên build bằng `sdkconfig` mặc định sẽ fail. Trong
ESP-IDF Terminal, mở thư mục dự án `AES_GCM` và chạy:

```bash
idf.py -B build-perf -DSDKCONFIG=sdkconfig.perf build
idf.py -B build-perf -DSDKCONFIG=sdkconfig.perf -p COM4 flash monitor
```

Chọn lại cổng nếu thiết bị dùng cổng khác. Phải giữ `-DSDKCONFIG=sdkconfig.perf`
kể cả khi thư mục gốc đã có `sdkconfig`: file đó bị `.gitignore` và trên máy này
đang là bản debug 160 MHz, không dùng để đo. Nếu muốn dùng `sdkconfig` mặc định,
xóa nó rồi build lại; ESP-IDF sẽ sinh từ `sdkconfig.defaults`, đã chứa cùng
baseline đo.

Kiểm tra build thực tế đã đúng cấu hình:

```bash
grep -E 'CONFIG_(ESP_DEFAULT_CPU_FREQ_MHZ|COMPILER_OPTIMIZATION_PERF|HEAP_USE_HOOKS|LOG_DEFAULT_LEVEL |MQTT_POLL_READ_TIMEOUT_MS)' build-perf/config/sdkconfig.h
```

Kết quả phải có 240 MHz, `CONFIG_COMPILER_OPTIMIZATION_PERF 1`,
`CONFIG_HEAP_USE_HOOKS 1`, `CONFIG_LOG_DEFAULT_LEVEL 2` và poll 10 ms. Build
bằng cấu hình khác vẫn chạy nhưng số đo không so sánh được với số trong báo cáo.


### Mức GPIO điều khiển khóa

Theo phản hồi thực tế: lệnh ON cũ xuất GPIO18 LOW nhưng chốt lại thò ra.
Firmware đã đổi sang `DOOR_UNLOCK_LEVEL=1`, `DOOR_LOCK_LEVEL=0`: ON xuất HIGH
để mở, OFF/boot xuất LOW để khóa. Mức HIGH/LOW này mô tả đầu ra điều khiển
khóa, không suy ra tiếp điểm COM–NO/COM–NC hay cực tính cuộn relay. GPIO19
kênh phụ vẫn giữ HIGH như trước. Sau khi nạp, cần xác nhận chốt thò ra khi
OFF/boot và thu vào khi ON ở cả AES bật/tắt; web vẫn xác nhận GPIO, chưa có
cảm biến vị trí chốt.


### Độ trễ điều khiển đầu-cuối có xác nhận (E2E)

Web hiển thị thêm E2E (ms), bên cạnh thời gian xử lý lệnh tại ESP32. Python
lấy mốc `perf_counter_ns()` trước khi chuẩn bị/mã hóa payload lệnh, kết thúc
khi nhận ACK không retained khớp `command_id`, `command`, `phase=applied` và
trạng thái GPIO mong đợi. Hai mốc cùng máy Python, không cần đồng bộ đồng hồ
với ESP32. Khoảng đo gồm đóng gói/mã hóa Python, xử lý gửi, MQTT hai chiều và
xử lý ESP32; không gồm yêu cầu HTTP từ trình duyệt, cập nhật giao diện hay
chuyển động cơ khí. ACK xác nhận GPIO, chưa xác nhận vị trí chốt.

Cột SQLite/CSV `e2e_ms` lưu riêng; `rtt_ms` vẫn giữ nghĩa từ trước publish tới
ACK, `execution_ms` vẫn là số đo trên ESP32. Bản ghi cũ không có E2E để trống,
không chuyển RTT cũ sang E2E. Thống kê có N/min/mean/P95/max và lọc AES bật/tắt.
Mất ACK sau 8 giây tính từ gửi, gửi thất bại hoặc lệnh bị từ chối không tạo
số đo 0. Các mẫu tamper/replay/oversize không đo E2E. Firmware ACK hiện tại
đã đủ thông tin, chỉ cần khởi động lại web, không cần nạp firmware cho tính
năng này.


### Chẩn đoán lỗi INA219 sau khi chuyển nhánh đo

Firmware gửi thêm `sensor_stage`, `sensor_error_name`, `bus_raw`, `shunt_raw`
trong telemetry. Web hiển thị bước lỗi: `write_config` / `read_bus` /
`read_shunt` là giao dịch I2C; `conversion_timeout` là chờ chuyển đổi;
`math_overflow` là cờ OVF; `shunt_out_of_range` là shunt ngoài ±320mV.
Thanh ghi raw chưa đọc trong mẫu được đánh dấu -1.

Mã 259 (`ESP_ERR_INVALID_STATE`) có thể đến từ driver I2C hoặc kiểm tra
OVF/shunt trong firmware; chỉ mã này chưa xác định được nguyên nhân.
Chẩn đoán chi tiết cần nạp firmware mới và khởi động lại web. Khi cảm biến
lỗi, số đo vẫn để null/— thay vì tạo số 0 hoặc dùng lại số đo cũ.

## Phạm vi đánh giá hiện tại

Đánh giá các lệnh ON/OFF của ứng dụng: thời gian mã hóa Python,
xác thực–giải mã ESP32, xử lý đến GPIO, độ trễ đầu-cuối và năng lượng
bo theo chu kỳ AES bật/tắt. Đã gỡ chức năng thử theo kích thước khỏi web,
API và firmware. Các bảng SQLite size_sessions/size_samples cũ được giữ
nguyên nếu đã tồn tại; ứng dụng không còn tạo hoặc cập nhật chúng.
Dữ liệu cũ thuộc phiên bản phương pháp trước; không kết luận hiệu năng
trên các kích thước khác từ lệnh ON/OFF ngắn.
Việc gỡ cũng bỏ task và buffer thử nghiệm khỏi RAM firmware; đo lại cả
hai chế độ trên cùng firmware mới khi lập cặp so sánh năng lượng.

## Năng lượng bo ESP32 cho đợt chu kỳ ON/OFF

Trang **Năng lượng chu kỳ** chạy thật các lệnh ON/OFF qua MQTT/TLS, mặc định
100 chu kỳ mỗi đợt (200 lệnh), một đợt AES bật và một đợt AES tắt. Chọn
1–100 chu kỳ và 1–5 cặp; thứ tự hai chế độ đảo giữa các cặp. Một cặp là kết
quả thăm dò; lặp nhiều cặp mới đánh giá được dao động. Không khôi phục phép
đo cửa sổ 1 giây từng lệnh đã gỡ. Không tự chạy khi mở web hoặc nạp firmware.

Trước mỗi đợt, web đổi AES có ACK và gửi OFF chuẩn bị, nằm ngoài cửa sổ.
Yêu cầu START có AES-GCM xác thực cấu hình/challenge mới, kể cả khi điều
khiển đang nhận plaintext. Body `START:<id16>:<cycles>:<challenge32>`;
ABORT dùng `ABORT:<id16>:<challenge32>`. AAD = timestamp8 + topic yêu cầu;
wire nonce12/tag16/timestamp8/ciphertext rồi HEX, không vượt 256 ký tự.
Challenge xoay khi chấp nhận yêu cầu; không dựa vào đồng hồ ESP32 cho START.

Cửa sổ bắt đầu trên ESP32 khi ráp đủ ON đầu tiên, trước HEX/AES, kết thúc
ngay sau đặt GPIO OFF cuối. Mỗi lần Python gửi một lệnh có ID mới, nonce mới
khi AES bật, đợi ACK đúng ID/command/mode rồi gửi tiếp. Không có sleep giữ
trạng thái chủ động. Vẫn có chờ mạng, lịch RTOS, xử lý máy chủ/ghi log và
phản hồi; các khoảng này nằm trong tổng năng lượng đợt. ACK cuối để kiểm
chứng đủ lệnh, việc truyền ACK cuối nằm sau điểm kết thúc GPIO. Không có
cảm biến xác nhận chốt cơ khí; cần chuẩn bị tải phù hợp cho ON/OFF liên tục.

INA219 đo nhánh 5V bo, không có USB cấp đi vòng; ghi rõ relay/buzzer/tải nào
cùng nguồn. Sensor lấy mẫu thường khoảng 20ms trong đợt, tích phân online
hình thang theo timestamp thực, giữ giá trị đầu/cuối ở hai biên. Không lưu
raw mẫu trong RAM theo độ dài đợt để tránh bộ đệm tăng không giới hạn.
Telemetry/log lỗi định kỳ tạm hoãn, tiến độ web lấy từ ACK. Mọi chế độ dùng
cùng phương pháp lấy mẫu; nhận từng lệnh không đánh thức lại sensor làm
thay đổi tần suất lấy mẫu theo tốc độ lệnh. Chỉ bắt đầu đo mới đánh thức.

Kết quả: tổng J, thời lượng thực, mẫu/lỗi, độ phủ, max gap, công suất/
điện áp/dòng TB có trọng số thời gian, CPU MHz, Wi-Fi PS, IDF và cấu hình
hardware AES. Năng lượng bo gồm xử lý mật mã, nhận bản tin, Wi-Fi, ACK giữa
các lệnh và phần cứng chung nhánh. Không đo năng lượng mã hóa Python.
Hai payload bật/tắt khác độ dài: đây là chi phí tích hợp AES-GCM trong ứng
dụng, không phải năng lượng riêng các vòng AES.

Chỉ tính E/N chu kỳ và E/(2N) lệnh khi đủ 2N ACK và danh sách ID/thứ tự trên
ESP32 khớp máy chủ, không trùng, ON/OFF xen kẽ; không mất mạng/can thiệp,
>=30 mẫu, thời lượng >=1s, lỗi sensor=0, max gap<=100ms, độ phủ>=90%,
điện áp TB 4–5,5V và công suất TB dương. E/lệnh là trung bình gộp ON+OFF;
không được diễn giải thành số đo riêng ON hoặc OFF. Đợt thiếu lệnh vẫn
giữ kết quả nếu nhận được nhưng không chia cho số chu kỳ hoàn tất thiếu.

So sánh chỉ ghép cặp có đủ hai đợt hợp lệ, tính trung bình J/chu kỳ và
chênh lệch có dấu. CI95 Student-t theo chênh lệch từng cặp (2–5 cặp) không
bao gồm sai số hệ thống sensor; dưới 3 cặp ghi kết quả thăm dò. Không ép
chênh lệch âm thành 0, không dùng 0 thay kết quả chưa nhận được.

Nút dừng chờ xong OFF của chu kỳ hiện tại rồi ABORT nếu chưa đủ N. Firmware
tự hủy khi chờ ON đầu >30s hoặc cửa sổ >600s. Mất kết nối/ACK có thể khiến
đầu ra chưa được xác nhận; máy chủ dừng gửi, thử ABORT và OFF khôi phục khi
có thể, ngoài cửa sổ. Thiết lập AES ban đầu được khôi phục có xác nhận; lỗi
khôi phục ghi trong trạng thái lượt. Nếu START có thể đã được nhận nhưng
chưa nhận done/idle sau khi hủy, web giữ trạng thái chưa xác nhận và không
gửi đổi AES bằng challenge có thể đã cũ; chờ trạng thái mới từ ESP32.
Web khởi động lại đánh dấu interrupted,
không tự chạy tiếp; Dừng/khôi phục có thể gửi ABORT cho ID đang được ESP32
báo qua MODE_STATE. Không dùng MQTT.fx hoặc client khác gửi song song.

Nạp firmware mới từ build-local và khởi động lại web. Broker cần quyền hai
topic `device/esp32/cycle-energy/request`, `device/esp32/cycle-energy/result`.
MODE_STATE cần `cycle_energy_supported:true`, `cycle_energy_protocol:1`.
Web đăng ký START/ABORT và kết quả bằng ID đợt, bỏ retained/ID lạ/kết quả lặp.
SQLite: `cycle_sessions`, `cycle_blocks`, `cycle_commands`; không sửa số đo
cũ. CSV từng đợt lưu chất lượng/cấu hình; CSV lệnh liên kết bảng measurements
để giữ encrypt/decrypt/execution/E2E. seq=0 chuẩn bị, seq=999 khôi phục,
nằm ngoài phép đo; seq=1..2N là các lệnh đo. API GET `/api/cycle-energy`,
POST `/api/cycle-energy/start`, POST `/api/cycle-energy/stop`, GET
`/api/cycle-energy.csv?session=<id>` và `/api/cycle-energy-commands.csv`.

### Điều kiện MQTT khi so sánh AES bật/tắt

Wi-Fi dùng cố định `WIFI_PS_NONE` sau khi start để loại ảnh hưởng độ trễ
nhận gói theo modem-sleep/DTIM trong phép thử. Đây là thay đổi điều kiện
thực nghiệm, có thể làm tăng công suất nền; không được ghép cặp số đo cũ
`wifi_ps=1` với số đo mới `wifi_ps=0`. CSV lưu giá trị thực tế của từng đợt.
Tắt tiết kiệm Wi-Fi không bảo đảm khắc phục timeout Internet/TLS tới broker.

`sdkconfig` và `sdkconfig.defaults` đặt `CONFIG_MQTT_POLL_READ_TIMEOUT_MS=10`
với `CONFIG_MQTT_USE_CUSTOM_CONFIG=y`. ESP-MQTT trong IDF 5.5.5 mặc định
poll đọc tới 1000ms; enqueue từ task phần cứng không đánh thức poll này.
ACK plaintext có thể nằm chờ dù GPIO đã được đặt. Giảm poll áp dụng chung
cho cả hai chế độ, không thêm khoảng nghỉ giữa các lệnh.

Lệnh có mã ID chỉ gửi một ACK chứa cả `decrypt_us` và `execution_us`.
Không gửi thêm telemetry giải mã trước GPIO ở chế độ AES; ON/OFF cũ
không có ID vẫn gửi số đo giải mã riêng. Thời gian xác thực–giải mã vẫn
bao gồm init/setkey/auth-decrypt/free như trước.

Phải nạp lại firmware để áp dụng. Dữ liệu cũ giữ nguyên; đo lại cả hai
chế độ với cùng firmware mới, vì lịch phục vụ MQTT và chi phí duy trì
hoạt động đã thay đổi. Poll 10ms không bảo đảm độ trễ mạng 10ms; Wi-Fi,
TLS và broker vẫn đóng góp vào độ trễ đầu-cuối.


## Bộ nhớ xử lý từng lệnh ON/OFF

Firmware protocol 2 đo hai thứ trong cùng tác vụ xử lý lệnh: heap cấp phát đỉnh (0 byte là hợp lệ — đường này không cấp phát động) và **stack đỉnh từng lệnh**, bằng cách tô lại vùng stack chưa dùng bằng 0xA5 rồi quét byte bị ghi sâu nhất. Ngữ cảnh `mbedtls_gcm_context` 392 byte nằm trên stack và đã nằm trong stack đỉnh; không cộng thêm. Chênh `stack_peak` giữa AES bật và tắt là phần RAM vận hành tăng thêm của AES.

Web có khối **Bộ nhớ xử lý lệnh · ESP32**, bảng so sánh riêng ON/OFF ở hai chế độ AES và CSV từng lệnh. Mẫu v1 cũ không có `stack_peak`; phải nạp firmware protocol 2 và đo lại cả hai chế độ, không suy stack từ dữ liệu v1. Cần khởi động lại web và Ctrl+F5. Phạm vi, giới hạn và hướng dẫn báo cáo: [docs/command-memory.md](docs/command-memory.md).
