# Rà soát độ trễ AES bật/tắt và năng lượng chu kỳ

Bản ghi lịch sử: chức năng thử theo kích thước được nhắc trong phạm vi
review này đã được gỡ khỏi project theo yêu cầu sau đó. Kết quả phân tích
các lượt đo cũ được giữ nguyên.

## Phạm vi

Rà soát các đường thực thi trong firmware (MQTT, crypto, phần cứng,
INA219, đo chu kỳ, Wi-Fi), Flask/Paho/SQLite, bộ chạy chu kỳ, hiển thị
JavaScript, generator, cấu hình build và các bài kiểm tra. Thư mục build
và môi trường Python là đầu ra/phụ thuộc, không phải một đường điều khiển
khác. Không chạy thử điều khiển phần cứng trong lần rà soát này.

## Bằng chứng từ dữ liệu thực

Lượt hoàn tất `78cc3f444360c605`, bắt đầu 21:07:37 ngày 20/10/2026,
múi giờ Việt Nam. Mỗi chế độ có 200 ACK tương ứng 100 chu kỳ. Firmware
báo IDF 5.5.5, Wi-Fi PS = 0 ở cả hai đợt. Số liệu đọc trực tiếp từ SQLite
ở chế độ chỉ đọc; không chỉnh sửa kết quả.

| Chỉ số | AES bật | AES tắt |
|---|---:|---:|
| Nhận đủ MQTT → đặt GPIO, trung bình ms | 1,775205 | 0,227060 |
| E2E, trung bình ms | 192,249144 | 207,251594 |
| E2E, trung vị ms | 181,907450 | 181,102350 |
| E2E, P95 ms | 246,425600 | 230,617900 |
| Chuẩn bị Python trước publish, trung bình ms (E2E − RTT) | 1,001234 | 0,900645 |
| Thời lượng cửa sổ s | 38,981545 | 42,162458 |
| Công suất trung bình W | 0,623788 | 0,621718 |
| Năng lượng J | 24,316226 | 26,213145 |

Ba mẫu chậm nhất của AES tắt:

| Thứ tự lệnh | Lệnh | E2E ms | Nhận đủ MQTT → GPIO ms |
|---|---|---:|---:|
| 169 | ON | 1392,2533 | 0,177 |
| 175 | ON | 1548,6202 | 0,206 |
| 176 | OFF | 1396,3313 | 0,397 |

Các mẫu này chứng minh phần chậm không nằm trong khoảng xử lý firmware
từ nhận đủ MQTT đến GPIO. E2E còn bao gồm chuẩn bị/lưu mẫu Python, hàng
đợi gửi, truyền hai chiều qua broker và phản hồi. Dữ liệu hiện có chưa
phân tách được từng chặng mạng hoặc thời gian ACK nằm chờ trong outbox.
Không quy toàn bộ E2E trừ execution cho đường truyền thuần túy.

Một lượt khác, `b9258e2a53c136bc`, AES tắt chạy trước: AES tắt hoàn thành
trong 80,182148 s, AES bật trong 83,582642 s. Vì vậy dữ liệu không cho
thấy AES tắt luôn chậm hơn. Không so năng lượng tuyệt đối giữa hai lượt
khác Wi-Fi PS, nguồn hoặc điều kiện hoạt động.

## Đối chiếu code

- `web_server.py:Dashboard.send`: AES tắt gửi thẳng `ON:<id>` hoặc
  `OFF:<id>`, không mã hóa và không có sleep dành riêng cho chế độ này.
  Hai chế độ cùng publish QoS 0, không retained. Cùng clock monotonic
  trước chuẩn bị lệnh và khi nhận ACK; chu kỳ refresh trình duyệt không
  được cộng vào E2E.
- `mqtt_app.c:dispatch_payload`: AES tắt bỏ HEX decode và gọi cùng hàm
  xử lý lệnh. Hai chế độ dùng cùng bộ ráp MQTT và cùng đường phản hồi.
- `crypto_app.c:process_mqtt_payload`: AES tắt đi thẳng tới
  `apply_control_text`; AES bật xác thực/giải mã và kiểm tra timestamp
  rồi tới cùng hàm này. Lệnh có ID hiện không gửi telemetry giải mã dư
  trước GPIO; thời gian giải mã nằm trong ACK.
- `hardware_control.c`: cả hai dùng cùng hàng đợi, cùng task và ACK
  sau GPIO. `xQueueReceive(...,10ms)` thức khi có phần tử, không phải
  sleep 10ms bắt buộc cho từng lệnh. Buzzer giữ cùng quy tắc 120ms,
  không chặn lệnh tiếp theo để đợi tiếng bíp kết thúc.
- `mqtt_app.c:publish_json`: ACK ở cả hai chế độ dùng chung QoS 1 và
  outbox. Poll nhận đã đặt 10ms. Điều này không bảo đảm gửi TLS luôn
  hoàn tất trong 10ms: timeout ghi/kết nối mạng là thông số khác.
- `cycle_energy_web.py:run/command`: ON → chờ ACK → OFF → chờ ACK,
  cùng vòng lặp cho hai chế độ; không có khoảng nghỉ riêng AES tắt.
- `cycle_energy.c` và `ina219_app.c`: cùng thời điểm bắt đầu/kết thúc,
  lịch lấy mẫu và tích phân cho cả hai chế độ. Telemetry định kỳ tạm
  hoãn trong đợt. Năng lượng gồm thời gian chờ giữa các lệnh, nên đợt
  dài hơn có thể tốn nhiều J dù công suất và CPU xử lý thấp hơn.
- `wifi_app.c`: đã dùng WIFI_PS_NONE chung. Dữ liệu lượt 21:07 xác nhận
  wifi_ps=0, nên lượt này không còn dùng cấu hình tiết kiệm Wi-Fi cũ.
- UI chỉ hiển thị số đo máy chủ; không nhân hoặc cộng thêm độ trễ riêng
  khi AES tắt. Generator phục vụ tạo payload thủ công, không chạy trong
  vòng gửi lệnh của web.

## Phát hiện phụ về cấu hình thư mục

`../.vscode/settings.json` của thư mục GCM vẫn trỏ CMake và ESP-IDF tới
ổ D:, còn `.vscode/settings.json` của dự án AES_GCM dùng IDF ổ C: và
build-local. Nếu mở thư mục ngoài thay vì dự án có thể dùng sai cấu hình.
Đây là rủi ro cấu hình riêng, không giải thích số đo lượt 21:07 đã báo
Wi-Fi PS = 0 đúng firmware mới. Không thay cấu hình IDE trong lần rà soát.

## Kết luận và giới hạn

Không tìm thấy nhánh code hiện tại cố ý trì hoãn riêng plaintext. Lượt
được phân tích cho thấy plaintext xử lý trên ESP32 nhanh hơn; trung vị
và P95 E2E cũng thấp hơn, nhưng ba mẫu phản hồi kéo dài làm trung bình
E2E và tổng năng lượng cao hơn. Công suất hai đợt gần bằng nhau; phần
chênh năng lượng ở lượt này chủ yếu gắn với thời lượng hoàn thành.

Log trước có timeout ghi TCP/TLS, gửi lại MQTT và kết nối lại broker.
Chưa xác định được nguyên nhân cụ thể giữa firmware transport/outbox,
AP/router, đường Internet và broker. Không có cơ sở sửa dấu, nhân hệ số,
loại mẫu chậm khỏi năng lượng thực hoặc tuyên bố AES tiết kiệm năng lượng.

35 bài kiểm tra hiện có đều đạt. Đây là kiểm chứng phần mềm, không phải
phép đo phần cứng mới hay bằng chứng đã chữa được sự cố mạng.

## Log bổ sung do người dùng cung cấp

| Uptime ms | Sự kiện | Outbox B | Heap thấp nhất B | Khối trống lớn nhất B | Heap trống B | RSSI dBm |
|---|---|---:|---:|---:|---:|---:|
| 1941110 | MQTT kết nối | 652 | 143936 | 110592 | 149556 | -33 |
| 2009880–2009890 | MQTT ngắt sau write timeout | 259 | 143936 | 110592 | 185500 | -46 |

Hai mốc cách nhau khoảng 68,77 giây. Không thấy tăng backlog hoặc suy giảm
heap ở hai snapshot này. Heap hiện tại tăng sau khi đóng kết nối phù hợp
với việc giải phóng bộ nhớ TLS; không tự nó chứng minh không có rò rỉ ở
mọi thời điểm. Wi-Fi vẫn associated ở lúc lỗi, nhưng RSSI không đo chất
lượng đường TCP tới broker. Một lần lỗi sau khoảng 69 giây chưa đủ để quy
nguyên nhân cho keepalive.

Thông báo `Error to resend data` của thư viện dùng trong cả đường gửi
phần tử QUEUED lần đầu và gửi lại TRANSMITTED. Không thể chỉ từ dòng này
khẳng định broker không trả PUBACK hoặc đã có nhiều lần retransmit.
