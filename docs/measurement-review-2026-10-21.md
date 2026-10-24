# Review số đo và phương pháp — 21/10/2026

Lưu ý lịch sử: bản review này được lập trước khi người dùng yêu cầu gỡ
phép thử theo kích thước. Phần firmware/web tương ứng đã được xóa sau đó;
các nhận xét về size_test, heap thử kích thước và dữ liệu thô chỉ còn là
ghi nhận của phiên bản trước, không phải chức năng hiện tại.

## Phạm vi và kết luận

Kiểm tra firmware C và headers, Flask/Paho/SQLite, bộ chạy thử kích thước,
bộ chạy năng lượng, HTML/JavaScript/CSS, generator, cấu hình và các bài
kiểm tra. Không điều khiển bo, không sửa dữ liệu và không thay code vận
hành trong lần review. Có đọc dữ liệu lịch sử bằng SQLite mode=ro.

Công thức và các mốc đo chính nhất quán với mô tả hiện tại. Chưa có cơ
sở chứng nhận độ chính xác vật lý hoặc gọi chênh lệch năng lượng là năng
lượng riêng của AES. Phân biệt lỗi chấp nhận dữ liệu, sai lệch do phần mềm
đo, và giới hạn phương pháp như các mục dưới đây.

## Phát hiện cần xử lý

### F1 — P1: Log riêng AES nằm trong cửa sổ so sánh

`main/crypto_app.c:293–295` in hai ESP_LOGI chỉ cho lệnh AES hợp lệ trước
khi gọi apply_control_text. Nhánh plaintext không có hai thao tác tương
ứng. Vì vậy execution_us và năng lượng đợt bao gồm công việc ghi log khác
nhau giữa hai chế độ. decrypt_us riêng được chụp trước log nên không bị
hai dòng này cộng vào, nhưng không thể lấy execution_AES trừ
execution_plain làm thời gian mật mã thuần.

Ảnh hưởng định lượng cần đo trên bo; chưa xác định phần năng lượng do
log là bao nhiêu. Đề xuất: tắt log theo lệnh trong cả hai chế độ khi đo
hoặc dùng một cấu hình ghi log có công việc tương đương; giữ log lỗi và
thông tin phiên. Lưu chế độ log cùng metadata thực nghiệm.

### F2 — P1, giới hạn phương pháp: Lấy mẫu thưa có thể bỏ lỡ xung ngắn

`main/ina219_app.c:37–50,74,85` kích hoạt từng lần chuyển đổi, đợi đọc sau
10ms, rồi nghỉ thêm khoảng 10ms trong đợt. Đây là khoảng 50 mẫu/giây,
không phải ADC đang lấy trung bình toàn bộ mỗi khoảng 20ms. Theo TI,
chuyển đổi 12-bit điển hình 532µs cho một đại lượng; shunt và bus được
chuyển đổi tuần tự. Có khoảng thời gian không được ADC đo giữa các lần
trigger. Xung tải dưới mili giây có thể bị bỏ lỡ hoặc lấy trúng không
đều. Tăng số chu kỳ không tự bảo đảm loại được sai lệch pha lấy mẫu.

`covered_us` cộng khoảng thời gian giữa các mẫu hợp lệ, không phải tổng
thời gian ADC thực sự quan sát tải. Độ phủ gần 100% do đó không chứng
minh đã bắt được mọi xung AES/Wi-Fi. Điều kiện max gap vẫn hữu ích để
phát hiện khoảng trống phần mềm lớn, nhưng không xác nhận độ chính xác
phép tích phân ở mức chênh lệch 1–2%.

Phép đo dùng được như ước lượng năng lượng bo trong cửa sổ điều khiển,
cần kiểm chứng bằng thiết bị tham chiếu hoặc đánh giá hội tụ/aliasing của
lịch lấy mẫu trước khi kết luận về chênh lệch nhỏ. Không tự nhân hệ số
hay loại mẫu năng lượng chỉ vì kết quả không như mong đợi.

### F3 — P2: Timestamp mẫu chưa khớp cửa sổ chuyển đổi ADC

`main/ina219_app.c:71–74` gán (start+now)/2 cho mẫu. Khoảng này gồm cả
thời gian chờ task 10ms và đọc I2C, không chỉ thời gian ADC chuyển đổi.
Mẫu có thể được gán muộn vài ms so với thời điểm đo thực. Ảnh hưởng chủ
yếu khi tải thay đổi và ở hai biên cửa sổ; chưa lượng hóa sai số trên bo.
Đề xuất: timestamp theo mốc trigger/conversion của cảm biến với cửa sổ
đã xác định, hoặc dùng chế độ liên tục và một quy trình đọc được mô tả
rõ. V và I cũng không được chuyển đổi đồng thời tuyệt đối.

### F4 — P2, tái hiện được: ACK khác chế độ vẫn được chấp nhận

`main/web_server.py:367–376` kiểm tra ID, lệnh, phase và trạng thái nhưng
chưa kiểm tra aes_enabled khớp pending['encrypted']. Kiểm chứng trên
dashboard RAM riêng: pending plaintext nhận ACK aes_enabled=true vẫn
được lưu outcome='applied'. Điều này có thể gán số đo sai nhóm khi phản
hồi sai schema hoặc trạng thái hai phía lệch. Bộ chạy chu kỳ có kiểm tra
chế độ thêm sau đó, nhưng bản ghi measurements đã có thể được đánh dấu
applied và thống kê điều khiển thường vẫn bị ảnh hưởng.

Đề xuất: bắt buộc chế độ ACK khớp trước cập nhật phép đo; kiểm tra cả
schema các trường số đo và thêm kiểm thử phản hồi sai chế độ.

### F5 — P2, tái hiện được: Ghép cặp chưa kiểm tra metadata đo

`main/cycle_energy_web.py:52–56` ghép theo pair_no và valid. Không kiểm tra
cpu_mhz, wifi_ps, hardware_aes, IDF hoặc nhận diện build tương thích.
Kiểm chứng bằng dữ liệu giả trong RAM: cặp on có wifi_ps=0/CPU160 và off
có wifi_ps=1/CPU80 vẫn trả n=1. Không có bằng chứng các cặp gần nhất trong
DB đã bị lỗi này; đây là thiếu hàng rào kiểm tra cấu hình.

Đề xuất: kiểm tra metadata chung trước ghép và lưu nhận diện firmware/
phiên bản phương pháp, shunt, chu kỳ lấy mẫu, chế độ log. CI giữa các cặp
không tự bao gồm sai số hệ thống của cảm biến hoặc chênh cấu hình.

### F6 — P2, thiếu chỉ số cho mục tiêu nghiên cứu: Heap chưa đo peak AES

`main/size_test.c:77–95` lấy heap trước cấp phát output, sau khi hàm mật
mã đã trả về, và sau giải phóng output. Ngữ cảnh GCM/bộ nhớ tạm có thể
đã được giải phóng trước mốc thứ hai; ngữ cảnh trên stack cũng không
được phản ánh bởi heap. Vì thế chủ yếu thấy buffer output và dao động
RAM hệ thống, không suy ra bộ nhớ cực đại riêng AES theo độ dài.

Phần chú thích trên web đã nêu giới hạn này, nên không phải giá trị bị
tính sai. Tuy nhiên chưa đủ để kết luận chi phí bộ nhớ AES trong báo cáo.
Cần đo peak cấp phát/stack với phạm vi rõ, hoặc thu hẹp cách diễn giải
thành 'heap trống toàn hệ thống tại ba mốc'.

### F7 — P2, metadata dễ hiểu sai: Byte nhị phân khác byte MQTT dạng HEX

`main/web_server.py:60–69,513` dùng len(bytes.fromhex(payload)) cho bytes
và payload_bytes khi AES bật. Ví dụ ON có ID: trường này là 55 byte,
nhưng chuỗi ASCII HEX thực gửi là 110 byte; OFF tương ứng 56/112.
Đây là số byte gói nhị phân sau decode, không phải độ dài payload MQTT.
Nếu dùng cột này để tính băng thông sẽ thiếu hệ số 2 ở nhánh AES.

Đề xuất: tách plaintext_bytes, decoded_packet_bytes và wire_payload_bytes,
ghi rõ không bao gồm header MQTT/TLS/IP. Phép thử theo kích thước đã có
wire_bytes riêng và công thức 2*(116+N) đúng với cách đóng gói của nó.

## Những phần đang đúng theo phạm vi công bố

- Dòng điện: đọc shunt có dấu, quy đổi 10µV/LSB với giả định R=0,1Ω;
  điện áp bus 4mV/LSB; P=V*I, đổi mA sang A. Không ép trị âm thành dương.
  Chưa kiểm chứng giá trị shunt thực tế/offset bằng thiết bị tham chiếu.
  Đổi đơn vị sang µA không làm cảm biến có độ chính xác đến từng µA.
- Tích phân hình thang theo timestamp, giữ mẫu ở biên: đúng về số học
  cho mô hình công suất được nội suy. E/N chu kỳ và E/(2N) lệnh đúng;
  không phải năng lượng riêng ON hoặc OFF.
- Rà 65 đợt status=valid trong DB: không thấy lệch đẳng thức E=Pmean*T.
  Đây là kiểm tra nhất quán nội bộ, không phải hiệu chuẩn độc lập.
- decrypt_us bao quanh init/setkey/auth-decrypt/free, không chỉ riêng
  các vòng AES. operation_us ở phép thử kích thước loại wrapper, cấp
  phát output, kiểm tra byte và truyền kết quả.
- E2E dùng clock monotonic trên cùng máy Python trước chuẩn bị lệnh đến
  callback nhận ACK. Không cộng chu kỳ refresh web hoặc phụ thuộc đồng
  bộ clock giữa Python và ESP32. ACK chỉ chứng minh đặt GPIO.
- Lượt kích thước dùng cùng dữ liệu trong mỗi cặp, nonce/mã thử riêng,
  hai warmup mỗi nhóm, loại warmup/lỗi khỏi tổng hợp. Dữ liệu thô là
  memcpy bên trong phong bì xác thực chung; không gọi đó là toàn hệ
  thống hoàn toàn không dùng AES-GCM.
- Chênh lệch và CI ghép cặp tính đúng số học trên các cặp được nhận.
  Một cặp không đủ đánh giá tính lặp lại; không ép chênh âm thành 0.

## Giới hạn năng lượng cần giữ trong báo cáo

Cửa sổ hiện tại: nhận đủ ON đầu trước HEX/AES → đặt GPIO cho OFF cuối.
Gồm CPU, Wi-Fi/TLS, task đo, buzzer/linh kiện chung nhánh và khoảng chờ
giữa lệnh. Không gồm mạng trước khi ESP32 nhận đủ ON đầu, truyền ACK cuối,
đổi chế độ/chuẩn bị/khôi phục, hay mã hóa Python. Chênh E còn phản ánh
thời lượng khác nhau và log, chưa cô lập năng lượng của mật mã.

65 đợt được ghi hợp lệ không đồng nghĩa 65 đợt có cùng nguồn, dây, mạng,
firmware hay cấu hình. Chưa có phép hiệu chuẩn/đánh giá độ lặp lại độc
lập chứng minh sai số nhỏ hơn mức tăng khoảng 1–2% gần đây.

Lỗi timeout MQTT/TLS còn tồn tại ở lịch sử. Chưa xác định được nguyên
nhân gốc giữa transport firmware, đường mạng và broker. Mất kết nối là
lý do loại đợt; không nên suy từ đó thành 'AES xử lý chậm'.

## Kiểm chứng và ưu tiên

- 35 bài kiểm tra hiện có đạt; JavaScript hai trang thử qua node --check.
- Ba kiểm chứng RAM độc lập tái hiện ACK sai mode, ghép metadata khác,
  và số byte decode 55 so với MQTT HEX 110. Không ghi vào DB dự án.
- Chưa sửa code vận hành, chưa chạy đo trên bo, chưa hiệu chuẩn phần cứng.
- Ưu tiên: chuẩn hóa log; kiểm chứng lấy mẫu/timestamp; chặn ACK sai mode;
  kiểm tra cấu hình cặp; phân biệt byte payload; hoàn thiện đo bộ nhớ nếu
  giữ mục tiêu đánh giá RAM riêng AES.

Nguồn đối chiếu phần cứng: TI INA219 datasheet Rev. G, mục ADC Timing,
Configuration Register và Data Output Registers:
https://www.ti.com/lit/ds/symlink/ina219.pdf
