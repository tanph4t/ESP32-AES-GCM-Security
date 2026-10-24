"""Tạo payload cho MQTT.fx, tương thích bản khóa giữ trạng thái + INA219 + Buzzer.

Chạy tại D:\\GCM\\AES_GCM:
    python generator.py                     # Tạo cả ON và OFF (AES bật)
    python generator.py ON                  # Mở khóa và giữ mở cho đến lệnh OFF
    python generator.py OFF                 # Khóa lại và giữ khóa cho đến lệnh ON
    python generator.py ON --aes off        # Xuất văn bản ON
    python generator.py ON --tamper         # Đảo một bit ciphertext để thử Tag
    python generator.py ON --raw            # Chỉ in payload để sao chép

Script chỉ sinh dữ liệu, không kết nối broker, không đổi chế độ AES trên ESP32.
Chọn chế độ bằng web và chờ ESP32 xác nhận trước khi thử --aes off.
Khởi động/reset ESP32: firmware đặt relay OFF, mặc định khóa.
ON: giữ mở cho đến OFF; OFF: giữ khóa cho đến ON; không tự khóa sau 3 giây.
Hành vi này cần bản hardware_control.c mới; sửa generator không thay firmware.
INA219 và buzzer do firmware xử lý; không có lệnh LED/PIR riêng.

Thanh web "Thời gian thực thi lệnh" đo gửi đến ACK của lệnh do web phát.
Generator không publish/nhận ACK nên không đo hoặc cập nhật chỉ số đó.
Lệnh gửi bằng MQTT.fx vẫn cập nhật trạng thái/lịch sử khi web nhận phản hồi.

Replay: lưu nguyên payload đã được chấp nhận và publish lại bằng MQTT.fx.
Sinh một gói mới không phải replay. Firmware hiện tại dùng cửa sổ ±10 giây,
chưa chặn được mọi lần phát lại bên trong cửa sổ này.
"""
import argparse
import os
import struct
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TOPIC = "device/esp32/control"
# 16 byte = AES-128; khớp s_system_key của crypto_app.c bản mới.
# Nếu thay AES_KEY_HEX thì phải đồng thời đổi khóa firmware và web.
KEY = bytes.fromhex(os.getenv("AES_KEY_HEX", "0102030405060708090A0B0C0D0E0F10"))
if len(KEY) != 16:
    raise ValueError("AES_KEY_HEX phải có đúng 16 byte (32 ký tự HEX) cho AES-128.")


def build_payload(cmd_str, aes_enabled=True, tamper=False):
    """Trả về chuỗi publish. Không tự thêm dấu nháy hoặc newline vào payload."""
    if cmd_str not in ("ON", "OFF"):
        raise ValueError("Firmware khóa chỉ nhận đúng ON hoặc OFF.")
    if not aes_enabled:
        if tamper:
            raise ValueError("Kiểm thử Authentication Tag cần bật AES.")
        return cmd_str
    # Nonce ngẫu nhiên 96 bit; không tái sử dụng nonce cho bản mã mới cùng khóa.
    nonce = os.urandom(12)
    # AAD xác thực timestamp; kiểm tra hết hạn do ESP32 thực hiện.
    aad = struct.pack("<Q", int(time.time()))
    encrypted = AESGCM(KEY).encrypt(nonce, cmd_str.encode("ascii"), aad)
    ciphertext, tag = encrypted[:-16], encrypted[-16:]
    if tamper:
        changed = bytearray(ciphertext)
        changed[-1] ^= 0x01  # Luôn thay đổi dữ liệu, giữ nguyên Tag gốc.
        ciphertext = bytes(changed)
    # Bắt buộc đúng thứ tự firmware: nonce12 | tag16 | timestamp8 LE | ciphertext.
    return (nonce + tag + aad + ciphertext).hex().upper()


def generate_hex_payload(cmd_str):
    """Giữ tên hàm cũ để dùng lại: tạo, in và trả về gói AES-128-GCM."""
    payload = build_payload(cmd_str)
    print_packet(cmd_str, payload, True, False)
    return payload


def print_packet(command, payload, aes_enabled, tamper):
    print(f"\n--- {'MỞ KHÓA' if command == 'ON' else 'KHÓA LẠI'}: {command} ---")
    if tamper:
        print("Kỳ vọng: ESP32 từ chối gói sai Tag, giữ nguyên trạng thái khóa hiện tại.")
    else:
        action = "giữ mở khóa cho đến lệnh OFF" if command == "ON" else "giữ khóa cho đến lệnh ON"
        print(f"Khi ESP32 chấp nhận lệnh: {action}; không có hẹn giờ tự khóa.")
    print(f"Topic: {TOPIC} | Retain: OFF")
    if aes_enabled:
        raw = bytes.fromhex(payload)
        print("Chế độ: AES-128-GCM" + (" · TEST SAI TAG" if tamper else ""))
        print(f"Timestamp: {struct.unpack('<Q', raw[28:36])[0]}")
        print(f"Kích thước: {len(raw)} byte = {len(payload)} ký tự HEX")
        print("Dán dưới dạng TEXT chứa chuỗi HEX; không dùng chế độ gửi binary HEX.")
    else:
        print("Chế độ: plaintext; cần ESP32 đã xác nhận AES OFF trên web.")
    print("Chỉ copy dòng payload bên dưới, không thêm dấu nháy/khoảng trắng/newline:")
    print(payload)


def main():
    parser = argparse.ArgumentParser(description="Sinh ON/OFF giữ trạng thái khóa cho ESP32 AES-128-GCM + MQTT.fx")
    parser.add_argument("command", nargs="?", choices=("ON", "OFF"),
                        help="ON: giữ mở; OFF: giữ khóa. Không chọn thì tạo cả hai payload, không gửi lệnh.")
    parser.add_argument("--aes", choices=("on", "off"), default="on",
                        help="Định dạng payload; KHÔNG thay đổi chế độ ESP32.")
    parser.add_argument("--tamper", action="store_true", help="Sửa ciphertext, giữ Tag gốc.")
    parser.add_argument("--raw", action="store_true", help="Chỉ in một payload; cần chọn ON/OFF.")
    args = parser.parse_args()
    if args.tamper and args.aes == "off":
        parser.error("--tamper chỉ dùng với --aes on.")
    if args.raw and args.command is None:
        parser.error("--raw cần chọn ON hoặc OFF để tránh ghép hai payload.")
    if not args.raw:
        print("=== GENERATOR · AES-128-GCM · KHÓA ĐIỆN TỬ ===")
        print("Script không gửi MQTT và không tự bật/tắt AES trên ESP32.")
        print("Firmware mới: mặc định khóa khi boot/reset; ON giữ mở, OFF giữ khóa.")
        print("Không còn tự khóa sau 3 giây; chép từng payload cần dùng vào MQTT.fx.")
        print("Đo 'Thời gian thực thi lệnh' trên web: gửi lệnh bằng công tắc web.")
        if args.aes == "on":
            print("Publish ngay sau khi tạo: firmware kiểm tra timestamp trong cửa sổ ±10s.")
            print("Đồng hồ máy tính và ESP32 phải đồng bộ; hết hạn thì tạo gói mới.")
    for command in (args.command,) if args.command else ("ON", "OFF"):
        payload = build_payload(command, args.aes == "on", args.tamper)
        if args.raw:
            print(payload)
        else:
            print_packet(command, payload, args.aes == "on", args.tamper)


if __name__ == "__main__":
    main()