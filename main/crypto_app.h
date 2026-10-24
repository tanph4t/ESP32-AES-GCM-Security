#ifndef CRYPTO_APP_H
#define CRYPTO_APP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Chỉ là chế độ MẶC ĐỊNH khi ESP32 khởi động.
// Công tắc web đổi biến runtime, không cần build/flash lại mỗi lần thử.
#define ENABLE_AES_GCM 1

// Độ dài khóa AES-128: 16 byte x 8 = 128 bit.
// mbedtls_gcm_setkey() tự chọn lịch khóa và 10 vòng AES tương ứng.
#define AES_KEY_SIZE 16
#define GCM_NONCE_SIZE 12 // Nonce/IV vẫn là 12 byte.
#define GCM_TAG_SIZE 16   // Authentication Tag vẫn là 16 byte.

// Kiểm thử mã hóa và giải mã nội bộ.
void test_crypto_engine(void);

// Nhận payload nhị phân đã được mqtt_app.c chuyển từ HEX.
// Plaintext hỗ trợ ON/OFF hoặc ON:<16HEX>/OFF:<16HEX> để ghép ACK với thời gian thực thi trên ESP32.
// Cấu trúc giữ nguyên: Nonce(12) + Tag(16) + Timestamp/AAD(8) + Ciphertext.
// received_us: esp_timer_get_time() khi MQTT đã ráp đủ bản tin, trước HEX-decode.
void process_mqtt_payload(const unsigned char *payload, size_t payload_len, int64_t received_us);

// Phần 1: đồng bộ công tắc AES. Giữ nguyên API/test/định dạng control cũ.
#define CRYPTO_MODE_TOPIC "device/esp32/config/aes"
#define CRYPTO_MODE_CHALLENGE_HEX_LEN 32
bool crypto_is_aes_enabled(void);
// Chỉ gọi trong task MQTT (khởi tạo, nhận GET, hoặc xử lý MODE).
void crypto_reset_mode_challenge(void);
const char *crypto_get_mode_challenge(void);
// Payload nhị phân AES-128-GCM; AAD = Timestamp8 + CRYPTO_MODE_TOPIC.
// Thành công: cập nhật chế độ, thay challenge, trả request_id 16 ký tự.
bool crypto_process_mode_payload(const unsigned char *payload, size_t len,
                                 char request_id[17]);

/* Data-only test uses the system key; never dispatches control commands. */
int crypto_decrypt_data(const unsigned char *ct, size_t len,
    const unsigned char *aad, size_t aad_len, const unsigned char *nonce,
    const unsigned char *tag, unsigned char *out);

int aes_gcm_encrypt(const unsigned char *key,
                    const unsigned char *plaintext, size_t pt_len,
                    const unsigned char *aad, size_t aad_len,
                    unsigned char *ciphertext, unsigned char *nonce,
                    unsigned char *tag);
int aes_gcm_decrypt(const unsigned char *key,
                    const unsigned char *ciphertext, size_t ct_len,
                    const unsigned char *aad, size_t aad_len,
                    const unsigned char *nonce, const unsigned char *tag,
                    unsigned char *decrypted);

#endif // CRYPTO_APP_H
