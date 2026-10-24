#include "esp_timer.h"
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include "hardware_control.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <inttypes.h>
#include "mbedtls/platform_util.h"
#include "esp_log.h"
#include "esp_random.h" 
#include "mbedtls/gcm.h"
#include "crypto_app.h"
#include "mqtt_app.h"
#include "command_memory.h"

static const char *TAG = "CRYPTO_APP";

/* Biến runtime; không dùng #if để loại bỏ một chế độ khỏi firmware. */
static atomic_bool s_aes_enabled = ENABLE_AES_GCM != 0;
static const unsigned char s_system_key[AES_KEY_SIZE] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
};
static char s_mode_challenge[CRYPTO_MODE_CHALLENGE_HEX_LEN + 1];

bool crypto_is_aes_enabled(void) { return atomic_load(&s_aes_enabled); }

void crypto_reset_mode_challenge(void) {
    unsigned char random_bytes[16];
    static const char hex[] = "0123456789ABCDEF";
    // Gọi sau khi Wi-Fi/MQTT đã hoạt động.
    esp_fill_random(random_bytes, sizeof(random_bytes));
    for (size_t i = 0; i < sizeof(random_bytes); ++i) {
        s_mode_challenge[2*i] = hex[random_bytes[i] >> 4];
        s_mode_challenge[2*i+1] = hex[random_bytes[i] & 15];
    }
    s_mode_challenge[32] = '\0';
}

const char *crypto_get_mode_challenge(void) { return s_mode_challenge; }

/* AES_KEY_SIZE, GCM_NONCE_SIZE và GCM_TAG_SIZE lấy từ crypto_app.h.
 * Chỉ định nghĩa một nơi: AES_KEY_SIZE = 16 byte = 128 bit.
 */

/* =========================================================================
 * CẤU TRÚC AES-128 BÊN TRONG AES-128-GCM (NIST FIPS 197)
 * =========================================================================
 * Khối AES: 16 byte, biểu diễn thành State 4 x 4 byte (xếp theo cột).
 * Khóa AES: 16 byte. KeyExpansion tạo 11 khóa vòng, mỗi khóa 16 byte.
 * Các bước A, B, C, D dưới đây được thư viện mbedTLS/backend AES thực hiện.
 * Đây là chú thích giải thích thuật toán; không phải các hàm tự cài đặt thêm.
 *
 * A. Substitute Bytes Transformation (SubBytes)
 *    Chú thích: Thay mỗi byte của State bằng giá trị tương ứng trong S-box AES.
 *    S-box là phép thế phi tuyến, tạo tính phi tuyến cho phép mã hóa.
 *
 * B. Biến đổi ShiftRows
 *    Chú thích: Dịch vòng sang trái các hàng 0, 1, 2, 3 của State lần lượt
 *    0, 1, 2, 3 byte. Các byte được phân bố lại giữa những cột khác nhau.
 *
 * C. Biến đổi MixColumns
 *    Chú thích: Trộn 4 byte trong mỗi cột bằng phép nhân ma trận cố định
 *    trên GF(2^8), tạo khuếch tán giữa các byte của cột.
 *    Chỉ thực hiện trong các vòng 1 đến 9; vòng 10 KHÔNG có MixColumns.
 *
 * D. Biến đổi AddRoundKey
 *    Chú thích: XOR State với khóa vòng tương ứng do KeyExpansion tạo ra.
 *    Có một AddRoundKey ban đầu và một AddRoundKey trong mỗi vòng AES.
 *
 * Thứ tự đầy đủ của một phép mã hóa khối AES-128:
 *    Khởi đầu : D với khóa vòng 0.
 *    Vòng 1-9 : A -> B -> C -> D.
 *    Vòng 10  : A -> B -> D.
 *
 * Trong GCM, AES mã hóa các khối bộ đếm để tạo keystream; keystream được
 * XOR với bản rõ/bản mã. GHASH kết hợp AAD và ciphertext để tạo/xác thực Tag.
 * GCM dùng phép AES mã hóa thuận ở cả hai chiều, không dùng InvSubBytes,
 * InvShiftRows hay InvMixColumns để giải mã payload.
 * mbedtls_gcm_setkey(..., AES_KEY_SIZE * 8) nhận 128 và cấu hình AES-128.
 *
 * Tham khảo:
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
 * ========================================================================= */

/* =========================================================================
 * HÀM MÃ HÓA AES-128-GCM (xác thực AAD do bên gọi cung cấp)
 * ========================================================================= */
int aes_gcm_encrypt(const unsigned char *key, 
                    const unsigned char *plaintext, size_t pt_len, 
                    const unsigned char *aad, size_t aad_len,
                    unsigned char *ciphertext, 
                    unsigned char *nonce, 
                    unsigned char *tag) 
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    
    // 16 byte x 8 = 128 bit: mbedTLS chọn AES-128 với 10 vòng.
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, AES_KEY_SIZE * 8);
    if (ret != 0) {
        ESP_LOGE(TAG, "Lỗi set key mã hóa: -0x%04X", -ret);
        goto exit;
    }

    // 1. Sinh Nonce ngẫu nhiên; phải tránh lặp Nonce với cùng khóa.
    esp_fill_random(nonce, GCM_NONCE_SIZE); 

    // 2. mbedTLS thực hiện AES-128 theo A-D phía trên và GCM với AAD.
    ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, pt_len, 
                                    nonce, GCM_NONCE_SIZE, 
                                    aad, aad_len, 
                                    plaintext, ciphertext, 
                                    GCM_TAG_SIZE, tag);
    if (ret != 0) {
        ESP_LOGE(TAG, "Lỗi crypt and tag: -0x%04X", -ret);
    }

exit:
    mbedtls_gcm_free(&ctx);
    return ret;
}

/* =========================================================================
 * HÀM GIẢI MÃ XÁC THỰC AES-128-GCM
 * ========================================================================= */
int aes_gcm_decrypt(const unsigned char *key,
                    const unsigned char *ciphertext, size_t ct_len,
                    const unsigned char *aad, size_t aad_len,
                    const unsigned char *nonce,
                    const unsigned char *tag,
                    unsigned char *decrypted) 
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    
    // 16 byte x 8 = 128 bit: mbedTLS chọn AES-128 với 10 vòng.
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, AES_KEY_SIZE * 8);
    if (ret != 0) goto exit;

    // 3. Giải mã AES-128-GCM và xác thực AAD, Tag trước khi dùng bản rõ.
    ret = mbedtls_gcm_auth_decrypt(&ctx, ct_len, 
                                   nonce, GCM_NONCE_SIZE, 
                                   aad, aad_len, 
                                   tag, GCM_TAG_SIZE, 
                                   ciphertext, decrypted);

    // KIỂM TRA PHÁT HIỆN GIẢ MẠO (TAMPERING)
    if (ret != 0) {
        // Hủy bỏ toàn bộ dữ liệu buffer để chống rò rỉ
        memset(decrypted, 0, ct_len); 
        
        if (ret == MBEDTLS_ERR_GCM_AUTH_FAILED) {
            // ESP_LOGE tự động in ra text màu đỏ trên Terminal
            ESP_LOGE(TAG, "[LỖI BẢO MẬT] Xác thực Tag thất bại! Có dấu hiệu giả mạo!");
        } else {
            // Bắt các lỗi cấu hình hệ thống khác
            ESP_LOGE(TAG, "[CẢNH BÁO AN NINH] Lỗi giải mã bất thường (Mã lỗi: -0x%04X)", -ret);
        }
    }

exit:
    mbedtls_gcm_free(&ctx);
    return ret;
}

/* =========================================================================
 * HÀM TEST (MÔ PHỎNG LUỒNG DỮ LIỆU IOT THỰC TẾ)
 * ========================================================================= */
int crypto_decrypt_data(const unsigned char *ct, size_t len,
    const unsigned char *aad, size_t aad_len, const unsigned char *nonce,
    const unsigned char *tag, unsigned char *out) {
    return aes_gcm_decrypt(s_system_key, ct, len, aad, aad_len, nonce, tag, out);
}

void test_crypto_engine(void) {
    ESP_LOGI(TAG, "=== KIỂM THỬ AES-128-GCM MODULE HÓA ===");

    const char *plaintext = "ON";
    size_t pt_len = strlen(plaintext);
    
    unsigned char key[AES_KEY_SIZE] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };

    // AAD cho bài test nội bộ; không phải kiểm thử freshness/chống replay.
    uint64_t timestamp_aad = 1724490000; 
    
    unsigned char nonce[GCM_NONCE_SIZE];
    unsigned char tag[GCM_TAG_SIZE];
    unsigned char ciphertext[64] = {0}; // Đảm bảo đủ rộng chứa pt_len
    unsigned char decrypted[64] = {0};

    // --- TEST MÃ HÓA ---
    if (aes_gcm_encrypt(key, (unsigned char*)plaintext, pt_len, 
                        (unsigned char*)&timestamp_aad, sizeof(timestamp_aad), 
                        ciphertext, nonce, tag) == 0) {
        
        ESP_LOGI(TAG, "[MÃ HÓA] Bản rõ: %s", plaintext);
        ESP_LOG_BUFFER_HEX_LEVEL("Nonce (TRNG)", nonce, GCM_NONCE_SIZE, ESP_LOG_INFO);
        ESP_LOG_BUFFER_HEX_LEVEL("Ciphertext", ciphertext, pt_len, ESP_LOG_INFO);
        ESP_LOG_BUFFER_HEX_LEVEL("Auth Tag", tag, GCM_TAG_SIZE, ESP_LOG_INFO);
    }

    // --- TEST GIẢI MÃ ---
    if (aes_gcm_decrypt(key, ciphertext, pt_len, 
                        (unsigned char*)&timestamp_aad, sizeof(timestamp_aad), 
                        nonce, tag, decrypted) == 0) {
        
        ESP_LOGI(TAG, "[GIẢI MÃ] HỢP LỆ. Dữ liệu: %.*s", (int)pt_len, decrypted);
    }
}
/* =========================================================================
 * HÀM XỬ LÝ PAYLOAD TỪ MQTT (Bóc tách, Chống Replay, Chống Tràn Bộ Nhớ & Điều khiển)
 * ========================================================================= */
/* Giữ ON/OFF cũ; mở rộng ON:<16HEX> / OFF:<16HEX> để đối chiếu ACK và thời gian thực thi.
 * Với AES ON, id nằm bên trong ciphertext và được Tag xác thực cùng lệnh. */
static void apply_control_text(const unsigned char *text, size_t len, int64_t decrypt_us, int64_t received_us) {
    size_t command_len; int state;
    if (len >= 2 && memcmp(text, "ON", 2) == 0) { command_len = 2; state = 1; }
    else if (len >= 3 && memcmp(text, "OFF", 3) == 0) { command_len = 3; state = 0; }
    else { mqtt_app_publish_status("REJECTED", "Lenh khong hop le"); return; }
    if (len == command_len) { hardware_set_state(state); return; }
    if (len != command_len+17 || text[command_len] != ':') {
        mqtt_app_publish_status("REJECTED", "Sai cau truc ma lenh"); return;
    }
    char id[17];
    for (unsigned i = 0; i < 16; ++i) {
        unsigned char c = text[command_len+1+i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            mqtt_app_publish_status("REJECTED", "Ma lenh phai la 16 HEX"); return;
        }
        id[i] = (char)c;
    }
    id[16] = 0;
    command_memory_t memory = command_memory_end();
    hardware_set_state_tracked(state, id, decrypt_us, received_us, &memory);
}

static void process_control_payload(const unsigned char *payload, size_t payload_len, int64_t received_us) {
    if (!payload) return;
    if (!crypto_is_aes_enabled()) {
        // Nhận ON/OFF MQTT.fx cũ, hoặc lệnh có id từ web đo thời gian thực thi.
        apply_control_text(payload, payload_len, -1, received_us);
        return;
    }

    // AES ON: giữ giao thức Nonce12 + Tag16 + Timestamp8-LE + Ciphertext.
    const size_t overhead = GCM_NONCE_SIZE + GCM_TAG_SIZE + sizeof(uint64_t);
    if (payload_len <= overhead || payload_len - overhead > 128) {
        ESP_LOGE(TAG, "[TU CHOI] Payload sai kich thuoc");
        return;
    }
    const unsigned char *nonce = payload;
    const unsigned char *tag = payload + GCM_NONCE_SIZE;
    const unsigned char *aad = tag + GCM_TAG_SIZE;
    const unsigned char *ciphertext = aad + sizeof(uint64_t);
    size_t ct_len = payload_len - overhead;
    unsigned char decrypted[129] = {0};
    int64_t start_time = esp_timer_get_time();
    int ret = aes_gcm_decrypt(s_system_key, ciphertext, ct_len, aad, 8, nonce, tag, decrypted);
    int64_t elapsed = esp_timer_get_time() - start_time;
    if (ret != 0) {
        mqtt_app_publish_status("AUTH_FAIL", "Sai Authentication Tag; khong thuc thi lenh");
        goto cleanup;
    }

    // Giữ cửa sổ timestamp ±10s. Xác thực Tag TRƯỚC khi dùng timestamp.
    // Chưa thêm cache nonce cho lệnh điều khiển trong Phần 1.
    uint64_t timestamp_received = 0;
    for (unsigned i = 0; i < 8; ++i) timestamp_received |= (uint64_t)aad[i] << (8*i);
    time_t now = time(NULL);
    uint64_t current_time = now > 0 ? (uint64_t)now : 0;
    if (current_time < 1000000000) {
        // Tương thích hành vi khởi tạo giờ của mã cũ, nhưng chỉ sau Tag hợp lệ.
        // Ưu tiên SNTP trong wifi_app nếu An đã bật. Đây không phải nguồn giờ độc lập.
        if (timestamp_received < 1000000000 || timestamp_received > 4102444800ULL) {
            ESP_LOGW(TAG, "Timestamp khoi tao khong hop le"); goto cleanup;
        }
        struct timeval tv = {.tv_sec = (time_t)timestamp_received, .tv_usec = 0};
        if (settimeofday(&tv, NULL) != 0) { ESP_LOGE(TAG, "Khong dat duoc gio"); goto cleanup; }
        current_time = timestamp_received;
    }
    if ((current_time > timestamp_received ? current_time - timestamp_received :
         timestamp_received - current_time) > 10) {
        ESP_LOGE(TAG, "[REPLAY/TIMESTAMP] Goi tin ngoai cua so 10s");
        mqtt_app_publish_status("REPLAY_REJECT", "Timestamp ngoai cua so 10 giay");
        goto cleanup;
    }
    ESP_LOGI(TAG, "[BAO MAT] Lenh hop le: %.*s", (int)ct_len, decrypted);
    ESP_LOGI(TAG, "[HIEU NANG] Giai ma AES-128-GCM: %" PRId64 " us", elapsed);
    apply_control_text(decrypted, ct_len, elapsed, received_us);
    /* Tracked commands already carry decrypt_us in their application ACK.
     * An extra metric ahead of GPIO changes MQTT scheduling only in AES mode.
     * Keep standalone telemetry only for legacy ON/OFF without a command ID. */
    if (ct_len == 2 || ct_len == 3) mqtt_app_publish_decrypt_time(elapsed);
cleanup:
    mbedtls_platform_zeroize(decrypted, sizeof(decrypted));
}

void process_mqtt_payload(const unsigned char *payload, size_t payload_len, int64_t received_us) {
    bool aes = crypto_is_aes_enabled();
    command_memory_begin(aes, aes ? sizeof(mbedtls_gcm_context) : 0);
    process_control_payload(payload, payload_len, received_us);
    /* Also close the scope on invalid/legacy commands. Successful tracked
     * commands already captured their sample before enqueueing hardware work. */
    command_memory_end();
}

/* Đổi chế độ luôn cần AES hợp lệ, kể cả khi control đang nhận plaintext.
 * Challenge ngẫu nhiên do ESP32 cấp thay cho việc phụ thuộc SNTP khi đổi mode.
 * Challenge thay sau mỗi lần đổi thành công và khi reconnect; GET chỉ đọc nó.
 * Không làm thay đổi cơ chế timestamp của ON/OFF hiện có. */
bool crypto_process_mode_payload(const unsigned char *payload, size_t len,
                                 char request_id[17]) {
    if (!request_id) return false;
    request_id[0] = '\0';
    // Plaintext: AES=0:<request_id 16 hex>:<challenge 32 hex> (55 byte).
    const size_t command_len = 55;
    if (!payload || len != 36 + command_len || !s_mode_challenge[0]) return false;
    unsigned char aad[8 + sizeof(CRYPTO_MODE_TOPIC)-1];
    memcpy(aad, payload+28, 8);
    memcpy(aad+8, CRYPTO_MODE_TOPIC, sizeof(CRYPTO_MODE_TOPIC)-1);
    unsigned char plain[56] = {0};
    bool ok = false;
    if (aes_gcm_decrypt(s_system_key, payload+36, command_len, aad, sizeof(aad),
                        payload, payload+12, plain) != 0) goto done;
    if (memcmp(plain, "AES=", 4) || (plain[4] != '0' && plain[4] != '1') ||
        plain[5] != ':' || plain[22] != ':' ||
        memcmp(plain+23, s_mode_challenge, 32)) goto done;
    for (unsigned i = 6; i < 22; ++i) {
        unsigned char c = plain[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) goto done;
    }
    atomic_store(&s_aes_enabled, plain[4] == '1');
    memcpy(request_id, plain+6, 16); request_id[16] = '\0';
    crypto_reset_mode_challenge();
    ESP_LOGW(TAG, "[MODE] AES-128-GCM %s", crypto_is_aes_enabled() ? "ON" : "OFF");
    ok = true;
done:
    mbedtls_platform_zeroize(plain, sizeof(plain));
    return ok;
}
