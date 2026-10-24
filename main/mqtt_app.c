#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>
#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "mqtt_client.h"
#include "mqtt_app.h"
#include "crypto_app.h"
#include "cycle_energy.h"
#include "hardware_control.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "esp_wifi.h"
#include <inttypes.h>

static const char *TAG = "MQTT_APP";
#define CONTROL_TOPIC "device/esp32/control"
#define STATUS_TOPIC "device/esp32/status"
#define MAX_WIRE_LEN 256  // Giữ giới hạn chuỗi HEX trong mã An gửi.

esp_mqtt_client_handle_t global_mqtt_client = NULL;
static atomic_bool s_connected = false;
extern const uint8_t emqxsl_ca_crt_start[] asm("_binary_emqxsl_ca_crt_start");
extern const uint8_t emqxsl_ca_crt_end[] asm("_binary_emqxsl_ca_crt_end");

// Không đặt các hàm này trong #if: cả hai chế độ đều có trong firmware.
static int hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static bool hex2bin(const char *hex, size_t len, unsigned char *out, size_t capacity) {
    if (!hex || !len || (len & 1) || len / 2 > capacity) return false;
    for (size_t i = 0; i < len / 2; ++i) {
        int a = hex_char_to_val(hex[2*i]), b = hex_char_to_val(hex[2*i+1]);
        if (a < 0 || b < 0) return false;
        out[i] = (unsigned char)((a << 4) | b);
    }
    return true;
}

void mqtt_app_publish_cycle(const char *json) {
    if(global_mqtt_client && atomic_load(&s_connected))
        esp_mqtt_client_enqueue(global_mqtt_client,CYCLE_ENERGY_RESULT,json,0,1,0,true);
}
static void publish_json(const char *json) {
    if (!global_mqtt_client || !atomic_load(&s_connected)) return;
    // Giữ QoS 1, retain=false của ACK; enqueue tránh chờ mạng trong callback/timer.
    int id = esp_mqtt_client_enqueue(global_mqtt_client, STATUS_TOPIC, json, 0, 1, 0, true);
    if (id < 0) ESP_LOGE(TAG, "Khong dua duoc ACK vao hang doi MQTT");
}

// Quote chuỗi JSON bằng buffer có giới hạn, không cần thêm thư viện/CMake.
static bool append_quoted(char *out, size_t cap, size_t *used, const char *text) {
    if (!text || *used + 2 >= cap) return false;
    out[(*used)++] = '"';
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < 32) {
            if (*used + 6 + 2 >= cap) return false;
            int n = snprintf(out + *used, cap - *used, "\\u%04x", (unsigned)*p);
            if (n != 6) return false;
            *used += 6;
        } else {
            size_t n = (*p == '"' || *p == '\\') ? 2 : 1;
            if (*used + n + 2 >= cap) return false;
            if (n == 2) out[(*used)++] = '\\';
            out[(*used)++] = (char)*p;
        }
    }
    out[(*used)++] = '"'; out[*used] = '\0';
    return true;
}

/* Phản hồi mở, khóa và cảnh báo từ task phần cứng. */
void mqtt_app_publish_status(const char *status, const char *msg) {
    char json[512] = "{\"status\":";
    size_t used = strlen(json);
    if (!append_quoted(json, sizeof(json), &used, status)) return;
    const char separator[] = ",\"message\":";
    if (used + sizeof(separator) >= sizeof(json)) return;
    memcpy(json + used, separator, sizeof(separator)); used += sizeof(separator) - 1;
    if (!append_quoted(json, sizeof(json), &used, msg)) return;
    int n = snprintf(json + used, sizeof(json) - used, ",\"aes_enabled\":%s}",
                     crypto_is_aes_enabled() ? "true" : "false");
    if (n < 0 || (size_t)n >= sizeof(json) - used) return;
    publish_json(json);
}

/* Application ACK: mã lệnh xuất phát từ plaintext đã được crypto xác thực.
 * Telemetry không mang id này, nên không bị ghép nhầm vào số đo lệnh.
 * GPIO đã đặt không có nghĩa chốt cơ khí đã tới vị trí cuối. */
void mqtt_app_publish_command_ack(const char *id, int state, int64_t decrypt_us, int64_t execution_us, bool applied,
                                  const command_memory_t *memory) {
    if (!id || strlen(id) != 16) return;
    for (unsigned i = 0; i < 16; ++i) if (hex_char_to_val(id[i]) < 0) return;
    char timing[48];
    if (decrypt_us >= 0) snprintf(timing, sizeof(timing), "%" PRId64, decrypt_us);
    else snprintf(timing, sizeof(timing), "null");
    char execution[48];
    if (applied && execution_us >= 0) snprintf(execution, sizeof(execution), "%" PRId64, execution_us);
    else snprintf(execution, sizeof(execution), "null");
    command_memory_t empty = {0};
    if (!memory) memory = &empty;
    char json[896];
    int n = snprintf(json, sizeof(json),
        "{\"status\":\"%s\",\"message\":\"%s\",\"command_id\":\"%s\","
        "\"command\":\"%s\",\"phase\":\"%s\",\"decrypt_us\":%s,\"execution_us\":%s,\"aes_enabled\":%s,"
        "\"memory\":{\"v\":1,\"valid\":%s,\"heap_before\":%" PRIu32 ",\"heap_after\":%" PRIu32
        ",\"heap_peak\":%" PRIu32 ",\"heap_retained\":%" PRIu32 ",\"allocations\":%" PRIu32
        ",\"stack_free_min\":%" PRIu32 ",\"context_bytes\":%" PRIu32 "}}",
        applied ? (state ? "UNLOCKED" : "LOCKED") : "BUSY",
        applied ? "GPIO relay da cap nhat" : "Khong thuc thi duoc GPIO / hang doi day",
        id, state ? "ON" : "OFF", applied ? "applied" : "rejected", timing, execution,
        memory->aes_enabled ? "true" : "false", memory->valid ? "true" : "false",
        memory->heap_before, memory->heap_after, memory->heap_peak, memory->heap_retained,
        memory->allocations, memory->stack_free_min, memory->context_bytes);
    if (n > 0 && (size_t)n < sizeof(json)) publish_json(json);
}

static void publish_mode_state(const char *request_id) {
    // request_id và challenge chỉ chứa HEX đã kiểm tra ở crypto_app.c.
    char json[512];
    int n = snprintf(json, sizeof(json),
        "{\"status\":\"%s\",\"aes_enabled\":%s,\"mode_challenge\":\"%s\",\"request_id\":\"%s\",\"relay_on\":%s,\"cycle_energy_supported\":true,\"cycle_energy_protocol\":1,\"cycle_energy_busy\":%s,\"cycle_energy_id\":\"%s\"}",
        request_id ? "MODE_CHANGED" : "MODE_STATE",
        crypto_is_aes_enabled() ? "true" : "false",
        crypto_get_mode_challenge(), request_id ? request_id : "",
        hardware_is_unlocked() ? "true" : "false", cycle_energy_busy()?"true":"false", cycle_energy_id());
    if (n > 0 && (size_t)n < sizeof(json)) publish_json(json);
}

static void dispatch_payload(bool mode_topic, const char *data, size_t len, int64_t received_us) {
    if (mode_topic && len == 3 && memcmp(data, "GET", 3) == 0) {
        // Chỉ đọc trạng thái, không đổi AES và không điều khiển GPIO.
        publish_mode_state(NULL);
        return;
    }
    if (mode_topic && cycle_energy_busy()) { cycle_energy_interference(); mqtt_app_publish_status("BUSY","Dang do nang luong theo dot"); return; }
    unsigned char binary[MAX_WIRE_LEN / 2];
    if (mode_topic || crypto_is_aes_enabled()) {
        if (!hex2bin(data, len, binary, sizeof(binary))) {
            ESP_LOGE(TAG, "[TU CHOI] Du lieu khong phai HEX hop le");
            mqtt_app_publish_status("REJECTED", "Payload HEX khong hop le");
            return;
        }
        if (mode_topic) {
            char request_id[17];
            if (crypto_process_mode_payload(binary, len / 2, request_id))
                publish_mode_state(request_id);
            else mqtt_app_publish_status("MODE_ERROR", "Sai Tag/challenge hoac sai cau truc yeu cau doi AES");
        } else process_mqtt_payload(binary, len / 2, received_us);
    } else {
        // AES OFF: gửi trực tiếp byte ON/OFF vào hàm cũ, không HEX-decode.
        process_mqtt_payload((const unsigned char *)data, len, received_us);
    }
}

// MQTT có thể chia payload thành nhiều sự kiện: ráp đủ rồi mới xử lý.
static struct { char data[MAX_WIRE_LEN]; size_t used, total; bool active, mode, cycle; } rx;
static bool topic_matches(esp_mqtt_event_handle_t e, const char *topic) {
    return e->topic && e->topic_len == (int)strlen(topic) &&
           memcmp(e->topic, topic, (size_t)e->topic_len) == 0;
}
static void receive_message(esp_mqtt_event_handle_t e) {
    if (e->current_data_offset == 0) {
        rx.active = false; rx.used = 0;
        if (!topic_matches(e, CONTROL_TOPIC) && !topic_matches(e, CRYPTO_MODE_TOPIC) && !topic_matches(e,CYCLE_ENERGY_REQUEST)) return;
        rx.cycle = topic_matches(e,CYCLE_ENERGY_REQUEST);
        if (e->retain) { mqtt_app_publish_status("REJECTED", "Khong nhan lenh retained"); return; }
        if (e->total_data_len <= 0 || e->total_data_len > MAX_WIRE_LEN) {
            ESP_LOGE(TAG, "[TU CHOI] Payload rong / vuot 256 ky tu");
            mqtt_app_publish_status("REJECTED", "Payload vuot gioi han kich thuoc"); return;
        }
        rx.total = (size_t)e->total_data_len;
        rx.mode = topic_matches(e, CRYPTO_MODE_TOPIC); rx.active = true;
    }
    if (!rx.active) return;
    if (!e->data || e->data_len <= 0 || e->current_data_offset < 0 ||
        (size_t)e->current_data_offset != rx.used || (size_t)e->total_data_len != rx.total ||
        (size_t)e->data_len > rx.total - rx.used) { rx.active = false; return; }
    memcpy(rx.data + rx.used, e->data, (size_t)e->data_len); rx.used += (size_t)e->data_len;
    if (rx.used == rx.total) {
        // Start after the full MQTT payload is assembled, before HEX/AES processing.
        int64_t received_us = esp_timer_get_time();
        rx.active = false;
        if(rx.cycle) {
            cycle_energy_request(rx.data,rx.total);
        } else {
            if(!rx.mode) cycle_energy_receive(received_us);
            dispatch_payload(rx.mode, rx.data, rx.total, received_us);
        }
    }
}

/* Read-only diagnostics on connection events, never per command/sample. */
static void log_network_state(void) {
    ESP_LOGI(TAG,"Network snapshot: outbox_bytes=%d, min_free_heap=%" PRIu32 ", largest_free_8bit=%u",
             global_mqtt_client?esp_mqtt_client_get_outbox_size(global_mqtt_client):-1,
             esp_get_minimum_free_heap_size(),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    wifi_ap_record_t ap;
    esp_err_t err=esp_wifi_sta_get_ap_info(&ap);
    if(err==ESP_OK)
        ESP_LOGI(TAG,"WiFi associated: RSSI=%d dBm, channel=%u; free_heap=%" PRIu32,
                 (int)ap.rssi,(unsigned)ap.primary,esp_get_free_heap_size());
    else
        ESP_LOGW(TAG,"WiFi AP unavailable: %s; free_heap=%" PRIu32,
                 esp_err_to_name(err),esp_get_free_heap_size());
}
static void mqtt_event_handler(void *args, esp_event_base_t base, int32_t event_id, void *event_data) {
    (void)args; (void)base;
    esp_mqtt_event_handle_t event = event_data;
    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        atomic_store(&s_connected, true);
        crypto_reset_mode_challenge();
        esp_mqtt_client_subscribe(event->client, CONTROL_TOPIC, 0);
        esp_mqtt_client_subscribe(event->client, CRYPTO_MODE_TOPIC, 0);
        esp_mqtt_client_subscribe(event->client, CYCLE_ENERGY_REQUEST, 0);
        ESP_LOGI(TAG, "Da ket noi; subscribe control + config/aes");
        log_network_state();
        publish_mode_state(NULL);
        break;
    case MQTT_EVENT_DATA: receive_message(event); break;
    case MQTT_EVENT_DISCONNECTED:
        cycle_energy_disconnected();
        atomic_store(&s_connected, false); rx.active = false;
        ESP_LOGI(TAG, "Mat ket noi MQTT Broker");
        /* Resend/write failures can dispatch DISCONNECTED without ERROR. */
        log_network_state();
        break;
    case MQTT_EVENT_ERROR:
        if(event->error_handle) {
            const esp_mqtt_error_codes_t *e=event->error_handle;
            ESP_LOGE(TAG,"MQTT error type=%d",(int)e->error_type);
            if(e->error_type==MQTT_ERROR_TYPE_TCP_TRANSPORT)
                ESP_LOGE(TAG,"TLS esp_err=0x%x (%s), stack_err=%d, cert_flags=0x%x, socket_errno=%d",
                         (unsigned)e->esp_tls_last_esp_err,esp_err_to_name(e->esp_tls_last_esp_err),
                         e->esp_tls_stack_err,(unsigned)e->esp_tls_cert_verify_flags,e->esp_transport_sock_errno);
            else if(e->error_type==MQTT_ERROR_TYPE_CONNECTION_REFUSED)
                ESP_LOGE(TAG,"Broker refused connection: code=%d",(int)e->connect_return_code);
        } else ESP_LOGE(TAG,"MQTT error: no error details");
        log_network_state();
        break;
    default: break;
    }
}

void mqtt_app_start(void) {
    // Wi-Fi reconnect có thể gọi hàm này nhiều lần: chỉ tạo một client.
    if (global_mqtt_client) return;
    ESP_LOGI(TAG, "MQTT transport poll=%d ms; tracked commands report timings in ACK",
             CONFIG_MQTT_POLL_READ_TIMEOUT_MS);
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = MQTT_BROKER_URI,
        .broker.verification.certificate = (const char *)emqxsl_ca_crt_start,
        .credentials.username = "esp32",
        .credentials.authentication.password = "1234",
    };
    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt_cfg);
    if (!client) { ESP_LOGE(TAG, "Khong khoi tao duoc MQTT client"); return; }
    global_mqtt_client = client;
    esp_err_t err = esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    if (err == ESP_OK) err = esp_mqtt_client_start(client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Khong start duoc MQTT: %s", esp_err_to_name(err));
        esp_mqtt_client_destroy(client); global_mqtt_client = NULL; return;
    }
    ESP_LOGI(TAG, "Dang khoi chay MQTT...");
}

/* Telemetry QoS0, không retained: số đo cũ không được coi là mẫu mới.
 * Giới hạn outbox để mất mạng không tích tụ số đo. */
void mqtt_app_publish_telemetry(bool valid, float voltage, float current_ma,
                                float power_w, esp_err_t error,
                                const char *sensor_stage, int bus_raw, int shunt_raw) {
    if (!atomic_load(&s_connected) || !global_mqtt_client) return;
    if (esp_mqtt_client_get_outbox_size(global_mqtt_client) > 4096) return;
    char values[128];
    if (valid) snprintf(values, sizeof(values),
        "\"voltage_v\":%.3f,\"current_ma\":%.2f,\"power_w\":%.4f", voltage, current_ma, power_w);
    else snprintf(values, sizeof(values),
        "\"voltage_v\":null,\"current_ma\":null,\"power_w\":null");
    char json[640];
    int n = snprintf(json, sizeof(json),
        "{%s,\"ina219_ok\":%s,\"sensor_error\":%d,\"sensor_error_name\":\"%s\",\"sensor_stage\":\"%s\",\"bus_raw\":%d,\"shunt_raw\":%d,\"relay_on\":%s,\"aes_enabled\":%s,\"heap_free_bytes\":%" PRIu32 "}",
        values, valid ? "true" : "false", (int)error, esp_err_to_name(error),
        sensor_stage ? sensor_stage : "unknown", bus_raw, shunt_raw,
        hardware_is_unlocked() ? "true" : "false", crypto_is_aes_enabled() ? "true" : "false",
        (uint32_t)esp_get_free_heap_size());
    if (n > 0 && (size_t)n < sizeof(json))
        esp_mqtt_client_enqueue(global_mqtt_client, "device/esp32/telemetry", json, n, 0, 0, true);
}
void mqtt_app_publish_decrypt_time(int64_t elapsed_us) {
    char json[96];
    snprintf(json, sizeof(json), "{\"decrypt_us\":%" PRId64 "}", elapsed_us);
    publish_json(json);
}
