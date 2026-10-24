#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "driver/gpio.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "hardware_control.h"
#include "mqtt_app.h"
#include "cycle_energy.h"

static const char *TAG = "HARDWARE";
static QueueHandle_t s_commands;
static atomic_bool s_unlocked = false;
typedef enum { CMD_LOCK, CMD_UNLOCK, CMD_BEEP, CMD_ALARM } command_t;
typedef struct {
    command_t kind;
    char id[17];
    int64_t decrypt_us;
    int64_t received_us;
    command_memory_t memory;
} queued_command_t;

bool hardware_is_unlocked(void) { return atomic_load(&s_unlocked); }

/* Một task sở hữu relay và buzzer. Chỉ lệnh LOCK/UNLOCK đổi relay.
 * ON giữ mở tới khi nhận OFF; không đóng lại sau một khoảng thời gian.
 * Deadline dưới đây chỉ dùng cho tiếng bíp/cảnh báo. */
static void control_task(void *arg) {
    (void)arg;
    int64_t beep_until = 0, alarm_start = -1;
    for (;;) {
        queued_command_t item = {0};
        bool received = xQueueReceive(s_commands, &item, pdMS_TO_TICKS(10)) == pdTRUE;
        int64_t now = esp_timer_get_time();
        if (received) {
            command_t cmd = item.kind;
            if (cmd == CMD_UNLOCK || cmd == CMD_LOCK) {
                bool unlock = cmd == CMD_UNLOCK;
                esp_err_t result = gpio_set_level(DOOR_RELAY_PIN,
                    unlock ? DOOR_UNLOCK_LEVEL : DOOR_LOCK_LEVEL);
                // Capture immediately after GPIO, excluding ACK construction/transmission.
                int64_t applied_us = esp_timer_get_time();
                if (result != ESP_OK) {
                    if (item.id[0])
                        mqtt_app_publish_command_ack(item.id, unlock, item.decrypt_us, -1, false, &item.memory);
                    else mqtt_app_publish_status("BUSY", "Khong dat duoc GPIO relay");
                } else {
                    cycle_energy_applied(item.id,unlock,applied_us);
                    atomic_store(&s_unlocked, unlock);
                    alarm_start = -1;
                    beep_until = now + BUZZER_BEEP_MS * 1000LL;
                    if (item.id[0])
                        mqtt_app_publish_command_ack(item.id, unlock, item.decrypt_us, applied_us - item.received_us, true, &item.memory);
                    else mqtt_app_publish_status(unlock ? "UNLOCKED" : "LOCKED",
                        unlock ? "Giu mo khoa cho den lenh OFF" : "Giu khoa cho den lenh ON");
                    ESP_LOGI(TAG, "Lenh %s / %s; GPIO%d=%d; giu trang thai cho den lenh moi",
                        unlock ? "ON" : "OFF", unlock ? "UNLOCKED" : "LOCKED",
                        DOOR_RELAY_PIN, unlock ? DOOR_UNLOCK_LEVEL : DOOR_LOCK_LEVEL);
                }
            } else {
                alarm_start = cmd == CMD_ALARM ? now : -1;
                beep_until = now + BUZZER_BEEP_MS * 1000LL;
                if (cmd == CMD_ALARM)
                    mqtt_app_publish_status("ALARM", "Canh bao bao mat");
            }
        }
        bool sound = now < beep_until;
        if (alarm_start >= 0) {
            int64_t age = now - alarm_start;
            sound = age < 600000 && ((age / 100000) % 2 == 0);
        }
        gpio_set_level(BUZZER_PIN, sound ? 1 : 0);
    }
}

static void post_item(const queued_command_t *item) {
    if (!s_commands || xQueueSend(s_commands, item, 0) != pdTRUE) {
        ESP_LOGW(TAG, "Hang doi phan cung day/chua san sang");
        if (item->id[0]) mqtt_app_publish_command_ack(item->id,
            item->kind == CMD_UNLOCK, item->decrypt_us, -1, false, &item->memory);
        else mqtt_app_publish_status("BUSY", "Lenh chua duoc thuc thi; hang doi phan cung day");
    }
}
static void post(command_t cmd) {
    queued_command_t item = {.kind = cmd, .decrypt_us = -1};
    post_item(&item);
}
void hardware_set_state_tracked(int state, const char *id, int64_t decrypt_us, int64_t received_us,
                                const command_memory_t *memory) {
    queued_command_t item = {.kind = state ? CMD_UNLOCK : CMD_LOCK, .decrypt_us = decrypt_us,
                             .received_us = received_us};
    if (!id || strlen(id) != 16) return;
    for (unsigned i = 0; i < 16; ++i) {
        char c = id[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return;
    }
    memcpy(item.id, id, 16); item.id[16] = 0;
    if (memory) item.memory = *memory;
    post_item(&item);
}
void hardware_init(void) {
    if (s_commands) return; /* Không tạo hai task cùng điều khiển GPIO. */
    /* Đặt mức khóa trước khi bật output. Kênh phụ giữ mức riêng. */
    gpio_reset_pin(DOOR_RELAY_PIN);
    gpio_set_level(DOOR_RELAY_PIN, DOOR_LOCK_LEVEL);
    gpio_set_direction(DOOR_RELAY_PIN, GPIO_MODE_OUTPUT);
    gpio_reset_pin(AUX_RELAY_PIN);
    gpio_set_level(AUX_RELAY_PIN, AUX_RELAY_INACTIVE_LEVEL);
    gpio_set_direction(AUX_RELAY_PIN, GPIO_MODE_OUTPUT);
    gpio_reset_pin(BUZZER_PIN);
    gpio_set_level(BUZZER_PIN, 0);
    gpio_set_direction(BUZZER_PIN, GPIO_MODE_OUTPUT);
    atomic_store(&s_unlocked, false); /* Boot luôn LOCKED, không khôi phục ON từ NVS. */
    s_commands = xQueueCreate(16, sizeof(queued_command_t));
    if (!s_commands || xTaskCreate(control_task, "lock_control", 4096, NULL, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "Khong tao duoc task; giu relay OFF");
        if (s_commands) { vQueueDelete(s_commands); s_commands = NULL; }
        return;
    }
    ESP_LOGI(TAG, "Boot LOCKED / relay OFF; khoa GPIO%d; buzzer GPIO%d; giu trang thai theo lenh", DOOR_RELAY_PIN, BUZZER_PIN);
}
void hardware_unlock_door(void) { post(CMD_UNLOCK); }
void hardware_lock_door(void) { post(CMD_LOCK); }
void hardware_set_state(int state) { post(state ? CMD_UNLOCK : CMD_LOCK); }
void hardware_beep_success(void) { post(CMD_BEEP); }
void hardware_trigger_security_alarm(void) { post(CMD_ALARM); }
