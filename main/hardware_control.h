#ifndef HARDWARE_CONTROL_H
#define HARDWARE_CONTROL_H
#include <stdbool.h>
#include <stdint.h>
#include "command_memory.h"
#define DOOR_RELAY_PIN 18
#define AUX_RELAY_PIN 19 /* Kênh 2 không dùng; luôn giữ OFF. */
#define BUZZER_PIN 21
/* Mức điều khiển khóa theo phản hồi thực tế của bộ phần cứng hiện tại:
 * GPIO18 LOW làm chốt thò ra (khóa); HIGH dùng cho chốt thu vào (mở).
 * Đây là mức điều khiển khóa, không khẳng định cực tính cuộn relay/tiếp điểm.
 * ON = mở khóa; OFF = khóa lại; boot luôn xuất mức khóa.
 * Nếu đổi phần cứng/cách đấu, cần xác minh lại hai mức này. */
#define DOOR_UNLOCK_LEVEL 1
#define DOOR_LOCK_LEVEL 0
#define AUX_RELAY_INACTIVE_LEVEL 1 /* Giữ kênh 2 ở mức HIGH như trước. */
/* Buzzer active, điều khiển qua transistor nếu dòng/điện áp vượt GPIO. */
#define BUZZER_BEEP_MS 120
void hardware_init(void);
void hardware_unlock_door(void);
void hardware_lock_door(void);
void hardware_set_state(int state); /* 1: giữ mở; 0: giữ khóa. */
// Mã lệnh 16 HEX; ACK chỉ sau khi task đặt GPIO thành công. -1 = AES OFF.
void hardware_set_state_tracked(int state, const char *command_id, int64_t decrypt_us, int64_t received_us,
                                const command_memory_t *memory);
void hardware_beep_success(void);
void hardware_trigger_security_alarm(void);
bool hardware_is_unlocked(void);
#endif
