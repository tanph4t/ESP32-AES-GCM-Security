#ifndef INA219_APP_H
#define INA219_APP_H
#include "esp_err.h"
#define INA219_SDA_PIN 25
#define INA219_SCL_PIN 26
#define INA219_ADDRESS 0x40
/* Xác nhận điện trở trên board: R100 = 0.1 ohm; sửa nếu khác. */
#define INA219_SHUNT_OHMS 0.1f
void ina219_app_start(void);
#endif
