#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/i2c_master.h"
#include "esp_log.h"
#include "ina219_app.h"
#include "mqtt_app.h"
#include "cycle_energy.h"
#include "esp_timer.h"

static const char *TAG = "INA219";
static i2c_master_bus_handle_t s_bus;
static i2c_master_dev_handle_t s_dev;
static TaskHandle_t sensor_handle;
void ina219_cycle_wake(void){if(sensor_handle)xTaskNotifyGive(sensor_handle);}
/* Owned by sensor_task; -1 means the register was not read in this sample. */
static const char *s_read_stage = "idle";
static int s_bus_raw = -1, s_shunt_raw = -1;

static esp_err_t write_reg(uint8_t reg, uint16_t value) {
    uint8_t data[] = {reg, (uint8_t)(value >> 8), (uint8_t)value};
    return i2c_master_transmit(s_dev, data, sizeof(data), 50);
}
static esp_err_t read_reg(uint8_t reg, uint16_t *value) {
    uint8_t data[2];
    esp_err_t err = i2c_master_transmit_receive(s_dev, &reg, 1, data, 2, 50);
    if (err == ESP_OK) *value = ((uint16_t)data[0] << 8) | data[1];
    return err;
}
static esp_err_t read_sample(float *voltage, float *current, float *power) {
    /* 0x399B: bus range32V (giới hạn đầu vào chip vẫn26V), PGA±320mV,
     * bus/shunt12bit, triggered shunt+bus. Mỗi lần ghi tạo một mẫu mới.
     * Đọc Vshunt trực tiếp: 10uV/LSB. I=Vshunt/R, không dùng Current Register
     * nên không phụ thuộc Calibration Register của INA219. */
    s_read_stage = "write_config";
    s_bus_raw = s_shunt_raw = -1;
    esp_err_t err = write_reg(0x00, 0x399B);
    if (err != ESP_OK) return err;
    uint16_t bus = 0, shunt = 0;
    for (int i = 0; i < 10; ++i) {
        vTaskDelay(pdMS_TO_TICKS(10));
        s_read_stage = "read_bus";
        err = read_reg(0x02, &bus);
        if (err != ESP_OK) return err;
        s_bus_raw = bus;
        if (bus & 2) break; /* CNVR: conversion ready */
    }
    if (!(bus & 2)) { s_read_stage = "conversion_timeout"; return ESP_ERR_TIMEOUT; }
    s_read_stage = "read_shunt";
    err = read_reg(0x01, &shunt);
    if (err != ESP_OK) return err;
    s_shunt_raw = shunt;
    if (bus & 1) { s_read_stage = "math_overflow"; return ESP_ERR_INVALID_STATE; }
    int16_t signed_shunt = (int16_t)shunt;
    if (signed_shunt <= -32000 || signed_shunt >= 32000) {
        s_read_stage = "shunt_out_of_range";
        return ESP_ERR_INVALID_STATE;
    }
    *voltage = (bus >> 3) * 0.004f; /* VIN- so với GND */
    *current = signed_shunt * 0.01f / INA219_SHUNT_OHMS; /* mA */
    *power = *voltage * *current / 1000.0f; /* W, nhánh nguồn đang được INA219 đo */
    s_read_stage = "ok";
    return ESP_OK;
}
static void sensor_task(void *arg) {
    (void)arg;
    esp_err_t previous = ESP_OK;
    int64_t last_telemetry=0;
    for (;;) {
        float v = 0, ma = 0, w = 0;
        int64_t start=esp_timer_get_time();
        esp_err_t err = read_sample(&v, &ma, &w);
        int64_t now=esp_timer_get_time();
        cycle_energy_sample((start+now)/2,err,v,ma,w);
        cycle_energy_tick();
        if (err != previous && !cycle_energy_busy()) {
            if (err == ESP_OK) ESP_LOGI(TAG, "Cam bien da phan hoi lai");
            else ESP_LOGW(TAG, "Loi %s tai %s; bus_raw=%d shunt_raw=%d; 3V3/GND/SDA25/SCL26/0x40",
                          esp_err_to_name(err), s_read_stage, s_bus_raw, s_shunt_raw);
            previous = err;
        }
        if(!cycle_energy_busy() && now-last_telemetry>=1000000){
            mqtt_app_publish_telemetry(err == ESP_OK, v, ma, w, err, s_read_stage, s_bus_raw, s_shunt_raw);
            last_telemetry=now;
        }
        ulTaskNotifyTake(pdTRUE,pdMS_TO_TICKS(cycle_energy_busy()?10:1000));
    }
}
void ina219_app_start(void) {
    i2c_master_bus_config_t cfg = {
        .i2c_port = I2C_NUM_0, .sda_io_num = INA219_SDA_PIN, .scl_io_num = INA219_SCL_PIN,
        .clk_source = I2C_CLK_SRC_DEFAULT, .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    ESP_ERROR_CHECK(i2c_new_master_bus(&cfg, &s_bus));
    i2c_device_config_t dev = {.dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = INA219_ADDRESS, .scl_speed_hz = 100000};
    ESP_ERROR_CHECK(i2c_master_bus_add_device(s_bus, &dev, &s_dev));
    /* Không yêu cầu sensor trả ACK lúc boot: task tiếp tục thử khi đấu lại dây. */
    if (xTaskCreate(sensor_task, "ina219", 4096, NULL, 3, &sensor_handle) != pdPASS) {
        ESP_LOGE(TAG, "Khong tao duoc task INA219");
    }
}
