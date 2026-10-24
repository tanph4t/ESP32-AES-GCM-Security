#ifndef CYCLE_ENERGY_H
#define CYCLE_ENERGY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#define CYCLE_ENERGY_REQUEST "device/esp32/cycle-energy/request"
#define CYCLE_ENERGY_RESULT "device/esp32/cycle-energy/result"
bool cycle_energy_busy(void);
const char *cycle_energy_id(void); /* MQTT task only reads for diagnostics. */
void cycle_energy_request(const char *hex,size_t len);
void cycle_energy_receive(int64_t us);
void cycle_energy_applied(const char *id,bool on,int64_t us);
void cycle_energy_interference(void);
void cycle_energy_sample(int64_t us,esp_err_t error,float v,float ma,float w);
void cycle_energy_tick(void);
void cycle_energy_disconnected(void);
void ina219_cycle_wake(void);
#endif
