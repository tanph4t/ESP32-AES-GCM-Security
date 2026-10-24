#include <stdio.h>
#include "ina219_app.h"
#include "nvs_flash.h"
#include "wifi_app.h"
#include "mqtt_app.h" 
#include "crypto_app.h" // Nhúng thư viện mật mã AES-GCM
#include "hardware_control.h" // 1. Thêm dòng này để nhúng thư viện điều khiển phần cứng

void app_main(void) {
    // 2. Khởi tạo phần cứng (các chân GPIO) ngay đầu tiên
    hardware_init();
    ina219_app_start();

    // 3. Chạy bài kiểm thử mã hóa AES-GCM (chưa cần Wi-Fi)
    test_crypto_engine();

    // 4. Khởi tạo NVS Flash (Bắt buộc cho Wi-Fi)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // 5. Khởi tạo Wi-Fi
    wifi_init_sta();
}
