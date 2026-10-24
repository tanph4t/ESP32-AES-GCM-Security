#include "wifi_app.h"
#include <string.h>
#include <time.h>               // Thêm thư viện xử lý thời gian
#include "esp_sntp.h"           // Thêm thư viện SNTP
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "mqtt_app.h"

static const char *TAG = "WIFI_APP";
static int s_retry_num = 0;

/* Hàm lấy thời gian thực từ Internet (NTP Server) */
//static void obtain_time(void) {
   // ESP_LOGI(TAG, "Đang khởi tạo kết nối NTP Server...");
   // esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
   // esp_sntp_setservername(0, "pool.ntp.org");
   /// esp_sntp_init();

    // Vòng lặp chờ đồng bộ (Tối đa 30 giây)
    //int retry = 0;
   // const int retry_count = 15;
  //  while (sntp_get_sync_status() == SNTP_SYNC_STATUS_RESET && ++retry < retry_count) {
  //      ESP_LOGI(TAG, "Chờ đồng bộ thời gian thực (%d/%d)...", retry, retry_count);
   //     vTaskDelay(2000 / portTICK_PERIOD_MS);
  //  }

    // Thiết lập múi giờ Việt Nam (UTC+7)
  //  setenv("TZ", "UTC-7", 1);
  // tzset();
    
   // time_t now;
   // struct tm timeinfo;
  //  time(&now);
  //  localtime_r(&now, &timeinfo);
   // ESP_LOGI(TAG, "Thời gian hệ thống hiện tại: %s", asctime(&timeinfo));
//}

/* Trình xử lý các sự kiện Wi-Fi và IP */
static void event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *disconnected=event_data;
        if(disconnected)
            ESP_LOGW(TAG,"WiFi disconnected: reason=%u, last_rssi=%d dBm",
                     (unsigned)disconnected->reason,(int)disconnected->rssi);
        if (s_retry_num < MAXIMUM_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Đang thử kết nối lại với AP...");
        } else {
            ESP_LOGE(TAG, "Không thể kết nối tới Wi-Fi");
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Đã nhận được IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        
        // --- ĐIỂM CẢI TIẾN QUAN TRỌNG ---
        // obtain_time();    // 1. Đồng bộ giờ Quốc tế trước
        mqtt_app_start(); // 2. Có giờ chuẩn rồi mới cho phép chạy MQTT
         
    }
}

/* Hàm khởi tạo Wi-Fi ở chế độ Station (Máy trạm) */
void wifi_init_sta(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = ESP_WIFI_SSID,
            .password = ESP_WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    /* Keep Wi-Fi receive latency independent of AP DTIM/modem-sleep.
     * Fixed for both AES modes; energy experiments must be rerun together. */
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_LOGI(TAG,"WiFi power save OFF (WIFI_PS_NONE); same setting for both AES modes");

    ESP_LOGI(TAG, "Quá trình khởi tạo wifi_init_sta hoàn tất.");
}
