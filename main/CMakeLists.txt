idf_component_register(
    SRCS "main.c" "wifi_app.c" "mqtt_app.c" "crypto_app.c"
         "hardware_control.c" "ina219_app.c" "cycle_energy.c" "command_memory.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES nvs_flash esp_wifi esp_event esp_netif lwip mqtt
                  mbedtls esp_timer esp_system esp_driver_gpio esp_driver_i2c json
    EMBED_TXTFILES "emqxsl-ca.crt"
)
