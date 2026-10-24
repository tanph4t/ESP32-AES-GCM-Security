#ifndef WIFI_APP_H
#define WIFI_APP_H

/* Optional local override, ignored by git. Copy wifi_credentials.local.h.example. */
#if __has_include("wifi_credentials.local.h")
#include "wifi_credentials.local.h"
#endif
#ifndef ESP_WIFI_SSID
#define ESP_WIFI_SSID      "YOUR_SSID"
#endif
#ifndef ESP_WIFI_PASS
#define ESP_WIFI_PASS      "YOUR_PASSWORD"
#endif
#define MAXIMUM_RETRY      5

void wifi_init_sta(void);

#endif