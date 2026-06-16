/*
 * storage.c
 *
 * NVS-backed credential store. All public functions are safe to call from
 * any task after nvs_flash_init() has returned ESP_OK.
 *
 * All key names are intentionally short and opaque:
 *   "pv" = provisioned, "wk" = wifi ssid, "wp" = wifi pass,
 *   "mu" = mqtt url,    "mp" = mqtt port, "ma" = mqtt user,
 *   "mb" = mqtt pass,   "hs" = hmac secret, "ts" = totp seed
 */

#include <string.h>
#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "storage.h"
#include "sdkconfig.h"
#include "iot_button.h"
#include "button_gpio.h"
#include "esp_system.h"

static const char *TAG   = "storage";
static const char *NS    = CONFIG_STORAGE_NVS_NAMESPACE;   /* e.g. "wol" */

/* Opaque NVS key names */
#define KEY_PROVISIONED   "pv"
#define KEY_WIFI_SSID     "wk"
#define KEY_WIFI_PASS     "wp"
#define KEY_MQTT_URL      "mu"
#define KEY_MQTT_PORT     "mp"
#define KEY_MQTT_USER     "ma"
#define KEY_MQTT_PASS     "mb"
#define KEY_HMAC_SECRET   "hs"
#define KEY_TOTP_SEED     "ts"

/* --------------------------------------------------------------------------
 * Internal helper — open the NVS namespace
 * -------------------------------------------------------------------------- */
static esp_err_t open_nvs(nvs_open_mode_t mode, nvs_handle_t *out_handle)
{
    esp_err_t err = nvs_open(NS, mode, out_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open(\"%s\") failed: %s", NS, esp_err_to_name(err));
    }
    return err;
}

/* --------------------------------------------------------------------------
 * Provisioning state
 * -------------------------------------------------------------------------- */
bool storage_is_provisioned(void)
{
    nvs_handle_t h;
    if (open_nvs(NVS_READONLY, &h) != ESP_OK) return false;

    uint8_t flag = 0;
    esp_err_t err = nvs_get_u8(h, KEY_PROVISIONED, &flag);
    nvs_close(h);

    return (err == ESP_OK && flag == 1);
}

/* --------------------------------------------------------------------------
 * Save / load credentials
 * -------------------------------------------------------------------------- */
esp_err_t storage_save_credentials(const storage_credentials_t *creds)
{
    if (creds == NULL) return ESP_ERR_INVALID_ARG;

    nvs_handle_t h;
    esp_err_t err = open_nvs(NVS_READWRITE, &h);
    if (err != ESP_OK) return err;

    /* Write each field — abort on first error */
    err = nvs_set_str(h, KEY_WIFI_SSID, creds->wifi_ssid);
    if (err != ESP_OK) goto done;

    err = nvs_set_str(h, KEY_WIFI_PASS, creds->wifi_pass);
    if (err != ESP_OK) goto done;

    err = nvs_set_str(h, KEY_MQTT_URL, creds->mqtt_url);
    if (err != ESP_OK) goto done;

    err = nvs_set_u16(h, KEY_MQTT_PORT, creds->mqtt_port);
    if (err != ESP_OK) goto done;

    err = nvs_set_str(h, KEY_MQTT_USER, creds->mqtt_user);
    if (err != ESP_OK) goto done;

    err = nvs_set_str(h, KEY_MQTT_PASS, creds->mqtt_pass);
    if (err != ESP_OK) goto done;

    /* Set provisioned flag last so a partial write is not mistaken for
     * a successful one on the next boot. */
    err = nvs_set_u8(h, KEY_PROVISIONED, 1);
    if (err != ESP_OK) goto done;

    err = nvs_commit(h);

done:
    nvs_close(h);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Credentials saved successfully");
    } else {
        ESP_LOGE(TAG, "Credential save failed: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t storage_load_credentials(storage_credentials_t *creds)
{
    if (creds == NULL) return ESP_ERR_INVALID_ARG;

    nvs_handle_t h;
    esp_err_t err = open_nvs(NVS_READONLY, &h);
    if (err != ESP_OK) return err;

    size_t len;

    len = sizeof(creds->wifi_ssid);
    err = nvs_get_str(h, KEY_WIFI_SSID, creds->wifi_ssid, &len);
    if (err != ESP_OK) goto done;

    len = sizeof(creds->wifi_pass);
    err = nvs_get_str(h, KEY_WIFI_PASS, creds->wifi_pass, &len);
    if (err != ESP_OK) goto done;

    len = sizeof(creds->mqtt_url);
    err = nvs_get_str(h, KEY_MQTT_URL, creds->mqtt_url, &len);
    if (err != ESP_OK) goto done;

    err = nvs_get_u16(h, KEY_MQTT_PORT, &creds->mqtt_port);
    if (err != ESP_OK) goto done;

    len = sizeof(creds->mqtt_user);
    err = nvs_get_str(h, KEY_MQTT_USER, creds->mqtt_user, &len);
    if (err != ESP_OK) goto done;

    len = sizeof(creds->mqtt_pass);
    err = nvs_get_str(h, KEY_MQTT_PASS, creds->mqtt_pass, &len);

done:
    nvs_close(h);
    return err;
}

/* --------------------------------------------------------------------------
 * OPSEC key material
 * -------------------------------------------------------------------------- */
static esp_err_t load_or_generate_blob(const char *key, uint8_t *buf,
                                        size_t len)
{
    nvs_handle_t h;
    esp_err_t err = open_nvs(NVS_READWRITE, &h);
    if (err != ESP_OK) return err;

    size_t actual_len = len;
    err = nvs_get_blob(h, key, buf, &actual_len);

    if (err == ESP_ERR_NVS_NOT_FOUND || (err == ESP_OK && actual_len != len)) {
        /* Generate a fresh random secret and persist it */
        esp_fill_random(buf, len);
        err = nvs_set_blob(h, key, buf, len);
        if (err == ESP_OK) {
            err = nvs_commit(h);
        }
        ESP_LOGI(TAG, "Generated new random blob for key \"%s\" (%zu bytes)", key, len);
    }

    nvs_close(h);
    return err;
}

esp_err_t storage_save_hmac_secret(const uint8_t secret[STORAGE_HMAC_SECRET_LEN])
{
    nvs_handle_t h;
    esp_err_t err = open_nvs(NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, KEY_HMAC_SECRET, secret, STORAGE_HMAC_SECRET_LEN);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t storage_load_or_generate_hmac_secret(uint8_t secret[STORAGE_HMAC_SECRET_LEN])
{
    return load_or_generate_blob(KEY_HMAC_SECRET, secret, STORAGE_HMAC_SECRET_LEN);
}

esp_err_t storage_save_totp_seed(const uint8_t seed[STORAGE_TOTP_SEED_LEN])
{
    nvs_handle_t h;
    esp_err_t err = open_nvs(NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, KEY_TOTP_SEED, seed, STORAGE_TOTP_SEED_LEN);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t storage_load_or_generate_totp_seed(uint8_t seed[STORAGE_TOTP_SEED_LEN])
{
    return load_or_generate_blob(KEY_TOTP_SEED, seed, STORAGE_TOTP_SEED_LEN);
}

/* --------------------------------------------------------------------------
 * Erase
 * -------------------------------------------------------------------------- */
esp_err_t storage_erase_all(void)
{
    nvs_handle_t h;
    esp_err_t err = open_nvs(NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_erase_all(h);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    ESP_LOGW(TAG, "NVS namespace \"%s\" erased", NS);
    return err;
}

/* --------------------------------------------------------------------------
 * Factory Reset Button
 * -------------------------------------------------------------------------- */

static void factory_reset_cb(void *button_handle, void *usr_data)
{
    ESP_LOGW(TAG, "Factory reset via BOOT button long-press — wiping credentials");
    storage_erase_all();
    ESP_LOGW(TAG, "Rebooting into portal mode");
    esp_restart();
    /* never returns */
}

void storage_button_init(void)
{
    button_config_t btn_cfg = {
        .long_press_time  = 0,    // 0 = use global Kconfig default
        .short_press_time = 200,  // minimum press duration to register a short click (ms)
    };
    button_gpio_config_t gpio_cfg = {
        .gpio_num = 0,            // BOOT button
        .active_level = 0,        // active low
        .enable_power_save = false,
    };
    button_handle_t btn_handle = NULL;
    esp_err_t err = iot_button_new_gpio_device(&btn_cfg, &gpio_cfg, &btn_handle);
    if (err != ESP_OK || btn_handle == NULL) {
        ESP_LOGE(TAG, "Failed to initialize BOOT button");
        return;
    }

    button_event_args_t long_press_args = {
        .long_press.press_time = CONFIG_WOL_FACTORY_RESET_HOLD_MS,
    };
    esp_err_t cb_err = iot_button_register_cb(btn_handle, BUTTON_LONG_PRESS_START,
                                           &long_press_args, factory_reset_cb, NULL);
    if (cb_err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register factory reset callback: %s",
                 esp_err_to_name(cb_err));
    }
}
