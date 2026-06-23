#pragma once

#include "esphome.h"
#include <algorithm>
#include <cstring>
#include <esp_now.h>
#include <map>
#include <string>
#include <vector>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>

// ESP-NOW bridge: encrypted app traffic (AES-GCM) vs cleartext pairing (ECDH when pairing_mode_active).
// Optional LED feedback via Config::led_feedback (nullptr = no-op).
// Instantiate one EspClickBridge (or use the glue header pattern from presence_1_basic/espnow_handler.h).

static constexpr size_t ESP_CLICK_SESSION_HISTORY_LEN = 16;

struct DeviceKey {
  uint8_t key[16];
  uint32_t last_counter = 0;
  uint64_t current_session_id = 0;
  uint64_t session_history[ESP_CLICK_SESSION_HISTORY_LEN] = {};
};

enum PressEvent { NONE_PRESS, SINGLE_PRESS, DOUBLE_PRESS, LONG_PRESS };
enum BatteryStatus {
  CHARGING,
  DISCHARGING,
  FULL_CHARGED,
  NOT_CONNECTED,
  CHARGE_FAULT
};

inline const char *battery_status_to_str(BatteryStatus s) {
  switch (s) {
  case CHARGING:
    return "charging";
  case DISCHARGING:
    return "discharging";
  case FULL_CHARGED:
    return "full";
  case NOT_CONNECTED:
    return "not_connected";
  case CHARGE_FAULT:
    return "charge_fault";
  default:
    return "unknown";
  }
}

enum MessageType {
  BUTTON_PRESS,
  BATTERY_STATUS,
  DISCOVERY_REQUEST,
  PAIRING_REQUEST,
  PAIRING_RESPONSE,
  UNPAIR_REQUEST,
};

enum AckReason : uint8_t {
  ACK_OK = 0,
  ACK_SESSION_ID_ZERO = 1,
  ACK_REPLAY_COUNTER = 2,
  ACK_SESSION_RETIRED = 3,
};

struct __attribute__((packed)) AckMessage {
  uint32_t counter;
  uint64_t sessionId = 0;
  bool success;
  AckReason reason = ACK_OK;
};

struct __attribute__((packed)) Message {
  uint32_t counter;
  uint64_t sessionId = 0;
  int deviceId = 0;
  MessageType type;
  union {
    struct {
      int buttonId;
      PressEvent event;
    } buttonPress;
    struct {
      int level;
      BatteryStatus status;
    } batteryLevel;
    struct {
      size_t keyLen;
      uint8_t publicKey[65];
    } pairing;
  } data;
};

#define ESP_CLICK_AES_IV_LENGTH 12
#define ESP_CLICK_AES_TAG_LENGTH 16

struct __attribute__((packed)) EncryptedPacket {
  uint8_t iv[ESP_CLICK_AES_IV_LENGTH];
  uint8_t ciphertext[sizeof(Message)];
  uint8_t tag[ESP_CLICK_AES_TAG_LENGTH];
};

struct __attribute__((packed)) EncryptedAckPacket {
  uint8_t iv[ESP_CLICK_AES_IV_LENGTH];
  uint8_t ciphertext[sizeof(AckMessage)];
  uint8_t tag[ESP_CLICK_AES_TAG_LENGTH];
};

class EspClickBridge {
public:
  using LedFeedbackFn = void (*)(const uint8_t *rgb, int passes);

  struct Config {
    const char *log_tag;
    LedFeedbackFn led_feedback;
    Config() : log_tag("esp_click"), led_feedback(nullptr) {}
    Config(const char *tag, LedFeedbackFn fn) : log_tag(tag ? tag : "esp_click"), led_feedback(fn) {}
  };

  explicit EspClickBridge(Config cfg = Config()) : cfg_(cfg) {}

  std::map<std::string, DeviceKey> known_devices;
  bool mqtt_paired_initial_sync_done{false};
  bool pairing_mode_active{false};
  volatile bool g_request_close_pairing_mode{false};
  volatile bool g_pairing_close_skip_red_led{false};

  void handle_packet(const uint8_t *addr, const uint8_t *data, int size);
  void mqtt_ensure_device_sync_subscription();
  void publish_one_device_to_mqtt(const std::string &mac);
  void publish_known_devices_to_mqtt();
  void clear_all_paired_devices_mqtt();

  static bool decrypt_packet(const EncryptedPacket *encrypted_packet,
                             const uint8_t *shared_key, Message *out_msg);

private:
  Config cfg_;

  std::vector<std::string> discovered_macs_;
  std::vector<std::string> discovered_buttons_;
  bool mqtt_sub_registered_{false};

  static constexpr const char *MQTT_DEVICE_TOPIC_PREFIX = "esp_click/device/";

  const char *tag() const { return cfg_.log_tag ? cfg_.log_tag : "esp_click"; }

  void led_wave_rgb(uint8_t r, uint8_t g, uint8_t b, int passes = 1) const {
    if (cfg_.led_feedback == nullptr)
      return;
    const uint8_t rgb[3] = {r, g, b};
    cfg_.led_feedback(rgb, passes);
  }

  static std::string mac_to_str_(const uint8_t *mac) {
    char buf[13];
    snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5]);
    return std::string(buf);
  }

  static std::string hex_encode_(const uint8_t *data, size_t len) {
    char buf[len * 2 + 1];
    for (size_t i = 0; i < len; ++i)
      snprintf(buf + i * 2, 3, "%02x", data[i]);
    return std::string(buf);
  }

  static std::string hex_encode_u64_(uint64_t v) {
    uint8_t b[8];
    memcpy(b, &v, sizeof(v));
    return hex_encode_(b, sizeof(b));
  }

  static bool hex_decode_u64_(const std::string &s, uint64_t *out) {
    if (s.length() != 16 || out == nullptr)
      return false;
    uint8_t b[8];
    for (int i = 0; i < 8; i++) {
      std::string byteString = s.substr(i * 2, 2);
      char *end = nullptr;
      unsigned long byte_val = strtoul(byteString.c_str(), &end, 16);
      if (end != byteString.c_str() + 2 || byte_val > 255)
        return false;
      b[i] = (uint8_t)byte_val;
    }
    memcpy(out, b, sizeof(uint64_t));
    return true;
  }

  static void build_ack_iv_(uint64_t session_id, uint32_t counter,
                             uint8_t iv[ESP_CLICK_AES_IV_LENGTH]) {
    memcpy(iv, &session_id, sizeof(session_id));
    uint32_t ctr_flipped = ~counter;
    memcpy(iv + sizeof(session_id), &ctr_flipped, sizeof(ctr_flipped));
  }

  static bool iv_matches_plaintext_(const EncryptedPacket *ep, const Message *msg) {
    uint8_t expected[ESP_CLICK_AES_IV_LENGTH];
    memcpy(expected, &msg->sessionId, sizeof(msg->sessionId));
    memcpy(expected + sizeof(msg->sessionId), &msg->counter, sizeof(msg->counter));
    return memcmp(expected, ep->iv, ESP_CLICK_AES_IV_LENGTH) == 0;
  }

  static bool session_id_is_retired_(const DeviceKey &dk, uint64_t sid) {
    for (size_t i = 0; i < ESP_CLICK_SESSION_HISTORY_LEN; i++) {
      if (dk.session_history[i] == sid)
        return true;
    }
    return false;
  }

  static void retire_current_session_(DeviceKey &dk) {
    if (dk.current_session_id == 0)
      return;
    memmove(dk.session_history + 1, dk.session_history,
           (ESP_CLICK_SESSION_HISTORY_LEN - 1) * sizeof(uint64_t));
    dk.session_history[0] = dk.current_session_id;
    dk.current_session_id = 0;
  }

  static AckReason accept_session_and_counter_(DeviceKey &dk, uint64_t session_id,
                                              uint32_t counter, const char *lg) {
    if (session_id == 0) {
      ESP_LOGW(lg, "Rejecting encrypted packet: sessionId 0 invalid");
      return ACK_SESSION_ID_ZERO;
    }
    if (dk.current_session_id == session_id) {
      if (counter <= dk.last_counter) {
        ESP_LOGW(lg, "Replay attack (counter) from session 0x%016llx. Dropped.",
                 (unsigned long long)session_id);
        return ACK_REPLAY_COUNTER;
      }
      dk.last_counter = counter;
      return ACK_OK;
    }
    if (session_id_is_retired_(dk, session_id)) {
      ESP_LOGW(lg, "Replay attack (retired session) 0x%016llx. Dropped.",
               (unsigned long long)session_id);
      return ACK_SESSION_RETIRED;
    }
    retire_current_session_(dk);
    dk.current_session_id = session_id;
    dk.last_counter = counter;
    return ACK_OK;
  }

  std::string mqtt_device_topic_(const std::string &mac) const {
    return std::string(MQTT_DEVICE_TOPIC_PREFIX) + mac;
  }

  void publish_mqtt_discovery_(const std::string &mac, int entity_id);
  void remove_paired_device_from_bridge_(const std::string &mac);
  void mqtt_on_device_topic_(const std::string &topic, const std::string &payload);
  void publish_device_key_json_to_mqtt__(const std::string &mac, const DeviceKey &dk);

  static bool encrypt_ack_packet_(const AckMessage *plain, const uint8_t *shared_key,
                                  uint64_t session_id, uint32_t counter,
                                  EncryptedAckPacket *out, const char *lg);
  void send_encrypted_ack_to_peer_(const uint8_t *addr, const std::string &sender_mac,
                                   uint64_t session_id, uint32_t counter, bool success,
                                   AckReason fail_reason = ACK_OK);
};

// -----------------------------------------------------------------------------
// EspClickBridge implementation (header-only)
// -----------------------------------------------------------------------------

inline bool EspClickBridge::decrypt_packet(const EncryptedPacket *encrypted_packet,
                                       const uint8_t *shared_key, Message *out_msg) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, shared_key, 128);
  if (ret != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }
  ret = mbedtls_gcm_auth_decrypt(&gcm, sizeof(Message), encrypted_packet->iv,
                                 ESP_CLICK_AES_IV_LENGTH, NULL, 0, encrypted_packet->tag,
                                 ESP_CLICK_AES_TAG_LENGTH, encrypted_packet->ciphertext,
                                 (unsigned char *)out_msg);
  mbedtls_gcm_free(&gcm);
  if (ret == MBEDTLS_ERR_GCM_AUTH_FAILED)
    return false;
  return ret == 0;
}

inline void EspClickBridge::publish_mqtt_discovery_(const std::string &mac, int entity_id) {
  if (mqtt::global_mqtt_client == nullptr || !mqtt::global_mqtt_client->is_connected())
    return;

  std::string device_json = R"("device":{"identifiers":["esp_click_)" + mac +
                            R"("],"name":"ESP Click )" + mac +
                            R"(","manufacturer":"M Industries","model":"ESP Click V1"})";

  if (std::find(discovered_macs_.begin(), discovered_macs_.end(), mac) ==
      discovered_macs_.end()) {
    ESP_LOGI(tag(), "Publishing HA Discovery for Device Battery: %s", mac.c_str());
    std::string bat_topic = "homeassistant/sensor/esp_click_" + mac + "/batt/config";
    std::string bat_payload =
        R"({"name":"Battery Level","state_topic":"esp_click/)" + mac +
        R"(/battery_level","unit_of_measurement":"%","device_class":"battery","unique_id":"esp_click_)" +
        mac + R"(_bat",)" + device_json + R"(})";
    mqtt::global_mqtt_client->publish(bat_topic, bat_payload, 0, true);

    std::string stat_topic = "homeassistant/sensor/esp_click_" + mac + "/stat/config";
    std::string stat_payload =
        R"({"name":"Battery Status","state_topic":"esp_click/)" + mac +
        R"(/battery_status","icon":"mdi:battery-charging","unique_id":"esp_click_)" +
        mac + R"(_stat",)" + device_json + R"(})";
    mqtt::global_mqtt_client->publish(stat_topic, stat_payload, 0, true);

    discovered_macs_.push_back(mac);
  }

  std::string button_key = mac + "_" + std::to_string(entity_id);
  if (std::find(discovered_buttons_.begin(), discovered_buttons_.end(), button_key) ==
      discovered_buttons_.end()) {
    ESP_LOGI(tag(), "Publishing HA Discovery for Device Triggers: %s (Entity %d)", mac.c_str(),
             entity_id);
    std::string base_state_topic =
        "esp_click/" + mac + "/entity_" + std::to_string(entity_id) + "/event";
    std::string ha_subtype = "button_" + std::to_string(entity_id + 1);

    std::string single_topic = "homeassistant/device_automation/esp_click_" + mac +
                               "/btn_" + std::to_string(entity_id) + "_single/config";
    std::string single_payload =
        R"({"automation_type":"trigger","type":"button_short_press","subtype":")" +
        ha_subtype + R"(","payload":"single","topic":")" + base_state_topic +
        R"(",)" + device_json + R"(})";
    mqtt::global_mqtt_client->publish(single_topic, single_payload, 0, true);

    std::string double_topic = "homeassistant/device_automation/esp_click_" + mac +
                               "/btn_" + std::to_string(entity_id) + "_double/config";
    std::string double_payload =
        R"({"automation_type":"trigger","type":"button_double_press","subtype":")" +
        ha_subtype + R"(","payload":"double","topic":")" + base_state_topic +
        R"(",)" + device_json + R"(})";
    mqtt::global_mqtt_client->publish(double_topic, double_payload, 0, true);

    std::string long_topic = "homeassistant/device_automation/esp_click_" + mac + "/btn_" +
                             std::to_string(entity_id) + "_long/config";
    std::string long_payload =
        R"({"automation_type":"trigger","type":"button_long_press","subtype":")" +
        ha_subtype + R"(","payload":"long","topic":")" + base_state_topic +
        R"(",)" + device_json + R"(})";
    mqtt::global_mqtt_client->publish(long_topic, long_payload, 0, true);

    discovered_buttons_.push_back(button_key);
  }
}

inline void EspClickBridge::remove_paired_device_from_bridge_(const std::string &mac) {
  mqtt_ensure_device_sync_subscription();
  int old_size = (int)known_devices.size();
  if (known_devices.erase(mac) == 0)
    return;

  discovered_macs_.erase(std::remove(discovered_macs_.begin(), discovered_macs_.end(), mac),
                        discovered_macs_.end());
  const std::string btn_prefix = mac + "_";
  discovered_buttons_.erase(
      std::remove_if(discovered_buttons_.begin(), discovered_buttons_.end(),
                     [&](const std::string &k) {
                       return k.size() >= btn_prefix.size() &&
                              k.compare(0, btn_prefix.size(), btn_prefix) == 0;
                     }),
      discovered_buttons_.end());

  if (mqtt::global_mqtt_client != nullptr && mqtt::global_mqtt_client->is_connected())
    mqtt::global_mqtt_client->publish(mqtt_device_topic_(mac), std::string(), 0, true);

  ESP_LOGI(tag(), "Removed paired device %s (UNPAIR_REQUEST)", mac.c_str());

  if (old_size > 0)
    led_wave_rgb(255, 0, 0, 1);
  mqtt_paired_initial_sync_done = true;
}

inline void EspClickBridge::mqtt_on_device_topic_(const std::string &topic,
                                               const std::string &payload) {
  const size_t plen = strlen(MQTT_DEVICE_TOPIC_PREFIX);
  if (topic.size() <= plen || topic.compare(0, plen, MQTT_DEVICE_TOPIC_PREFIX) != 0)
    return;
  std::string topic_mac = topic.substr(plen);

  int old_size = (int)known_devices.size();

  if (payload.empty()) {
    if (known_devices.erase(topic_mac) > 0) {
      ESP_LOGI(tag(), "Removed device %s (MQTT retained delete)", topic_mac.c_str());
      if (mqtt_paired_initial_sync_done && old_size > 0)
        led_wave_rgb(255, 0, 0, 1);
    }
    mqtt_paired_initial_sync_done = true;
    return;
  }

  JsonDocument doc;
  if (deserializeJson(doc, payload))
    return;
  JsonObjectConst dev = doc.as<JsonObjectConst>();
  std::string mac = dev["mac"].as<std::string>();
  if (mac.empty())
    mac = topic_mac;
  std::string key_hex = dev["key"].as<std::string>();

  DeviceKey dk{};
  if (key_hex.length() == 32) {
    for (int i = 0; i < 16; i++) {
      std::string byteString = key_hex.substr(i * 2, 2);
      dk.key[i] = (uint8_t)strtol(byteString.c_str(), NULL, 16);
    }
    if (!dev["last_counter"].isNull())
      dk.last_counter = dev["last_counter"].as<uint32_t>();
    if (!dev["current_session_id"].isNull()) {
      std::string sid = dev["current_session_id"].as<std::string>();
      hex_decode_u64_(sid, &dk.current_session_id);
    }
    if (!dev["session_history"].isNull()) {
      JsonArrayConst hist = dev["session_history"].as<JsonArrayConst>();
      int idx = 0;
      for (JsonVariantConst hv : hist) {
        if (idx >= (int)ESP_CLICK_SESSION_HISTORY_LEN)
          break;
        std::string hs = hv.as<std::string>();
        hex_decode_u64_(hs, &dk.session_history[idx]);
        idx++;
      }
    }
    known_devices[mac] = dk;
  }

  int new_size = (int)known_devices.size();
  ESP_LOGI(tag(), "Merged device %s from MQTT. Total paired: %d", mac.c_str(), new_size);

  if (mqtt_paired_initial_sync_done && new_size > old_size)
    led_wave_rgb(0, 255, 0, 1);
  mqtt_paired_initial_sync_done = true;
}

inline void EspClickBridge::mqtt_ensure_device_sync_subscription() {
  if (mqtt_sub_registered_ || mqtt::global_mqtt_client == nullptr)
    return;
  mqtt_sub_registered_ = true;
  mqtt::global_mqtt_client->subscribe(
      "esp_click/device/+",
      [this](const std::string &topic, const std::string &payload) {
        mqtt_on_device_topic_(topic, payload);
      },
      0);
}

inline void EspClickBridge::publish_device_key_json_to_mqtt__(const std::string &mac,
                                                         const DeviceKey &dk) {
  JsonDocument doc;
  JsonObject dev = doc.to<JsonObject>();
  dev["mac"] = mac;
  dev["key"] = hex_encode_(dk.key, 16);
  dev["last_counter"] = dk.last_counter;
  dev["current_session_id"] = hex_encode_u64_(dk.current_session_id);
  JsonArray hist = dev["session_history"].to<JsonArray>();
  for (size_t i = 0; i < ESP_CLICK_SESSION_HISTORY_LEN; i++)
    hist.add(hex_encode_u64_(dk.session_history[i]));

  std::string json_str;
  serializeJson(doc, json_str);
  mqtt::global_mqtt_client->publish(mqtt_device_topic_(mac), json_str, 0, true);
}

inline void EspClickBridge::publish_one_device_to_mqtt(const std::string &mac) {
  mqtt_ensure_device_sync_subscription();
  if (mqtt::global_mqtt_client == nullptr || !mqtt::global_mqtt_client->is_connected())
    return;
  auto it = known_devices.find(mac);
  if (it == known_devices.end())
    return;
  publish_device_key_json_to_mqtt__(mac, it->second);
}

inline void EspClickBridge::publish_known_devices_to_mqtt() {
  mqtt_ensure_device_sync_subscription();
  if (mqtt::global_mqtt_client == nullptr || !mqtt::global_mqtt_client->is_connected())
    return;
  for (const auto &pair : known_devices)
    publish_device_key_json_to_mqtt__(pair.first, pair.second);
  ESP_LOGI(tag(), "Published device keys to esp_click/device/<mac> (retained).");
}

inline void EspClickBridge::clear_all_paired_devices_mqtt() {
  mqtt_ensure_device_sync_subscription();
  if (mqtt::global_mqtt_client == nullptr || !mqtt::global_mqtt_client->is_connected())
    return;

  std::vector<std::string> macs;
  macs.reserve(known_devices.size());
  for (const auto &p : known_devices)
    macs.push_back(p.first);

  for (const auto &mac : macs)
    mqtt::global_mqtt_client->publish(mqtt_device_topic_(mac), std::string(), 0, true);

  known_devices.clear();
  if (!macs.empty()) {
    mqtt_paired_initial_sync_done = true;
    led_wave_rgb(255, 0, 0, 1);
  }
  ESP_LOGI(tag(), "Cleared all paired devices (per-MQTT-topic delete).");
}

inline bool EspClickBridge::encrypt_ack_packet_(const AckMessage *plain, const uint8_t *shared_key,
                                            uint64_t session_id, uint32_t counter,
                                            EncryptedAckPacket *out, const char *lg) {
  uint8_t iv[ESP_CLICK_AES_IV_LENGTH];
  build_ack_iv_(session_id, counter, iv);
  memcpy(out->iv, iv, ESP_CLICK_AES_IV_LENGTH);

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, shared_key, 128) != 0) {
    ESP_LOGE(lg, "encrypt_ack: setkey failed");
    mbedtls_gcm_free(&gcm);
    return false;
  }

  int ret = mbedtls_gcm_crypt_and_tag(
      &gcm, MBEDTLS_GCM_ENCRYPT, sizeof(AckMessage), iv, ESP_CLICK_AES_IV_LENGTH, NULL, 0,
      (const unsigned char *)plain, out->ciphertext, ESP_CLICK_AES_TAG_LENGTH, out->tag);

  mbedtls_gcm_free(&gcm);

  if (ret != 0) {
    ESP_LOGE(lg, "encrypt_ack: gcm_crypt_and_tag failed: -0x%04X", -ret);
    return false;
  }
  return true;
}

inline void EspClickBridge::send_encrypted_ack_to_peer_(const uint8_t *addr,
                                                    const std::string &sender_mac,
                                                    uint64_t session_id, uint32_t counter,
                                                    bool success, AckReason fail_reason) {
  auto it = known_devices.find(sender_mac);
  if (it == known_devices.end())
    return;
  AckMessage ack;
  ack.counter = counter;
  ack.sessionId = session_id;
  ack.success = success;
  ack.reason = success ? ACK_OK : fail_reason;
  EncryptedAckPacket pkt;
  if (!encrypt_ack_packet_(&ack, it->second.key, session_id, counter, &pkt, tag()))
    return;
  esp_err_t err = esp_now_send(addr, (uint8_t *)&pkt, sizeof(pkt));
  if (err != ESP_OK)
    ESP_LOGW(tag(), "esp_now_send encrypted ACK failed: %s", esp_err_to_name(err));
}

inline void EspClickBridge::handle_packet(const uint8_t *addr, const uint8_t *data, int size) {
  std::string sender_mac = mac_to_str_(addr);
  bool is_known = (known_devices.find(sender_mac) != known_devices.end());

  if (size == sizeof(EncryptedPacket)) {
    if (!is_known) {
      ESP_LOGW(tag(), "Rejected encrypted packet from unknown MAC: %s", sender_mac.c_str());
      return;
    }

    auto encrypted_msg = (const EncryptedPacket *)data;
    Message msg;

    if (!decrypt_packet(encrypted_msg, known_devices[sender_mac].key, &msg)) {
      ESP_LOGE(tag(), "Decryption failed for %s", sender_mac.c_str());
      return;
    }

    if (!iv_matches_plaintext_(encrypted_msg, &msg)) {
      ESP_LOGW(tag(), "IV / plaintext mismatch for %s (session/counter vs wire IV).",
               sender_mac.c_str());
      return;
    }

    AckReason session_result =
        accept_session_and_counter_(known_devices[sender_mac], msg.sessionId, msg.counter, tag());
    if (session_result != ACK_OK) {
      send_encrypted_ack_to_peer_(addr, sender_mac, msg.sessionId, msg.counter, false,
                                  session_result);
      return;
    }

    if (msg.type == DISCOVERY_REQUEST) {
      ESP_LOGD(tag(), "Received ENCRYPTED Discovery Ping from %s. Sending silent ACK.",
               sender_mac.c_str());
      send_encrypted_ack_to_peer_(addr, sender_mac, msg.sessionId, msg.counter, true);
      return;
    }

    if (msg.type == UNPAIR_REQUEST) {
      ESP_LOGI(tag(), "UNPAIR_REQUEST from %s — ACK then remove from MQTT", sender_mac.c_str());
      send_encrypted_ack_to_peer_(addr, sender_mac, msg.sessionId, msg.counter, true);
      remove_paired_device_from_bridge_(sender_mac);
      return;
    }

    send_encrypted_ack_to_peer_(addr, sender_mac, msg.sessionId, msg.counter, true);
    publish_one_device_to_mqtt(sender_mac);

    if (mqtt::global_mqtt_client != nullptr && mqtt::global_mqtt_client->is_connected()) {
      if (msg.type == BUTTON_PRESS) {
        publish_mqtt_discovery_(sender_mac, msg.data.buttonPress.buttonId);
        std::string base_topic = "esp_click/" + sender_mac + "/entity_" +
                                std::to_string(msg.data.buttonPress.buttonId);
        std::string payload;
        switch (msg.data.buttonPress.event) {
        case SINGLE_PRESS:
          payload = "single";
          led_wave_rgb(255, 255, 255, 1);
          break;
        case DOUBLE_PRESS:
          payload = "double";
          led_wave_rgb(255, 255, 0, 1);
          break;
        case LONG_PRESS:
          payload = "long";
          led_wave_rgb(0, 0, 255, 1);
          break;
        default:
          payload = "none";
          break;
        }
        mqtt::global_mqtt_client->publish(base_topic + "/event", payload, 0, false);
        ESP_LOGI(tag(), "[%s] Button %d: %s (Encrypted)", sender_mac.c_str(),
                 msg.data.buttonPress.buttonId, payload.c_str());
      } else if (msg.type == BATTERY_STATUS) {
        std::string bat_base_topic = "esp_click/" + sender_mac;
        mqtt::global_mqtt_client->publish(bat_base_topic + "/battery_level",
                                         std::to_string(msg.data.batteryLevel.level), 0, true);
        mqtt::global_mqtt_client->publish(
            bat_base_topic + "/battery_status",
            std::string(battery_status_to_str(msg.data.batteryLevel.status)), 0, true);
        ESP_LOGI(tag(), "[%s] Battery: %d%% %s (Encrypted)", sender_mac.c_str(),
                 msg.data.batteryLevel.level,
                 battery_status_to_str(msg.data.batteryLevel.status));
      }
    }
  } else if (size == sizeof(Message)) {
    if (!pairing_mode_active) {
      ESP_LOGD(tag(), "Cleartext packet dropped. Pairing Mode is OFF.");
      return;
    }

    auto msg = (const Message *)data;

    if (is_known && msg->type != PAIRING_REQUEST) {
      ESP_LOGW(tag(),
               "Strict Mode: Rejected cleartext packet from known device %s. "
               "Possible downgrade attack.",
               sender_mac.c_str());
      return;
    }

    if (msg->type == PAIRING_REQUEST) {
      if (is_known) {
        ESP_LOGI(tag(), "Re-pairing request from known device %s. Replacing stale key...",
                 sender_mac.c_str());
      } else {
        ESP_LOGI(tag(), "Pairing Request received from %s. Processing ECDH...", sender_mac.c_str());
      }

      mbedtls_ecdh_context ecdh;
      mbedtls_ctr_drbg_context ctr_drbg;
      mbedtls_entropy_context entropy;

      mbedtls_ecdh_init(&ecdh);
      mbedtls_ctr_drbg_init(&ctr_drbg);
      mbedtls_entropy_init(&entropy);

      const char *pers = "esp_click_rx_pairing";
      mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                            (const unsigned char *)pers, strlen(pers));

      if (mbedtls_ecdh_setup(&ecdh, MBEDTLS_ECP_DP_CURVE25519) != 0) {
        ESP_LOGE(tag(), "ECDH Setup Failed");
        mbedtls_ecdh_free(&ecdh);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return;
      }

      if (mbedtls_ecdh_read_public(&ecdh, msg->data.pairing.publicKey, msg->data.pairing.keyLen) !=
          0) {
        ESP_LOGE(tag(), "Failed to read sender public key");
        mbedtls_ecdh_free(&ecdh);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return;
      }

      Message responseMsg;
      responseMsg.type = PAIRING_RESPONSE;
      responseMsg.counter = msg->counter;
      responseMsg.sessionId = 0;

      size_t olen = 0;
      if (mbedtls_ecdh_make_public(&ecdh, &olen, responseMsg.data.pairing.publicKey, 65,
                                   mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        ESP_LOGE(tag(), "Failed to generate receiver public key");
        mbedtls_ecdh_free(&ecdh);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return;
      }
      responseMsg.data.pairing.keyLen = olen;

      uint8_t shared_secret[32];
      size_t secret_len;
      if (mbedtls_ecdh_calc_secret(&ecdh, &secret_len, shared_secret, sizeof(shared_secret),
                                   mbedtls_ctr_drbg_random, &ctr_drbg) == 0) {
        DeviceKey new_dev;
        memcpy(new_dev.key, shared_secret, 16);
        new_dev.last_counter = 0;
        new_dev.current_session_id = 0;
        memset(new_dev.session_history, 0, sizeof(new_dev.session_history));
        known_devices[sender_mac] = new_dev;

        esp_now_send(addr, (uint8_t *)&responseMsg, sizeof(Message));

        ESP_LOGI(tag(), "Pairing Successful! Key established for %s", sender_mac.c_str());

        led_wave_rgb(0, 255, 0, 1);
        publish_known_devices_to_mqtt();

        g_pairing_close_skip_red_led = true;
        g_request_close_pairing_mode = true;
      }

      mbedtls_ecdh_free(&ecdh);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
    }
  }
}
