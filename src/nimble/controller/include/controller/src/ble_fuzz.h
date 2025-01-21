#ifndef BLE_FUZZ_H
#define BLE_FUZZ_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Vendor-specific HCI commands */
#define BLE_HCI_OGF_VENDOR                 0x3f
#define BLE_HCI_OCF_RAW_TX                 0x01
#define BLE_HCI_RAW_TX_OPCODE              (BLE_HCI_OGF_VENDOR << 10 | BLE_HCI_OCF_RAW_TX)
#define BLE_HCI_CMD_RAW_TX_LEN             251

/* Global fuzzing state */
extern bool g_fuzzing_mode_enabled;
extern bool g_phy_raw_tx_mode;

/* Fuzzing API */
void ble_fuzz_set_mode(bool enable);
void ble_fuzz_inject_packet(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* BLE_FUZZ_H */