// src/nimble/controller/include/controller/ble_fuzz.h
#ifndef BLE_FUZZ_H
#define BLE_FUZZ_H

#define BLE_MBUF_HDR_F_RAW_CRC     (1 << 0)
#define BLE_MBUF_HDR_F_RAW_WHITEN  (1 << 1)

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Global fuzzing controls
extern bool g_fuzzing_enabled;
extern bool g_phy_raw_tx_mode;
extern bool g_ble_ll_conn_fuzz_mode;
extern uint16_t g_ble_ll_conn_params_upd_timeout;

// HCI Command Definitions
#define BLE_HCI_OGF_VENDOR                 0x3f
#define BLE_HCI_OCF_RAW_TX                 0x01
#define BLE_HCI_RAW_TX_OPCODE              (BLE_HCI_OGF_VENDOR << 10 | BLE_HCI_OCF_RAW_TX)

// Fuzzing API
void ble_fuzz_init(void);
void ble_fuzz_set_mode(bool enable);
void ble_fuzz_override_conn_params(uint16_t min_int, uint16_t max_int);
int ble_hci_vendor_raw_tx(uint8_t *data, int len);

#ifdef __cplusplus
}
#endif

#endif /* BLE_FUZZ_H */