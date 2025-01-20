/* File: ble_fuzz.h */
#ifndef BLE_FUZZ_H
#define BLE_FUZZ_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/* Public API */
void ble_fuzz_init(void);
void ble_fuzz_set_mode(bool enable);
void ble_fuzz_inject_packet(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* BLE_FUZZ_H */