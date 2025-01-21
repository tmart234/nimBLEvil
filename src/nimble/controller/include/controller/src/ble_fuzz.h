#ifndef BLE_FUZZ_H
#define BLE_FUZZ_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

extern bool g_fuzzing_mode_enabled;
void ble_fuzz_set_mode(bool enable);
void ble_fuzz_inject_packet(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* BLE_FUZZ_H */