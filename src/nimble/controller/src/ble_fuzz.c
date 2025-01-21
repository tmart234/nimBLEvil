#include "ble_fuzz.h"
#include "controller/ble_phy.h"
#include "controller/ble_ll.h"

bool g_fuzzing_mode_enabled;

void ble_fuzz_set_mode(bool enable) 
{
    g_fuzzing_mode_enabled = enable;
    ble_phy_set_fuzz_mode(enable);  // Hypothetical PHY fuzz API
}

void ble_fuzz_inject_packet(const uint8_t *data, size_t len)
{
    if (g_fuzzing_mode_enabled) {
        ble_ll_tx_raw_packet(data, len);  // Hypothetical LL raw TX
    }
}