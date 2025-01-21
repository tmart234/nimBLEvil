#include "controller/ble_fuzz.h"
#include "controller/ble_phy.h"
#include "controller/ble_ll.h"

bool g_phy_raw_tx_mode;
bool g_fuzzing_mode_enabled;

void ble_fuzz_init(void) {
    g_fuzzing_mode_enabled = true;
    g_phy_raw_tx_mode = true;
}

void ble_fuzz_set_mode(bool enable) {
    g_fuzzing_mode_enabled = enable;
    g_phy_raw_tx_mode = enable;
    ble_phy_disable_whiten(enable);  // Existing PHY function
}