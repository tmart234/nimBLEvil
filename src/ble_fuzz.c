/* File: ble_fuzz.c */
#include "ble_fuzz.h"
#include "host/ble_hs.h"
#include "controller/ble_phy.h"
#include "services/gap/ble_svc_gap.h"

/* Internal state */
static bool fuzzing_active = false;

void ble_fuzz_init(void)
{
    /* Initialize fuzzing-specific hardware */
    // Add any radio pre-configuration here
    
    /* Set safe defaults */
    ble_fuzz_set_mode(true);
}

void ble_fuzz_set_mode(bool enable)
{
    fuzzing_active = enable;
    
    /* Configure stack-wide fuzzing parameters */
    ble_ll_conn_fuzz_mode = enable;
    fuzzing_mode_enabled = enable;
    
    /* Set PHY layer defaults */
    g_phy_raw_tx_mode = enable;
    g_phy_disable_whiten = enable;
}

void ble_fuzz_inject_packet(const uint8_t *data, size_t len)
{
    if (!fuzzing_active) return;
    
    struct os_mbuf *m = ble_hci_trans_alloc_buf();
    if (!m) return;
    
    os_mbuf_append(m, data, len);
    ble_phy_tx(m, BLE_PHY_TX_PWR_DBM_0);
}