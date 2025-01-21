// src/nimble/controller/src/ble_fuzz.c
#include "ble_fuzz.h"
#include "controller/ble_phy.h"
#include "host/ble_hs.h"

// Global fuzzing state
bool g_fuzzing_enabled = false;
bool g_phy_raw_tx_mode = false;
bool g_ble_ll_conn_fuzz_mode = false;
uint16_t g_ble_ll_conn_params_upd_timeout = 0;

void ble_fuzz_init(void)
{
    g_fuzzing_enabled = false;
    // Register vendor command handler
    static const struct ble_hci_vs_func hci_vs_funcs[] = {
        { BLE_HCI_RAW_TX_OPCODE, ble_hci_vendor_raw_tx },
        { 0 }
    };
    ble_hs_hci_set_vs_cmds(hci_vs_funcs);
}

void ble_fuzz_set_mode(bool enable)
{
    g_fuzzing_enabled = enable;
    g_phy_raw_tx_mode = enable;
    g_ble_ll_conn_fuzz_mode = enable;
}

void ble_fuzz_override_conn_params(uint16_t min_int, uint16_t max_int)
{
    if (g_fuzzing_enabled) {
        ble_ll_conn_params_set_limits(min_int, max_int);
    }
}

int ble_hci_vendor_raw_tx(uint8_t *data, int len)
{
    if (!g_fuzzing_enabled) {
        return BLE_HS_EDISABLED;
    }
    
    // Raw packet injection implementation
    struct os_mbuf *m = ble_hci_trans_alloc_buf();
    if (!m) return BLE_HS_ENOMEM;
    
    int rc = os_mbuf_append(m, data, len);
    if (rc != 0) {
        os_mbuf_free_chain(m);
        return rc;
    }
    
    return ble_phy_tx(m, BLE_PHY_TX_PWR_DBM_0);
}

static int
ble_hs_hci_vendor_raw_tx(uint8_t *data, int len)
{
    struct ble_ll_conn_sm *connsm;
    struct os_mbuf *m;
    uint8_t flags;
    uint16_t pkt_len;
    
    if (!g_fuzzing_enabled) {
        return BLE_HS_EDISABLED;
    }

    if (len < 3) {
        return BLE_HS_EBADDATA;
    }

    flags = data[0];
    pkt_len = data[1] | (data[2] << 8);
    if (pkt_len + 3 > len) {
        return BLE_HS_EBADDATA;
    }

    // Get current connection
    connsm = g_ble_ll_conn_cur_sm;
    if (!connsm) {
        return BLE_HS_ENOTCONN;
    }

    m = ble_hci_trans_alloc_buf();
    if (!m) {
        return BLE_HS_ENOMEM;
    }

    // Store flags in mbuf header
    struct ble_mbuf_hdr *ble_hdr = BLE_MBUF_HDR_PTR(m);
    ble_hdr->txinfo.flags = 0;
    if (flags & 0x01) ble_hdr->txinfo.flags |= BLE_MBUF_HDR_F_RAW_CRC;
    if (flags & 0x02) ble_hdr->txinfo.flags |= BLE_MBUF_HDR_F_RAW_WHITEN;

    // Add access address and PDU
    os_mbuf_append(m, &connsm->access_addr, 4); // Prepend access address
    os_mbuf_append(m, data + 3, pkt_len);       // Add PDU from command

    return ble_phy_tx(m, BLE_PHY_TX_PWR_DBM_0);
}