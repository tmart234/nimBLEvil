#include "ble_ll_hci_fuzz.h"
#include "ble_ll_fuzz_nrf52.h"
#include "ble_phy_fuzz.h"

static int
ble_ll_hci_fuzz_handler(uint8_t *data, uint16_t len) {
    if (len < 3) return BLE_ERR_INV_HCI_CMD_PARMS;

    // Parse flags: [0]=disable CRC, [1]=disable whitening
    uint8_t flags = data[0];
    uint16_t pdu_len = (data[2] << 8) | data[1];
    uint8_t *pdu = &data[3];

    // Override radio registers
    ble_ll_fuzz_radio_override(
        (flags & 0x01) != 0,
        (flags & 0x02) != 0
    );

    // Transmit raw PDU through PHY
    ble_phy_fuzz_tx(pdu, pdu_len);

    // Restore radio config
    ble_ll_fuzz_radio_restore();
    
    return BLE_ERR_SUCCESS;
}