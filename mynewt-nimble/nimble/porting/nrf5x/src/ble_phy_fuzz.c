#include "ble_phy_fuzz.h"
#include "nrf.h"

void ble_phy_fuzz_tx(uint8_t *pdu, uint16_t len) {
    // Bypass normal TX pipeline
    // Validate max PDU length for nRF52
    // TODO: can we remove?
    if (len > 255) return;

    NRF_RADIO->PACKETPTR = (uint32_t)pdu;
    NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk | 
                       RADIO_SHORTS_END_DISABLE_Msk;
    NRF_RADIO->EVENTS_END = 0;
    NRF_RADIO->TASKS_TXEN = 1;
    
    // Wait for transmission complete
    while (!NRF_RADIO->EVENTS_END);
    NRF_RADIO->EVENTS_END = 0;
}