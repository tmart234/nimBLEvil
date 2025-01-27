#include "ble_ll_fuzz_nrf52.h"
#include "nrf.h"

static uint32_t g_original_crc_config;
static uint32_t g_original_pcnf0;
static bool g_radio_locked = false;

void ble_ll_fuzz_radio_override(bool disable_crc, bool disable_whiten) {
    if(g_radio_locked) return;
    g_radio_locked = true;
    // Save original radio state
    g_original_crc_config = NRF_RADIO->CRCCNF;
    g_original_pcnf0 = NRF_RADIO->PCNF0;

    // Configure CRC
    if (disable_crc) {
        NRF_RADIO->CRCCNF = 0;  // Disable CRC
    }

    // Configure whitening
    if (disable_whiten) {
        NRF_RADIO->PCNF0 &= ~(RADIO_PCNF0_WHITEEN_Msk);
    }
}

void ble_ll_fuzz_radio_restore(void) {
    g_radio_locked = false;
    // Restore original radio config
    NRF_RADIO->CRCCNF = g_original_crc_config;
    NRF_RADIO->PCNF0 = g_original_pcnf0;
}