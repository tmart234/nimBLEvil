#pragma once

void ble_ll_fuzz_process(uint8_t fuzz_type, uint8_t *data, uint16_t len);
void ble_ll_fuzz_mode_enable(bool enable);