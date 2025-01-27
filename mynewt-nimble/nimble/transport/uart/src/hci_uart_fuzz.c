// Command registration

#include "hci_uart_fuzz.h"
#include "ble_ll_hci_fuzz.h"

void
hci_uart_fuzz_init(void) {
    // Register vendor command handler at startup
    ble_ll_hci_fuzz_register();
}