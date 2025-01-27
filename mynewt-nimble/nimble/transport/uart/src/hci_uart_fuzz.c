// Command registration

#include "hci_uart_fuzz.h"
#include "ble_ll_hci_fuzz.h"
#include "uart/uart.h"

static void
hci_uart_fuzz_tx_byte(uint8_t byte)
{
    /* Use USB CDC as transport */
    extern int uart0_putchar(uint8_t c);
    uart0_putchar(byte);
}

void
hci_uart_fuzz_init(void) {
    uart0_init(115200);
}