# NimBLE Fuzzing Patches

This document outlines the modifications made to the NimBLE stack to enable Bluetooth Low Energy (BLE) fuzzing capabilities.

## Patch Files

| Patch File                   | Modified Components               | Purpose                                   |
|------------------------------|------------------------------------|-------------------------------------------|
| `ble_header.patch`           | Core header definitions           | Base modifications                        |
| `ble_ll_conn_params.patch`   | `ble_ll_conn_params.h/c`          | Connection parameter validation bypass    |
| `ble_ll_conn.patch`          | `ble_ll_conn.c`                   | Connection state management               |
| `ble_ll.patch`               | `ble_ll.c`                        | Link Layer processing bypass              |
| `controller.patch`           | `ble_phy.c`                       | PHY layer CRC/whitening control           |
| `gap.patch`                  | `ble_gap.c`                       | GAP parameter validation                  |
| `hci_vendor.patch`           | `ble_hs_hci.c`                    | HCI vendor command implementation         |


## Detailed Patch Information

### 1. PHY Layer (`ble_phy.c`)
Bypass physical layer processing (CRC/whitening) for raw packet transmission.


### 2. HCI Layer (ble_hs_hci.c)
Implements custom vendor command (0xFD01) for raw packet injection.

### 4. Link Layer (ble_ll.c)
Skips Link Layer header validation and fragmentation for fuzzed packets.

### 5. Connection Manager (ble_ll_conn.c)
Enables transmission without an invalid connection state.

