This project is 3 things:
1) patch files for a 'hacked' Apache nimBLE
    - works as UART over USB HCI device
    - supports a custom vendor HCI command for raw ll packets
2) automated FW builds w BLE hacking FW
    - only nrf52dk (pca10040) support currently
    - GitHub Actions for FW build
3) python, scapy, and HCI based fuzzer
    - supports Scapy's BluetoothUserSocket for fuzzing bluetooth host layers
    - supports custom vendor command for fuzzing bluetooth4LE controller layers
