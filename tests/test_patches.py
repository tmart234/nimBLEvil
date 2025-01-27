import subprocess
import pytest

def test_flags():
    result = subprocess.run(
        ["arm-none-eabi-objdump", "-t", "firmware.elf"],
        capture_output=True, text=True
    )
    assert "g_phy_raw_tx_mode" in result.stdout
    assert "ble_fuzz_init" in result.stdout
    assert "ble_ll_hci_fuzz_register" in result.stdout

def test_firmware_build():
    # Verify that the firmware builds successfully
    result = subprocess.run(
        ["newt", "build", "nrf52_fuzzer"],
        capture_output=True, text=True
    )
    assert result.returncode == 0, "Firmware build failed"

def test_symbols():
    """Verify symbols exist"""
    result = subprocess.run(
        ["arm-none-eabi-nm", "firmware.elf"],
        capture_output=True, text=True
    )
    assert "ble_ll_fuzz_radio_override" in result.stdout
    assert "ble_phy_fuzz_tx" in result.stdout