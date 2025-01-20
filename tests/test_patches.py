import subprocess
import pytest

def test_phy_flags():
    result = subprocess.run(
        ["arm-none-eabi-objdump", "-t", "firmware.elf"],
        capture_output=True, text=True
    )
    assert "g_phy_raw_tx_mode" in result.stdout
    assert "ble_fuzz_init" in result.stdout

def test_firmware_build():
    # Verify that the firmware builds successfully
    result = subprocess.run(
        ["newt", "build", "nrf52_fuzzer"],
        capture_output=True, text=True
    )
    assert result.returncode == 0, "Firmware build failed"

def test_patch_application():
    # Verify that patches are applied correctly
    result = subprocess.run(
        ["git", "apply", "--check", "patches/ble_header.patch"],
        capture_output=True, text=True
    )
    assert result.returncode == 0, "Patch application failed"