import subprocess

def test_phy_flags():
    result = subprocess.run(
        ["arm-none-eabi-objdump", "-t", "firmware.elf"],
        capture_output=True, text=True
    )
    assert "g_phy_raw_tx_mode" in result.stdout
    assert "ble_fuzz_init" in result.stdout