#!/bin/bash
set -euo pipefail

# Create new project
newt new numBLEvil
cd numBLEvil

# Update project.yml to use latest versions
cat > project.yml << 'EOL'
project.name: "numBLEvil"

project.repositories:
    - apache-mynewt-core
    - apache-mynewt-nimble

repository.apache-mynewt-core:
    type: github
    vers: 0-latest
    user: apache
    repo: mynewt-core
    repository.defrepo.depth: 1


repository.apache-mynewt-nimble:
    type: github
    vers: 0-latest
    user: apache
    repo: mynewt-nimble
    repository.defrepo.depth: 1

# Ignore all repositories except what we need for nRF52
project.ignore_repos:
    - mcuboot
    - apache-mynewt-mcumgr
    - tinyusb
    - mbedtls
    - arm-CMSIS_5
    - littlefs
    - liblc3
    - libsamplerate
    - lvgl
    - eembc-coremark
    - blues-note-c
    - atmel-samd21xx
    - nxp-mcux-sdk
    # STM32 related repos
    - stm-cmsis_device_f0
    - stm-stm32f0xx_hal_driver
    - stm-cmsis_device_f1
    - stm-stm32f1xx_hal_driver
    - stm-cmsis_device_f3
    - stm-stm32f3xx_hal_driver
    - stm-cmsis_device_f4
    - stm-stm32f4xx_hal_driver
    - stm-cmsis_device_f7
    - stm-stm32f7xx_hal_driver
    - stm-cmsis_device_g0
    - stm-stm32g0xx_hal_driver
    - stm-cmsis_device_g4
    - stm-stm32g4xx_hal_driver
    - stm-cmsis_device_h7
    - stm-stm32h7xx_hal_driver
    - stm-cmsis_device_l0
    - stm-stm32l0xx_hal_driver
    - stm-cmsis_device_l1
    - stm-stm32l1xx_hal_driver
    - stm-cmsis_device_l4
    - stm-stm32l4xx_hal_driver
    - stm-cmsis_device_u5
    - stm-stm32u5xx_hal_driver
    - stm-cmsis_device_wb
    - stm-stm32wbxx_hal_driver
    - cirruslogic-mcu-drivers

EOL

# Initialize project
newt upgrade -f

# Create required directories
mkdir -p apps/numBLEvil
mkdir -p targets/nrf52_bsp
mkdir -p apps/numBLEvil/include/numBLEvil
mkdir -p apps/numBLEvil/src

NIMBLE_PATH="repos/apache-mynewt-nimble"

# Create app package.yml
cat > apps/numBLEvil/pkg.yml << 'EOL'
pkg.name: apps/numBLEvil
pkg.type: app
pkg.description: "BLE Fuzzing Application"
pkg.author: "Tyler M <tmart234@gmail.com>"
pkg.homepage: "https://github.com/tmart234"
pkg.keywords:

pkg.deps:
    - "@apache-mynewt-core/kernel/os"
    - "@apache-mynewt-core/sys/console"
    - "@apache-mynewt-core/sys/log"
    - "@apache-mynewt-core/sys/stats"
    - "@apache-mynewt-nimble/nimble/host"
    - "@apache-mynewt-nimble/nimble/host/services/gap"
    - "@apache-mynewt-nimble/nimble/host/services/gatt"
    - "@apache-mynewt-nimble/nimble/host/store/config"
    - "@apache-mynewt-nimble/nimble/transport/uart"
    - "@apache-mynewt-nimble/nimble/controller"

pkg.cflags: -DNIMBLE_CFG_CONTROLLER=1 -DNIMBLE_CFG_CUSTOM_VS_CMDS=1
EOL

# Create syscfg.yml
cat > apps/numBLEvil/syscfg.yml << 'EOL'
syscfg.vals:
    BLE_CONTROLLER: 1
    BLE_HCI_VS_ENABLE: 1
    BLE_LL_CFG_FEAT_LE_ENCRYPTION: 0
    BLE_LL_RAW_PACKET_ENABLE: 1
    MSYS_1_BLOCK_COUNT: 32
    MSYS_1_BLOCK_SIZE: 292
    BLE_HCI_UART_PORT: 0
    BLE_HCI_UART_BAUD: 115200
    BLE_HCI_UART_FLOW_CTRL: 0
    BLE_CUSTOM_VS_CMDS: 1
    BLE_RAW_PACKET_TX: 1
EOL

# Patch NimBLE with custom modifications
# Add custom header files first
cat > ${NIMBLE_PATH}/nimble/host/include/host/ble_hs_custom.h << 'EOL'
#ifndef H_BLE_HS_CUSTOM_
#define H_BLE_HS_CUSTOM_

#include <inttypes.h>

int ble_hs_send_raw_packet(uint16_t conn_handle, uint8_t *data, uint16_t len);

#endif
EOL

# Modify ble_ll.h
echo '
void ble_ll_custom_init(void);
extern bool g_raw_mode_enabled;
' >> ${NIMBLE_PATH}/nimble/controller/include/controller/ble_ll.h

# Add custom controller code
mkdir -p ${NIMBLE_PATH}/nimble/controller/src/custom
cat > ${NIMBLE_PATH}/nimble/controller/src/custom/ble_ll_custom.c << 'EOL'
#include "nimble/ble.h"
#include "controller/ble_ll.h"
#include "controller/ble_ll_hci.h"

#include "nimble/ble.h"
#include "controller/ble_ll.h"
#include "controller/ble_ll_hci.h"
#include "controller/ble_ll_pdu.h"
#include "controller/ble_phy.h"

// Custom HCI commands
#define BLE_HCI_OCF_RAW_LL_PKT         0x01
#define BLE_HCI_OCF_RAW_MODE           0x02

// Raw packet flag
static bool g_raw_mode_enabled = false;

// Custom vendor command handlers
static int
ble_ll_hci_raw_ll_pkt(uint8_t *cmdbuf, uint8_t len)
{
    struct os_mbuf *om;
    
    if (!g_raw_mode_enabled) {
        return BLE_ERR_CMD_DISALLOWED;
    }
    
    // Allocate mbuf for raw packet
    om = os_msys_get_pkthdr(len, sizeof(struct ble_mbuf_hdr));
    if (!om) {
        return BLE_ERR_MEM_CAPACITY;
    }
    
    // Copy raw packet data
    memcpy(om->om_data, cmdbuf, len);
    om->om_len = len;
    
    // Set raw packet flag in mbuf header
    struct ble_mbuf_hdr *hdr = BLE_MBUF_HDR_PTR(om);
    hdr->raw_pkt = 1;
    
    // Queue for transmission
    ble_ll_tx_pkt_in(om);
    
    return 0;
}

static int
ble_ll_hci_raw_mode(uint8_t *cmdbuf, uint8_t len)
{
    if (len < 1) {
        return BLE_ERR_INV_HCI_CMD_PARMS;
    }
    
    g_raw_mode_enabled = cmdbuf[0];
    return 0;
}

// Modify packet transmission path
void
ble_ll_tx_pkt_proc(struct os_mbuf *om)
{
    struct ble_mbuf_hdr *hdr = BLE_MBUF_HDR_PTR(om);
    
    if (g_raw_mode_enabled && hdr->raw_pkt) {
        // Disable whitening and CRC for raw packets
        NRF_RADIO->PCNF1 &= ~RADIO_PCNF1_WHITEEN_Msk;
        NRF_RADIO->CRCCNF &= ~RADIO_CRCCNF_EN_Msk;
    } else {
        // Normal packet processing
        NRF_RADIO->PCNF1 |= RADIO_PCNF1_WHITEEN_Msk;
        NRF_RADIO->CRCCNF |= RADIO_CRCCNF_EN_Msk;
    }
    
    // Continue with normal transmission
    ble_phy_tx(om, 0);
}

// Register custom vendor commands
static const struct ble_ll_hci_vs_cmd custom_commands[] = {
    {
        .ocf = BLE_HCI_OCF_RAW_LL_PKT,
        .handler = ble_ll_hci_raw_ll_pkt
    },
    {
        .ocf = BLE_HCI_OCF_RAW_MODE,
        .handler = ble_ll_hci_raw_mode
    },
};

// Initialize custom commands
void
ble_ll_custom_init(void)
{
    ble_ll_hci_vs_register(custom_commands, 
                          sizeof(custom_commands)/sizeof(custom_commands[0]));
}
EOL

cp ${NIMBLE_PATH}/nimble/controller/src/ble_ll.c ${NIMBLE_PATH}/nimble/controller/src/ble_ll.c.orig



# Create main.c with proper initialization
cat > apps/numBLEvil/src/main.c << 'EOL'
#include "sysinit/sysinit.h"
#include "os/os.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "controller/ble_ll.h"
#include "host/ble_hs_custom.h"
#include "host/util/util.h"
#include "console/console.h"

// Device info
static const char *device_name = "numBLEvil";
static uint8_t own_addr_type;

// Connection handle for central mode
static uint16_t conn_handle;
static bool is_connected = false;

// Function declarations
static void ble_on_sync(void);
static void ble_on_reset(int reason);
static void ble_host_task(void *param);

// GAP event callback
static int
gap_event_cb(struct ble_gap_event *event, void *arg)
{
    struct ble_gap_conn_desc desc;
    int rc;

    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT:
            if (event->connect.status == 0) {
                rc = ble_gap_conn_find(event->connect.conn_handle, &desc);
                assert(rc == 0);
                conn_handle = event->connect.conn_handle;
                is_connected = true;
                console_printf("Connected as %s\n", 
                    desc.role == BLE_GAP_ROLE_MASTER ? "central" : "peripheral");
            }
            return 0;

        case BLE_GAP_EVENT_DISCONNECT:
            console_printf("Disconnected\n");
            is_connected = false;
            return 0;

        case BLE_GAP_EVENT_ADV_COMPLETE:
            console_printf("Advertising complete\n");
            return 0;

        case BLE_GAP_EVENT_SUBSCRIBE:
            console_printf("Subscribe event; cur_notify=%d\n", 
                event->subscribe.cur_notify);
            return 0;
    }

    return 0;
}

// Start advertising
static void
start_advertising(void)
{
    struct ble_gap_adv_params adv_params;
    struct ble_hs_adv_fields fields;
    int rc;

    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.tx_pwr_lvl_is_present = 1;
    fields.tx_pwr_lvl = BLE_HS_ADV_TX_PWR_LVL_AUTO;
    fields.name = (uint8_t *)device_name;
    fields.name_len = strlen(device_name);
    fields.name_is_complete = 1;

    rc = ble_gap_adv_set_fields(&fields);
    assert(rc == 0);

    memset(&adv_params, 0, sizeof(adv_params));
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;

    rc = ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER,
                          &adv_params, gap_event_cb, NULL);
    assert(rc == 0);
}

// Start scanning
static void
start_scanning(void)
{
    struct ble_gap_disc_params scan_params = {
        .passive = 0,
        .filter_duplicates = 0,
        .itvl = 0,
        .window = 0,
        .filter_policy = 0,
        .limited = 0,
    };

    int rc = ble_gap_disc(own_addr_type, BLE_HS_FOREVER, &scan_params,
                         gap_event_cb, NULL);
    assert(rc == 0);
}

static void
ble_on_sync(void)
{
    int rc;

    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    assert(rc == 0);

    // Device ready for commands from Python framework
    console_printf("BLE device ready for commands\n");
}

static void
ble_on_reset(int reason)
{
    console_printf("Resetting state; reason=%d\n", reason);
}

void
ble_host_task(void *param)
{
    ble_hs_cfg.sync_cb = ble_on_sync;
    ble_hs_cfg.reset_cb = ble_on_reset;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

    // Initialize custom commands
    ble_ll_custom_init();

    while (1) {
        os_eventq_run(os_eventq_dflt_get());
    }
}

// Console command handler for Python framework interface
static int
cmd_handler(int argc, char **argv)
{
    if (argc < 2) {
        return 0;
    }

    if (!strcmp(argv[1], "adv")) {
        start_advertising();
    } else if (!strcmp(argv[1], "scan")) {
        start_scanning();
    } else if (!strcmp(argv[1], "stop")) {
        if (is_connected) {
            ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        } else {
            ble_gap_disc_cancel();
            ble_gap_adv_stop();
        }
    }

    return 0;
}

int
main(void)
{
    sysinit();

    // Initialize console for Python framework communication
    console_init(NULL);
    console_register_rx_cb(cmd_handler);

    // Create host task
    os_task_init(&host_task_struct, "host_task", ble_host_task, NULL,
                 MYNEWT_VAL(BLE_HOST_TASK_PRIO), OS_WAIT_FOREVER,
                 host_task_stack, MYNEWT_VAL(BLE_HOST_STACK_SIZE));

    while (1) {
        os_eventq_run(os_eventq_dflt_get());
    }

    return 0;
}
EOL

# Add custom header files
cat > ${NIMBLE_PATH}/nimble/host/include/host/ble_hs_custom.h << 'EOL'
#ifndef H_BLE_HS_CUSTOM_
#define H_BLE_HS_CUSTOM_

#include <inttypes.h>

int ble_hs_send_raw_packet(uint16_t conn_handle, uint8_t *data, uint16_t len);

#endif
EOL

# Add custom initialization to ble_ll.c
awk '/int ble_ll_init(void)/ {
    print;
    print "#if MYNEWT_VAL(BLE_LL_RAW_PACKET_ENABLE)";
    print "    ble_ll_custom_init();";
    print "#endif";
    next;
} {print}' ${NIMBLE_PATH}/nimble/controller/src/ble_ll.c.orig > ${NIMBLE_PATH}/nimble/controller/src/ble_ll.c


# Add custom host code
mkdir -p ${NIMBLE_PATH}/nimble/host/src/custom
cat > ${NIMBLE_PATH}/nimble/host/src/custom/ble_hs_custom.c << 'EOL'
#include "host/ble_hs.h"
#include "host/ble_hs_hci.h"
#include "host/ble_l2cap.h"

#include "host/ble_hs.h"
#include "host/ble_hs_hci.h"
#include "host/ble_l2cap.h"

// Add to host stack to support raw L2CAP packets
static int
ble_l2cap_send_raw_packet(uint16_t conn_handle, struct os_mbuf *sdu)
{
    struct ble_hs_conn *conn;
    int rc;

    ble_hs_lock();
    conn = ble_hs_conn_find(conn_handle);
    if (conn == NULL) {
        ble_hs_unlock();
        return BLE_HS_ENOTCONN;
    }

    // Bypass normal L2CAP fragmentation and channel lookup
    rc = ble_hs_hci_acl_tx(conn, sdu);
    
    ble_hs_unlock();
    return rc;
}

// Export the function
int
ble_hs_send_raw_packet(uint16_t conn_handle, uint8_t *data, uint16_t len)
{
    struct os_mbuf *om;

    om = os_msys_get_pkthdr(len, 0);
    if (om == NULL) {
        return BLE_HS_ENOMEM;
    }

    os_mbuf_append(om, data, len);
    return ble_l2cap_send_raw_packet(conn_handle, om);
}
EOL

# Update pkg.yml to include new source files
echo '
pkg.src_files:
    - "custom/ble_ll_custom.c"
' >> ${NIMBLE_PATH}/nimble/controller/pkg.yml

echo '
pkg.src_files:
    - "custom/ble_hs_custom.c"
' >> ${NIMBLE_PATH}/nimble/host/pkg.yml

# Ensure custom headers are included in the build
echo '
pkg.include_dirs:
    - "include/host"
' >> ${NIMBLE_PATH}/nimble/host/pkg.yml

# Create target definition
cat > targets/nrf52_bsp/pkg.yml << 'EOL'
pkg.name: "targets/nrf52_bsp"
pkg.type: "target"
pkg.description: "BLE Fuzzer Target for nRF52"
pkg.author: Tyler M
pkg.homepage: https://github.com/tmart234

pkg.deps:
    - "@apache-mynewt-core/hw/bsp/nrf52dk"
    - "@apache-mynewt-core/libc/baselibc"
    - "apps/numBLEvil"
EOL

cat > targets/nrf52_bsp/target.yml << 'EOL'
target.app: "apps/numBLEvil"
target.bsp: "@apache-mynewt-core/hw/bsp/nordic_pca10040"
target.build_profile: "debug"
EOL

# Build the firmware
newt build nrf52_bsp
newt create-image nrf52_bsp 1.0.0

# Print build info
echo "Build completed. Firmware available in bin/targets/nrf52_bsp/app/"
ls -l bin/targets/nrf52_bsp/app/
ls -l bin/targets/nrf52_bsp/app/
