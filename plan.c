// in ble_ll_conn.c
// replaces ble_ll_conn_enqueue_pkt and ble_ll_conn_tx_pkt_in for custom ll packets
void enqueue_custom_ll_packet(struct os_mbuf *om, uint16_t handle) {
    uint16_t conn_handle;
    struct ble_ll_conn_sm *connsm;
    struct os_mbuf_pkthdr *pkthdr;
    struct ble_mbuf_hdr *ble_hdr;
    os_sr_t sr;

    // See if we have an active matching connection handle
    conn_handle = handle & 0x0FFF;
    connsm = ble_ll_conn_find_by_handle(conn_handle);
    if (connsm) {
        // Add to the transmit queue for the connection
        pkthdr = OS_MBUF_PKTHDR(om);
        OS_ENTER_CRITICAL(sr);
        // could also insert in head 
        STAILQ_INSERT_TAIL(&connsm->conn_txq, pkthdr, omp_next);
        OS_EXIT_CRITICAL(sr);
    } else {
        // No connection found!
        STATS_INC(ble_ll_conn_stats, handle_not_found);
        os_mbuf_free_chain(om);
    }
}

// in ble_ll.c
// c
#if MYNEWT_VAL(BLE_LL_ROLE_CENTRAL) || MYNEWT_VAL(BLE_LL_ROLE_PERIPHERAL)
static void
ble_ll_tx_pkt_in(void){
    ....}
static void
void ble_ll_tx_pkt_in_custom(struct os_mbuf *om, uint16_t handle, uint16_t length) {
    uint16_t conn_handle;
  
    struct ble_ll_conn_sm *connsm;
    // todo: get handle
    // Extract connection handle from handle
    conn_handle = handle & 0x0FFF;
    connsm = ble_ll_conn_find_by_handle(conn_handle);
    if (connsm) {
        // Directly process the LL packet without L2CAP encapsulation
        enqueue_custom_ll_packet(om, handle);
    } else {
        // No connection found, handle the error
        STATS_INC(ble_ll_conn_stats, handle_not_found);
        os_mbuf_free_chain(om);
    }
}
#endif
