from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import (
    BTLE_DATA,
    LL_CONNECTION_UPDATE_IND,
    LL_PING_REQ
)
from scapy.layers.bluetooth4LE import BTLE
from nimble_connector import NimBLEConnectionManager
import os
import random

class NimBLEFuzzer(NimBLEConnectionManager):
    def __init__(self, adapter=0, role='central'):
        super().__init__(adapter, role) 
        
    def fuzz_link_layer(self, conn):
        """Fuzz link layer packets with selective CRC/whitening bypass."""
        access_addr = conn['access_addr']
        
        # Fuzzed LL control packet with CRC/whitening disabled
        fuzzed_ll = self.fuzz_packet(
            BTLE(access_addr=access_addr)/BTLE_DATA()/LL_CONNECTION_UPDATE_IND(
                win_size=15,
                timeout=100
            ),
            fuzz_fields={'win_size': random.randint(1, 255), 'timeout': random.randint(10, 500)}
        )
        self.ll_send_raw(fuzzed_ll, disable_crc=True, disable_whiten=True) 

    def fuzz_l2cap(self, conn):
        """Fuzz L2CAP layer packets."""
        # Fuzzed L2CAP CID
        bad_cid = int.from_bytes(os.urandom(2), 'big')
        l2cap_pkt = L2CAP_Hdr(cid=bad_cid)/os.urandom(30)
        self.l2cap_send_raw(conn, l2cap_pkt)
        
    def fuzz_att(self, conn):
        """Fuzz ATT layer packets."""
        # Fuzzed ATT Read Request
        fuzzed_att = self.fuzz_packet(
            ATT_Hdr()/ATT_Read_Request(gatt_handle=0x0001),
            fuzz_fields={'gatt_handle': random.randint(0x0001, 0xFFFF)}
        )
        self.att_send_raw(conn, fuzzed_att)

def main():
    peer_address = "AA:BB:CC:DD:EE:FF"
    
    with NimBLEFuzzer(adapter=0, role='central') as fuzzer:
        # Initialize and connect
        conn = fuzzer.init_connection(peer_address, "public")
        fuzzer.connect(conn)
        
        # Run fuzzing procedures
        fuzzer.fuzz_link_layer(conn)
        fuzzer.fuzz_l2cap(conn)
        fuzzer.fuzz_att(conn)

if __name__ == "__main__":
    main()