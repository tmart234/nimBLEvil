import struct
import os
import random
from scapy.layers.bluetooth import *
from serial import Serial

class NimBLEConnectionManager:
    def __init__(self, adapter=0, role='central', baudrate=115200):
        """
        Initialize the NimBLE connection manager.
        
        :param adapter: HCI adapter index (default: 0)
        :param role: Role ('central' or 'peripheral')
        :param baudrate: Serial baudrate for HCI communication
        """
        self.ser = Serial(f'/dev/ttyACM{adapter}', baudrate, timeout=1)
        self.role = role
        self.connections = {}
        self.current_conn = None
        
    def __enter__(self):
        """Context manager entry point."""
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit point."""
        self.ser.close()
        
    def send_hci_command(self, opcode, params):
        """
        Send an HCI command to the NimBLE controller.
        
        :param opcode: HCI command opcode
        :param params: Command parameters (bytes)
        """
        hdr = struct.pack('<HB', opcode, len(params))
        self.ser.write(b'\x01' + hdr + params)
         
    def init_connection(self, address, address_type='public'):
        """
        Initialize a BLE connection object.
        
        :param address: Peer device address (e.g., "AA:BB:CC:DD:EE:FF")
        :param address_type: Address type ('public' or 'random')
        :return: Connection object
        """
        conn = {
            'address': address,
            'address_type': 0 if address_type == 'public' else 1,
            'handle': None,
            'access_addr': None,
            'crc_init': None
        }
        self.current_conn = conn
        return conn
        
    def connect(self, conn):
        """
        Establish a connection to the peer device.
        
        :param conn: Connection object
        """
        addr_bytes = bytes.fromhex(conn['address'].replace(':', ''))[::-1]
        cmd = struct.pack('<B6sBBHHHH', 
            0x0D,       # LE Create Connection
            addr_bytes,
            conn['address_type'],  # addr type
            0,          # Own addr type
            0x0010,     # Scan interval
            0x0010,     # Scan window
            0x0006,     # Min connection interval
            0x0C80      # Max connection interval
        )
        self.send_hci_command(0x200D, cmd)
        
        # Wait for connection complete event
        while True:
            pkt = self.ser.read()
            if pkt[0] == 0x3E:  # LE Meta Event
                if pkt[2] == 0x01:  # Connection Complete
                    conn['handle'] = struct.unpack('<H', pkt[3:5])[0]
                    conn['access_addr'] = struct.unpack('<I', pkt[5:9])[0]
                    conn['crc_init'] = struct.unpack('<I', pkt[9:13])[0]
                    break
                    
    def ll_send_raw(self, pkt, disable_crc=False, disable_whiten=False):
        """
        Send raw LL packet with per-packet CRC/whitening control.
        
        :param disable_crc: Disable CRC ONLY for this packet
        :param disable_whiten: Disable whitening ONLY for this packet
        """
        flags = 0
        flags |= 0x01 if disable_crc else 0
        flags |= 0x02 if disable_whiten else 0
        
        raw_bytes = bytes(pkt)
        params = struct.pack('<BH', flags, len(raw_bytes)) + raw_bytes
        self.send_hci_command(0xFD01, params)  # nimBLEvil's Custom LL TX command  # Custom LL raw TX opcode
        
    def l2cap_send_raw(self, conn, pkt):
        """
        Send a raw L2CAP packet.
        
        :param conn: Connection object
        :param pkt: Scapy packet (L2CAP layer)
        """
        l2cap_payload = bytes(pkt)
        params = struct.pack('<HH', conn['handle'], 4) + l2cap_payload  # CID=4 (ATT)
        self.send_hci_command(0xFD02, params)  # Custom L2CAP raw TX opcode
        
    def att_send_raw(self, conn, pkt):
        """
        Send a raw ATT packet.
        
        :param conn: Connection object
        :param pkt: Scapy packet (ATT layer)
        """
        att_payload = bytes(pkt)
        l2cap_pkt = L2CAP_Hdr(cid=4) / att_payload  # Encapsulate in L2CAP
        self.l2cap_send_raw(conn, l2cap_pkt)
        
    def fuzz_packet(self, base_pkt, fuzz_fields):
        """
        Generate a fuzzed packet using manual field manipulation.
        
        :param base_pkt: Base packet to fuzz
        :param fuzz_fields: Fields to fuzz (dict of field names to values)
        :return: Fuzzed packet
        """
        pkt = base_pkt.copy()
        for field, value in fuzz_fields.items():
            if hasattr(pkt, field):
                setattr(pkt, field, value)
            else:
                raise ValueError(f"Field {field} not found in packet")
        return pkt
        
    def disconnect(self, conn):
        """
        Disconnect from the peer device.
        
        :param conn: Connection object
        """
        params = struct.pack('<HB', conn['handle'], 0x16)  # Reason: Local Host Terminated
        self.send_hci_command(0x0406, params)