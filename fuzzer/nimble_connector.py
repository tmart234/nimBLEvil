from scapy.all import *
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
import time

class NimBLEConnectionManager:
    def __init__(self, adapter=0, role='central'):
        """
        Initialize the NimBLE connection manager with BluetoothUserSocket.
        
        :param adapter: HCI adapter index (default: 0)
        :param role: Role ('central' or 'peripheral')
        """
        self.socket = BluetoothUserSocket(adapter)
        self.role = role
        self.connections = {}
        self.current_conn = None
        self.connection_handle = None  # Store active connection handle
        self.NORDIC_LE_OPCODE = 0xFD01
        self.vendor_ops = {'nordic': {'disable_crc': 0x01, 'disable_whiten': 0x02}}

    def __enter__(self):
        """Context manager entry point"""
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit point"""
        self.socket.close()
        
    def send_hci_command(self, cmd_pkt):
        """
        Send HCI command using Scapy's BluetoothUserSocket.
        
        :param cmd_pkt: Scapy HCI command packet
        """
        try:
            self.socket.send(cmd_pkt)
        except Exception as e:
            print(f"Command send failed: {e}")

    def init_connection(self, address, address_type='public'):
        """
        Initialize a BLE connection object.
        
        :param address: Peer device address (e.g., "AA:BB:CC:DD:EE:FF")
        :param address_type: Address type ('public' or 'random')
        """
        return {
            'address': address,
            'address_type': 0 if address_type == 'public' else 1,
            'handle': None
        }
        
    def connect(self, conn, timeout=5):
        """
        Establish a connection to the peer device using Scapy's HCI commands.
        
        :param conn: Connection object
        :param timeout: Connection timeout in seconds
        """
        # Convert address to HCI format
        addr = bytes.fromhex(conn['address'].replace(':', ''))[::-1]
        
        # Send LE Create Connection command
        cmd = HCI_Cmd_Create_Connection(
            peer_addr=addr,
            peer_addr_type=conn['address_type'],
            own_addr_type=0,  # Public address
            le_scan_interval=0x0010,
            le_scan_window=0x0010,
            conn_interval_min=0x0006,
            conn_interval_max=0x0C80
        )
        self.send_hci_command(cmd)
        
        # Wait for connection complete event
        start = time.time()
        while time.time() - start < timeout:
            pkt = self.socket.recv()
            if pkt and pkt.type == 0x02 and pkt.code == 0x3e:  # LE Meta Event
                if pkt.event == 0x01:  # Connection Complete
                    conn['handle'] = pkt.handle
                    self.connection_handle = pkt.handle
                    print(f"Connected! Handle: 0x{pkt.handle:04x}")
                    return
        raise TimeoutError("Connection timed out")
                
    def l2cap_send_raw(self, conn, pkt):
        """
        Send raw L2CAP packet via ACL using Scapy's stack.
        
        :param conn: Connection object
        :param pkt: Scapy L2CAP packet
        """
        acl = HCI_Hdr(type=2) / HCI_ACL_Hdr(
            handle=conn['handle'],
            PB=0x02,  # Continuation fragment
            BC=0x00
        ) / pkt
        self.socket.send(acl)

    def att_send_raw(self, conn, pkt):
        """
        Send raw ATT packet through L2CAP channel.
        
        :param conn: Connection object
        :param pkt: Scapy ATT packet
        """
        l2cap = L2CAP_Hdr(cid=4) / pkt  # ATT channel
        self.l2cap_send_raw(conn, l2cap)
        
    def fuzz_packet(self, base_pkt, fuzz_fields):
        """
        Generate a fuzzed packet using manual field manipulation.
        
        :param base_pkt: Base packet to fuzz
        :param fuzz_fields: Fields to fuzz (dict of field names to values)
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
        cmd = HCI_Cmd_Disconnect(handle=conn['handle'], reason=0x16)
        self.send_hci_command(cmd)
        print(f"Disconnected handle 0x{conn['handle']:04x}")

    def _send_vendor_hci(self, vendor, cmd_type, params):
        """Send vendor-specific HCI command"""
        nordic_params = self.vendor_ops.get('nordic', {})
        cmd = struct.pack('<BH', 
            nordic_params.get(cmd_type, 0x00),
            len(params)
        ) + params
        pkt = HCI_Hdr(type=1)/HCI_Command_Hdr(opcode=self.NORDIC_LE_OPCODE)/Raw(cmd)
        self.send_hci_command(pkt)

    def nordic_disable_crc(self, disabled=True):
        """Nordic-specific command to disable CRC validation"""
        print(f"[+] {'Disabling' if disabled else 'Enabling'} CRC via Nordic command")
        params = struct.pack('<B', 
            self.vendor_ops['nordic']['disable_crc'] if disabled else 0x00
        )
        self._send_vendor_hci('nordic', 'disable_crc', params)

    def nordic_disable_whiten(self, disabled=True):
        """Nordic-specific command to disable whitening"""
        print(f"[+] {'Disabling' if disabled else 'Enabling'} Whitening via Nordic command")
        params = struct.pack('<B', 
            self.vendor_ops['nordic']['disable_whiten'] if disabled else 0x00
        )
        self._send_vendor_hci('nordic', 'disable_whiten', params)

    def ll_send_raw(self, pdu, disable_crc=False, disable_whiten=False):
        """Send raw LL PDU using vendor command"""
        flags = 0
        if disable_crc: flags |= 0x01
        if disable_whiten: flags |= 0x02
        
        params = struct.pack('<BH', flags, len(pdu)) + bytes(pdu)
        cmd = HCI_Hdr(type=1)/HCI_Command_Hdr(opcode=0xFD01)/Raw(params)
        self.nordic_disable_crc()
        self.nordic_disable_whiten()
        self.send_hci_command(cmd)
        # re-enable for other packets
        self.nordic_disable_crc(disabled=False)
        self.nordic_disable_whiten(disabled=False)

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