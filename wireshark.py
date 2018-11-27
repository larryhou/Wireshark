#!/usr/bin/env python3
import re, os, struct, io, enum, binascii
from typing import BinaryIO, List, Type

LINUX_SSL_SIZE = 16

class Debugger(object):
    def __init__(self, debug: bool):
        self.debug = debug

    def print(self, *args):
        if self.debug: print(*args)

class MemoryStream(object):
    def __init__(self, data: bytes = None, file_path: str = None):
        if file_path and os.path.exists(file_path):
            self.__buffer: BinaryIO = open(file_path, 'rb')
        elif data:
            self.fill(data)
        else:
            self.__buffer = io.BytesIO()
        self.endian = '>'

    def fill(self, data: bytes):
        assert data
        self.__buffer = io.BytesIO(data)

    @property
    def position(self) -> int:
        return self.__buffer.tell()
    @position.setter
    def position(self, position:int):
        self.seek(position, os.SEEK_SET)

    @property
    def length(self) -> int:
        position = self.__buffer.tell()
        self.__buffer.seek(0, os.SEEK_END)
        length = self.__buffer.tell()
        self.__buffer.seek(position)
        return length

    @property
    def bytes_available(self):
        return self.length - self.position

    def read(self, n: int = 1) -> bytes:
        char = self.__buffer.read(n)
        if not char: raise RuntimeError('expect more data')
        return char

    def align(self, size: int = 4):
        mode = self.position % size
        if mode > 0:
            self.seek(size - mode, os.SEEK_CUR)

    def seek(self, offset: int, whence: int = os.SEEK_SET):
        self.__buffer.seek(offset, whence)

    def append(self, data: bytes):
        position = self.__buffer.tell()
        self.seek(0, os.SEEK_END)
        self.__buffer.write(data)
        self.__buffer.seek(position)

    # write
    def write(self, data: bytes):
        self.__buffer.write(data)

    def write_boolean(self, v:bool):
        self.__buffer.write(bytes(1 if v else 0))

    def write_sbyte(self, v:int):
        self.write(struct.pack('b', v))

    def write_ubyte(self, v:int):
        self.write(struct.pack('B', v))

    def write_uint16(self, v:int):
        self.write(struct.pack('{}H'.format(self.endian), v))

    def write_sint16(self, v:int):
        self.write(struct.pack('{}h'.format(self.endian), v))

    def write_ushort(self, v:int):
        self.write_uint16(v)

    def write_short(self, v:int):
        self.write_sint16(v)

    def write_uint32(self, v:int):
        self.write(struct.pack('{}I'.format(self.endian), v))

    def write_sint32(self, v:int):
        self.write(struct.pack('{}i'.format(self.endian), v))

    def write_uint64(self, v:int):
        self.write(struct.pack('{}Q'.format(self.endian), v))

    def write_sint64(self, v:int):
        self.write(struct.pack('{}q'.format(self.endian), v))

    def write_float(self, v:float):
        self.write(struct.pack('{}f'.format(self.endian), v))

    def write_double(self, v:float):
        self.write(struct.pack('{}d'.format(self.endian), v))

    def write_hex(self, v:str):
        self.write(binascii.unhexlify(v))

    def write_sqlit_sint32(self, value):
        mask = (1 << 32) - 1
        self.write_sqlit_uint32(value & mask)

    def write_sqlit_uint32(self, value):
        assert value < (1 << 32)
        if value <= 240:
            self.write_ubyte(value)
            return
        if value <= 2287:
            self.write_ubyte((value - 240) / 256 + 241)
            self.write_ubyte((value - 240) % 256)
            return
        if value <= 67823:
            self.write_ubyte(249)
            self.write_ubyte((value - 2288) / 256)
            self.write_ubyte((value - 2288) % 256)
            return
        if value <= 16777215:
            self.write_ubyte(250)
            self.write_ubyte(value >> 0 & 0xFF)
            self.write_ubyte(value >> 8 & 0xFF)
            self.write_ubyte(value >> 16 & 0xFF)
            return
        self.write_ubyte(251)
        self.write_ubyte(value >> 0 & 0xFF)
        self.write_ubyte(value >> 8 & 0xFF)
        self.write_ubyte(value >> 16 & 0xFF)
        self.write_ubyte(value >> 24 & 0xFF)

    def write_compact_sint32(self, value):
        mask = (1 << 32) - 1
        self.write_compact_uint32(value & mask)

    def write_compact_uint32(self, value):
        assert value < (1 << 32)
        while value > 0:
            byte = value & 0x7F
            value >>= 7
            if value > 0: byte |= (1 << 7)
            self.write_ubyte(byte)

    def write_string(self, s:str, encoding:str = 'utf-8'):
        self.write(s.encode(encoding=encoding))

    # read
    def read_boolean(self)->bool:
        return struct.unpack('?', self.__buffer.read(1))[0]

    def read_sbyte(self)->int:
        return struct.unpack('b', self.__buffer.read(1))[0]

    def read_ubyte(self) -> int:
        return self.read(1)[0]

    def read_short(self) -> int:
        return struct.unpack('{}h'.format(self.endian), self.read(2))[0]

    def read_ushort(self) -> int:
        return struct.unpack('{}H'.format(self.endian), self.read(2))[0]

    def read_sint16(self) -> int:
        return self.read_short()

    def read_uint16(self) -> int:
        return self.read_ushort()

    def read_sint32(self) -> int:
        return struct.unpack('{}i'.format(self.endian), self.read(4))[0]

    def read_uint32(self) -> int:
        return struct.unpack('{}I'.format(self.endian), self.read(4))[0]

    def read_uint64(self) -> int:
        return struct.unpack('{}Q'.format(self.endian), self.read(8))[0]

    def read_sint64(self) -> int:
        return struct.unpack('{}q'.format(self.endian), self.read(8))[0]

    def read_float(self) -> float:
        return struct.unpack('{}f'.format(self.endian), self.read(4))[0]

    def read_double(self) -> float:
        return struct.unpack('{}d'.format(self.endian), self.read(8))[0]

    def read_hex(self, length:int)->int:
        data = self.read(length)
        return binascii.hexlify(data).decode('ascii')

    def read_sqlit_sint32(self)->int:
        data = struct.pack('>I', self.read_sqlit_uint32())
        return struct.unpack('>i', data)[0]

    def read_sqlit_uint32(self)->int:
        byte0 = self.read_ubyte()
        if byte0 < 241: return byte0
        byte1 = self.read_ubyte()
        if byte0 < 249:
            return 240 + 256 * (byte0 - 241) + byte1
        byte2 = self.read_ubyte()
        if byte0 == 249:
            return 2288 + 256 * byte1 + byte2
        byte3 = self.read_ubyte()
        if byte0 == 250:
            return byte1 << 0 | byte2 << 8 | byte3 << 16
        byte4 = self.read_ubyte()
        if byte0 >= 251:
            return byte1 << 0 | byte2 << 8 | byte3 << 16 | byte4 << 24

    def read_compact_sint32(self)->int:
        data = struct.pack('>I', self.read_compact_uint32())
        return struct.unpack('>i', data)[0]

    def read_compact_uint32(self)->int:
        value, shift = 0, 0
        while True:
            byte = self.read_ubyte()
            value |= (byte & 0x7F) << shift
            if byte & 0x80 == 0: break
            shift += 7
        assert value < (1 << 32)
        return value

    def read_string(self, length:int=0, encoding='utf-8')->str:
        assert length >= 0
        if not length:
            string = b''
            while True:
                char = self.read(1)
                if char == b'\x00': break
                string += char
        else:
            string = self.read(length) # type: bytes
        if not encoding: return string
        else:
            return None if not string else string.decode(encoding=encoding)

    def read_address(self) -> bytes:
        return self.read(4)

    def swap_endian(self, v: int) -> int:
        if v >= 0:
            if v < (1 << 32):
                data = struct.pack('>I', v)
                return struct.unpack('<I', data)[0]
            else:
                data = struct.pack('>Q', v)
                return struct.unpack('<Q', data)[0]
        else:
            if v >= -(1 << 31):
                data = struct.pack('>i', v)
                return struct.unpack('<i', data)[0]
            else:
                data = struct.pack('>q', v)
                return struct.unpack('<q', data)[0]

class ProtocolType(enum.Enum):
    L2TP = 115
    IPv6 = 41
    ICMP = 1
    MTP = 92
    UDP = 17
    TCP = 6

class Codec(object):
    def __init__(self):
        pass

    def decode(self, stream:MemoryStream):
        pass

    def encode(self, stream:MemoryStream):
        pass

class LinkHeader(Codec):
    def __init__(self):
        super(LinkHeader, self).__init__()
        self.src_mac_address:bytes = None
        self.dst_mac_address:bytes = None
        self.ether_type:int = 0


class IPv4Header(Codec):
    def __init__(self, frame_number: int = 0):
        super(IPv4Header, self).__init__()
        self.version: int = 4
        self.header: int = 5 * 4
        self.length: int = -1
        self.payload: int = 0
        self.dscp: int = 0
        self.ecn: int = 0
        self.id: int = -1
        self.flags: int = 0
        self.fragment_offset: int = -1
        self.ttl: int = 0
        self.protocol: int = 0
        self.checksum: int = 0
        self.src_address: bytes = None
        self.dst_address: bytes = None
        self.options: bytes = None
        self.frame_number: int = frame_number

    @staticmethod
    def format_address(address: bytes) -> str:
        return '.'.join([str(x) for x in address])

    def decode(self, stream: MemoryStream):
        byte = stream.read_ubyte()
        self.version = byte >> 4
        self.header = (byte & 0x0F) * 4
        byte = stream.read_ubyte()
        self.dscp = byte >> 2
        self.ecn = byte & 0b11
        self.length = stream.read_ushort()
        self.payload = self.length - self.header
        self.id = stream.read_ushort()
        byte = stream.read_ubyte()
        self.flags = byte >> 5
        self.fragment_offset = ((byte & 0b11111) << 8) | stream.read_ubyte()
        self.ttl = stream.read_ubyte()
        self.protocol = stream.read_ubyte()
        self.checksum = stream.read_ushort()
        self.src_address = stream.read_address()
        self.dst_address = stream.read_address()
        if self.header > 20:
            self.options = stream.read(self.header - 20)

    def __repr__(self):
        return '{} => {} protocol={} checksum={:04X} length={} header={} payload={}'.format(
            self.format_address(self.src_address),
            self.format_address(self.dst_address),
            self.protocol, self.checksum, self.length, self.header, self.payload
        )

class SocketHeader(Codec):
    def __init__(self, ipv4: IPv4Header):
        super(SocketHeader, self).__init__()
        self.ipv4: IPv4Header = ipv4
        self.src_port: int = 0
        self.dst_port: int = 0

    @property
    def src_client(self): return self.ipv4.src_address, self.src_port

    @property
    def dst_client(self): return self.ipv4.dst_address, self.dst_port

    @property
    def socket_uuid(self)->int:
        uuid = \
            (self.src_client + self.dst_client)    \
            if self.src_port >= self.dst_port else \
            (self.dst_client + self.src_client)
        return hash(uuid)

class TCPHeader(SocketHeader):
    FLAG_NAMES = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']

    def __init__(self, ipv4: IPv4Header):
        super(TCPHeader, self).__init__(ipv4)
        self.seq: int = 0
        self.ack: int = 0
        self.header: int = 0
        self.length: int = 0
        self.payload: int = 0
        self.flags: int = 0
        self.flag_cwr: int = 0
        self.flag_ece: int = 0
        self.flag_urg: int = 0
        self.flag_ack: int = 0
        self.flag_psh: int = 0
        self.flag_rst: int = 0
        self.flag_syn: int = 0
        self.flag_fin: int = 0
        self.window: int = 0
        self.checksum: int = 0
        self.urgent_pointer: int = 0
        self.options: bytes = None
        self.seq_offset: int = 0
        self.ack_offset: int = 0
        self.data: bytes = None

    def decode(self, stream: MemoryStream):
        self.src_port = stream.read_ushort()
        self.dst_port = stream.read_ushort()
        self.seq = stream.read_uint32()
        self.ack = stream.read_uint32()
        self.header = (stream.read_ubyte() >> 4) * 4
        self.length = self.ipv4.payload
        self.payload = self.length - self.header
        self.flags = flags = stream.read_ubyte()
        self.flag_cwr = flags >> 7 & 1
        self.flag_ece = flags >> 6 & 1
        self.flag_urg = flags >> 5 & 1
        self.flag_ack = flags >> 4 & 1
        self.flag_psh = flags >> 3 & 1
        self.flag_rst = flags >> 2 & 1
        self.flag_syn = flags >> 1 & 1
        self.flag_fin = flags >> 0 & 1
        self.window = stream.read_ushort()
        self.checksum = stream.read_ushort()
        self.urgent_pointer = stream.read_ushort()
        if self.header > 20:
            self.options = stream.read(self.header - 20)

    def __repr__(self):
        flags = []
        for n in range(8):
            if (self.flags >> n & 1) == 1: flags.append(TCPHeader.FLAG_NAMES[n])
        return '[TCP] {} => {} seq={} ack={} <{}> window={} checksum={:04X} length={} header={} payload={}'.format(
            self.src_port, self.dst_port, self.seq - self.seq_offset, self.ack - self.ack_offset, ','.join(flags),
            self.window, self.checksum, self.length, self.header, self.payload)

class UDPHeader(SocketHeader):
    def __init__(self, ipv4:IPv4Header):
        super(UDPHeader, self).__init__(ipv4)
        self.length:int = 0
        self.payload:int = 0
        self.checksum:int = 0
        self.data:bytes = None

    @property
    def header(self)->int: return 8

    def decode(self, stream:MemoryStream):
        self.src_port = stream.read_uint16()
        self.dst_port = stream.read_uint16()
        self.length = stream.read_uint16()
        self.checksum = stream.read_uint16()
        self.payload = self.length - self.header

    def __repr__(self):
        return '[UDP] {} => {} checksum={:04X} length={} header={} payload={}'.format(
            self.src_port, self.dst_port, self.checksum, self.length, self.header, self.payload
        )

class ConnectionSession(Debugger):
    def __init__(self, debug:bool):
        super(ConnectionSession, self).__init__(debug)
        self.src_port:int = 0
        self.dst_port:int = 0
        self.src_address:bytes = None
        self.dst_address:bytes = None
        self.src_client:tuple[bytes, int] = None
        self.dst_client:tuple[bytes, int] = None

    def set_src_client(self, address:bytes, port:int):
        self.src_client = address, port
        self.src_address = address
        self.src_port = port

    def set_dst_client(self, address:bytes, port:int):
        self.dst_client = address, port
        self.dst_address = address
        self.dst_port = port

    def flush(self):
        pass

class TCPConnectionSession(ConnectionSession):
    def __init__(self, debug: bool = False):
        super(TCPConnectionSession, self).__init__(debug=debug)

        self.session: dict[int, list[TCPHeader]] = {}
        self.offsets: dict[int, int] = {}

        self.cursor: TCPHeader = None
        self.application: NetworkApplication = None
        self.counter:int = 0

        self.uniques:list[int] = []

    def __insert(self, header: TCPHeader, packages: List[TCPHeader]) -> int:
        # self.print('! insert => {}={}'.format(header.src_port, len(packages)))
        if header.payload == 0: return -1
        min_index = 0
        max_index = len(packages) - 1
        if not packages:
            packages.append(header)
            return 0
        while min_index <= max_index:
            mid = (min_index + max_index) // 2
            diff = packages[mid].seq - header.seq
            if diff == 0: diff = packages[mid].ack - header.ack
            if diff == 0:
                if header.payload > packages[mid].payload:
                    self.print('**', packages[mid])
                    packages[mid] = header
                return mid
            if diff > 0:
                max_index = mid - 1
            else:
                min_index = mid + 1
        packages.insert(min_index, header)
        # self.print('+ insert => {}={}'.format(header.src_port, len(packages)))
        return min_index

    def accept(self, header: TCPHeader):
        self.counter += 1
        if header.src_port not in self.offsets:
            self.offsets[header.src_port] = header.seq
        header.seq_offset = self.offsets.get(header.src_port)
        header.ack_offset = self.offsets.get(header.dst_port) if header.dst_port in self.offsets else 0
        self.print('>>', header)
        if header.src_port not in self.session:
            self.session[header.src_port] = []
        self.__insert(header, self.session.get(header.src_port))

    def forward(self, flushing: bool = False):
        src_packages = self.session.get(self.src_port)
        dst_packages = self.session.get(self.dst_port)
        if not src_packages or not dst_packages: return
        src, dst = src_packages[0], dst_packages[0]
        self.print('##', src)
        self.print('##', dst)
        if flushing: self.cursor:TCPHeader = None
        pair = [src_packages, dst_packages]
        if self.cursor:
            turn = 0 if self.cursor.src_port == self.src_port else 1
        else:
            if src.ack <= dst.seq:
                turn = 0
            elif src.seq >= dst.ack:
                turn = 1
            elif src.ack > dst.seq:
                turn = 1
            else:
                turn = 0
        while True:
            ack = 0
            packages = pair[turn]
            if not packages:
                turn = 1 - turn
                if not pair[turn]:
                    return
                else:
                    continue
            temp_turn = turn
            self.print('++ turn:{} remain:{} {}={}'.format(turn, len(packages), 1 - turn, len(pair[1-turn])))
            updated:bool = False
            for n in range(len(packages)):
                header = packages[n]
                need_print = flushing or header.flag_syn == 1 or header.flag_fin == 1 or (self.cursor and self.cursor.ack == header.ack)
                if (0 < ack != header.ack) or need_print:
                    self.cursor = header
                    updated = True
                    n = max(1, n)
                    for i in range(n):
                        header = packages[i]
                        if header.ipv4:
                            print(header.ipv4.frame_number, '\n', header.ipv4, sep='')
                            print(header, '\n')
                        if header.payload > 0:
                            uuid = hash(header.data)
                            if uuid not in self.uniques:
                                self.uniques.append(uuid)
                                del self.uniques[:-10]
                                self.application.receive(header.data)
                    del packages[:n]
                    break
                ack = header.ack
            if not self.application.decoding and updated:
                self.cursor = None
                turn = 1 - turn
            if temp_turn == turn: return

    def flush(self):
        self.forward(flushing=True)
        self.application.finish()

class UDPConnectionSession(ConnectionSession):
    def __init__(self, debug: bool = False):
        super(UDPConnectionSession, self).__init__(debug)
        self.stream = MemoryStream()
        self.application:NetworkApplication = None

    def accept(self, header:UDPHeader):
        print(header.ipv4.frame_number, '\n', header.ipv4, sep='')
        print(header)
        if header.payload > 0:
            assert header.data
            self.application.receive(header.data)

    def flush(self):
        self.application.finish()

class NetworkApplication(Debugger):
    def __init__(self, session:ConnectionSession, debug:bool):
        super(NetworkApplication, self).__init__(debug)
        self.stream:MemoryStream = MemoryStream()
        self.session:ConnectionSession = session
        self.decoding:bool = False

    def receive(self, data:bytes):
        pass

    def finish(self):
        pass

class Wireshark(Debugger):
    def __init__(self, file_path: str, linux_ssl:bool = False):
        super(Wireshark, self).__init__(debug=False)
        self.__stream = MemoryStream(file_path=file_path)
        # TCP sessions
        self.__tcp_sessions:dict[int, TCPConnectionSession] = {}
        self.__tcp_application_class:Type[NetworkApplication] = NetworkApplication
        # UDP sessions
        self.__udp_sessions:dict[int, UDPConnectionSession] = {}
        self.__udp_application_class:Type[NetworkApplication] = NetworkApplication
        self.linux_ssl:bool = linux_ssl

    def register_tcp_application(self, tcp_application_class:Type[NetworkApplication]):
        assert issubclass(tcp_application_class, NetworkApplication)
        self.__tcp_application_class = tcp_application_class

    def register_udp_application(self, udp_application_class:Type[NetworkApplication]):
        assert issubclass(udp_application_class, NetworkApplication)
        self.__udp_application_class = udp_application_class

    def locate(self, address: str):
        seg = bytes([int(x, 10) for x in re.split(r'\s*[:.]\s*', address)])
        assert len(seg) == 4
        stream = self.__stream
        stream.seek(0)
        while True:
            position = stream.position
            for n in range(4):
                char = stream.read_ubyte()
                if char != seg[n]:
                    stream.seek(position + 1)
                    continue
            offset = position - 16
            if offset <= 4:
                stream.seek(position + 1)
                continue
            stream.seek(offset)
            header = IPv4Header()
            header.decode(stream)
            if header.version != 4 or header.src_address != seg:
                stream.seek(position + 1)
                continue
            stream.seek(offset)
            if self.linux_ssl:
                stream.seek(-LINUX_SSL_SIZE, os.SEEK_CUR)
            offset = stream.position
            stream.seek(-8, os.SEEK_CUR)
            sslen = stream.swap_endian(stream.read_uint32()), stream.swap_endian(stream.read_uint32())
            if sslen[0] != sslen[1]:
                stream.seek(position + 1)
                continue
            print('[LOCATE] offset={} size:{} {}\n'.format(offset, sslen, header))
            stream.seek(offset)
            return

    def __decode_tcp(self, ipv4: IPv4Header, data: bytes):
        stream = MemoryStream(data=data)
        header = TCPHeader(ipv4)
        header.decode(stream)
        if header.payload > 0:
            header.data = stream.read(header.payload)
        assert stream.position == stream.length
        if header.socket_uuid not in self.__tcp_sessions:
            session = TCPConnectionSession(debug=self.debug)
            session.set_src_client(*header.src_client)
            session.set_dst_client(*header.dst_client)
            session.application = self.__tcp_application_class(session, debug=self.debug)
            self.__tcp_sessions[header.socket_uuid] = session
        else:
            session = self.__tcp_sessions.get(header.socket_uuid)
        session.accept(header)
        if header.ipv4.frame_number % 10 == 0:
            session.forward()

    def __decode_udp(self, ipv4: IPv4Header, data: bytes):
        stream = MemoryStream(data=data)
        header = UDPHeader(ipv4)
        header.decode(stream)
        if header.payload > 0:
            header.data = stream.read(header.payload)
        assert stream.position == stream.length
        if header.socket_uuid not in self.__udp_sessions:
            session = UDPConnectionSession(debug=self.debug)
            session.set_src_client(*header.src_client)
            session.set_dst_client(*header.dst_client)
            session.application = self.__udp_application_class(session, debug=self.debug)
            self.__udp_sessions[header.socket_uuid] = session
        else:
            session = self.__udp_sessions.get(header.socket_uuid)
        session.accept(header)

    def decode(self):
        stream = self.__stream
        length = stream.length
        stream.seek(-8, os.SEEK_CUR)
        frame_number = 0
        while stream.position < length:
            sslen = stream.swap_endian(stream.read_uint32()), stream.swap_endian(stream.read_uint32())
            assert sslen[0] == sslen[1]
            position = stream.position + sslen[0]
            if self.linux_ssl: stream.read(LINUX_SSL_SIZE) # linux cookied capture
            frame_number += 1
            ipv4 = IPv4Header(frame_number)
            ipv4.decode(stream)
            payload = stream.read(ipv4.length - ipv4.header)
            if ipv4.protocol == ProtocolType.TCP.value:
                self.__decode_tcp(ipv4, payload)
            elif ipv4.protocol == ProtocolType.UDP.value:
                self.__decode_udp(ipv4, payload)
            if position > stream.position: # padding
                stream.read(position - stream.position)
            stream.align(4)
            stream.read(24)
        for _, session in self.__tcp_sessions.items():  # type: int, TCPConnectionSession
            session.flush()
        for _, session in self.__udp_sessions.items():
            session.flush()

