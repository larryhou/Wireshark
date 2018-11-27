#!/usr/bin/env python3
from wireshark import *
import sys, dict_to_protobuf, json, binascii
import frame

class ClientProtocol(object):
    def __init__(self):
        self.len: int = 0
        self.cmd: int = 0
        self.seq: int = 0

    @property
    def header(self)->int: return 0

    def decode(self, stream:MemoryStream):
        pass

class ArenaProtocol(ClientProtocol):
    def __init__(self):
        super(ArenaProtocol, self).__init__()
        self.ack:int = 0
        self.client_frame:int = 0

    @property
    def header(self): return 12 + 2

    def decode(self, stream:MemoryStream):
        self.len = stream.read_uint16()
        self.cmd = stream.read_uint16()
        self.seq = stream.read_uint16()
        self.ack = stream.read_uint16()
        self.client_frame = stream.read_sint32()

    def __repr__(self):
        return 'cmd={:04X} seq={} ack={} len={} client_frame={}'.format(self.cmd, self.seq, self.ack, self.len, self.client_frame)

class LogicProtocol(ClientProtocol):
    def __init__(self):
        super(LogicProtocol, self).__init__()
        self.uin: int = 0
        self.ver: int = 0
        self.app: int = 0
        self.zid: int = 0
        self.sum: int = 0

    @property
    def header(self): return 24 + 2

    def decode(self, stream: MemoryStream):
        self.len = stream.read_uint32()
        self.uin = stream.read_uint32()
        self.ver = stream.read_uint16()
        self.app = stream.read_uint32()
        self.zid = stream.read_uint16()
        self.cmd = stream.read_uint16()
        self.sum = stream.read_uint16()
        self.seq = stream.read_uint32()

    def __repr__(self):
        return 'cmd={:04X} seq={} len={} uin={} zid={} ver={} app={} sum={}'.format(
            self.cmd, self.seq, self.len, self.uin, self.zid, self.ver, self.app, self.sum
        )

class ClientApplication(NetworkApplication):
    __shared_module_map = {} # type: dict[str, object]
    def __init__(self, session:ConnectionSession, debug:bool):
        super(ClientApplication, self).__init__(session, debug)
        self.command_map:dict[int, object] = {}
        if ClientApplication.__shared_module_map:
            self.module_map = ClientApplication.__shared_module_map
        else:
            self.module_map: dict[str, object] = self.__build_module_map()
            ClientApplication.__shared_module_map = self.module_map
        self.register_command_map()
        self.header:int = self.create_protocol().header

    def register_command_map(self):
        pass

    @staticmethod
    def __build_module_map():
        python_out = os.path.abspath('__pb2')
        proto_path = os.path.abspath(options.proto_path)
        assert os.path.exists(proto_path)
        if not os.path.exists(python_out):
            os.makedirs(python_out)
        command = 'protoc --proto_path={} --python_out={} {}/*.proto'.format(proto_path, python_out, proto_path)
        assert os.system(command) == 0
        os.system('touch {}/__init__.py'.format(python_out))
        sys.path.append(python_out)
        for file_name in os.listdir(python_out):
            if not file_name.endswith('_pb2.py'): continue
            module_name = re.sub(r'\.py$', '', file_name)
            exec('from {} import *'.format(module_name))
        return locals()

    def get_message_class(self, name:str)->object:
        return self.module_map.get(name)

    def convert_jsonable(self, data: object):
        if isinstance(data, dict):
            for name, value in data.items():
                data[name] = self.convert_jsonable(value)
        elif isinstance(data, list):
            for n in range(len(data)):
                data[n] = self.convert_jsonable(data[n])
        elif isinstance(data, bytes):
            try:
                content = data.decode('utf-8')  # type: str
                if content and content.find('\u0000') >= 0: raise RuntimeError()
                return content
            except:
                return binascii.hexlify(data).decode('ascii')
        return data

    def check_qualified(self, protocol:ClientProtocol):
        return protocol.cmd in self.command_map

    def decode_bytes(self, data:bytes, protocol:ClientProtocol):
        print('UnknownMessage', protocol)
        print(binascii.hexlify(data).decode('ascii'), '\n')

    def create_protocol(self)->ClientProtocol:
        return ClientProtocol()

    def decode_protocol(self):
        stage = 0
        length = self.stream.length
        protocol: ClientProtocol
        self.print('offset={} length={} header={}\n'.format(self.stream.position, self.stream.length, self.header))
        while self.stream.position + self.header < length:
            offset = self.stream.position
            char = self.stream.read_ubyte()
            if stage == 0:
                if char == 0x55:
                    char = self.stream.read_ubyte()
                    if char == 0xAA:
                        protocol = self.create_protocol()
                        protocol.decode(stream=self.stream)
                        self.print(protocol, 'expect={} receive={}'.format(protocol.len - protocol.header, self.stream.bytes_available))
                        if not self.check_qualified(protocol):
                            self.stream.seek(-1, os.SEEK_CUR)
                            continue
                        self.decoding = True
                        stage = 1
                        assert protocol.header == self.stream.position - offset
                        if offset + protocol.len > self.stream.length:
                            self.stream.seek(offset)
                            return
            if stage == 1:
                assert protocol
                serializer = self.command_map.get(protocol.cmd)  # type: object
                payload = self.stream.read(protocol.len - protocol.header) if protocol.len > protocol.header else b''
                if serializer:
                    message = getattr(serializer, 'FromString')(payload)  # type: object
                    print(message.__class__.__name__, protocol)
                    data = dict_to_protobuf.protobuf_to_dict(message, use_enum_labels=True)
                    self.convert_jsonable(data)
                    print(json.dumps(data, ensure_ascii=False, indent=4), '\n')
                else:
                    self.decode_bytes(payload, protocol)
                stage = 0
                self.decoding = False

    def receive(self, data:bytes):
        self.stream.append(data)
        self.decode_protocol()

class LogicApplication(ClientApplication):
    def __init__(self, session: TCPConnectionSession, debug: bool):
        super(LogicApplication, self).__init__(session, debug)
        self.uin:int = 0

    def register_command_map(self):
        command_enum = self.module_map.get('ZoneSvrCmd')
        message_map = {}
        for name, value in command_enum.items():  # type: str, int
            message_name = ''.join([x.title() for x in name.split('_')])
            message_class = self.module_map.get(message_name)
            if not message_class: continue
            message_map[value] = message_class
        self.command_map = message_map

    def check_qualified(self, protocol:LogicProtocol)->bool:
        qualified = protocol.cmd in self.command_map or (0 != self.uin == protocol.uin)
        if qualified and self.uin == 0: self.uin = protocol.uin
        return qualified

    def create_protocol(self): return LogicProtocol()

class ApolloHeader(TCPHeader):
    def __init__(self):
        super(ApolloHeader, self).__init__(None)

    def decode(self, stream: MemoryStream):
        self.src_port = stream.read_uint16()
        self.dst_port = stream.read_uint16()
        self.seq = stream.read_uint32()
        self.ack = stream.read_uint32()

    def __repr__(self):
        return '[LWP] {:5} => {:5} seq={} ack={} length={} payload={}'.format(
            self.src_port, self.dst_port, (self.seq - self.seq_offset) if self.seq else self.seq, (self.ack - self.ack_offset) if self.ack else self.ack, self.length, self.payload
        )

class ArenaTunnelApplication(ClientApplication):
    def __init__(self, debug: bool):
        super(ArenaTunnelApplication, self).__init__(None, debug)
        self.__shared_stream:MemoryStream = MemoryStream()

    def register_command_map(self):
        command_enum = self.module_map.get('GameSvrCmd')
        message_map = {}
        for name, value in command_enum.items():  # type: str, int
            message_name = ''.join([x.title() for x in name.split('_')])
            message_class = self.module_map.get(message_name)
            if not message_class: continue
            message_map[value] = message_class
        self.command_map = message_map
        message_map[0x0310] = self.get_message_class('GamePingPkg')
        message_map[0x0311] = self.get_message_class('GamePingPkg')
        message_map[0x0303] = self.get_message_class('GameLoadResReq')
        message_map[0x0304] = self.get_message_class('GameLoadResRsp')
        message_map[0x0305] = self.get_message_class('GameStartPkg')
        message_map[0x0312] = self.get_message_class('GameObjHashCodeReq')
        message_map[0x0313] = self.get_message_class('GameObjHashCodeRsp')
        message_map[0x0308] = self.get_message_class('GameEndPkg')
        message_map[0x0309] = self.get_message_class('GameEndPkg')

    def create_protocol(self):
        return ArenaProtocol()

    def receive(self, data:bytes):
        self.print(binascii.hexlify(data))
        self.stream.append(data)
        self.decode_protocol()

class ArenaApplication(ClientApplication):
    def __init__(self, session: UDPConnectionSession, debug: bool):
        super(ArenaApplication, self).__init__(session, debug)
        self.__shared_stream:MemoryStream = MemoryStream()
        self.tunnel:TCPConnectionSession = TCPConnectionSession(debug=self.debug)
        self.tunnel.application = ArenaTunnelApplication(debug=self.debug)

    def create_protocol(self): return ArenaProtocol()

    def check_qualified(self, protocol:ClientProtocol):
        return True

    def decode_user_action(self, data:bytes):
        stream = self.__shared_stream
        stream.position = 0
        stream.write(data)
        stream.position = 0
        num = stream.read_ubyte()
        for _ in range(num):
            offset = stream.position
            length = stream.read_ubyte() + 1
            action_id = stream.read_ushort()
            action = frame.ActionObject(self.debug)
            action.id = action_id
            action.decode(stream)
            assert stream.position == offset + length, 'position:{} != offset:{} + length:{}'.format(stream.position, offset, length)

    def decode_frame(self, data:bytes):
        stream = self.__shared_stream
        stream.position = 0
        stream.write(data)
        stream.position = 0
        tick = frame.FrameContainer(self.debug)
        tick.decode(stream)

    def decode_bytes(self, data:bytes, protocol:ClientProtocol):
        print(protocol)
        if protocol.cmd == 0x0306:
            self.decode_user_action(data)
        elif protocol.cmd == 0x0307:
            self.decode_frame(data)
        else:
            super(ArenaApplication, self).decode_bytes(data, protocol)
        print()

    def receive(self, data:bytes):
        stream = self.__shared_stream
        stream.position = 0
        stream.write(data)
        stream.position = 0
        apollo = ApolloHeader()
        apollo.decode(stream)
        apollo.length = len(data)
        apollo.payload = apollo.length - 24
        apollo.data = data[20:-4]
        # set offsets
        offsets = self.tunnel.offsets
        apollo.seq_offset = offsets.get(apollo.src_port) if apollo.src_port in offsets else 0
        apollo.ack_offset = offsets.get(apollo.dst_port) if apollo.dst_port in offsets else 0
        print(apollo, '\n')
        if not apollo.payload: return
        if apollo.seq == 0:
            super(ArenaApplication, self).receive(apollo.data)
        else:
            if not self.tunnel.src_port:
                self.tunnel.set_src_client(b'abcd', apollo.src_port)
                self.tunnel.set_dst_client(b'dcba', apollo.dst_port)
            self.tunnel.accept(apollo)
            self.tunnel.forward()

    def finish(self):
        self.tunnel.flush()

if __name__ == '__main__':
    import argparse
    arguments = argparse.ArgumentParser()
    arguments.add_argument('--capture-file', '-cf', required=True, help='raw file captured within Wireshark')
    arguments.add_argument('--proto-path', '-pp', required=True, help='*.proto file path')
    arguments.add_argument('--address', '-a', required=True, help='client/server ip address')
    arguments.add_argument('--linux-ssl', '-s', action='store_true')
    arguments.add_argument('--debug', '-d', action='store_true')
    options = arguments.parse_args(sys.argv[1:])
    shark = Wireshark(file_path=options.capture_file, linux_ssl=options.linux_ssl)
    shark.register_tcp_application(LogicApplication)
    shark.register_udp_application(ArenaApplication)
    shark.debug = options.debug
    shark.locate(address=options.address)
    shark.decode()
