#!/usr/bin/env python
#encoding:utf-8

import message, binascii
from wireshark import MemoryStream, Debugger
from message import ActionMessage

ACTION_HEADER_SIZE = 3

__share_stream__ = MemoryStream()

class ActionObject(Debugger):
    def __init__(self, debug:bool):
        super(ActionObject, self).__init__(debug)
        self.size = 0
        self.source_player = 0
        self.data:bytes = None
        self.type:int = 0
        self.message:ActionMessage = None
        self.id:int = 0

    def decode(self, stream:MemoryStream):
        self.size = stream.read_ubyte()
        self.source_player = stream.read_ubyte()
        self.type = stream.read_ubyte()
        self.data = stream.read(self.size - ACTION_HEADER_SIZE)

        __share_stream__.position = 0
        __share_stream__.write(self.data)
        __share_stream__.position = 0
        self.message = message.get_message(self.type)
        self.message.decode(__share_stream__)
        self.print(self.type, message.MessageType(self.type))
        if self.id !=0:
            print('[Action] id:%d %s'%(self.id, self.message))
        else:
            print('   [Action] uin:%d %s'%(self.source_player, self.message))
        assert __share_stream__.position == len(self.data), 'length:%s expect:%s raw:%s'%(len(self.data), __share_stream__.position, binascii.hexlify(self.data))

    def encode(self, stream:MemoryStream):
        stream.write_ubyte(self.source_player)
        stream.write_ubyte(self.type)
        self.message.encode(stream)

class FrameObject(Debugger):
    def __init__(self, debug:bool):
        super(FrameObject, self).__init__(debug)
        self.size = 0
        self.frame_index = 0
        self.action_list:list[ActionObject] = []

    def decode(self, stream:MemoryStream):
        self.size = stream.position
        self.frame_index = stream.read_sint32()
        action_count = stream.read_ubyte()
        print('[frame] index:%d action_count:%d'%(self.frame_index, action_count))
        self.action_list = []
        for _ in range(action_count):
            action = ActionObject(debug=self.debug)
            action.decode(stream)
            self.action_list.append(action)
        self.size = stream.position - self.size

    def encode(self, stream:MemoryStream):
        stream.write_sint32(self.frame_index)
        if not self.action_list:
            stream.write_ubyte(0)
            return
        action_count = len(self.action_list)
        stream.write_ubyte(action_count)
        for n in range(action_count):
            action = self.action_list[n]
            action.encode(stream)

class FrameContainer(Debugger):
    def __init__(self, debug:bool):
        super(FrameContainer, self).__init__(debug)
        self.frame_list:list[FrameObject] = []

    def decode(self, stream:MemoryStream):
        frame_count = stream.read_ubyte()
        self.frame_list = []
        for n in range(frame_count):
            frame = FrameObject(debug=self.debug)
            frame.decode(stream)
            self.frame_list.append(frame)

    def encode(self, stream:MemoryStream):
        if not self.frame_list:
            stream.write_ubyte(0)
            return
        stream.write_ubyte(len(self.frame_list))
        for n in range(len(self.frame_list)):
            frame = self.frame_list[n]
            frame.encode(stream)