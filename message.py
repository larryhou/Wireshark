#!/usr/bin/env python
# encoding:utf-8
import enum
from wireshark import MemoryStream

class MessageType(enum.IntEnum):
    MOVE_POS, \
    ATTACK_TARGET, \
    LEVEL_UP_ABILITY, \
    CAST_ABILITY, \
    BUY_ITEM, \
    SELL_ITEM, \
    CONSUME_ITEM, \
    TERMINAL_COMMAND, \
    STOP_MOVE, \
    DISCONNECT, \
    RECONNECT, \
    SIGNAL, \
    AI_CAST_ABILITY, \
    DAY_NIGHT_FAVOR, \
    VOTE, \
    USE_BLOOD_ALTAR, \
    TRANSPORT, \
    FOLLOW_TEAMMATE, \
    AI_SET, \
    CAST_ITEM_ABILITY, \
    SET_ITEM_ABILITY, \
    AI_HOST_LIST = range(22)


__message_factory = None


def get_message(message_type):
    global __message_factory
    if not __message_factory:
        __message_factory = {
            int(MessageType.MOVE_POS): MoveMessage,
            int(MessageType.ATTACK_TARGET): AttackTargetMessage,
            int(MessageType.LEVEL_UP_ABILITY): LevelUpAbilityMessage,
            int(MessageType.CAST_ABILITY): CastAbilityMessage,
            int(MessageType.BUY_ITEM): BuyItemMessage, int(MessageType.SELL_ITEM): SellItemMessage,
            int(MessageType.CONSUME_ITEM): ConsumeItemMessage,
            int(MessageType.TERMINAL_COMMAND): StringMessage, int(MessageType.STOP_MOVE): StopMessage,
            int(MessageType.DISCONNECT): DisconnectMessage,
            int(MessageType.RECONNECT): ReconnectMessage, int(MessageType.SIGNAL): UISignalMessage,
            int(MessageType.DAY_NIGHT_FAVOR): DayNightFavorMessage,
            int(MessageType.VOTE): UIVoteMessage,
            int(MessageType.USE_BLOOD_ALTAR): UseBloodAltarMessage,
            int(MessageType.TRANSPORT): TransportMessage,
            int(MessageType.FOLLOW_TEAMMATE): FollowTeammateMessage,
            int(MessageType.AI_SET): AISetMessage,
            int(MessageType.CAST_ITEM_ABILITY): CastItemAblityMessage,
            int(MessageType.SET_ITEM_ABILITY): SetItemAbilityMessage,
            int(MessageType.AI_HOST_LIST): AIHostListMessage
        }
    MessageClass = __message_factory.get(message_type)
    return MessageClass() if MessageClass else ActionMessage()


class ActionMessage(object):
    def __init__(self):
        super(ActionMessage, self).__init__()
        self.type = MessageType.MOVE_POS
        self.data = None

    def decode(self, stream:MemoryStream):
        pass

    def encode(self, stream:MemoryStream):
        pass

    def __repr__(self):
        return '<%s>' % self.__class__.__name__


class AIHostListMessage(ActionMessage):
    def __init__(self):
        super(AIHostListMessage, self).__init__()
        self.host_list = None  # type: list[int]

    def decode(self, stream):
        self.host_list = []
        for _ in range(5):
            self.host_list.append(stream.read_uint32())

    def encode(self, stream):
        pass

    def __repr__(self):
        return '%s list:%r' % (super(AIHostListMessage, self).__repr__(), self.host_list)


# s = 5
class AISetMessage(ActionMessage):
    def __init__(self):
        super(AISetMessage, self).__init__()
        self.type = MessageType.AI_SET
        self.mode = 0
        self.host_uin = 0

    def decode(self, stream):
        self.mode = stream.read_ubyte()
        self.host_uin = stream.read_uint32()

    def encode(self, stream):
        stream.write_ubyte(self.mode)
        stream.write_uint32(self.host_uin)

    def __repr__(self):
        return '%s mode:%d host_uint:%d' % (super(AISetMessage, self).__repr__(), self.mode, self.host_uin)


# 1 <= s <= 4
class AttackTargetMessage(ActionMessage):
    def __init__(self):
        super(AttackTargetMessage, self).__init__()
        self.type = MessageType.ATTACK_TARGET
        self.target = 0

    def decode(self, stream):
        self.target = stream.read_sqlit_uint32()

    def encode(self, stream):
        stream.write_sqlit_uint32(self.target)

    def __repr__(self):
        return '%s target:%d' % (super(AttackTargetMessage, self).__repr__(), self.target)

# s = 3
class BuyItemMessage(ActionMessage):
    def __init__(self):
        super(BuyItemMessage, self).__init__()
        self.type = MessageType.BUY_ITEM
        self.position = 0
        self.item = 0

    def decode(self, stream):
        self.position = stream.read_ubyte()
        self.item = stream.read_uint16()

    def encode(self, stream):
        stream.write_ubyte(self.position)
        stream.write_uint16(self.item)

    def __repr__(self):
        return '%s slot:%d item:%d' % (super(BuyItemMessage, self).__repr__(), self.position, self.item)


class CastType(enum.IntEnum):
    NONE, TARGET, POSITION, DIRECTION = range(4)


# 12 <= s <= 18 TARGET
#  6 <= s <= 12 DIRECTION
#  5 <= s <= 14 POSITION
class CastAbilityMessage(ActionMessage):
    def __init__(self):
        super(CastAbilityMessage, self).__init__()
        self.type = MessageType.CAST_ABILITY
        self.ability = 0
        self.ability_type = 0
        self.target = 0
        self.position = None  # type: tuple[int,int]
        self.cast_index = 0
        self.repeated = False # type: bool

    def decode(self, stream):
        self.ability = stream.read_sqlit_uint32()  # 1 <= s <= 4
        self.ability_type = CastType(stream.read_ubyte())  # 1
        if self.ability_type == CastType.TARGET:
            self.target = stream.read_sqlit_uint32()  # 1 <= s <= 4
        elif self.ability_type == CastType.DIRECTION:
            self.target = stream.read_int16()  # 2
        elif self.ability_type == CastType.POSITION:
            self.position = (stream.read_uint32(), stream.read_uint32())  # 8
        self.cast_index = stream.read_sqlit_uint32()  # 1 <= s <= 4
        self.repeated = stream.read_boolean()  # 1

    def encode(self, stream):
        stream.write_sqlit_uint32(self.ability)
        stream.write_ubyte(int(self.ability_type))
        if self.ability_type == CastType.TARGET:
            stream.write_sqlit_uint32(self.target)
        elif self.ability_type == CastType.DIRECTION:
            stream.write_sint16(self.target)
        elif self.ability_type == CastType.POSITION:
            stream.write_uint32(self.position[0])
            stream.write_uint32(self.position[1])
        stream.write_sqlit_uint32(self.cast_index)
        stream.write_boolean(self.repeated)

    def __repr__(self):
        base_repr = super(CastAbilityMessage, self).__repr__()
        self_repr = 'ability:%d type:%r' % (self.ability, self.ability_type)
        if self.ability_type == CastType.TARGET:
            self_repr = '%s target:%d' % (self_repr, self.target)
        elif self.ability_type == CastType.DIRECTION:
            self_repr = '%s direction:%d' % (self_repr, self.target)
        elif self.ability_type == CastType.POSITION:
            self_repr = '%s position:%r' % (self_repr, self.position)
        return '%s %s cast_index:%d repeated:%r' % (base_repr, self_repr, self.cast_index, self.repeated)


# s = 3
class CastItemAblityMessage(BuyItemMessage):
    def __init__(self):
        super(CastItemAblityMessage, self).__init__()
        self.type = MessageType.CAST_ITEM_ABILITY

# s = 3
class ConsumeItemMessage(BuyItemMessage):
    def __init__(self):
        super(ConsumeItemMessage, self).__init__()
        self.type = MessageType.CONSUME_ITEM

# s = 1
class DayNightFavorMessage(ActionMessage):
    def __init__(self):
        super(DayNightFavorMessage, self).__init__()
        self.type = MessageType.DAY_NIGHT_FAVOR
        self.flag = False # type: bool

    def decode(self, stream):
        self.flag = stream.read_boolean()

    def encode(self, stream):
        stream.write_boolean(self.flag)

    def __repr__(self):
        return '%s flag:%r' % (super(DayNightFavorMessage, self).__repr__(), self.flag)

# s = 0
class DisconnectMessage(ActionMessage):
    def __init__(self):
        super(DisconnectMessage, self).__init__()
        self.type = MessageType.DISCONNECT

# s = 3
class FollowTeammateMessage(ActionMessage):
    def __init__(self):
        super(FollowTeammateMessage, self).__init__()
        self.type = MessageType.FOLLOW_TEAMMATE
        self.follower = 0
        self.executor = 0
        self.flag = False

    def decode(self, stream):
        self.follower = stream.read_ubyte()
        self.flag = stream.read_boolean()
        self.executor = stream.read_ubyte()

    def encode(self, stream):
        stream.write_ubyte(self.follower)
        stream.write_boolean(self.flag)
        stream.write_ubyte(self.executor)

    def __repr__(self):
        return '%s follower:%d flag:%r executor:%d' % (
        super(FollowTeammateMessage, self).__repr__(), self.follower, self.flag, self.executor)

# s = 1
class LevelUpAbilityMessage(ActionMessage):
    def __init__(self):
        super(LevelUpAbilityMessage, self).__init__()
        self.type = MessageType.LEVEL_UP_ABILITY
        self.ability_position = 0

    def decode(self, stream):
        self.ability_position = stream.read_ubyte()

    def encode(self, stream):
        stream.write_ubyte(self.ability_position)

    def __repr__(self):
        return '%s ability_position:%d' % (super(LevelUpAbilityMessage, self).__repr__(), self.ability_position)

# s = 2
class MoveMessage(ActionMessage):
    def __init__(self):
        super(MoveMessage, self).__init__()
        self.type = MessageType.MOVE_POS
        self.position = None # type: tuple[int,int]
        self.is_direction_move = False # type: bool
        self.direction = 0

    def decode(self, stream):
        self.is_direction_move = stream.read_boolean()
        if self.is_direction_move:
            self.direction = stream.read_ubyte()
        else:
            self.position = (stream.read_uint32(), stream.read_uint32())

    def encode(self, stream):
        stream.write_boolean(self.is_direction_move)
        if self.is_direction_move:
            stream.write_ubyte(self.direction)
        else:
            stream.write_uint32(self.position[0])
            stream.write_uint32(self.position[1])

    def __repr__(self):
        position = (-1, -1) if not self.position else self.position
        if self.is_direction_move:
            return '%s direction:%3d %6.2f°' % (
            super(MoveMessage, self).__repr__(), self.direction, (self.direction / 255.0) * 360)
        else:
            return '%s position:{x=%d y=%d}' % (super(MoveMessage, self).__repr__(), position[0], position[1])

# s = 0
class StopMessage(ActionMessage):
    def __init__(self):
        super(StopMessage, self).__init__()
        self.type = MessageType.STOP_MOVE

# s = 0
class ReconnectMessage(ActionMessage):
    def __init__(self):
        super(ReconnectMessage, self).__init__()
        self.type = MessageType.RECONNECT

# s = 3
class SellItemMessage(BuyItemMessage):
    def __init__(self):
        super(SellItemMessage, self).__init__()
        self.type = MessageType.SELL_ITEM

# s = 3
class SetItemAbilityMessage(BuyItemMessage):
    def __init__(self):
        super(SetItemAbilityMessage, self).__init__()
        self.type = MessageType.SET_ITEM_ABILITY

# s =
class StringMessage(ActionMessage):
    def __init__(self):
        super(StringMessage, self).__init__()
        self.type = MessageType.TERMINAL_COMMAND
        self.size = 0
        self.content = None # type: bytes

    def decode(self, stream):
        self.size = stream.read_uint16()
        if self.size <= 0: return
        if self.size >= 256: return
        self.content = stream.read(self.size)

    def encode(self, stream:MemoryStream):
        if not self.content:
            stream.write_uint16(0)
            return
        stream.write_uint16(len(self.content))
        stream.write(self.content)

    def __repr__(self):
        return '%s content:%s' % (super(StringMessage, self).__repr__(), self.content.decode('utf-8'))

# 1 <= s <= 4
class TransportMessage(ActionMessage):
    def __init__(self):
        super(TransportMessage, self).__init__()
        self.type = MessageType.TRANSPORT
        self.portal = 0

    def decode(self, stream):
        self.portal = stream.read_sqlit_uint32()

    def encode(self, stream):
        stream.write_sqlit_uint32(self.portal)

    def __repr__(self):
        return '%s portal:%d' % (super(TransportMessage, self).__repr__(), self.portal)


# s = 11
class UISignalMessage(ActionMessage):
    def __init__(self):
        super(UISignalMessage, self).__init__()
        self.type = MessageType.SIGNAL
        self.signal = 0
        self.signal_type = 0
        self.position:tuple[int,int] = None
        self.target = 0

    def decode(self, stream):
        self.signal_type = stream.read_ubyte()
        self.target = stream.read_ubyte()
        self.position = (stream.read_uint32(), stream.read_uint32())
        self.signal = stream.read_ubyte()

    def encode(self, stream):
        stream.write_ubyte(self.signal_type)
        stream.write_ubyte(self.target)
        stream.write_uint32(self.position[0])
        stream.write_uint32(self.position[1])
        stream.write_ubyte(self.signal)

    def __repr__(self):
        return '%s signal_type:%d target:%d position:{x=%d y=%d} signal:%d' % (
            super(UISignalMessage, self).__repr__(), self.signal_type, self.target, self.position[0], self.position[1], self.signal
        )

# s = 2
class UIVoteMessage(ActionMessage):
    def __init__(self):
        super(UIVoteMessage, self).__init__()
        self.type = MessageType.VOTE
        self.vote_state = 0
        self.leave_game_mode = 0

    def decode(self, stream):
        self.vote_state = stream.read_ubyte()
        self.leave_game_mode = stream.read_ubyte()

    def encode(self, stream):
        stream.write_ubyte(self.vote_state)
        stream.write_ubyte(self.leave_game_mode)

    def __repr__(self):
        return '%s vote_state:%d leave_game_mode:%r' % (
            super(UIVoteMessage, self).__repr__(), self.vote_state, self.leave_game_mode
        )

# 1 <= s <= 4
class UseBloodAltarMessage(ActionMessage):
    def __init__(self):
        super(UseBloodAltarMessage, self).__init__()
        self.type = MessageType.USE_BLOOD_ALTAR
        self.executor = 0

    def decode(self, stream):
        self.executor = stream.read_sqlit_uint32()

    def encode(self, stream):
        stream.write_sqlit_uint32(self.executor)

    def __repr__(self):
        return '%s executor:%d' % (super(UseBloodAltarMessage, self).__repr__(), self.executor)

class GhostObject(object):
    def __init__(self, *args):
        super(GhostObject, self).__init__(*args)
