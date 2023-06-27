#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import inspect, base64, json, struct, lz4.frame as lz4frame



class ptr_t(int):
    '''  '''

class size_t(int):
    '''  '''

class reqBuffer:

    @staticmethod
    def serialize(buffer:bytearray):
        IN_BUFF_SIZE = 1024
        raw_buffer = lz4frame.compress(buffer) \
            if IN_BUFF_SIZE < len(buffer) else buffer
        payload = {
            "payload": base64.b64encode(raw_buffer).decode(),
            # https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md#general-structure-of-lz4-frame-format
            "compressed": IN_BUFF_SIZE < len(raw_buffer) \
                and 0x184D2204 == struct.unpack("<i", raw_buffer[:4])[0]
        }
        return json.dumps(payload)

    @staticmethod
    def deserialize(buffer:str):
        payload = json.loads(buffer)

        raw_buffer = base64.b64decode(payload["payload"])
        return bytearray(
            lz4frame.decompress(raw_buffer) if bool(payload["compressed"]) else raw_buffer)

class DBGNS:
    def __init__(self, **kwargs):
        if (kwargs):
            for n in kwargs: self.__setattr__(n, kwargs[n])


FUNCTION_NAME = lambda n: "::".join([ getattr(n, "__name__"), inspect.stack()[1][3] ])