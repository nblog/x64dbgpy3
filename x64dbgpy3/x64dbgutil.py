#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import inspect



class ptr_t(int):
    '''  '''

class size_t(int):
    '''  '''

class reqBuffer:
    '''  '''
    @staticmethod
    def serialize(data:bytearray):
        return " ".join( map( lambda c: "%02x" % c, data ) )

    @staticmethod
    def deserialize(buffer:str):
        return bytearray( map( lambda h: int(h, 16), buffer.split(" ") ) )

class DBGNS:
    def __init__(self, **kwargs):
        if (kwargs):
            for n in kwargs: self.__setattr__(n, kwargs[n])


FUNCTION_NAME = lambda n: "::".join([ getattr(n, "__name__"), inspect.stack()[1][3] ])