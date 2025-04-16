#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import inspect, base64, json, struct



class ptr_t(int):
    '''  '''
class size_t(int):
    '''  '''

class reqBuffer:

    @staticmethod
    def serialize(buffer:bytearray):
        raise NotImplementedError

    @staticmethod
    def deserialize(buffer:str):
        raise NotImplementedError


class DBGUtils:
    def __init__(self, **kwargs):
        for n in kwargs: self.__setattr__(n, kwargs[n])
FUNCTION_NAME = lambda n: "::".join([ getattr(n, "__name__"), inspect.stack()[1][3] ])