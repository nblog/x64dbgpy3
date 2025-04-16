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
FUNCTION_NAME = lambda n: "::".join([ getattr(n, "__name__"), inspect.currentframe().f_back.f_code.co_name ])
FUNCTION_HAS_RESULT = lambda n: inspect.signature(getattr(n, inspect.stack()[1][3])).return_annotation is not type(None)