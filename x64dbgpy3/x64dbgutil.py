#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, functools, inspect, base64
from enum import IntEnum, IntFlag
from typing import List, Tuple, Dict, Union, Optional, Callable, Any, get_args


class ptr_t(int):
    '''  '''
class size_t(int):
    '''  '''

class RequestBuffer:
    from lz4.block import compress, decompress

    @staticmethod
    def serialize(buffer:bytes):
        return base64.b64encode(RequestBuffer.compress(buffer)).decode()

    @staticmethod
    def deserialize(buffer:str):
        return RequestBuffer.decompress(base64.b64decode(buffer))

class DBGSTRUCT:
    def __init__(self, **kwargs):
        for n in kwargs: self.__setattr__(n, kwargs[n])
FUNCTION_NAME = lambda n: "::".join([ getattr(n, "__name__"), inspect.currentframe().f_back.f_code.co_name ])
FUNCTION_HAS_RESULT = lambda n: inspect.signature(getattr(n, inspect.stack()[1][3])).return_annotation is not type(None)


def get_debugger_host():
    host_env = os.getenv("X64DBGPY3_HOST", "localhost:27041")
    parts = host_env.split(":")
    host = parts[0] if parts else "localhost"
    try:
        port = int(parts[1]) if len(parts) > 1 else 27041
    except ValueError:
        port = 27041
    return host, str(port)


def jsonrpc(func:Callable) -> Callable:
    """Decorator to handle JSON-RPC calls for x64dbgpy3 methods."""
    sig = inspect.signature(func)
    return_annotation = sig.return_annotation

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Get class and function name for the JSON-RPC method
        qualname_parts = func.__qualname__.split('.')
        if len(qualname_parts) != 2:
            raise TypeError(f"Decorator @jsonrpc expected to be used on a method within a class, got {func.__qualname__}")
        class_name, func_name = qualname_parts
        method_name = f"{class_name}::{func_name}"

    return wrapper