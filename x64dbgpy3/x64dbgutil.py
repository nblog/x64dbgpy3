#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, datetime, functools, inspect, base64
from enum import IntEnum, IntFlag
from typing import List, Tuple, Dict, Union, Optional, Callable, Any, get_args
from pydantic import BaseModel, Field
from pydantic_core import core_schema

FUNCTION_NAME = lambda n: "::".join([ getattr(n, "__name__"), inspect.currentframe().f_back.f_code.co_name ])


def get_debugger_host():
    host_env = os.getenv("X64DBGPY3_HOST", "localhost:27041")
    parts = host_env.split(":")
    host = parts[0] if parts else "localhost"
    try:
        port = int(parts[1]) if len(parts) > 1 else 27041
    except ValueError:
        port = 27041
    return host, str(port)


class ptr_t(int):
    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: Any
    ) -> core_schema.CoreSchema:
        """
        Tell Pydantic how to handle this type.
        We want it to be treated just like an int.
        """
        # Use the handler to get the CoreSchema for the parent type (int)
        # and return a schema that validates as an int but returns instances of ptr_t
        int_schema = handler(int)

        return core_schema.no_info_after_validator_function(
            cls, # The function to call after validation (the class itself to instantiate)
            int_schema # The schema to validate against (int schema)
        )
class size_t(int):
    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: Any
    ) -> core_schema.CoreSchema:
        """
        Tell Pydantic how to handle this type.
        We want it to be treated just like an int.
        """
        # Use the handler to get the CoreSchema for the parent type (int)
        # and return a schema that validates as an int but returns instances of size_t
        int_schema = handler(int)

        return core_schema.no_info_after_validator_function(
            cls, # The function to call after validation (the class itself to instantiate)
            int_schema # The schema to validate against (int schema)
        )
class RequestBuffer:
    from lz4.block import compress, decompress

    @staticmethod
    def serialize(buffer:bytes):
        return base64.b64encode(RequestBuffer.compress(buffer)).decode()

    @staticmethod
    def deserialize(buffer:str):
        return RequestBuffer.decompress(base64.b64decode(buffer))


# Constants
HUNDRED_NANOSECONDS_PER_MICROSECOND = 10
HUNDRED_NANOSECONDS_PER_SECOND = 10 * 1000 * 1000 # 10 million
SECONDS_BETWEEN_EPOCHS = 11644473600 # Seconds between 1601-01-01 and 1970-01-01
EPOCH_AS_FILETIME = SECONDS_BETWEEN_EPOCHS * HUNDRED_NANOSECONDS_PER_SECOND
def filetime_to_datetime(filetime_int: int) -> datetime.datetime:
    """Converts a Windows FILETIME (64-bit int) to a Python datetime object (UTC)."""
    if filetime_int < 0:
        raise ValueError("FILETIME value cannot be negative")

    # Convert FILETIME from 100-nanosecond intervals since 1601
    # to microseconds since 1970-01-01 (Unix epoch)
    try:
        # Calculate microseconds since 1601 epoch
        microseconds_since_1601 = filetime_int // HUNDRED_NANOSECONDS_PER_MICROSECOND
        # Calculate microseconds since 1970 epoch
        epoch_diff_microseconds = SECONDS_BETWEEN_EPOCHS * 1000 * 1000
        microseconds_since_1970 = microseconds_since_1601 - epoch_diff_microseconds

        # Handle potential overflow for dates very far in the future if needed,
        # though standard datetime handles a wide range.

        # Create timedelta from microseconds and add to Unix epoch
        td = datetime.timedelta(microseconds=microseconds_since_1970)
        unix_epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
        dt = unix_epoch + td
        return dt
    except OverflowError:
        # Handle cases where the resulting date might be outside Python's datetime range
        # This is unlikely with typical FILETIME values but good practice
        print(f"Warning: FILETIME {filetime_int} resulted in overflow, returning max/min datetime.")
        if filetime_int > EPOCH_AS_FILETIME:
             return datetime.datetime.max.replace(tzinfo=datetime.timezone.utc)
        else:
             # Technically FILETIME shouldn't represent dates before 1601,
             # but if the input was somehow small...
             return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)


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