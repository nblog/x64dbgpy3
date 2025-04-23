#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class JSONRPCError(Exception):
    def __init__(self, code: int, message: str, data = None):
        self.code = code
        self.message = message
        self.data = data

class RequestJsonRpc:
    def __init__(self, hostUrl:str):
        from httpx import Client
        self.hostUrl, self.session = hostUrl, \
            Client()

    def x64dbg_info(self):
        res = self.session.get( "/".join( [ self.hostUrl, "x64dbg", "api", "info" ] ) )
        return res.json()

    def x64dbg_call(self, method:str, args:...):
        from uuid import uuid4
        payload = \
            dict( **{ "id": str(uuid4()), "jsonrpc": "2.0", "method": method, "params": args } )

        res = self.session.post(
            "/".join( [ self.hostUrl, "x64dbg", "api", "call" ] ), 
            json=payload
        )

        res.raise_for_status()

        rtJson = res.json()
        if "id" in rtJson and "result" in rtJson \
            and rtJson["id"] == payload["id"]:
            return rtJson["result"]

        ''' exception '''
        raise JSONRPCError( 
            code=rtJson["error"]["code"], 
            message=rtJson["error"]["message"], 
            data=rtJson["error"].get("data") )