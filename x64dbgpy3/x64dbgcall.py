#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class RequestException(Exception):
    '''  '''

class RequestJsonRpc:
    def __init__(self, hostUrl:str):
        from httpx import Client
        self.hostUrl, self.session = hostUrl, \
            Client()

    def x64dbg_info(self):
        res = self.session.get( "/".join( [ self.hostUrl, "x64dbg", "api", "info" ] ) )
        return res.json()

    def x64dbg_call(self, method:str, args:..., no_result:bool=False):
        from uuid import uuid4
        payload = \
            dict( { } if no_result else { "id": str(uuid4()) }, \
                 **{ "jsonrpc": "2.0", "method": method, "params": args } )

        res = self.session.post(
            "/".join( [ self.hostUrl, "x64dbg", "api", "call" ] ), 
            json=payload
        )

        if (200 != res.status_code): 
            raise RequestException( {"code": -32003, "message": "client connector error"} )

        if not res.content: return None

        rtJson = res.json()
        if "id" in rtJson and "result" in rtJson \
            and rtJson["id"] == payload["id"]:
            return rtJson["result"]

        ''' exception '''
        raise RequestException( rtJson["error"] )