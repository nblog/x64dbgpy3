#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import httpx



class reqException(Exception):
    '''  '''

class reqJson:
    def __init__(self, hostUrl:str):
        self.hostUrl, self.session = hostUrl, \
            httpx.Client(proxies={})

    def x64dbg_info(self):
        res = self.session.get( "/".join( [ self.hostUrl, "x64dbginfo" ] ) )
        return res.json()

    def req_call(self, method:str, args:..., void:bool=False):
        reqJson = \
            dict( { } if (void) else { "id": '' },
            **{ "jsonrpc":"2.0", "method":method, "params": args } )

        res = self.session.post(
            "/".join( [ self.hostUrl, "x64dbgreq" ] ), 
            json=reqJson
        )

        if (200 != res.status_code): 
            raise reqException( {"code": -32003, "message": "client connector error"} )

        ''' no result '''
        if (void): return None

        ''' result '''
        rtJson = res.json()
        if ("result" in rtJson): return rtJson["result"]

        ''' exception '''
        raise reqException( rtJson["error"] )