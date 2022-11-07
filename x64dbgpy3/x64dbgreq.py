#!/usr/bin/env python3
# coding=utf-8


import requests



class reqException(Exception):
    '''  '''

class reqJson:
    def __init__(self, hostUrl:str):
        self.session, self.hostUrl = requests.session(), hostUrl

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
        if ("result" in res.json()): return res.json()["result"]

        raise reqException( res.json()["error"] )