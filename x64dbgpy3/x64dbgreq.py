#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, List


class JSONRPCError(Exception):
    def __init__(self, code: int, message: str, data=None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"JSON-RPC Error {code}: {message}")


class RequestJsonRpc:
    def __init__(self, hostUrl: str):
        from httpx import Client, Timeout
        self.hostUrl = hostUrl
        self.session = Client(timeout=Timeout(30.0))

    def x64dbg_info(self):
        """Get x64dbg server information."""
        try:
            res = self.session.get(f"{self.hostUrl}/x64dbg/api/info")
            res.raise_for_status()
            return res.json()
        except Exception as e:
            raise JSONRPCError(-32000, f"Failed to get server info: {str(e)}", None)

    def x64dbg_call(self, method: str, args: List[Any]):
        """
        Call a JSON-RPC method on the x64dbg server.
        
        Args:
            method: The RPC method name
            args: List of arguments to pass to the method
            
        Returns:
            The result from the RPC call
            
        Raises:
            JSONRPCError: If the RPC call fails or returns an error
        """
        from httpx import HTTPStatusError, RequestError
        from uuid import uuid4
        
        payload = {
            "id": str(uuid4()),
            "jsonrpc": "2.0",
            "method": method,
            "params": args
        }

        try:
            res = self.session.post(
                f"{self.hostUrl}/x64dbg/api/call",
                json=payload
            )
            res.raise_for_status()
            
            rtJson = res.json()
            
            # Check for successful response
            if "id" in rtJson and "result" in rtJson and rtJson["id"] == payload["id"]:
                return rtJson["result"]
            
            # Handle JSON-RPC error response
            if "error" in rtJson:
                raise JSONRPCError(
                    code=int(rtJson["error"]["code"]),
                    message=str(rtJson["error"]["message"]),
                    data=rtJson["error"].get("data")
                )
            
            # Unexpected response format
            raise JSONRPCError(-32603, "Invalid JSON-RPC response format", rtJson)
            
        except HTTPStatusError as e:
            raise JSONRPCError(-32000, f"HTTP Error {e.response.status_code}: {str(e)}", None)
        except RequestError as e:
            raise JSONRPCError(-32000, f"Request Error: {str(e)}", None)
        except JSONRPCError:
            # Re-raise JSON-RPC errors as-is
            raise
        except Exception as e:
            raise JSONRPCError(-32603, f"Internal error: {str(e)}", None)