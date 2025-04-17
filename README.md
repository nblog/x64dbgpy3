## x64dbgpy3 [中文说明](README-CN.md)

**x64dbgpy3** is a plugin for [x64dbg](https://x64dbg.com/) that enables remote invocation via [HTTP-RPC](https://github.com/jsonrpcx/json-rpc-cxx) and the `x64dbgpy3svr` server. This allows for seamless integration with external tools and scripts, such as those written in Python.  
Contributions are welcome! Please see our [Pull Requests](https://github.com/nblog/x64dbgpy3/pulls) page.

---

### Getting Started

Start the server with the following command:

```sh
x64dbgpy3svr [port=27041] [host=0.0.0.0]
```

---

### Screenshots

![Run Service](screenshot/run%20service.png)  
*Running the x64dbgpy3 server*

![VSCode Python Test](screenshot/vscode%20python.png)  
*Testing with Python in VSCode*

---

### License

This project is licensed under the WTFPL License.  

---