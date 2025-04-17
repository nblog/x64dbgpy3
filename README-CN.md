## x64dbgpy3

x64dbgpy3 是 [x64dbg](https://x64dbg.com/) 的一个插件，通过 [HTTP-RPC](https://github.com/jsonrpcx/json-rpc-cxx) 和 `x64dbgpy3svr` 服务端实现远程调用，便于与 Python 等外部工具和脚本集成。欢迎[PRs](https://github.com/nblog/x64dbgpy3/pulls)，提 issues 请谨慎。

---

### x64dbgpy3

为了提高使用体验，禁止Python接口中返回或者字段出现 **Any** 类型

---

### 快速开始

使用以下命令启动服务端：

```sh
x64dbgpy3svr [port=27041] [host=0.0.0.0]
```

---

### 截图

![run service](screenshot/run%20service.png)  
*运行 x64dbgpy3 服务端*

![vscode python](screenshot/vscode%20python.png)  
*在 VSCode 中用 Python 测试*

---

### 慈善家

本项目采用 [WTFPL License](http://www.wtfpl.net/) 协议。

---