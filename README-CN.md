## x64dbgpy3

> [!WARNING]
> **本项目已不再积极维护。**
> 我将其归类为"x64dbg SDK 的薄包装层"，本身也不值得继续投入维护，且该项目并非为 AI 工作流而设计。
> 它的继任者提供了对 AI 更友好的支持：[x64dbgMCP](https://github.com/nblog/x64dbgMCP)，一个将 MCP server 嵌入 x64dbg 的 C++/CLI 插件（a vibe coding project; keep the vibes immaculate）。

x64dbgpy3 是 [x64dbg](https://x64dbg.com/) 的一个插件，通过 [HTTP-RPC](https://github.com/jsonrpcx/json-rpc-cxx) 和 `x64dbgpy3svr` 服务端实现远程调用，便于与 Python 等外部工具和脚本集成。欢迎[PRs](https://github.com/nblog/x64dbgpy3/pulls)，提 issues 请谨慎。

---

### x64dbgpy3

为了提高使用体验，禁止Python接口中返回或者字段出现 **Any** 类型

---

### 快速开始

使用以下命令启动服务端：

```sh
x64dbgpy3svr [port=27041],[host=localhost]
```

---

### 截图

![run](screenshot/x64dbgpy3svr.png)  
*运行 x64dbgpy3 服务端*

![python-test](screenshot/python-test.png)  
*在 VSCode 中用 Python 测试*

---

### 慈善家

本项目采用 [WTFPL License](http://www.wtfpl.net/) 协议。

---