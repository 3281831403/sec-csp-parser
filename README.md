# sec-csp-parser

上线 CSP 之后仍被注入脚本，排查发现策略解析出来的白名单比实际宽得多：host 匹配用后缀比较，`evil-example.com` 能命中 `example.com`；`*.example.com` 把 `example.com` 本身也放行；`*` 后面的 path 限制被丢掉，任意路径都能加载；没写端口被当成任意端口；`/js` 前缀把 `/js-evil/x.js` 也放进来；nonce 不匹配时仍回落到主机白名单；hash 用前缀比较，前缀相同即通过；缺少 `default-src` 时返回 `*` 默认放行；重复指令取最后一条，后注入的宽策略覆盖前一条；token 里的 `;` 等非法字符不校验，注入内容直接混进 source list。csp/policy.py 是核心，tests/test_policy.py 15个红。要修的是：按 CSP 语义收紧 source list 解析与 URL 匹配，把上述 10 个缺陷全部修掉。

## 运行方式

在仓库根目录执行：

```bash
python -m pytest tests -q
```

初始状态应恰好是 `15 failed`，没有 collection / import / syntax error；修复后应为 `15 passed`。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 约束

- 只使用标准库（`re`、`urllib.parse`）与 pytest；离线运行，不使用随机数。
- 所有匹配遵循容差 0：除文档写明的 scheme/host 小写归一化外，不做模糊匹配、前后缀猜测、路径解码或额外默认端口推断。
- `tests/` 不可修改；只允许修改 `csp/policy.py`。

## 文件

```
sec-csp-parser/
├── README.md
├── conftest.py
├── .gitignore
├── csp/
│   ├── __init__.py
│   └── policy.py
└── tests/
    └── test_policy.py
```

`csp/policy.py` 提供 8 个待实现函数：`parse_policy`、`parse_source`、
`host_matches`、`port_matches`、`path_matches`、`allows`、
`effective_directive`、`validate_header`。各函数的完整契约见 docstring。
`allows` 额外接受 keyword-only 参数 `origin`（受保护文档的源，如
`https://app.example`），仅用于 `'self'` 的同源判断。

## 测试

`tests/test_policy.py` 共 15 个用例：前 10 个分别锁定 10 个缺陷（绕过输入必须被拒绝、合法输入必须被放行），其余 5 个覆盖 `'none'`、`'self'`、`default-src` 回退、合法 header 校验和同一 header 的两次解析结果一致。该文件不可修改。
