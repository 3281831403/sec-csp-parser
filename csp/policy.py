"""CSP（Content Security Policy）策略解析与 URL 放行判定。

本模块只覆盖 CSP 的一个子集：directive / source list 解析，以及
host-source、scheme-source、'self'、'none'、nonce-source、hash-source
的匹配。所有比较遵循“容差 0”：除了 docstring 明确写出的大小写归一化，
不做任何模糊匹配、前后缀猜测、路径解码或默认端口以外的推断。
"""

__all__ = [
    "parse_policy",
    "parse_source",
    "host_matches",
    "port_matches",
    "path_matches",
    "allows",
    "effective_directive",
    "validate_header",
]


def parse_policy(header: str) -> dict:
    """解析 CSP header，返回 {directive: [source, ...]}。

    规则：
    - 按 ";" 切分 directive，每个 directive 内按空白切分：首项为
      directive 名（统一小写），其余为 source list（保持原样、不去重）。
    - 重复 directive 只保留第一次出现的定义；后出现的同名段整段忽略，
      防止后注入的宽策略覆盖前一条。
    - 空段（例如末尾多余的 ";"）跳过；directive 没有 source 时值为 []。
    - 本函数只做切分，不校验 token 合法性；校验交给 validate_header。

    容差 0：不合并重复 directive，也不对 source list 做任何规范化。
    """
    raise NotImplementedError("parse_policy 尚未实现")


def parse_source(token: str) -> dict:
    """把单个 source token 解析为 dict。

    返回 dict 固定包含以下键：raw、type、scheme、host、port、path、
    wildcard、nonce、hash、algorithm、keyword；不适用的键为 None/False。
    type 取值：

    - "host"：host-source。语法 [scheme "://"] host [":" port] ["/" path]；
      host 可为 "*"、"*.example.com"、普通域名、IPv4 或 "[IPv6]"；
      scheme 缺省为 None，port 缺省为 None，path 缺省为 None。
      单独的 "*" 表示任意 host（host="*", wildcard=False）；
      "*.example.com" 表示至少一级子域（host="example.com",
      wildcard=True）。
    - "scheme"：scheme-source，如 "https:"，只约束 scheme。
    - "self" / "none"：关键字 source。
    - "nonce"：'nonce-<base64>'，值放在 nonce。
    - "hash"：'sha256-' / 'sha384-' / 'sha512-'，值放在 hash，算法放在
      algorithm。
    - "keyword"：'unsafe-inline'、'strict-dynamic' 等不参与 URL 匹配的
      关键字，名称放在 keyword。

    非法 token（未闭合引号、控制字符、";"、非法 host/port、未知关键字等）
    抛出 ValueError。容差 0：scheme/host 仅做小写归一化，path、nonce、
    hash 原样保留。
    """
    raise NotImplementedError("parse_source 尚未实现")


def host_matches(source: dict, host: str) -> bool:
    """判断 host-source 是否匹配 host。

    - source 必须来自 parse_source 且 type == "host"，否则返回 False；
    - host 比较不区分大小写；
    - source 的 host 为 "*" 时匹配任意非空 host；
    - wildcard 为 True 时只匹配源域的至少一级子域：*.example.com 匹配
      cdn.example.com，不匹配 example.com 本身，也不匹配 badexample.com；
    - 其余情况要求 host 完全相等，禁止后缀 / 子串匹配；
    - 不处理端口、路径、scheme（容差 0）。
    """
    raise NotImplementedError("host_matches 尚未实现")


def port_matches(source: dict, port: int, scheme: str) -> bool:
    """判断 host-source 的端口约束是否匹配 (port, scheme)。

    - source 必须 type == "host"，否则返回 False；
    - 未写端口时只接受 scheme 的默认端口（http=80、https=443）；没有
      已知默认端口的 scheme 未写端口时返回 False；
    - 写了端口时要求完全相等；
    - port 为 None 时按 scheme 默认端口折算；
    - 不做“未写端口即任意端口”的放宽（容差 0）。
    """
    raise NotImplementedError("port_matches 尚未实现")


def path_matches(source: dict, path: str) -> bool:
    """判断 host-source 的路径约束是否匹配 path。

    - source 无路径约束（path is None）时返回 True；
    - 以 "/" 结尾的 path 视为目录前缀，要求目标 path 以它开头；
    - 不以 "/" 结尾的 path 视为完整路径，要求完全相等；
    - 因此 "/js" 不匹配 "/js-evil/x.js"，"/static/" 匹配
      "/static/app.js"；
    - 区分大小写，不做百分号解码、"." / ".." 归一化（容差 0）。
    """
    raise NotImplementedError("path_matches 尚未实现")


def allows(
    policy: dict,
    directive: str,
    url: str,
    nonce: str,
    hashes,
    *,
    origin: str = None,
) -> bool:
    """判断 url 是否被 policy 中 directive 的 source list 放行。

    - directive 缺失时经 effective_directive 回退到 default-src；仍无
      可用 directive 时拒绝；
    - source list 中只要出现 nonce-source 或 hash-source，就只认
      nonce/hash：nonce 精确相等，或 hashes 中某项与
      "<algorithm>-<value>" 完全相等；不匹配时直接拒绝，绝不回落到
      host-source 白名单；
    - 否则按 host-source / scheme-source / 'self' 匹配，scheme、host、
      port、path 全部满足才放行；
    - 'self' 用 origin（受保护文档的源，如 "https://app.example"）判断
      同源；origin 为 None 时只匹配不含 host 的相对 URL；
    - 'none' 不匹配任何 URL；与其他 source 并存时其他 source 仍然有效；
    - 非法 source token 忽略，URL 无法解析时拒绝。

    nonce 为 str 或 None；hashes 为 str 序列（元素形如
    "sha256-<base64>"）或 None。以上所有匹配容差 0。
    """
    raise NotImplementedError("allows 尚未实现")


def effective_directive(policy: dict, directive: str) -> str:
    """返回 directive 实际生效的指令名。

    - directive 在 policy 中存在，返回其小写名（即使 source list 为 []）；
    - 否则存在 default-src 时返回 "default-src"；
    - 都不存在时返回 ""，表示没有可用策略、调用方必须拒绝；不允许返回
      "*" 之类的默认放行值。
    """
    raise NotImplementedError("effective_directive 尚未实现")


def validate_header(header: str) -> list:
    """校验 header 并返回问题列表；合法策略返回 []。

    检查：
    1. 未知 directive（不在已知 CSP directive 集合中）；
    2. 非法 source token（parse_source 抛 ValueError，如未闭合引号、
       控制字符、";" 注入残留、非法端口等）；
    3. 没有 source list 的 directive；upgrade-insecure-requests、
       block-all-mixed-content 和 sandbox 允许无 source。

    不抛异常；问题为人类可读字符串，按 header 中出现顺序返回。
    """
    raise NotImplementedError("validate_header 尚未实现")
