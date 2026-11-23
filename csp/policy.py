"""CSP（Content Security Policy）策略解析与 URL 放行判定。

本模块只覆盖 CSP 的一个子集：directive / source list 解析，以及
host-source、scheme-source、'self'、'none'、nonce-source、hash-source
的匹配。所有比较遵循“容差 0”：除了 docstring 明确写出的大小写归一化，
不做任何模糊匹配、前后缀猜测、路径解码或默认端口以外的推断。
"""

import re
from urllib.parse import urljoin, urlsplit

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


_DEFAULT_PORTS = {"http": 80, "https": 443}

# 带引号、但不参与 URL 匹配的关键字（'self' / 'none' 单独处理）。
_KNOWN_KEYWORDS = {
    "unsafe-inline",
    "unsafe-eval",
    "strict-dynamic",
    "unsafe-hashes",
    "wasm-unsafe-eval",
    "report-sample",
    "inline-speculation-rules",
}

_KNOWN_DIRECTIVES = {
    "base-uri",
    "block-all-mixed-content",
    "child-src",
    "connect-src",
    "default-src",
    "disown-opener",
    "font-src",
    "form-action",
    "frame-ancestors",
    "frame-src",
    "img-src",
    "manifest-src",
    "media-src",
    "navigate-to",
    "object-src",
    "plugin-types",
    "prefetch-src",
    "referrer",
    "reflected-xss",
    "report-to",
    "report-uri",
    "require-sri-for",
    "require-trusted-types-for",
    "sandbox",
    "script-src",
    "script-src-attr",
    "script-src-elem",
    "style-src",
    "style-src-attr",
    "style-src-elem",
    "trusted-types",
    "upgrade-insecure-requests",
    "webrtc",
    "worker-src",
}

# 允许不带 source list 的 directive。
_NO_SOURCE_DIRECTIVES = {
    "sandbox",
    "upgrade-insecure-requests",
    "block-all-mixed-content",
}

_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*")
_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?")
# nonce / hash 值：CSP 的 base64-value 语法。
_BASE64_RE = re.compile(r"[A-Za-z0-9+/\-_]+={0,2}")
_IPV4_RE = re.compile(r"\d+(?:\.\d+){3}")
_IPV6_CHARS_RE = re.compile(r"[0-9A-Fa-f:.]+")
_HASH_RE = re.compile(r"(sha256|sha384|sha512)-(.+)", re.IGNORECASE)


def _make_source(
    raw,
    type_,
    *,
    scheme=None,
    host=None,
    port=None,
    path=None,
    wildcard=False,
    nonce=None,
    hash=None,
    algorithm=None,
    keyword=None,
):
    """构造 parse_source 的返回 dict，保证键集合固定。"""
    return {
        "raw": raw,
        "type": type_,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
        "wildcard": wildcard,
        "nonce": nonce,
        "hash": hash,
        "algorithm": algorithm,
        "keyword": keyword,
    }


def _parse_port(text):
    """解析端口部分：数字（0-65535）或 "*"。非法时抛 ValueError。"""
    if text == "*":
        return "*"
    if not re.fullmatch(r"\d{1,5}", text):
        raise ValueError("invalid port: %r" % (text,))
    value = int(text)
    if value > 65535:
        raise ValueError("port out of range: %r" % (text,))
    return value


def _validate_host(part):
    """校验 host（不含 "*." 前缀）；返回小写 host。"""
    if not part:
        raise ValueError("empty host")
    if part.startswith("[") or part.endswith("]"):
        raise ValueError("malformed IPv6 host")
    if part.startswith(".") or part.endswith("."):
        raise ValueError("host must not start or end with '.'")
    if part.count(".") == 3 and all(
        re.fullmatch(r"\d+", label) for label in part.split(".")
    ):
        octets = part.split(".")
        if any(int(octet) > 255 for octet in octets):
            raise ValueError("invalid IPv4 host: %r" % (part,))
        return part.lower()
    if len(part) > 253:
        raise ValueError("host too long")
    labels = part.split(".")
    for label in labels:
        if not _LABEL_RE.fullmatch(label):
            raise ValueError("invalid host: %r" % (part,))
    return part.lower()


def _parse_host_port(hostport):
    """解析 [scheme 已剥离的] host[:port]，返回 (host, wildcard, port)。"""
    if not hostport:
        raise ValueError("missing host")

    if hostport.startswith("["):
        end = hostport.find("]")
        if end == -1:
            raise ValueError("unclosed IPv6 host")
        inner = hostport[1:end]
        if not inner or ":" not in inner or not _IPV6_CHARS_RE.fullmatch(inner):
            raise ValueError("invalid IPv6 host")
        remainder = hostport[end + 1:]
        if remainder == "":
            return inner.lower(), False, None
        if not remainder.startswith(":"):
            raise ValueError("malformed host")
        return inner.lower(), False, _parse_port(remainder[1:])

    if hostport.count(":") > 1:
        raise ValueError("IPv6 host must be bracketed")
    if ":" in hostport:
        hostpart, porttext = hostport.rsplit(":", 1)
        port = _parse_port(porttext)
    else:
        hostpart, port = hostport, None

    if hostpart == "*":
        return "*", False, port

    if hostpart.startswith("*."):
        base = hostpart[2:]
        if _IPV4_RE.fullmatch(base):
            raise ValueError("wildcard must not target an IP address")
        return _validate_host(base), True, port

    return _validate_host(hostpart), False, port


def _parse_quoted(token):
    if not token.endswith("'") or len(token) < 3:
        raise ValueError("unclosed quote in source token")
    inner = token[1:-1]
    if not inner or "'" in inner:
        raise ValueError("malformed quoted source token")

    lowered = inner.lower()
    if lowered == "self":
        return _make_source(token, "self")
    if lowered == "none":
        return _make_source(token, "none")
    if lowered in _KNOWN_KEYWORDS:
        return _make_source(token, "keyword", keyword=lowered)

    if lowered.startswith("nonce-"):
        value = inner[len("nonce-"):]
        if not _BASE64_RE.fullmatch(value):
            raise ValueError("invalid nonce value")
        return _make_source(token, "nonce", nonce=value)

    match = _HASH_RE.fullmatch(inner)
    if match:
        algorithm, value = match.group(1).lower(), match.group(2)
        if not _BASE64_RE.fullmatch(value):
            raise ValueError("invalid hash value")
        return _make_source(token, "hash", hash=value, algorithm=algorithm)

    raise ValueError("unknown keyword source: %r" % (inner,))


def _parse_unquoted(token):
    scheme = None
    rest = token

    if "://" in token:
        scheme_part, rest = token.split("://", 1)
        if not _SCHEME_RE.fullmatch(scheme_part):
            raise ValueError("invalid scheme: %r" % (scheme_part,))
        if not rest:
            raise ValueError("missing host")
        scheme = scheme_part.lower()
    elif token.endswith(":") and _SCHEME_RE.fullmatch(token[:-1]):
        # scheme-source，例如 "https:" 或 "data:"。
        return _make_source(token, "scheme", scheme=token[:-1].lower())

    slash = rest.find("/")
    if slash == -1:
        hostport, path = rest, None
    else:
        hostport, path = rest[:slash], rest[slash:]

    host, wildcard, port = _parse_host_port(hostport)
    return _make_source(
        token,
        "host",
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        wildcard=wildcard,
    )


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
    policy = {}
    if not isinstance(header, str):
        return policy

    for segment in header.split(";"):
        segment = segment.strip()
        if not segment:
            continue
        parts = segment.split()
        if not parts:
            continue
        name = parts[0].lower()
        # 第一次出现的定义生效，后出现的同名 directive 整段忽略。
        if name in policy:
            continue
        policy[name] = parts[1:]

    return policy


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
    if not isinstance(token, str):
        raise ValueError("source token must be a string")
    if not token:
        raise ValueError("empty source token")
    if token != token.strip():
        raise ValueError("source token has surrounding whitespace")
    for char in token:
        if ord(char) < 0x20 or ord(char) == 0x7F:
            raise ValueError("source token contains control characters")
    if ";" in token:
        raise ValueError("source token contains ';'")

    if token.startswith("'"):
        return _parse_quoted(token)
    if "'" in token:
        raise ValueError("unbalanced quote in source token")

    return _parse_unquoted(token)


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
    if not isinstance(source, dict) or source.get("type") != "host":
        return False
    if not isinstance(host, str) or not host:
        return False

    candidate = host.lower()
    expected = source.get("host")
    if not expected:
        return False

    if expected == "*":
        return True

    expected = expected.lower()
    if source.get("wildcard"):
        suffix = "." + expected
        # 必须存在至少一级子域，且严格以 ".<expected>" 结尾。
        return len(candidate) > len(suffix) and candidate.endswith(suffix)

    return candidate == expected


def port_matches(source: dict, port: int, scheme: str) -> bool:
    """判断 host-source 的端口约束是否匹配 (port, scheme)。

    - source 必须 type == "host"，否则返回 False；
    - 未写端口时只接受 scheme 的默认端口（http=80、https=443）；没有
      已知默认端口的 scheme 未写端口时返回 False；
    - 写了端口时要求完全相等；
    - port 为 None 时按 scheme 默认端口折算；
    - 不做“未写端口即任意端口”的放宽（容差 0）。
    """
    if not isinstance(source, dict) or source.get("type") != "host":
        return False

    scheme = scheme.lower() if isinstance(scheme, str) else None
    default_port = _DEFAULT_PORTS.get(scheme)

    if port is None:
        if default_port is None:
            # 没有默认端口可折算：只有显式 "*" 端口能通过。
            return source.get("port") == "*"
        port = default_port

    expected = source.get("port")
    if expected is None:
        # 未写端口：只等价于 scheme 的默认端口。
        return default_port is not None and port == default_port
    if expected == "*":
        return True
    return port == expected


def path_matches(source: dict, path: str) -> bool:
    """判断 host-source 的路径约束是否匹配 path。

    - source 无路径约束（path is None）时返回 True；
    - 以 "/" 结尾的 path 视为目录前缀，要求目标 path 以它开头；
    - 不以 "/" 结尾的 path 视为完整路径，要求完全相等；
    - 因此 "/js" 不匹配 "/js-evil/x.js"，"/static/" 匹配
      "/static/app.js"；
    - 区分大小写，不做百分号解码、"." / ".." 归一化（容差 0）。
    """
    if not isinstance(source, dict) or source.get("type") != "host":
        return False

    expected = source.get("path")
    if expected is None:
        return True
    if not isinstance(path, str):
        return False

    if expected.endswith("/"):
        return path.startswith(expected)
    return path == expected


def _url_parts(url):
    """解析 URL，返回 (scheme, host, port, path)；无法解析时返回 None。"""
    try:
        parts = urlsplit(url)
        port = parts.port  # 非法端口在这里抛 ValueError
    except (TypeError, ValueError):
        return None
    scheme = parts.scheme.lower()
    host = parts.hostname.lower() if parts.hostname else None
    return scheme, host, port, parts.path or "/"


def _effective_port(scheme, port):
    if port is None:
        return _DEFAULT_PORTS.get(scheme)
    return port


def _self_matches(url_info, origin):
    if not origin or not isinstance(origin, str):
        return False
    origin_info = _url_parts(origin)
    if origin_info is None:
        return False
    o_scheme, o_host, o_port, _ = origin_info
    if not o_scheme or not o_host:
        return False
    u_scheme, u_host, u_port, _ = url_info
    if not u_scheme or not u_host:
        return False
    return (
        o_scheme == u_scheme
        and o_host == u_host
        and _effective_port(o_scheme, o_port) == _effective_port(u_scheme, u_port)
    )


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
    if not isinstance(policy, dict):
        return False

    effective = effective_directive(policy, directive)
    if not effective:
        return False

    raw_sources = policy.get(effective) or []
    sources = []
    for token in raw_sources:
        try:
            sources.append(parse_source(token))
        except (TypeError, ValueError):
            # 非法 source token 忽略。
            continue

    credential_sources = [
        source for source in sources if source["type"] in ("nonce", "hash")
    ]
    if credential_sources:
        # 出现 nonce/hash 后只认 nonce/hash，绝不回落到主机白名单。
        if isinstance(nonce, str):
            for source in credential_sources:
                if source["type"] == "nonce" and source["nonce"] == nonce:
                    return True
        if isinstance(hashes, str):
            hashes = [hashes]
        if hashes:
            candidates = set(hashes)
            for source in credential_sources:
                if source["type"] != "hash":
                    continue
                combined = "%s-%s" % (source["algorithm"], source["hash"])
                if combined in candidates:
                    return True
        return False

    if not isinstance(url, str) or not url:
        return False

    try:
        split = urlsplit(url)
        _ = split.port
    except (TypeError, ValueError):
        return False

    if not split.scheme:
        if split.netloc:
            # 协议相对 URL（"//host/path"）：没有 origin 无法确定 scheme。
            if origin is None:
                return False
            try:
                split = urlsplit(urljoin(origin, url))
                _ = split.port
            except (TypeError, ValueError):
                return False
        else:
            # 不含 host 的相对 URL：origin 为 None 时只允许 'self'。
            if origin is None:
                return any(source["type"] == "self" for source in sources)
            try:
                split = urlsplit(urljoin(origin, url))
                _ = split.port
            except (TypeError, ValueError):
                return False

    url_info = _url_parts(split.geturl())
    if url_info is None:
        return False
    scheme, host, port, path = url_info

    for source in sources:
        source_type = source["type"]

        if source_type == "self":
            if _self_matches(url_info, origin):
                return True
            continue

        if source_type == "scheme":
            if source["scheme"] == scheme:
                return True
            continue

        if source_type != "host":
            # 'none' 与普通关键字不匹配任何 URL。
            continue

        if not host:
            continue

        source_scheme = source["scheme"]
        if source_scheme is not None:
            if source_scheme != scheme:
                continue
        elif scheme not in ("http", "https"):
            # 未写 scheme 只能沿用 web 的 http/https。
            continue

        if not host_matches(source, host):
            continue
        if not port_matches(source, port, scheme):
            continue
        if not path_matches(source, path):
            continue
        return True

    return False


def effective_directive(policy: dict, directive: str) -> str:
    """返回 directive 实际生效的指令名。

    - directive 在 policy 中存在，返回其小写名（即使 source list 为 []）；
    - 否则存在 default-src 时返回 "default-src"；
    - 都不存在时返回 ""，表示没有可用策略、调用方必须拒绝；不允许返回
      "*" 之类的默认放行值。
    """
    if not isinstance(policy, dict):
        return ""
    if not isinstance(directive, str):
        return ""
    name = directive.lower()
    if name in policy:
        return name
    if "default-src" in policy:
        return "default-src"
    return ""


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
    issues = []
    if not isinstance(header, str):
        return ["header must be a string"]

    for segment in header.split(";"):
        segment = segment.strip()
        if not segment:
            continue
        parts = segment.split()
        if not parts:
            continue
        name = parts[0].lower()
        sources = parts[1:]

        known = name in _KNOWN_DIRECTIVES
        if not known:
            issues.append("unknown directive: %s" % (parts[0],))

        for token in sources:
            try:
                parse_source(token)
            except ValueError as exc:
                issues.append(
                    "invalid source %r in %s: %s" % (token, name, exc)
                )

        if not sources and known and name not in _NO_SOURCE_DIRECTIVES:
            issues.append("directive %s has no source list" % (name,))

    return issues
