"""sec-csp-parser 的验收测试。

前 10 个用例分别对应 README 中描述的 10 个安全缺陷，要求“绕过的输入必须
被拒绝、合法的输入必须被放行”；后 5 个用例覆盖 'none'、'self'、
default-src 回退、合法 header 校验和无状态解析。

测试只通过公开 API 断言行为，不依赖内部辅助函数。
"""

from csp.policy import (
    allows,
    effective_directive,
    host_matches,
    parse_policy,
    parse_source,
    path_matches,
    port_matches,
    validate_header,
)


def test_host_matches_rejects_suffix_substring_bypass():
    """缺陷 1：后缀比较让 evil-example.com 命中 example.com。"""
    source = parse_source("https://example.com")

    assert host_matches(source, "example.com") is True
    assert host_matches(source, "evil-example.com") is False
    assert host_matches(source, "example.com.evil.example") is False
    assert host_matches(source, "sub.example.com") is False


def test_wildcard_host_does_not_match_bare_domain():
    """缺陷 2：*.example.com 不得匹配 example.com 本身。"""
    source = parse_source("*.example.com")

    assert host_matches(source, "cdn.example.com") is True
    assert host_matches(source, "deep.cdn.example.com") is True
    assert host_matches(source, "example.com") is False
    assert host_matches(source, "badexample.com") is False


def test_wildcard_host_still_restricts_path():
    """缺陷 3：host 为 * 时，后面的 path 约束不能被丢弃。"""
    source = parse_source("https://*/admin/")
    assert source["host"] == "*"
    assert source["path"] == "/admin/"

    policy = parse_policy("script-src https://*/admin/")
    assert allows(policy, "script-src", "https://evil.example/admin/x.js", None, None) is True
    assert allows(policy, "script-src", "https://evil.example/other.js", None, None) is False
    assert allows(policy, "script-src", "http://evil.example/admin/x.js", None, None) is False


def test_unspecified_port_is_not_any_port():
    """缺陷 4：未写端口只等价于 scheme 默认端口，不是任意端口。"""
    source = parse_source("https://example.com")
    assert port_matches(source, 443, "https") is True
    assert port_matches(source, 8443, "https") is False

    explicit = parse_source("https://example.com:8443")
    assert explicit["port"] == 8443
    assert port_matches(explicit, 8443, "https") is True
    assert port_matches(explicit, 443, "https") is False


def test_path_prefix_requires_directory_boundary():
    """缺陷 5：/js 不是目录前缀，不得命中 /js-evil/x.js。"""
    file_source = parse_source("https://example.com/js")
    assert path_matches(file_source, "/js") is True
    assert path_matches(file_source, "/js-evil/x.js") is False

    dir_source = parse_source("https://example.com/static/")
    assert path_matches(dir_source, "/static/app.js") is True
    assert path_matches(dir_source, "/static-evil/app.js") is False


def test_nonce_mismatch_does_not_fall_back_to_hosts():
    """缺陷 6：出现 nonce 后只认 nonce，不能回落到主机白名单。"""
    policy = parse_policy("script-src 'nonce-abc123' https://cdn.example.com")

    assert allows(policy, "script-src", "https://cdn.example.com/app.js", "abc123", None) is True
    assert allows(policy, "script-src", "https://cdn.example.com/app.js", "abc124", None) is False
    assert allows(policy, "script-src", "https://cdn.example.com/app.js", None, None) is False


def test_hash_comparison_is_exact():
    """缺陷 7：hash 必须完全相等，前缀相同不能放行。"""
    policy = parse_policy("script-src 'sha256-abc123'")

    assert allows(policy, "script-src", "https://app.example/app.js", None, ["sha256-abc123"]) is True
    assert allows(policy, "script-src", "https://app.example/app.js", None, ["sha256-abc1234"]) is False
    assert allows(policy, "script-src", "https://app.example/app.js", None, []) is False


def test_missing_default_src_denies():
    """缺陷 8：没有 default-src 时不能默认放行 *。"""
    assert effective_directive({}, "script-src") == ""
    assert allows({}, "script-src", "https://app.example/app.js", None, None) is False

    policy = parse_policy("default-src https://app.example")
    assert allows(policy, "script-src", "https://app.example/app.js", None, None) is True
    assert allows(policy, "script-src", "https://evil.example/app.js", None, None) is False


def test_duplicate_directive_first_wins():
    """缺陷 9：重复 directive 取第一条，后注入的 * 不得覆盖。"""
    policy = parse_policy("script-src https://good.example; script-src *")

    assert policy["script-src"] == ["https://good.example"]
    assert allows(policy, "script-src", "https://good.example/app.js", None, None) is True
    assert allows(policy, "script-src", "https://evil.example/app.js", None, None) is False


def test_validate_header_rejects_injected_and_malformed_tokens():
    """缺陷 10：分号注入和未闭合引号都必须是可见问题。"""
    injected = "script-src 'self' https://cdn.example.com; https://evil.example/x.js"
    assert validate_header(injected) != []

    malformed = "script-src 'self' 'nonce-"
    assert validate_header(malformed) != []


def test_none_source_denies_everything():
    """合法用例：'none' 拒绝一切 URL。"""
    policy = parse_policy("script-src 'none'")
    assert policy["script-src"] == ["'none'"]

    assert allows(policy, "script-src", "https://app.example/app.js", None, None) is False
    assert allows(policy, "script-src", "https://app.example/app.js", "abc123", None) is False


def test_self_matches_only_same_origin():
    """合法用例：'self' 只放行同源 URL。"""
    policy = parse_policy("script-src 'self'")
    origin = "https://app.example"

    assert allows(policy, "script-src", "https://app.example/js/app.js", None, None, origin=origin) is True
    assert allows(policy, "script-src", "https://app.example:443/js/app.js", None, None, origin=origin) is True
    assert allows(policy, "script-src", "https://cdn.example/js/app.js", None, None, origin=origin) is False
    assert allows(policy, "script-src", "http://app.example/js/app.js", None, None, origin=origin) is False
    assert allows(policy, "script-src", "https://app.example:8443/js/app.js", None, None, origin=origin) is False


def test_default_src_fallback_is_used():
    """合法用例：缺失的 directive 回退到 default-src。"""
    policy = parse_policy(
        "default-src 'self' https://cdn.example.com; img-src https://img.example.com"
    )
    origin = "https://app.example"

    assert effective_directive(policy, "script-src") == "default-src"
    assert effective_directive(policy, "img-src") == "img-src"
    assert allows(policy, "script-src", "https://cdn.example.com/app.js", None, None, origin=origin) is True
    assert allows(policy, "script-src", "https://evil.example/app.js", None, None, origin=origin) is False
    assert allows(policy, "img-src", "https://img.example.com/logo.png", None, None, origin=origin) is True


def test_validate_header_accepts_valid_policy():
    """合法用例：规范策略的问题列表为空。"""
    header = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.example.com 'nonce-abc123'; "
        "img-src https: data:; "
        "object-src 'none'; "
        "upgrade-insecure-requests"
    )

    assert validate_header(header) == []
    assert parse_policy(header)["object-src"] == ["'none'"]


def test_parse_policy_is_stateless_between_calls():
    """合法用例：同一 header 两次解析结果一致，不残留状态。"""
    header = "default-src 'self'; script-src 'nonce-abc123' https://cdn.example.com; img-src https:"

    first = parse_policy(header)
    second = parse_policy(header)

    assert first == second
    assert first["script-src"] == ["'nonce-abc123'", "https://cdn.example.com"]
    assert first["default-src"] == ["'self'"]
