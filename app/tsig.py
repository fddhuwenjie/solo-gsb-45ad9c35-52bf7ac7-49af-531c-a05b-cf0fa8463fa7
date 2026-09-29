"""离线 TSIG（RFC 2845；HMAC-SHA-256/512 见 RFC 4635）报文验证。

不发起任何真实 DNS 查询：输入 Base64 编码的单个 DNS 报文（``message``）、
Base64 编码的共享密钥（``shared_secret``）、期望密钥名（``key_name``）、
验证时刻（``now``，Unix 秒）与可选的上一条请求 MAC（``request_mac``，
Base64），按 RFC 2845 §2-3 离线验证报文上唯一一条 TSIG 记录。

结构要求（任一不符即 ``422``）：

- 报文头/问题区/记录区不得截断（``message_truncated``），记录解析
  结束后不得有多余字节（``trailing_bytes``）；
- 名称支持 RFC 1035 压缩指针，指针越界
  （``compression_pointer_out_of_bounds``）或成环
  （``compression_pointer_loop``）、非法标签类型（``invalid_name``）
  一律拒绝；
- 附加区（additional）必须恰好包含一条 TSIG（类型 250）记录且它位于
  附加区**最末**：无 TSIG 为 ``tsig_not_found``，TSIG 之后还有记录为
  ``tsig_not_unique``；
- TSIG 的 CLASS 必须为 ANY（255，``tsig_bad_class``）、TTL 必须为 0
  （``tsig_bad_ttl``）；
- TSIG RDATA 中的 Original ID 必须等于报文头 ID
  （``original_id_mismatch``）；RDATA 字段截断/长度不符为
  ``tsig_rdata_truncated``。

四个验证步骤依次为 **密钥名 → 算法 → MAC → 时间窗**，全部使用
:func:`hmac.compare_digest` 比较，任一步失败即停止并分别返回
``badkey`` / ``badalg`` / ``badsig`` / ``badtime``（均为 HTTP 200 下的
验证终态）；``badtime`` 响应附 48 位 ``time_signed``（及
``time_high``/``time_low``）。支持算法仅有
``hmac-sha256.``（32 字节 MAC）与 ``hmac-sha512.``（64 字节 MAC）。

MAC 计算严格按 RFC 2845 §2.2：把原报文的 TSIG RR 整体移除并把头部
ARCOUNT 减 1；随后拼接规范编码变量（密钥名与算法名一律按小写、无压缩
的规范 wire 名称编码，算法名仅用于识别不参与散列），提供
``request_mac`` 时在最前面前置其 2 字节长度与内容。成功返回
``authenticated`` 与**不泄露共享密钥/MAC**（仅给出长度）的轨迹。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
from dataclasses import dataclass

from .review import ReviewError
from .zoneparse import ZoneParseError, validate_name

TYPE_TSIG = 250
CLASS_ANY = 255

# RFC 4635 算法名 -> (hashlib 构造名, MAC 字节长度)
ALGORITHMS = {
    "hmac-sha256.": ("sha256", 32),
    "hmac-sha512.": ("sha512", 64),
}

_MAX_UINT48 = 2**48 - 1


# ---------------------------------------------------------------------------
# 报文结构解析
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _ParsedName:
    text: str           # 小写绝对名
    wire: bytes         # 规范 wire 编码：小写标签、无压缩


@dataclass(frozen=True)
class _TsigRecord:
    start: int                  # TSIG RR（owner 名称）在报文中的起点
    end: int                    # TSIG RR 结束偏移（不含）
    rdata_start: int
    arcount: int
    message_id: int
    key: _ParsedName
    algorithm: _ParsedName
    time_high: int
    time_low: int
    fudge: int
    mac: bytes
    original_id: int
    error: int
    other: bytes

    @property
    def time_signed(self) -> int:
        return (self.time_high << 32) | self.time_low


def _read_name(msg: bytes, offset: int, where: str) -> tuple[_ParsedName, int]:
    """读取一个可压缩域名，返回（规范名称，名称结束后的下一偏移）。

    规范 wire 编码由读到的标签重建：标签 ASCII 小写、逐标签长度前缀、
    root 零字节结尾、不含压缩指针。截断/指针越界/成环/名称非法均抛 422。
    """
    labels: list[bytes] = []
    pos = offset
    end: int | None = None  # 首次跟随指针后确定的“下一偏移”
    visited: set[int] = set()
    while True:
        if pos >= len(msg):
            raise ReviewError(
                "message_truncated", f"{where}：名称超出报文末尾", 422
            )
        length = msg[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise ReviewError(
                    "message_truncated",
                    f"{where}：压缩指针只有半个字节",
                    422,
                )
            target = ((length & 0x3F) << 8) | msg[pos + 1]
            if target >= len(msg):
                raise ReviewError(
                    "compression_pointer_out_of_bounds",
                    f"{where}：压缩指针指向报文外偏移 {target}",
                    422,
                )
            if end is None:
                end = pos + 2
            if target in visited:
                raise ReviewError(
                    "compression_pointer_loop",
                    f"{where}：压缩指针在偏移 {target} 处成环",
                    422,
                )
            visited.add(target)
            pos = target
            continue
        if length & 0xC0:
            raise ReviewError(
                "invalid_name",
                f"{where}：非法标签类型字节 0x{length:02x}",
                422,
            )
        pos += 1
        if length == 0:
            break
        if length > 63:  # 普通标签最长 63（0b11 前缀已在上面排除）
            raise ReviewError(
                "invalid_name", f"{where}：标签长度 {length} 超过 63", 422
            )
        if pos + length > len(msg):
            raise ReviewError(
                "message_truncated", f"{where}：标签超出报文末尾", 422
            )
        raw = msg[pos : pos + length]
        try:
            labels.append(raw.decode("ascii").lower().encode("ascii"))
        except UnicodeDecodeError as exc:
            raise ReviewError(
                "invalid_name",
                f"{where}：名称标签含非 ASCII 字节: {exc}",
                422,
            ) from exc
        pos += length

    wire = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    text = (".".join(label.decode("ascii") for label in labels) + ".") \
        if labels else "."
    try:
        validate_name(text)
    except ZoneParseError as exc:
        raise ReviewError(
            "invalid_name", f"{where}：名称非法: {exc}", 422
        ) from exc
    return _ParsedName(text=text, wire=wire), (end if end is not None else pos)


def _parse_tsig_rdata(
    msg: bytes, start: int, end: int, message_id: int, where: str
) -> dict:
    """解析 TSIG RDATA（RFC 2845 Appendix A），返回字段字典。"""
    pos = start
    algorithm, pos = _read_name(msg, pos, f"{where} algorithm")
    fixed = end - pos
    # time_high(2) time_low(4) fudge(2) mac_size(2)，随后 mac，
    # original_id(2) error(2) other_len(2)，随后 other
    if fixed < 16:
        raise ReviewError(
            "tsig_rdata_truncated",
            f"{where}：TSIG 定长字段不足（剩余 {fixed} 字节，至少 16）",
            422,
        )
    time_high, time_low, fudge, mac_size = struct.unpack(
        "!HIHH", msg[pos : pos + 10]
    )
    pos += 10
    if pos + mac_size + 6 > end:
        raise ReviewError(
            "tsig_rdata_truncated",
            f"{where}：MAC（{mac_size} 字节）超出 RDATA 末尾",
            422,
        )
    mac = msg[pos : pos + mac_size]
    pos += mac_size
    original_id, error, other_len = struct.unpack(
        "!HHH", msg[pos : pos + 6]
    )
    pos += 6
    if pos + other_len > end:
        raise ReviewError(
            "tsig_rdata_truncated",
            f"{where}：Other Data（{other_len} 字节）超出 RDATA 末尾",
            422,
        )
    other = msg[pos : pos + other_len]
    pos += other_len
    if pos != end:
        raise ReviewError(
            "tsig_rdata_truncated",
            f"{where}：RDATA 解析结束位置与 RDLENGTH 不符",
            422,
        )
    return {
        "algorithm": algorithm,
        "time_high": time_high,
        "time_low": time_low,
        "fudge": fudge,
        "mac": mac,
        "original_id": original_id,
        "error": error,
        "other": other,
    }


def parse_message(msg: bytes) -> _TsigRecord:
    """解析报文并定位、校验唯一的末尾 TSIG RR（结构不符即 422）。"""
    if len(msg) < 12:
        raise ReviewError(
            "message_truncated",
            f"DNS 头不足 12 字节（实际 {len(msg)} 字节）",
            422,
        )
    message_id, _flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", msg[:12]
    )
    pos = 12

    def skip_record(section: str, index: int) -> int:
        nonlocal pos
        where = f"{section}第 {index} 条记录"
        _, pos = _read_name(msg, pos, where)
        if pos + 10 > len(msg):
            raise ReviewError(
                "message_truncated", f"{where}：记录头截断", 422
            )
        _rtype, _rclass, _ttl, rdlength = struct.unpack(
            "!HHIH", msg[pos : pos + 10]
        )
        pos += 10
        if pos + rdlength > len(msg):
            raise ReviewError(
                "message_truncated", f"{where}：RDATA 超出报文末尾", 422
            )
        return pos + rdlength

    for i in range(1, qdcount + 1):
        _, pos = _read_name(msg, pos, f"问题区第 {i} 个问题")
        if pos + 4 > len(msg):
            raise ReviewError(
                "message_truncated",
                f"问题区第 {i} 个问题的 QTYPE/QCLASS 截断",
                422,
            )
        pos += 4
    for i in range(1, ancount + 1):
        pos = skip_record("回答区", i)
    for i in range(1, nscount + 1):
        pos = skip_record("授权区", i)

    tsig: _TsigRecord | None = None
    for i in range(1, arcount + 1):
        record_start = pos
        _, after_name = _read_name(msg, pos, f"附加区第 {i} 条记录")
        if after_name + 10 > len(msg):
            raise ReviewError(
                "message_truncated",
                f"附加区第 {i} 条记录：记录头截断",
                422,
            )
        rtype, rclass, ttl, rdlength = struct.unpack(
            "!HHIH", msg[after_name : after_name + 10]
        )
        rdata_start = after_name + 10
        rdata_end = rdata_start + rdlength
        if rdata_end > len(msg):
            raise ReviewError(
                "message_truncated",
                f"附加区第 {i} 条记录：RDATA 超出报文末尾",
                422,
            )
        if rtype == TYPE_TSIG:
            if i != arcount:
                raise ReviewError(
                    "tsig_not_unique",
                    "TSIG 必须是附加区唯一且最末的记录：第 "
                    f"{i}/{arcount} 条记录为 TSIG，其后仍有记录",
                    422,
                )
            if rclass != CLASS_ANY:
                raise ReviewError(
                    "tsig_bad_class",
                    f"TSIG 的 CLASS 必须为 ANY（255），实际为 {rclass}",
                    422,
                )
            if ttl != 0:
                raise ReviewError(
                    "tsig_bad_ttl",
                    f"TSIG 的 TTL 必须为 0，实际为 {ttl}",
                    422,
                )
            key, _ = _read_name(msg, record_start, "TSIG key name")
            fields = _parse_tsig_rdata(
                msg, rdata_start, rdata_end, message_id, "TSIG"
            )
            if fields["original_id"] != message_id:
                raise ReviewError(
                    "original_id_mismatch",
                    "TSIG Original ID "
                    f"{fields['original_id']} 不等于报文 ID {message_id}",
                    422,
                )
            tsig = _TsigRecord(
                start=record_start,
                end=rdata_end,
                rdata_start=rdata_start,
                arcount=arcount,
                message_id=message_id,
                key=key,
                **fields,
            )
        pos = rdata_end

    if tsig is None:
        raise ReviewError(
            "tsig_not_found",
            "附加区末尾不存在 TSIG 记录"
            + ("（附加区为空）" if arcount == 0 else ""),
            422,
        )
    if pos != len(msg):
        raise ReviewError(
            "trailing_bytes",
            f"记录区结束后仍有 {len(msg) - pos} 个多余字节",
            422,
        )
    return tsig


# ---------------------------------------------------------------------------
# MAC 计算（RFC 2845 §2.2，RFC 4635 算法）
# ---------------------------------------------------------------------------

def _compute_mac(
    secret: bytes,
    msg: bytes,
    tsig: _TsigRecord,
    digest_name: str,
    request_mac: bytes | None,
) -> bytes:
    """按 RFC 2845 §3.4 计算 TSIG MAC。

    摘要输入依次为（连续字节流、无填充）：

    1. 可选的请求 MAC：``MAC Length``（2 字节）+ ``MAC Data``（§3.4.3）；
    2. **DNS Message**（§3.4.1）：整条 TSIG RR 移除、ARCOUNT 减 1 后的
       完整报文；报文头 ID 若与 Original ID 不同则替换为 Original ID；
    3. **TSIG Variables**（§3.4.2）：密钥名（规范 wire）、CLASS（ANY）、
       TTL（0）、算法名（规范 wire）、Time Signed（48 位）、Fudge、
       Error、Other Len、Other Data。

    RDLENGTH、MAC Size/MAC 与 Original ID 不单独进变量表（Original ID
    已作为报文头 ID 代入；见 §3.4.2 末两段）。密钥名与算法名一律按小写、
    无压缩的规范 wire 名称编码（RFC 2535 §6.2）。
    """
    # 2) DNS Message：移除 TSIG、ARCOUNT 减 1，ID 替换为 Original ID
    dns_message = (
        struct.pack("!H", tsig.original_id)
        + msg[2:10]
        + struct.pack("!H", tsig.arcount - 1)
        + msg[12 : tsig.start]
    )
    # 3) TSIG Variables
    variables = (
        tsig.key.wire
        + struct.pack("!HI", CLASS_ANY, 0)
        + tsig.algorithm.wire
        + struct.pack(
            "!HIHH",
            tsig.time_high,
            tsig.time_low,
            tsig.fudge,
            tsig.error,
        )
        + struct.pack("!H", len(tsig.other))
        + tsig.other
    )
    data = dns_message + variables
    # 1) 续传（响应）时最前面前置 request_mac 的 2 字节长度与内容
    if request_mac is not None:
        data = struct.pack("!H", len(request_mac)) + request_mac + data
    return hmac.new(secret, data, digest_name).digest()


# ---------------------------------------------------------------------------
# 请求解析与对外入口
# ---------------------------------------------------------------------------

def _decode_base64(value, field: str) -> bytes:
    if not isinstance(value, str):
        raise ReviewError(
            "invalid_request", f"{field} 必须是 Base64 字符串", 400
        )
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ReviewError(
            "invalid_request", f"{field} 不是合法 Base64: {exc}", 400
        ) from exc


def _canonical_name_wire(name: str) -> bytes:
    if name != ".":
        labels = [
            label.encode("ascii").lower() for label in name[:-1].split(".")
        ]
    else:
        labels = []
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"


def verify_tsig(payload: dict) -> dict:
    """验证一条带 TSIG 的 DNS 报文，返回可直接序列化的结果字典。"""
    if not isinstance(payload, dict):
        raise ReviewError("invalid_request", "请求体必须是 JSON 对象", 400)

    msg = _decode_base64(payload.get("message"), "message")
    secret = _decode_base64(payload.get("shared_secret"), "shared_secret")
    if not secret:
        raise ReviewError(
            "invalid_request", "shared_secret 解码后不得为空", 400
        )
    key_name = payload.get("key_name")
    if not isinstance(key_name, str) or not key_name.strip():
        raise ReviewError(
            "invalid_request", "key_name 必须是非空字符串", 400
        )
    key_name = key_name.strip().lower()
    if not key_name.endswith("."):
        key_name += "."
    try:
        validate_name(key_name)
    except ZoneParseError as exc:
        raise ReviewError(
            "invalid_request", f"key_name 非法: {exc}", 400
        ) from exc
    now = payload.get("now")
    if not isinstance(now, int) or isinstance(now, bool) or not 0 <= now <= _MAX_UINT48:
        raise ReviewError(
            "invalid_request",
            "now 必须是 0..2^48-1 的 Unix 秒整数",
            400,
        )
    request_mac: bytes | None = None
    if "request_mac" in payload and payload["request_mac"] is not None:
        request_mac = _decode_base64(payload["request_mac"], "request_mac")
        if len(request_mac) > 0xFFFF:
            raise ReviewError(
                "invalid_request",
                "request_mac 解码后不得超过 65535 字节",
                400,
            )

    tsig = parse_message(msg)

    info = {
        "message_id": tsig.message_id,
        "original_id": tsig.original_id,
        "arcount": tsig.arcount,
        "key_name": tsig.key.text,
        "algorithm": tsig.algorithm.text,
        "mac_size": len(tsig.mac),
        "time_signed": tsig.time_signed,
        "time_high": tsig.time_high,
        "time_low": tsig.time_low,
        "fudge": tsig.fudge,
        "tsig_error": tsig.error,
        "other_length": len(tsig.other),
        "request_mac_size": (
            len(request_mac) if request_mac is not None else None
        ),
        "now": now,
    }
    trace: list[dict] = []

    def finish(status: str, authenticated: bool) -> dict:
        result = {
            "status": status,
            "authenticated": authenticated,
            "trace": trace,
        }
        result.update(info)
        return result

    # ---- 1) 密钥名（规范 wire 形式常量时间比较） ----
    expected_key_wire = _canonical_name_wire(key_name)
    key_ok = hmac.compare_digest(tsig.key.wire, expected_key_wire)
    trace.append(
        {
            "check": "key_name",
            "valid": key_ok,
            "expected": key_name,
            "provided": tsig.key.text,
        }
    )
    if not key_ok:
        return finish("badkey", False)

    # ---- 2) 算法 ----
    alg_spec = ALGORITHMS.get(tsig.algorithm.text)
    alg_ok = alg_spec is not None
    trace.append(
        {
            "check": "algorithm",
            "valid": alg_ok,
            "provided": tsig.algorithm.text,
            "supported": sorted(ALGORITHMS),
        }
    )
    if not alg_ok:
        return finish("badalg", False)
    digest_name, digest_size = alg_spec

    # ---- 3) MAC（常量时间比较；只记录长度，绝不回传 MAC） ----
    computed = _compute_mac(secret, msg, tsig, digest_name, request_mac)
    mac_ok = (
        len(tsig.mac) == digest_size
        and hmac.compare_digest(tsig.mac, computed)
    )
    trace.append(
        {
            "check": "mac",
            "valid": mac_ok,
            "mac_size": len(tsig.mac),
            "expected_mac_size": digest_size,
            "computed_mac_size": len(computed),
        }
    )
    if not mac_ok:
        return finish("badsig", False)

    # ---- 4) 时间窗：|now - Time Signed| <= Fudge ----
    skew = abs(now - tsig.time_signed)
    time_ok = skew <= tsig.fudge
    trace.append(
        {
            "check": "time_window",
            "valid": time_ok,
            "now": now,
            "time_signed": tsig.time_signed,
            "fudge": tsig.fudge,
            "skew_seconds": skew,
        }
    )
    if not time_ok:
        # badtime 附 48 位时间（高位/低位拆分同时给出）
        return finish("badtime", False)

    return finish("authenticated", True)


def sign_message(
    msg: bytes,
    key_name: str,
    secret: bytes,
    now: int,
    fudge: int = 300,
    algorithm: str = "hmac-sha256.",
    request_mac: bytes | None = None,
    error: int = 0,
    other: bytes = b"",
) -> bytes:
    """离线辅助：给一条不含 TSIG 的报文追加规范 TSIG RR（供测试/示例）。"""
    if len(msg) < 12:
        raise ValueError("message too short")
    _mid, _flags, _qd, _an, _ns, arcount = struct.unpack("!HHHHHH", msg[:12])
    key_wire = _canonical_name_wire(key_name)
    algo_wire = _canonical_name_wire(algorithm)
    digest_name, digest_size = ALGORITHMS[algorithm]
    time_high, time_low = (now >> 32) & 0xFFFF, now & 0xFFFFFFFF
    rdata_before_mac = (
        algo_wire
        + struct.pack("!HIHH", time_high, time_low, fudge, digest_size)
    )
    rdata_after_mac = struct.pack("!HHH", _mid, error, len(other)) + other
    placeholder = _TsigRecord(
        start=len(msg),
        end=0,
        rdata_start=0,
        arcount=arcount + 1,
        message_id=_mid,
        key=_ParsedName(text=key_name, wire=key_wire),
        algorithm=_ParsedName(text=algorithm, wire=algo_wire),
        time_high=time_high,
        time_low=time_low,
        fudge=fudge,
        mac=b"\x00" * digest_size,
        original_id=_mid,
        error=error,
        other=other,
    )
    mac = _compute_mac(secret, msg, placeholder, digest_name, request_mac)
    rr = (
        key_wire
        + struct.pack(
            "!HHIH",
            TYPE_TSIG,
            CLASS_ANY,
            0,
            len(rdata_before_mac) + digest_size + len(rdata_after_mac),
        )
        + rdata_before_mac
        + mac
        + rdata_after_mac
    )
    return (
        msg[:10]
        + struct.pack("!H", arcount + 1)
        + msg[12:]
        + rr
    )


__all__ = ["verify_tsig", "sign_message"]
