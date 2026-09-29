"""离线 TSIG（RFC 8945，取代 RFC 2845）报文校验。

不发起任何真实 DNS 查询：输入 Base64 编码的单个 DNS 报文（``message``）、
共享密钥（``secret``）、密钥名（``key_name``）与当前时间（``now``，
Unix 秒），可选地在核对**响应**报文时给出对应请求的
``request_mac``（Base64），按 RFC 8945 §5 离线验证 TSIG。

结构要求（任一不符均为 ``422``）：

- 报文中 TSIG（TYPE=250）必须**恰好出现一次**，且位于**附加区末尾**
  （``missing_tsig`` / ``multiple_tsig`` / ``tsig_not_last`` /
  ``tsig_wrong_section``）；
- TSIG 的 CLASS 必须为 ANY（255）、TTL 必须为 0
  （``tsig_bad_class`` / ``tsig_bad_ttl``）；
- TSIG RDATA 中的 Original ID 必须等于报文头 ID
  （``tsig_original_id_mismatch``）；
- 报文/各区/TSIG RDATA 截断（``message_truncated``）、压缩指针越界
  （``compression_pointer_out_of_bounds``）或成环
  （``compression_pointer_loop``）、非法名称（``invalid_name``）。

MAC 计算（RFC 8945 §5.2，HMAC 密钥为共享密钥的规范字节编码）：

1. 从原报文中**移除 TSIG RR**（TSIG 在附加区末尾，即截断到其起始偏移），
   并把头中的 ARCOUNT **减一**，得到“已签名报文”；
2. 核对响应且提供 ``request_mac`` 时，前置 2 字节长度 + request MAC；
3. 拼接规范编码的 TSIG 变量：Original ID（2 字节）、算法名（小写、
   不压缩的规范 wire 域名）、Time Signed（48 位/6 字节）、Fudge
   （2 字节）、MAC Size（2 字节，取 RDATA 中的 MAC 长度但**不含 MAC
   本身**）、Error（2 字节）、Other Len（2 字节）+ Other；
4. 支持 ``hmac-sha256``（32 字节）与 ``hmac-sha512``（64 字节）。

依次核对：密钥名（``badkey``）→ 算法（``badalg``）→ MAC
（``badsig``，恒用 :func:`hmac.compare_digest` 比较）→ 时间窗
（``badtime``，``|now - time_signed| > fudge``）。``badtime`` 响应附
48 位服务器时间（``server_time`` / ``server_time_hex``）。

``authenticated`` 与四种否定结论都是 HTTP 200 下的校验终态；只有请求
格式错误（400）与报文结构错误（422）走错误响应。成功轨迹只包含
密钥名/算法/长度等非敏感信息，**绝不回显共享密钥或其等价形式**。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct

from .review import ReviewError
from .zoneparse import ZoneParseError, validate_name

TYPE_TSIG = 250
CLASS_ANY = 255

# RFC 4635 算法名（wire 上为单标签根下绝对名）-> (hash 名, 摘要长度)
ALGORITHMS = {
    "hmac-sha256.": ("sha256", hashlib.sha256().digest_size),
    "hmac-sha512.": ("sha512", hashlib.sha512().digest_size),
}


# ---------------------------------------------------------------------------
# 名称读取（RFC 1035 §4.1.4，与 app.axfr 同一套压缩规则）
# ---------------------------------------------------------------------------

def _read_name(message: bytes, offset: int, where: str) -> tuple[str, int]:
    """在 ``offset`` 处读取一个（可压缩的）域名，返回 (小写绝对名, 下一偏移)。"""
    labels: list[str] = []
    pos = offset
    end: int | None = None
    visited: set[int] = set()
    while True:
        if pos >= len(message):
            raise ReviewError(
                "message_truncated", f"{where}：名称超出报文末尾", 422
            )
        length = message[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(message):
                raise ReviewError(
                    "message_truncated", f"{where}：压缩指针只有半个字节", 422
                )
            target = ((length & 0x3F) << 8) | message[pos + 1]
            if target >= len(message):
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
                "invalid_name", f"{where}：非法标签类型字节 0x{length:02x}",
                422,
            )
        pos += 1
        if length == 0:
            break
        if pos + length > len(message):
            raise ReviewError(
                "message_truncated", f"{where}：标签超出报文末尾", 422
            )
        raw = message[pos : pos + length]
        try:
            labels.append(raw.decode("ascii").lower())
        except UnicodeDecodeError as exc:
            raise ReviewError(
                "invalid_name", f"{where}：名称标签含非 ASCII 字节: {exc}",
                422,
            ) from exc
        pos += length
    name = (".".join(labels) + ".") if labels else "."
    try:
        validate_name(name)
    except ZoneParseError as exc:
        raise ReviewError(
            "invalid_name", f"{where}：名称非法: {exc}", 422
        ) from exc
    return name, (end if end is not None else pos)


def _wire_name(name: str) -> bytes:
    """小写绝对名 -> 规范 wire（不压缩；RFC 4034 §6.1 的名称编码）。"""
    if name == ".":
        return b"\x00"
    out = bytearray()
    for label in name[:-1].split("."):
        raw = label.encode("ascii")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


# ---------------------------------------------------------------------------
# 报文结构解析
# ---------------------------------------------------------------------------

def _skip_rr(message: bytes, pos: int, where: str) -> tuple[int, int, int, int,
                                                            int, str, int]:
    """跳过一条资源记录。

    返回 ``(下一偏移, type, class, ttl, rdlength, owner, rdata 起始偏移)``。
    """
    owner, pos = _read_name(message, pos, where)
    if pos + 10 > len(message):
        raise ReviewError(
            "message_truncated", f"{where}：记录头截断", 422
        )
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", message[pos : pos + 10])
    rdata_start = pos + 10
    pos += 10
    if ttl > 2**31 - 1:
        raise ReviewError(
            "invalid_record", f"{where}：TTL {ttl} 超出 31 位范围", 422
        )
    if pos + rdlength > len(message):
        raise ReviewError(
            "message_truncated", f"{where}：RDATA 超出报文末尾", 422
        )
    return (
        pos + rdlength, rtype, rclass, ttl, rdlength, owner, rdata_start
    )


def _parse_tsig_rdata(
    message: bytes, start: int, rdlength: int, where: str
) -> dict:
    """解析 TSIG RDATA（RFC 8945 §3），任一字段截断均为 422。"""
    end = start + rdlength
    algorithm, pos = _read_name(message, start, f"{where} 算法名")
    # time signed(6) + fudge(2) + mac size(2) 共 10 字节
    if pos + 10 > end:
        raise ReviewError(
            "message_truncated", f"{where}：TSIG 时间/模糊度/MAC 长度截断", 422
        )
    time_hi, time_lo, fudge, mac_size = struct.unpack(
        "!HIHH", message[pos : pos + 10]
    )
    time_signed = (time_hi << 32) | time_lo
    pos += 10
    if pos + mac_size > end:
        raise ReviewError(
            "message_truncated", f"{where}：TSIG MAC 超出 RDATA 末尾", 422
        )
    mac = message[pos : pos + mac_size]
    pos += mac_size
    # original id(2) + error(2) + other len(2)
    if pos + 6 > end:
        raise ReviewError(
            "message_truncated", f"{where}：TSIG Original ID/Error/Other 截断",
            422,
        )
    original_id, error, other_len = struct.unpack(
        "!HHH", message[pos : pos + 6]
    )
    pos += 6
    if pos + other_len != end:
        raise ReviewError(
            "message_truncated",
            f"{where}：TSIG Other 长度（{other_len}）未恰好占满 RDATA",
            422,
        )
    other = message[pos : pos + other_len]
    return {
        "algorithm": algorithm,
        "time_signed": time_signed,
        "fudge": fudge,
        "mac": mac,
        "original_id": original_id,
        "error": error,
        "other": other,
    }


def _parse_message(message: bytes) -> dict:
    """解析 DNS 头与四个区，定位唯一且位于附加区末尾的 TSIG。"""
    if len(message) < 12:
        raise ReviewError(
            "message_truncated",
            f"DNS 头不足 12 字节（实际 {len(message)} 字节）",
            422,
        )
    message_id, _flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", message[:12]
    )

    pos = 12
    for i in range(1, qdcount + 1):
        _qname, pos = _read_name(message, pos, f"问题区第 {i} 项名称")
        if pos + 4 > len(message):
            raise ReviewError(
                "message_truncated", f"问题区第 {i} 项 QTYPE/QCLASS 截断", 422
            )
        pos += 4

    tsig_hits: list[dict] = []

    def scan(count: int, section: str) -> None:
        nonlocal pos
        for i in range(1, count + 1):
            rr_start = pos
            where = f"{section}第 {i} 条记录"
            after, rtype, rclass, ttl, rdlength, owner, rdata_start = _skip_rr(
                message, pos, where
            )
            if rtype == TYPE_TSIG:
                tsig_hits.append(
                    {
                        "section": section,
                        "index": i,
                        "count": count,
                        "start": rr_start,
                        "rdata_start": rdata_start,
                        "rclass": rclass,
                        "ttl": ttl,
                        "rdlength": rdlength,
                        "owner": owner,
                    }
                )
            pos = after

    scan(ancount, "回答区")
    scan(nscount, "授权区")
    scan(arcount, "附加区")

    if pos != len(message):
        raise ReviewError(
            "message_trailing_bytes",
            f"各区解析后仍有 {len(message) - pos} 个尾随字节",
            422,
        )

    if not tsig_hits:
        raise ReviewError("missing_tsig", "报文中不存在 TSIG 记录", 422)
    if len(tsig_hits) > 1:
        raise ReviewError(
            "multiple_tsig",
            f"报文中存在 {len(tsig_hits)} 条 TSIG 记录，必须恰好一条",
            422,
        )
    hit = tsig_hits[0]
    if hit["section"] != "附加区":
        raise ReviewError(
            "tsig_wrong_section",
            f"TSIG 必须位于附加区，实际位于{hit['section']}",
            422,
        )
    if hit["index"] != hit["count"]:
        raise ReviewError(
            "tsig_not_last",
            f"TSIG 必须是附加区最后一条记录（附加区共 {hit['count']} 条，"
            f"TSIG 为第 {hit['index']} 条）",
            422,
        )
    if hit["rclass"] != CLASS_ANY:
        raise ReviewError(
            "tsig_bad_class",
            f"TSIG CLASS 必须为 ANY（{CLASS_ANY}），实际为 {hit['rclass']}",
            422,
        )
    if hit["ttl"] != 0:
        raise ReviewError(
            "tsig_bad_ttl", f"TSIG TTL 必须为 0，实际为 {hit['ttl']}", 422
        )

    rdata = _parse_tsig_rdata(
        message,
        hit["rdata_start"],
        hit["rdlength"],
        "TSIG",
    )
    if rdata["original_id"] != message_id:
        raise ReviewError(
            "tsig_original_id_mismatch",
            f"TSIG Original ID {rdata['original_id']} 与报文 ID "
            f"{message_id} 不一致",
            422,
        )

    return {
        "message_id": message_id,
        "arcount": arcount,
        "tsig_start": hit["start"],
        "key_name": hit["owner"],
        **rdata,
    }


# ---------------------------------------------------------------------------
# MAC 计算（RFC 8945 §5.2）
# ---------------------------------------------------------------------------

def _signed_message(message: bytes, tsig_start: int) -> bytes:
    """移除 TSIG RR 并把 ARCOUNT 减一（RFC 8945 §5.2 第 1/2 项）。"""
    if tsig_start < 12:
        raise ReviewError("missing_tsig", "TSIG 位置异常", 422)
    rebuilt = bytearray(message[:tsig_start])
    (arcount,) = struct.unpack("!H", bytes(rebuilt[10:12]))
    if arcount < 1:
        raise ReviewError(
            "missing_tsig", "附加区计数为 0 却出现 TSIG，报文非法", 422
        )
    struct.pack_into("!H", rebuilt, 10, arcount - 1)
    return bytes(rebuilt)


def _canonical_variables(parsed: dict, mac_size: int) -> bytes:
    """规范编码 TSIG 变量（Original ID/算法/时间/fudge/MAC 长度/error/other）。"""
    return b"".join((
        struct.pack("!H", parsed["original_id"]),
        _wire_name(parsed["algorithm"]),
        parsed["time_signed"].to_bytes(6, "big"),
        struct.pack("!H", parsed["fudge"]),
        struct.pack("!H", mac_size),
        struct.pack("!H", parsed["error"]),
        struct.pack("!H", len(parsed["other"])),
        parsed["other"],
    ))


def _compute_mac(
    message: bytes, parsed: dict, secret: bytes, hash_name: str,
    request_mac: bytes | None,
) -> bytes:
    data = _signed_message(message, parsed["tsig_start"])
    if request_mac is not None:
        # 响应：前置请求 MAC 的 2 字节长度与内容
        data += struct.pack("!H", len(request_mac)) + request_mac
    data += _canonical_variables(parsed, len(parsed["mac"]))
    return hmac.new(secret, data, hash_name).digest()


# ---------------------------------------------------------------------------
# 请求规范化
# ---------------------------------------------------------------------------

def _b64_field(payload: dict, field: str, required: bool, default=None):
    value = payload.get(field)
    if value is None:
        if required:
            raise ReviewError(
                "invalid_request", f"{field} 必须是 Base64 字符串", 400
            )
        return default
    if not isinstance(value, str):
        raise ReviewError(
            "invalid_request", f"{field} 必须是 Base64 字符串", 400
        )
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ReviewError(
            "invalid_request", f"{field} 不是合法 Base64: {exc}", 400
        ) from exc


def _normalize_key_name(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError(
            "invalid_request", "key_name 必须是非空域名", 400
        )
    name = value.strip().lower()
    if name != "." and not name.endswith("."):
        name += "."
    try:
        validate_name(name)
    except ZoneParseError as exc:
        raise ReviewError(
            "invalid_request", f"key_name 非法: {exc}", 400
        ) from exc
    return name


def _secret_bytes(payload: dict) -> bytes:
    secret = payload.get("secret")
    if not isinstance(secret, str) or secret == "":
        raise ReviewError(
            "invalid_request", "secret 必须是非空共享密钥字符串", 400
        )
    encoding = payload.get("secret_encoding", "utf8")
    if encoding not in ("utf8", "base64"):
        raise ReviewError(
            "invalid_request",
            "secret_encoding 仅支持 utf8（默认）或 base64",
            400,
        )
    if encoding == "utf8":
        return secret.encode("utf-8")
    try:
        key = base64.b64decode(secret, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ReviewError(
            "invalid_request", f"secret 不是合法 Base64: {exc}", 400
        ) from exc
    if not key:
        raise ReviewError(
            "invalid_request", "Base64 解码后的共享密钥为空", 400
        )
    return key


# ---------------------------------------------------------------------------
# 校验编排
# ---------------------------------------------------------------------------

def verify_tsig(payload: dict) -> dict:
    """校验一个携带 TSIG 的 Base64 DNS 报文，返回可序列化的结果字典。"""
    if not isinstance(payload, dict):
        raise ReviewError("invalid_request", "请求体必须是 JSON 对象", 400)

    message = _b64_field(payload, "message", required=True)
    expected_key = _normalize_key_name(payload.get("key_name"))
    secret = _secret_bytes(payload)

    now = payload.get("now")
    if isinstance(now, bool) or not isinstance(now, int) or not 0 <= now < 2**48:
        raise ReviewError(
            "invalid_request",
            f"now 必须是 0..2^48-1 的 Unix 秒整数，实际为 {now!r}",
            400,
        )
    request_mac = _b64_field(payload, "request_mac", required=False)

    parsed = _parse_message(message)

    trace: list[dict] = []

    def trace_step(step: str, check: str, ok: bool, detail: str) -> None:
        trace.append(
            {"step": step, "check": check, "result": "ok" if ok else "fail",
             "detail": detail}
        )

    trace_step(
        "message", "解析报文头与四个区", True,
        f"报文 {len(message)} 字节，ID={parsed['message_id']}，"
        f"ARCOUNT={parsed['arcount']}",
    )
    trace_step(
        "tsig", "TSIG 唯一且位于附加区末尾", True,
        f"TSIG owner={parsed['key_name']}，起始偏移 {parsed['tsig_start']}",
    )
    trace_step(
        "class_ttl", "TSIG CLASS=ANY、TTL=0", True,
        "CLASS=ANY(255)，TTL=0",
    )
    trace_step(
        "original_id", "Original ID 等于报文 ID", True,
        f"Original ID={parsed['original_id']}",
    )

    result = {
        "key_name": parsed["key_name"],
        "algorithm": parsed["algorithm"],
        "message_id": parsed["message_id"],
        "time_signed": parsed["time_signed"],
        "fudge": parsed["fudge"],
        "error": parsed["error"],
        "other_len": len(parsed["other"]),
        "mac_size": len(parsed["mac"]),
        "now": now,
        "request_mac_size": (
            len(request_mac) if request_mac is not None else None
        ),
        "trace": trace,
    }

    def finish(status: str, reason: str) -> dict:
        out = {"status": status, "reason": reason}
        out.update(result)
        trace.append(
            {"step": "result", "check": "校验结论",
             "result": status, "detail": reason}
        )
        return out

    # 1) 密钥名
    if parsed["key_name"] != expected_key:
        return finish(
            "badkey",
            f"TSIG 密钥名 {parsed['key_name']} 与期望的 {expected_key} 不符",
        )
    trace_step(
        "key", "密钥名匹配", True, f"密钥名 {expected_key} 匹配（不回显密钥）"
    )

    # 2) 算法
    alg_spec = ALGORITHMS.get(parsed["algorithm"])
    if alg_spec is None:
        return finish(
            "badalg",
            f"算法 {parsed['algorithm']} 不受支持，仅支持 "
            "hmac-sha256. 与 hmac-sha512.",
        )
    hash_name, digest_size = alg_spec
    trace_step(
        "algorithm", "算法受支持", True,
        f"{parsed['algorithm']}（{hash_name}，摘要 {digest_size} 字节）",
    )

    # 3) MAC（恒为定长比较；长度不符 compare_digest 也返回 False）
    computed = _compute_mac(message, parsed, secret, hash_name, request_mac)
    provided = parsed["mac"]
    mac_ok = len(provided) == digest_size and hmac.compare_digest(
        computed, provided
    )
    if not mac_ok:
        trace_step(
            "mac", "HMAC 比较", False,
            f"报文 MAC 长度 {len(provided)}、算法摘要长度 {digest_size}；"
            "compare_digest 不一致（不回显 MAC 与密钥）",
        )
        return finish("badsig", "TSIG MAC 校验失败")
    trace_step(
        "mac", "HMAC 比较", True,
        f"compare_digest 一致（{digest_size} 字节，不回显 MAC 与密钥）",
    )

    # 4) 时间窗
    delta = abs(now - parsed["time_signed"])
    if delta > parsed["fudge"]:
        result["server_time"] = now
        result["server_time_hex"] = f"{now:012x}"
        result["time_delta"] = delta
        trace_step(
            "time", "时间窗 |now - time_signed| <= fudge", False,
            f"|{now} - {parsed['time_signed']}| = {delta} > "
            f"fudge {parsed['fudge']}；附 48 位服务器时间",
        )
        return finish(
            "badtime",
            f"时间偏差 {delta} 秒超过 fudge {parsed['fudge']} 秒",
        )
    trace_step(
        "time", "时间窗 |now - time_signed| <= fudge", True,
        f"|{now} - {parsed['time_signed']}| = {delta} <= "
        f"fudge {parsed['fudge']}",
    )

    return finish(
        "authenticated",
        f"TSIG 校验通过：密钥名、算法、MAC（{digest_size} 字节）与时间窗"
        " 全部一致",
    )
