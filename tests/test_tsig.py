"""离线 TSIG（RFC 2845 / RFC 4635）验证测试。

MAC 构造已与 dnspython 双向交叉验证（外部环境，不在本测试套件依赖中）；
本套件用 :func:`app.tsig.sign_message` 离线构造规范报文，覆盖成功、四类
验证终态与全部 422 报文结构错误。
"""

import base64
import struct
import unittest

from app.review import ReviewError
from app.tsig import sign_message, verify_tsig


def _qname(name: str) -> bytes:
    return b"".join(
        bytes([len(label)]) + label.encode()
        for label in name.strip(".").split(".")
    ) + b"\x00"


def _query(message_id: int = 0x1234, name: str = "host.example.com.") -> bytes:
    return (
        struct.pack("!HHHHHH", message_id, 0x0100, 1, 0, 0, 0)
        + _qname(name)
        + struct.pack("!HH", 1, 1)
    )


SECRET = b"shared-secret"
KEY = "key.example.com."
NOW = 1700000000


def _payload(msg: bytes, **overrides) -> dict:
    payload = {
        "message": base64.b64encode(msg).decode(),
        "shared_secret": base64.b64encode(SECRET).decode(),
        "key_name": KEY,
        "now": NOW,
    }
    payload.update(overrides)
    return payload


def _signed(algorithm: str = "hmac-sha256.", **sign_kw) -> bytes:
    return sign_message(
        _query(), KEY, SECRET, NOW, fudge=300, algorithm=algorithm, **sign_kw
    )


class TsigSuccessTests(unittest.TestCase):
    def test_hmac_sha256_authenticated(self):
        result = verify_tsig(_payload(_signed()))
        self.assertEqual(result["status"], "authenticated")
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["mac_size"], 32)
        self.assertEqual(result["algorithm"], "hmac-sha256.")
        self.assertEqual([t["check"] for t in result["trace"]],
                         ["key_name", "algorithm", "mac", "time_window"])
        self.assertTrue(all(t["valid"] for t in result["trace"]))

    def test_hmac_sha512_authenticated(self):
        msg = _signed(algorithm="hmac-sha512.")
        result = verify_tsig(_payload(msg))
        self.assertEqual(result["status"], "authenticated")
        self.assertEqual(result["mac_size"], 64)

    def test_key_name_case_insensitive(self):
        result = verify_tsig(_payload(_signed(), key_name="KEY.Example.COM"))
        self.assertEqual(result["status"], "authenticated")
        self.assertEqual(result["key_name"], KEY)

    def test_key_name_without_trailing_dot(self):
        result = verify_tsig(_payload(_signed(), key_name="key.example.com"))
        self.assertEqual(result["status"], "authenticated")

    def test_time_window_boundary_is_valid(self):
        for offset in (-300, 0, 300):
            with self.subTest(offset=offset):
                result = verify_tsig(_payload(_signed(), now=NOW + offset))
                self.assertEqual(result["status"], "authenticated")

    def test_request_mac_chaining(self):
        request_mac = b"a" * 32
        msg = _signed(request_mac=request_mac)
        result = verify_tsig(
            _payload(msg, request_mac=base64.b64encode(request_mac).decode())
        )
        self.assertEqual(result["status"], "authenticated")
        self.assertEqual(result["request_mac_size"], 32)

    def test_trace_never_leaks_secret_or_mac(self):
        result = verify_tsig(_payload(_signed()))
        dumped = repr(result)
        self.assertNotIn(SECRET.decode(), dumped)
        # MAC 本身绝不出现（只给出长度）
        self.assertNotIn("mac\"", dumped.replace("mac_size", ""))

    def test_arcount_decrement_visible(self):
        result = verify_tsig(_payload(_signed()))
        self.assertEqual(result["arcount"], 1)


class TsigFailureTests(unittest.TestCase):
    def _fail(self, status, trace_len, **overrides):
        result = verify_tsig(_payload(_signed(), **overrides))
        self.assertEqual(result["status"], status)
        self.assertFalse(result["authenticated"])
        self.assertEqual(len(result["trace"]), trace_len)
        return result

    def test_badkey(self):
        result = self._fail("badkey", 1, key_name="other.example.")
        self.assertFalse(result["trace"][0]["valid"])

    def test_badalg(self):
        msg = bytearray(_signed(algorithm="hmac-sha512."))
        idx = bytes(msg).find(b"\x0bhmac-sha512\x00")
        self.assertGreaterEqual(idx, 0)
        msg[idx + 1 : idx + 12] = b"hmac-sha999"  # 11 字节合法标签
        result = self._fail("badalg", 2, message=base64.b64encode(bytes(msg)).decode())
        self.assertEqual(result["algorithm"], "hmac-sha999.")
        self.assertFalse(result["trace"][1]["valid"])

    def test_badsig_wrong_secret(self):
        result = self._fail(
            "badsig", 3, shared_secret=base64.b64encode(b"wrong").decode()
        )
        self.assertFalse(result["trace"][2]["valid"])

    def test_badsig_tampered_message(self):
        msg = bytearray(_signed())
        msg[15] ^= 0x01  # 翻转问题区一个比特
        result = self._fail(
            "badsig", 3, message=base64.b64encode(bytes(msg)).decode()
        )

    def test_badsig_wrong_mac_size(self):
        # 手工构造 MAC 长度为 16 的 TSIG（sha256 期望 32），结构合法
        import hmac as _hmac
        from app.tsig import _canonical_name_wire

        key_wire = _canonical_name_wire(KEY)
        algo_wire = _canonical_name_wire("hmac-sha256.")
        rdata = (
            algo_wire
            + struct.pack("!HIHH", 0, NOW, 300, 16)
            + b"\x11" * 16
            + struct.pack("!HHH", 0x1234, 0, 0)
        )
        rr = (
            key_wire
            + struct.pack("!HHIH", 250, 255, 0, len(rdata))
            + rdata
        )
        msg = _query() + rr
        msg = msg[:10] + struct.pack("!H", 1) + msg[12:]
        result = verify_tsig(_payload(msg))
        self.assertEqual(result["status"], "badsig")
        self.assertEqual(result["mac_size"], 16)
        self.assertEqual(result["trace"][2]["expected_mac_size"], 32)

    def test_badsig_missing_request_mac(self):
        request_mac = b"a" * 32
        msg = _signed(request_mac=request_mac)
        self._fail("badsig", 3, message=base64.b64encode(msg).decode())

    def test_badtime_outside_window(self):
        result = self._fail("badtime", 4, now=NOW + 301)
        # badtime 附 48 位时间
        self.assertEqual(result["time_signed"], NOW)
        self.assertEqual(result["time_high"], 0)
        self.assertEqual(result["time_low"], NOW)
        self.assertEqual(result["fudge"], 300)
        self.assertEqual(result["trace"][3]["skew_seconds"], 301)

    def test_badtime_future_with_high_bits(self):
        now = (1 << 40) + NOW
        msg = sign_message(_query(), KEY, SECRET, now, fudge=10)
        result = verify_tsig(_payload(msg, now=now + 11))
        self.assertEqual(result["status"], "badtime")
        self.assertEqual(result["time_high"], 1 << 8)
        self.assertEqual(result["time_low"], NOW)
        self.assertEqual(result["time_signed"], now)

    def test_check_order_key_before_algorithm(self):
        # 密钥名错误时即使算法也不支持，也只报 badkey
        msg = bytearray(_signed(algorithm="hmac-sha512."))
        idx = bytes(msg).find(b"\x0bhmac-sha512\x00")
        msg[idx + 1 : idx + 12] = b"hmac-sha999"
        result = verify_tsig(
            _payload(bytes(msg), key_name="other.example.")
        )
        self.assertEqual(result["status"], "badkey")
        self.assertEqual(len(result["trace"]), 1)


class TsigStructureTests(unittest.TestCase):
    def _expect_422(self, code, msg, **overrides):
        with self.assertRaises(ReviewError) as ctx:
            verify_tsig(_payload(msg, **overrides))
        self.assertEqual(ctx.exception.status, 422)
        self.assertEqual(ctx.exception.code, code)

    def test_header_truncated(self):
        self._expect_422("message_truncated", b"\x00" * 11)

    def test_body_truncated(self):
        self._expect_422("message_truncated", _signed()[:-1])

    def test_question_truncated(self):
        q = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x04host"
        self._expect_422("message_truncated", q)

    def test_trailing_bytes(self):
        self._expect_422("trailing_bytes", _signed() + b"\x00")

    def test_no_tsig(self):
        self._expect_422("tsig_not_found", _query())

    def test_tsig_not_last(self):
        extra = _qname("opt.") + struct.pack("!HHIH", 41, 0, 0, 0)
        msg = _signed() + extra
        msg = msg[:10] + struct.pack("!H", 2) + msg[12:]
        self._expect_422("tsig_not_unique", msg)

    def test_tsig_bad_class(self):
        msg = bytearray(_signed())
        idx = bytes(msg).find(struct.pack("!HHI", 250, 255, 0))
        msg[idx + 2 : idx + 4] = struct.pack("!H", 1)
        self._expect_422("tsig_bad_class", bytes(msg))

    def test_tsig_bad_ttl(self):
        msg = bytearray(_signed())
        idx = bytes(msg).find(struct.pack("!HHI", 250, 255, 0))
        msg[idx + 4 : idx + 8] = struct.pack("!I", 60)
        self._expect_422("tsig_bad_ttl", bytes(msg))

    def test_original_id_mismatch(self):
        msg = bytearray(_signed())
        msg[0:2] = b"\x99\x99"
        self._expect_422("original_id_mismatch", bytes(msg))

    def test_compression_pointer_out_of_bounds(self):
        bad = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\xff"
        self._expect_422("compression_pointer_out_of_bounds", bad)

    def test_compression_pointer_loop(self):
        bad = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c"
        self._expect_422("compression_pointer_loop", bad)

    def test_compressed_names_are_supported(self):
        # 密钥名取问题名 host.example.com.，把 TSIG owner 改写为指向
        # 偏移 12（问题区 QNAME）的压缩指针；解析出的规范名称不变，
        # MAC 仍应验证通过。
        ckey = "host.example.com."
        q = _query()
        msg = bytearray(sign_message(q, ckey, SECRET, NOW, fudge=300))
        owner = _qname(ckey)
        tsig_offset = len(q)
        msg[tsig_offset : tsig_offset + len(owner)] = b"\xc0\x0c"
        result = verify_tsig(_payload(
            bytes(msg), key_name=ckey,
        ))
        self.assertEqual(result["status"], "authenticated")
        self.assertEqual(result["key_name"], "host.example.com.")

    def test_tsig_rdata_truncated(self):
        msg = _signed()[:-3]
        self._expect_422("message_truncated", msg)

    def test_other_data_length_truncated(self):
        # RDLENGTH 声称的 Other Data 超过报文末尾
        msg = bytearray(_signed())
        # 找到 other len 字段（固定为 0x0000，在 rdata 末尾 8..6 字节之间）
        # 定位 TSIG RR：把 RDLENGTH 加 1
        key_wire = _qname(KEY)
        # RR 起点 = 查询长度；RDLENGTH 在 owner + 8 字节处
        rr = len(_query())
        rdl_off = rr + len(key_wire) + 8
        rdlength = struct.unpack("!H", msg[rdl_off : rdl_off + 2])[0]
        msg[rdl_off : rdl_off + 2] = struct.pack("!H", rdlength + 1)
        self._expect_422("message_truncated", bytes(msg))


class TsigRequestValidationTests(unittest.TestCase):
    def _expect_400(self, payload):
        with self.assertRaises(ReviewError) as ctx:
            verify_tsig(payload)
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.code, "invalid_request")

    def test_missing_fields(self):
        self._expect_400({})
        self._expect_400({"message": "AA=="})

    def test_bad_base64(self):
        self._expect_400(
            {"message": "not base64!!", "shared_secret": "AA==",
             "key_name": "k.", "now": 1}
        )

    def test_empty_secret(self):
        self._expect_400(
            {"message": base64.b64encode(_signed()).decode(),
             "shared_secret": "", "key_name": "k.", "now": 1}
        )

    def test_bad_key_name(self):
        msg = base64.b64encode(_signed()).decode()
        sec = base64.b64encode(SECRET).decode()
        self._expect_400({"message": msg, "shared_secret": sec,
                          "key_name": "", "now": 1})
        self._expect_400({"message": msg, "shared_secret": sec,
                          "key_name": "bad label.", "now": 1})

    def test_bad_now(self):
        msg = base64.b64encode(_signed()).decode()
        sec = base64.b64encode(SECRET).decode()
        self._expect_400({"message": msg, "shared_secret": sec,
                          "key_name": KEY, "now": -1})
        self._expect_400({"message": msg, "shared_secret": sec,
                          "key_name": KEY, "now": "now"})
        self._expect_400({"message": msg, "shared_secret": sec,
                          "key_name": KEY, "now": True})

    def test_oversized_request_mac(self):
        self._expect_400(
            _payload(_signed(),
                     request_mac=base64.b64encode(b"\x00" * 65536).decode())
        )


if __name__ == "__main__":
    unittest.main()
