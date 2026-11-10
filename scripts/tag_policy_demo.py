"""
Demonstration of the explicit pure-Python tag admission policy.

Run with the project's Python environment, e.g. ``python scripts/tag_policy_demo.py``.

Shows:
  1. the conservative ``TagPolicy.safe()`` configuration that only admits basic
     CBOR data plus the self-describe tag (55799),
  2. how unknown tags survive as data (raw ``CBORTag``) instead of triggering a
     semantic conversion or an unauthorized custom handler,
  3. constructor/decoder/hook counters proving that rejected date, big-number
     and custom tags never undergo semantic conversion.
"""

from binascii import unhexlify
from datetime import datetime

import cbor2._decoder as decoder
from cbor2 import CBORDecodeError, CBORTag, TagPolicy, loads
from cbor2._decoder import TAG_ALLOW, TAG_PRESERVE, TAG_REJECT

EPOCH_DATETIME = unhexlify("c11a43b41e54")  # tag 1, epoch 1135877716
BIGNUM = unhexlify("c249010000000000000000")  # tag 2, value 2**64
CUSTOM_TAG = unhexlify("d917706548656c6c6f")  # tag 6000, "Hello" (no built-in decoder)
SET_TAG = unhexlify("d9010283616361626161")  # tag 258, {"a", "b", "c"}
SELF_DESCRIBE = unhexlify("d9d9f701")  # tag 55799 wrapping integer 1


def heading(text: str) -> None:
    print(f"\n=== {text} ===")


def main() -> None:
    safe_policy = TagPolicy.safe()

    heading("Default behavior (no policy): semantic tags are interpreted")
    print("epoch datetime ->", repr(loads(EPOCH_DATETIME)))
    print("unknown tag     ->", repr(loads(CUSTOM_TAG)))

    heading("TagPolicy.safe(): basic data and self-describe only")
    print("ordinary array  ->", loads(b"\x83\x01\x02\x03", tag_policy=safe_policy))
    print("self-describe   ->", loads(SELF_DESCRIBE, tag_policy=safe_policy))

    heading("Unknown tags are retained as data, never auto-handled")

    def unauthorized_hook(dec, tag):  # pragma: no cover - must never be called
        raise RuntimeError(f"unauthorized handler invoked for tag {tag.tag}")

    retained = loads(CUSTOM_TAG, tag_hook=unauthorized_hook, tag_policy=safe_policy)
    print("tag 6000        ->", repr(retained))
    assert retained == CBORTag(6000, "Hello")

    heading("Built-in semantic tags are preserved or rejected, not constructed")
    preserved_date = loads(EPOCH_DATETIME, tag_policy=safe_policy)
    print("epoch datetime  ->", repr(preserved_date))
    assert isinstance(preserved_date, CBORTag) and not isinstance(preserved_date, datetime)

    preserved_set = loads(SET_TAG, tag_policy=safe_policy)
    print("set tag 258     ->", repr(preserved_set))
    assert isinstance(preserved_set, CBORTag)

    for label, payload in (
        ("shareable (28)", b"\xd8\x1c\x01"),
        ("sharedref (29)", b"\xd8\x1d\x00"),
        ("stringref (25)", b"\xd8\x19\x00"),
        ("namespace (256)", b"\xd9\x01\x00\x01"),
    ):
        try:
            loads(payload, tag_policy=safe_policy)
        except CBORDecodeError as exc:
            print(f"{label:<16}-> rejected: {exc}")

    heading("Proof: rejected tags never trigger semantic conversion")

    class CountingDatetime(decoder.datetime):
        count = 0

        def __new__(cls, *args, **kwargs):
            cls.count += 1
            return super().__new__(cls, *args, **kwargs)

    original_datetime = decoder.datetime
    decoder.datetime = CountingDatetime
    try:
        loads(EPOCH_DATETIME)
        print(f"datetime constructions without policy : {CountingDatetime.count}")
        CountingDatetime.count = 0
        try:
            loads(EPOCH_DATETIME, tag_policy=TagPolicy({1: TAG_REJECT}))
        except CBORDecodeError:
            pass
        print(f"datetime constructions with reject    : {CountingDatetime.count}")
        assert CountingDatetime.count == 0
    finally:
        decoder.datetime = original_datetime

    bignum_calls = []
    original_bignum = decoder.CBORDecoder.decode_positive_bignum

    def spying_bignum(self):
        bignum_calls.append("called")
        return original_bignum(self)

    decoder.CBORDecoder.decode_positive_bignum = spying_bignum
    decoder.semantic_decoders[2] = spying_bignum
    try:
        try:
            loads(BIGNUM, tag_policy=TagPolicy({2: TAG_REJECT}))
        except CBORDecodeError:
            pass
        print(f"bignum semantic decoder calls          : {len(bignum_calls)}")
        assert bignum_calls == []
    finally:
        decoder.CBORDecoder.decode_positive_bignum = original_bignum
        decoder.semantic_decoders[2] = original_bignum

    hook_calls = []

    def counting_hook(dec, tag):
        hook_calls.append(tag.tag)
        return tag

    try:
        loads(
            CUSTOM_TAG,
            tag_hook=counting_hook,
            tag_policy=TagPolicy({6000: TAG_REJECT}),
        )
    except CBORDecodeError:
        pass
    print(f"tag_hook calls for rejected custom tag  : {len(hook_calls)}")
    assert hook_calls == []

    heading("Explicit per-tag choices via a plain mapping")
    policy = {0: TAG_ALLOW, 1: TAG_REJECT, 258: TAG_PRESERVE}
    datetime_string = unhexlify("c074323032302d30312d30315430303a30303a30305a")
    print("allowed tag 0   ->", repr(loads(datetime_string, tag_policy=policy)))
    try:
        loads(EPOCH_DATETIME, tag_policy=policy)
    except CBORDecodeError as exc:
        print("rejected tag 1  ->", exc)
    print("preserved 258   ->", repr(loads(SET_TAG, tag_policy=policy)))

    print("\nAll demonstrations passed.")


if __name__ == "__main__":
    main()
