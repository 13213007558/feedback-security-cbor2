"""
Tests for the explicit, pure-Python semantic tag admission policy.

These tests exercise the pure Python decoder directly (``cbor2._decoder``);
the C extension does not implement ``tag_policy``.
"""

from binascii import unhexlify
from datetime import datetime
from io import BytesIO

import pytest

import cbor2._decoder as decoder
from cbor2._types import CBORDecodeError, CBORTag
from cbor2._decoder import (
    CBORDecoder,
    STRUCTURAL_TAGS,
    TAG_ALLOW,
    TAG_PRESERVE,
    TAG_REJECT,
    TagPolicy,
    load,
    loads,
)

# tag(1, epoch datetime 2005-12-29T17:35:16Z)
EPOCH_DATETIME = unhexlify("c11a43b41e54")
# tag(2, positive bignum 2**64)
BIGNUM = unhexlify("c249010000000000000000")
# tag(6000, "Hello") – a tag with no built-in decoder
CUSTOM_TAG = unhexlify("d917706548656c6c6f")
# tag(55799, 1) self-describe CBOR wrapping an integer
SELF_DESCRIBE = unhexlify("d9d9f701")
# {"tag(6000, [1, 2])": 1} – a preserved tag used as a map key
TAG_MAP_KEY = unhexlify("a1d9177082010201")
# string referencing: tag(256, ["hello", tag(25, 0)])
STRINGREF = unhexlify("d90100826568656c6c6fd81900")
# tag(256, tag(1, ...)) – a rejected tag inside a stringref namespace
NAMESPACE_WRAPPING_REJECTED = unhexlify("d90100c11a43b3dc54")


class TestDefaultBehavior:
    def test_no_policy_keeps_builtin_semantics(self):
        value = loads(EPOCH_DATETIME)
        assert isinstance(value, datetime)

    def test_no_policy_unknown_tag_uses_hook(self):
        calls = []

        def hook(dec, tag):
            calls.append(tag.tag)
            return tag.value[::-1]

        assert loads(CUSTOM_TAG, tag_hook=hook) == "olleH"
        assert calls == [6000]

    def test_no_policy_unknown_tag_without_hook_is_cbor_tag(self):
        assert loads(CUSTOM_TAG) == CBORTag(6000, "Hello")

    def test_tag_policy_attribute_defaults_none(self):
        dec = CBORDecoder(BytesIO(b""))
        assert dec.tag_policy is None


class TestPolicyConstruction:
    def test_mapping_is_coerced_to_tag_policy(self):
        dec = CBORDecoder(BytesIO(b""), tag_policy={1: TAG_ALLOW})
        assert isinstance(dec.tag_policy, TagPolicy)
        assert dec.tag_policy.decide(1) == TAG_ALLOW
        assert dec.tag_policy.decide(999) == TAG_PRESERVE

    def test_callable_is_kept(self):
        policy = lambda tagnum: TAG_REJECT  # noqa: E731
        dec = CBORDecoder(BytesIO(b""), tag_policy=policy)
        assert dec.tag_policy is policy

    def test_tag_policy_instance_is_kept(self):
        policy = TagPolicy.safe()
        dec = CBORDecoder(BytesIO(b""), tag_policy=policy)
        assert dec.tag_policy is policy

    def test_invalid_type_raises(self):
        with pytest.raises(ValueError, match="tag_policy must be"):
            CBORDecoder(BytesIO(b""), tag_policy=123)

    def test_invalid_action_raises(self):
        with pytest.raises(ValueError, match="invalid tag action"):
            TagPolicy({1: "explode"})

    def test_invalid_tag_number_raises(self):
        with pytest.raises(ValueError, match="tag numbers must be"):
            TagPolicy({-1: TAG_ALLOW})
        with pytest.raises(ValueError, match="tag numbers must be"):
            TagPolicy({True: TAG_ALLOW})

    @pytest.mark.parametrize("tagnum", sorted(STRUCTURAL_TAGS))
    def test_structural_tag_cannot_be_preserved_in_rules(self, tagnum):
        with pytest.raises(ValueError, match="structural tag"):
            TagPolicy({tagnum: TAG_PRESERVE})

    @pytest.mark.parametrize("tagnum", sorted(STRUCTURAL_TAGS))
    def test_structural_tag_preserve_via_default_raises_at_decode(self, tagnum):
        payload = {
            25: b"\xd8\x19\x00",
            28: b"\xd8\x1c\x01",
            29: b"\xd8\x1d\x00",
            256: b"\xd9\x01\x00\x01",
        }
        with pytest.raises(CBORDecodeError, match="structural tag"):
            loads(payload[tagnum], tag_policy=TagPolicy())

    def test_setter_validates_value(self):
        dec = CBORDecoder(BytesIO(b""))
        dec.tag_policy = {1: TAG_REJECT}
        assert isinstance(dec.tag_policy, TagPolicy)
        dec.tag_policy = None
        assert dec.tag_policy is None
        with pytest.raises(ValueError):
            dec.tag_policy = object()


class TestActions:
    def test_allow_runs_builtin_semantic_decoder(self):
        value = loads(EPOCH_DATETIME, tag_policy=TagPolicy({1: TAG_ALLOW}))
        assert isinstance(value, datetime)

    def test_reject_raises_before_value_decode(self):
        with pytest.raises(CBORDecodeError, match="tag 1 is not permitted"):
            loads(EPOCH_DATETIME, tag_policy=TagPolicy({1: TAG_REJECT}))

    def test_preserve_keeps_raw_tag_but_decodes_payload(self):
        value = loads(EPOCH_DATETIME, tag_policy=TagPolicy({1: TAG_PRESERVE}))
        assert value == CBORTag(1, 1135877716)
        assert not isinstance(value, datetime)

    def test_preserve_decodes_structured_payload(self):
        # tag(6000, [1, 2]) -> payload is a fully decoded tuple-in-tag
        value = loads(unhexlify("d91770820102"), tag_policy=TagPolicy.safe())
        assert value == CBORTag(6000, [1, 2])

    def test_nested_tags_remain_subject_to_policy(self):
        # outer tag 6000 preserved; inner tag 1 allowed
        policy = TagPolicy({1: TAG_ALLOW}, default_action=TAG_PRESERVE)
        value = loads(unhexlify("d91770c11a43b41e54"), tag_policy=policy)
        assert value.tag == 6000
        assert isinstance(value.value, datetime)

    def test_nested_rejected_tag_aborts_preservation(self):
        policy = TagPolicy({1: TAG_REJECT}, default_action=TAG_PRESERVE)
        with pytest.raises(CBORDecodeError, match="tag 1 is not permitted"):
            loads(unhexlify("d91770c11a43b41e54"), tag_policy=policy)

    def test_unknown_tag_is_preserved_not_hooked(self):
        def hook(dec, tag):
            raise AssertionError("tag_hook must not run for a preserved tag")

        value = loads(CUSTOM_TAG, tag_hook=hook, tag_policy=TagPolicy.safe())
        assert value == CBORTag(6000, "Hello")

    def test_allowed_unknown_tag_still_reaches_hook(self):
        calls = []

        def hook(dec, tag):
            calls.append(tag.tag)
            return "converted"

        value = loads(CUSTOM_TAG, tag_hook=hook, tag_policy=TagPolicy({6000: TAG_ALLOW}))
        assert value == "converted"
        assert calls == [6000]

    def test_rejected_unknown_tag_never_reaches_hook(self):
        def hook(dec, tag):
            raise AssertionError("tag_hook must not run for a rejected tag")

        with pytest.raises(CBORDecodeError):
            loads(CUSTOM_TAG, tag_hook=hook, tag_policy=TagPolicy({6000: TAG_REJECT}))

    def test_callable_policy(self):
        policy = lambda tagnum: TAG_ALLOW if tagnum == 6000 else TAG_REJECT  # noqa: E731
        assert loads(CUSTOM_TAG, tag_policy=policy) == CBORTag(6000, "Hello")
        with pytest.raises(CBORDecodeError):
            loads(EPOCH_DATETIME, tag_policy=policy)

    def test_callable_returning_invalid_action_raises(self):
        policy = lambda tagnum: "nope"  # noqa: E731
        with pytest.raises(CBORDecodeError, match="invalid action"):
            loads(CUSTOM_TAG, tag_policy=policy)


class TestNoSemanticConstruction:
    def test_rejected_datetime_never_constructs_datetime(self, monkeypatch):
        class CountingDatetime(decoder.datetime):
            count = 0

            def __new__(cls, *args, **kwargs):
                cls.count += 1
                return super().__new__(cls, *args, **kwargs)

        monkeypatch.setattr(decoder, "datetime", CountingDatetime)
        loads(EPOCH_DATETIME)
        assert CountingDatetime.count >= 1
        CountingDatetime.count = 0
        with pytest.raises(CBORDecodeError):
            loads(EPOCH_DATETIME, tag_policy=TagPolicy({1: TAG_REJECT}))
        assert CountingDatetime.count == 0

    def test_rejected_bignum_never_enters_semantic_decoder(self, monkeypatch):
        calls = []
        original = CBORDecoder.decode_positive_bignum

        def spy(self):
            calls.append("bignum")
            return original(self)

        monkeypatch.setattr(CBORDecoder, "decode_positive_bignum", spy)
        monkeypatch.setitem(decoder.semantic_decoders, 2, spy)
        with pytest.raises(CBORDecodeError):
            loads(BIGNUM, tag_policy=TagPolicy({2: TAG_REJECT}))
        assert calls == []

    def test_rejected_custom_tag_never_calls_hook(self):
        calls = []

        def hook(dec, tag):
            calls.append(tag.tag)
            return tag

        with pytest.raises(CBORDecodeError):
            loads(CUSTOM_TAG, tag_hook=hook, tag_policy=TagPolicy({6000: TAG_REJECT}))
        assert calls == []


class TestStructuralTags:
    @pytest.mark.parametrize(
        "payload",
        [b"\xd8\x1c\x01", b"\xd8\x1d\x00", b"\xd8\x19\x00", b"\xd9\x01\x00\x01"],
    )
    def test_safe_policy_rejects_structural_tags(self, payload):
        with pytest.raises(CBORDecodeError, match="not permitted"):
            loads(payload, tag_policy=TagPolicy.safe())

    def test_allowed_shareable_and_sharedref_still_work(self):
        policy = TagPolicy({28: TAG_ALLOW, 29: TAG_ALLOW})
        value = loads(unhexlify("82d81c6568656c6c6fd81d00"), tag_policy=policy)
        assert value == ["hello", "hello"]
        assert value[0] is value[1]

    def test_allowed_stringref_namespace_and_reference_work(self):
        policy = TagPolicy({256: TAG_ALLOW, 25: TAG_ALLOW})
        assert loads(STRINGREF, tag_policy=policy) == ["hello", "hello"]

    def test_namespace_without_stringref_permission_cannot_dangle(self):
        # namespace allowed, but tag 25 falls through to reject
        policy = TagPolicy({256: TAG_ALLOW}, default_action=TAG_REJECT)
        with pytest.raises(CBORDecodeError, match="tag 25 is not permitted"):
            loads(STRINGREF, tag_policy=policy)


class TestReferenceTableCleanup:
    def test_failure_clears_shareables_and_share_index(self):
        dec = CBORDecoder(BytesIO(b""), tag_policy=TagPolicy.safe())
        with pytest.raises(CBORDecodeError):
            dec.decode_from_bytes(b"\xd8\x1c\x01")
        assert dec._shareables == []
        assert dec._share_index is None
        # the same decoder can still decode ordinary values
        assert dec.decode_from_bytes(b"\x07") == 7

    def test_structural_failure_allocates_no_shareable_slot(self):
        dec = CBORDecoder(BytesIO(b""), tag_policy=TagPolicy.safe())
        with pytest.raises(CBORDecodeError):
            dec.decode_from_bytes(unhexlify("82d81c01d81d00"))
        assert dec._shareables == []

    def test_namespace_state_restored_after_inner_rejection(self):
        policy = TagPolicy({256: TAG_ALLOW, 1: TAG_REJECT})
        dec = CBORDecoder(BytesIO(b""), tag_policy=policy)
        with pytest.raises(CBORDecodeError):
            dec.decode_from_bytes(NAMESPACE_WRAPPING_REJECTED)
        assert dec._stringref_namespace is None
        assert dec.decode_from_bytes(b"\x01") == 1


class TestImmutableContext:
    def test_preserved_tag_is_usable_as_map_key(self):
        value = loads(TAG_MAP_KEY, tag_policy=TagPolicy.safe())
        (key,) = value.keys()
        assert isinstance(key, CBORTag)
        assert hash(key) == hash(CBORTag(6000, (1, 2)))
        assert value == {CBORTag(6000, (1, 2)): 1}

    def test_preserved_tag_in_frozen_map_key(self):
        # decode under immutable requirement via an object_hook-free map:
        # keys are always decoded immutably, so the payload becomes a tuple
        value = loads(TAG_MAP_KEY, tag_policy=TagPolicy.safe())
        key = next(iter(value))
        assert key.value == (1, 2)
        assert isinstance(key.value, tuple)


class TestSafePreset:
    def test_allows_only_basic_data_and_self_describe(self):
        assert loads(SELF_DESCRIBE, tag_policy=TagPolicy.safe()) == 1
        assert loads(b"\x83\x01\x02\x03", tag_policy=TagPolicy.safe()) == [1, 2, 3]
        assert loads(b"\xa1\x61\x61\x01", tag_policy=TagPolicy.safe()) == {"a": 1}

    def test_unknown_tag_survives_as_data(self):
        value = loads(CUSTOM_TAG, tag_policy=TagPolicy.safe())
        assert value == CBORTag(6000, "Hello")

    def test_builtin_semantic_tag_is_preserved(self):
        value = loads(EPOCH_DATETIME, tag_policy=TagPolicy.safe())
        assert value == CBORTag(1, 1135877716)

    def test_safe_preset_rules(self):
        policy = TagPolicy.safe()
        assert policy.default_action == TAG_PRESERVE
        assert policy.rules[55799] == TAG_ALLOW
        for tagnum in STRUCTURAL_TAGS:
            assert policy.rules[tagnum] == TAG_REJECT


class TestLoadFunctions:
    def test_loads_accepts_tag_policy(self):
        assert isinstance(
            loads(EPOCH_DATETIME, tag_policy=TagPolicy({1: TAG_PRESERVE})), CBORTag
        )

    def test_load_accepts_tag_policy(self):
        fp = BytesIO(EPOCH_DATETIME)
        with pytest.raises(CBORDecodeError):
            load(fp, tag_policy=TagPolicy({1: TAG_REJECT}))
