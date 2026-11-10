"""Tests for lossless CBOR map decoding (``map_representation="lossless"``).

The lossless representation only exists in the pure Python implementation, so
these tests run exclusively against the pure Python modules.
"""
from __future__ import annotations

from binascii import unhexlify
from io import BytesIO

import pytest

import cbor2._decoder
import cbor2._encoder
import cbor2._types
from cbor2 import CBORMap, CBORMapConflictError


class _Module:
    pass


_python_impl = _Module()
for _source in (cbor2._types, cbor2._encoder, cbor2._decoder):
    for _name in dir(_source):
        setattr(_python_impl, _name, getattr(_source, _name))


@pytest.fixture
def py_impl():
    return _python_impl


# Wire samples, kept deliberately short (see RFC 8949 appendix A for the
# building blocks).
DUPLICATE_TEXT_KEYS = unhexlify("a3616101616102616203")  # {"a":1,"a":2,"b":3}
EQUAL_TYPED_KEYS = unhexlify("a3f5010102fb3ff000000000000003")  # {true:1, 1:2, 1.0:3}
COMPOUND_KEYS = unhexlify("a282010203a161780904")  # {[1,2]:3, {"x":9}:4}
INDEFINITE_DUPLICATE = unhexlify("bf616101616102ff")  # {"a":1, "a":2}
NESTED_MAP = unhexlify("a1616ba1617802")  # {"k": {"x": 2}}
NESTED_DUPLICATE = unhexlify("a1616ba2617801617802")  # {"k": {"x":1,"x":2}}
NESTED_COMPOUND_KEY = unhexlify("a1616ba1810102")  # {"k": {[1]: 2}}
SHARED_REFERENCES = unhexlify("a36162d81ca16178016163d81d006164d81d00")


def test_default_representation_is_dict(py_impl):
    decoded = py_impl.loads(DUPLICATE_TEXT_KEYS)
    assert type(decoded) is dict
    # Default mode keeps its historical last-write-wins behavior.
    assert decoded == {"a": 2, "b": 3}


def test_lossless_preserves_duplicate_text_keys(py_impl):
    decoded = py_impl.loads(DUPLICATE_TEXT_KEYS, map_representation="lossless")
    assert isinstance(decoded, CBORMap)
    assert decoded.entries == (("a", 1), ("a", 2), ("b", 3))
    assert len(decoded) == 3
    # The Mapping view collapses duplicate keys to their first value.
    assert decoded["a"] == 1
    assert list(decoded.keys()) == ["a", "b"]
    assert decoded.values() == [1, 2, 3]
    assert decoded.items() == [("a", 1), ("a", 2), ("b", 3)]


def test_lossless_preserves_equal_but_typed_keys(py_impl):
    decoded = py_impl.loads(EQUAL_TYPED_KEYS, map_representation="lossless")
    assert [key for key, _ in decoded.entries] == [True, 1, 1.0]
    assert [type(key) for key, _ in decoded.entries] == [bool, int, float]
    assert [value for _, value in decoded.entries] == [1, 2, 3]


def test_lossless_supports_compound_keys(py_impl):
    decoded = py_impl.loads(COMPOUND_KEYS, map_representation="lossless")
    assert decoded.entries == (
        ([1, 2], 3),
        (CBORMap((("x", 9),)), 4),
    )


def test_lossless_indefinite_map(py_impl):
    decoded = py_impl.loads(INDEFINITE_DUPLICATE, map_representation="lossless")
    assert decoded.entries == (("a", 1), ("a", 2))


def test_lossless_nested_maps_use_same_representation(py_impl):
    decoded = py_impl.loads(NESTED_MAP, map_representation="lossless")
    assert isinstance(decoded, CBORMap)
    inner = decoded["k"]
    assert isinstance(inner, CBORMap)
    assert inner.entries == (("x", 2),)


def test_lossless_shared_references_keep_identity(py_impl):
    decoded = py_impl.loads(SHARED_REFERENCES, map_representation="lossless")
    shared_value = decoded.entries[0][1]
    assert isinstance(shared_value, CBORMap)
    assert decoded.entries[1][1] is shared_value
    assert decoded.entries[2][1] is shared_value


def test_object_hook_receives_cbormap_in_lossless_mode(py_impl):
    seen = []

    def hook(decoder, value):
        seen.append(value)
        return value

    decoded = py_impl.loads(NESTED_MAP, map_representation="lossless", object_hook=hook)
    assert len(seen) == 2
    assert all(isinstance(value, CBORMap) for value in seen)
    assert decoded is seen[1]


def test_object_hook_receives_dict_in_dict_mode(py_impl):
    seen = []

    def hook(decoder, value):
        seen.append(value)
        return value

    py_impl.loads(NESTED_MAP, object_hook=hook)
    assert len(seen) == 2
    assert all(type(value) is dict for value in seen)


def test_invalid_map_representation_rejected(py_impl):
    with pytest.raises(ValueError, match="map_representation"):
        py_impl.loads(b"", map_representation="bogus")
    with pytest.raises(ValueError, match="map_representation"):
        py_impl.CBORDecoder(BytesIO(b""), map_representation="bogus")


def test_round_trip_duplicate_text_keys(py_impl):
    original = py_impl.loads(DUPLICATE_TEXT_KEYS, map_representation="lossless")
    encoded = py_impl.dumps(original)
    assert encoded == DUPLICATE_TEXT_KEYS
    decoded = py_impl.loads(encoded, map_representation="lossless")
    # Independent entry-by-entry check: no entry may disappear on re-encoding.
    assert decoded.entries == original.entries


def test_round_trip_equal_typed_keys(py_impl):
    original = py_impl.loads(EQUAL_TYPED_KEYS, map_representation="lossless")
    encoded = py_impl.dumps(original)
    decoded = py_impl.loads(encoded, map_representation="lossless")
    assert decoded.entries == original.entries
    assert [type(key) for key, _ in decoded.entries] == [bool, int, float]


def test_round_trip_compound_keys(py_impl):
    original = py_impl.loads(COMPOUND_KEYS, map_representation="lossless")
    encoded = py_impl.dumps(original)
    decoded = py_impl.loads(encoded, map_representation="lossless")
    assert decoded.entries == original.entries


def test_round_trip_shared_references(py_impl):
    original = py_impl.loads(SHARED_REFERENCES, map_representation="lossless")
    encoded = py_impl.dumps(original, value_sharing=True)
    decoded = py_impl.loads(encoded, map_representation="lossless")
    assert decoded.entries[0][1] is decoded.entries[1][1]
    assert decoded.entries[2][1] is decoded.entries[1][1]


def test_round_trip_indefinite_encoding(py_impl):
    original = py_impl.loads(DUPLICATE_TEXT_KEYS, map_representation="lossless")
    encoded = py_impl.dumps(original, indefinite_containers=True)
    assert encoded[0] == 0xBF and encoded[-1] == 0xFF
    decoded = py_impl.loads(encoded, map_representation="lossless")
    assert decoded.entries == original.entries


def test_canonical_encoding_keeps_every_entry(py_impl):
    original = py_impl.loads(EQUAL_TYPED_KEYS, map_representation="lossless")
    encoded = py_impl.dumps(original, canonical=True)
    decoded = py_impl.loads(encoded, map_representation="lossless")
    assert sorted(decoded.entries, key=lambda entry: repr(entry[0])) == sorted(
        original.entries, key=lambda entry: repr(entry[0])
    )


def test_to_dict_succeeds_for_compatible_maps(py_impl):
    decoded = py_impl.loads(NESTED_MAP, map_representation="lossless")
    assert decoded.dict_compatible is True
    assert decoded.dict_conflicts() == ()
    assert decoded.to_dict() == {"k": {"x": 2}}


def test_to_dict_reports_duplicate_conflicts(py_impl):
    decoded = py_impl.loads(DUPLICATE_TEXT_KEYS, map_representation="lossless")
    assert decoded.dict_compatible is False
    conflicts = decoded.dict_conflicts()
    assert len(conflicts) == 1
    conflict = conflicts[0]
    assert conflict.reason == "duplicate"
    assert conflict.key == "a"
    assert conflict.index == 1
    with pytest.raises(CBORMapConflictError) as exc_info:
        decoded.to_dict()
    assert exc_info.value.conflicts == conflicts


def test_to_dict_reports_type_collision_conflicts(py_impl):
    decoded = py_impl.loads(EQUAL_TYPED_KEYS, map_representation="lossless")
    conflicts = decoded.dict_conflicts()
    assert [conflict.reason for conflict in conflicts] == [
        "type_collision",
        "type_collision",
    ]
    with pytest.raises(CBORMapConflictError):
        decoded.to_dict()


def test_to_dict_reports_unhashable_conflicts(py_impl):
    decoded = py_impl.loads(COMPOUND_KEYS, map_representation="lossless")
    conflicts = decoded.dict_conflicts()
    assert all(conflict.reason == "unhashable" for conflict in conflicts)
    with pytest.raises(CBORMapConflictError):
        decoded.to_dict()


def test_conflicts_include_paths_for_nested_maps(py_impl):
    decoded = py_impl.loads(NESTED_DUPLICATE, map_representation="lossless")
    conflict = decoded.dict_conflicts()[0]
    assert conflict.path == ("k", "x")
    assert conflict.reason == "duplicate"

    decoded = py_impl.loads(NESTED_COMPOUND_KEY, map_representation="lossless")
    conflict = decoded.dict_conflicts()[0]
    assert conflict.path == ("k", [1])
    assert conflict.reason == "unhashable"


def test_cbormap_mapping_semantics():
    mapping = CBORMap((("a", 1), ("a", 2), ("b", 3)))
    assert mapping.get("a") == 1
    assert mapping.get("missing", 7) == 7
    assert "b" in mapping and "missing" not in mapping
    with pytest.raises(KeyError):
        mapping["missing"]


def test_cbormap_equality_and_unhashability():
    left = CBORMap((("a", 1), ("a", 2)))
    right = CBORMap((("a", 1), ("a", 2)))
    assert left == right
    assert left != CBORMap((("a", 1),))
    assert left != {"a": 1}
    with pytest.raises(TypeError):
        hash(left)


def test_cbormap_repr_handles_cycles():
    mapping = CBORMap()
    mapping.add("self", mapping)
    assert repr(mapping) == "CBORMap([('self', ...)])"


def test_load_entry_point_supports_lossless(py_impl):
    decoded = py_impl.load(
        BytesIO(DUPLICATE_TEXT_KEYS), map_representation="lossless"
    )
    assert decoded.entries == (("a", 1), ("a", 2), ("b", 3))
