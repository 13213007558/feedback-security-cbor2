from __future__ import annotations

import threading
from collections import namedtuple
from collections.abc import Iterable, Iterator, Mapping, Sequence
from functools import total_ordering
from reprlib import recursive_repr
from typing import Any, NamedTuple, TypeVar

KT = TypeVar("KT")
VT_co = TypeVar("VT_co", covariant=True)

thread_locals = threading.local()


class CBORError(Exception):
    """Base class for errors that occur during CBOR encoding or decoding."""


class CBOREncodeError(CBORError):
    """Raised for exceptions occurring during CBOR encoding."""


class CBOREncodeTypeError(CBOREncodeError, TypeError):
    """Raised when attempting to encode a type that cannot be serialized."""


class CBOREncodeValueError(CBOREncodeError, ValueError):
    """Raised when the CBOR encoder encounters an invalid value."""


class CBORDecodeError(CBORError):
    """Raised for exceptions occurring during CBOR decoding."""


class CBORDecodeValueError(CBORDecodeError, ValueError):
    """Raised when the CBOR stream being decoded contains an invalid value."""


class CBORDecodeEOF(CBORDecodeError, EOFError):
    """Raised when decoding unexpectedly reaches EOF."""


class CBORMapConflictError(CBORError):
    """
    Raised when a lossless :class:`CBORMap` cannot be converted into an ordinary
    Python :class:`dict` without dropping or merging entries.

    The offending :class:`MapConflict` records are available on the
    :attr:`conflicts` attribute.
    """

    def __init__(self, conflicts: Sequence[MapConflict]) -> None:
        self.conflicts: tuple[MapConflict, ...] = tuple(conflicts)
        super().__init__(f"map cannot be represented as a dict: {len(self.conflicts)} conflict(s)")


@total_ordering
class CBORTag:
    """
    Represents a CBOR semantic tag.

    :param int tag: tag number
    :param value: encapsulated value (any object)
    """

    __slots__ = "tag", "value"

    def __init__(self, tag: str | int, value: Any) -> None:
        if not isinstance(tag, int) or tag not in range(2**64):
            raise TypeError("CBORTag tags must be positive integers less than 2**64")
        self.tag = tag
        self.value = value

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CBORTag):
            return (self.tag, self.value) == (other.tag, other.value)

        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, CBORTag):
            return (self.tag, self.value) <= (other.tag, other.value)

        return NotImplemented

    @recursive_repr()
    def __repr__(self) -> str:
        return f"CBORTag({self.tag}, {self.value!r})"

    def __hash__(self) -> int:
        self_id = id(self)
        try:
            running_hashes = thread_locals.running_hashes
        except AttributeError:
            running_hashes = thread_locals.running_hashes = set()

        if self_id in running_hashes:
            raise RuntimeError(
                "This CBORTag is not hashable because it contains a reference to itself"
            )

        running_hashes.add(self_id)
        try:
            return hash((self.tag, self.value))
        finally:
            running_hashes.remove(self_id)
            if not running_hashes:
                del thread_locals.running_hashes


class CBORSimpleValue(namedtuple("CBORSimpleValue", ["value"])):
    """
    Represents a CBOR "simple value".

    :param int value: the value (0-255)
    """

    __slots__ = ()

    value: int

    def __hash__(self) -> int:
        return hash(self.value)

    def __new__(cls, value: int) -> CBORSimpleValue:
        if value < 0 or value > 255 or 23 < value < 32:
            raise TypeError("simple value out of range (0..23, 32..255)")

        return super().__new__(cls, value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, int):
            return self.value == other
        elif isinstance(other, CBORSimpleValue):
            return self.value == other.value

        return NotImplemented

    def __ne__(self, other: object) -> bool:
        if isinstance(other, int):
            return self.value != other
        elif isinstance(other, CBORSimpleValue):
            return self.value != other.value

        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, int):
            return self.value < other
        elif isinstance(other, CBORSimpleValue):
            return self.value < other.value

        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, int):
            return self.value <= other
        elif isinstance(other, CBORSimpleValue):
            return self.value <= other.value

        return NotImplemented

    def __ge__(self, other: object) -> bool:
        if isinstance(other, int):
            return self.value >= other
        elif isinstance(other, CBORSimpleValue):
            return self.value >= other.value

        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, int):
            return self.value > other
        elif isinstance(other, CBORSimpleValue):
            return self.value > other.value

        return NotImplemented


class FrozenDict(Mapping[KT, VT_co]):
    """
    A hashable, immutable mapping type.

    The arguments to ``FrozenDict`` are processed just like those to ``dict``.
    """

    def __init__(self, *args: Mapping[KT, VT_co] | Iterable[tuple[KT, VT_co]]) -> None:
        self._d: dict[KT, VT_co] = dict(*args)
        self._hash: int | None = None

    def __iter__(self) -> Iterator[KT]:
        return iter(self._d)

    def __len__(self) -> int:
        return len(self._d)

    def __getitem__(self, key: KT) -> VT_co:
        return self._d[key]

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._d})"

    def __hash__(self) -> int:
        if self._hash is None:
            self._hash = hash((frozenset(self), frozenset(self.values())))

        return self._hash


class MapConflict(NamedTuple):
    """
    Describes a single entry that prevents a :class:`CBORMap` from being
    represented as an ordinary Python :class:`dict`.

    :ivar path: the sequence of map keys and array indices leading from the
        outermost :class:`CBORMap` to the offending entry
    :ivar key: the offending key
    :ivar reason: one of ``"duplicate"`` (a previous entry uses the same
        Python key), ``"type_collision"`` (a previous entry has a key that is
        equal in Python but had a different CBOR type, e.g. ``True`` and
        ``1`` or ``1`` and ``1.0``) or ``"unhashable"`` (the key cannot be
        used as a Python dict key at all, e.g. a list or another map)
    :ivar index: zero-based index of the entry within its containing map
    """

    path: tuple[Any, ...]
    key: Any
    reason: str
    index: int


class CBORMap(Mapping[Any, Any]):
    """
    A lossless representation of a CBOR map.

    Unlike a regular :class:`dict`, this type preserves:

    * the order of every entry,
    * duplicate entries (including repeated text keys),
    * the distinction between keys that compare equal in Python but have
      different CBOR types (such as ``True``, ``1`` and ``1.0``), and
    * entries whose keys are compound values (arrays or nested maps) that
      cannot be used as Python dict keys.

    The entries are available through :attr:`entries` as ``(key, value)``
    tuples. The read-only :class:`~collections.abc.Mapping` interface treats
    duplicate keys as a single entry: indexing and :meth:`get` return the
    first matching value, and :meth:`items` yields each entry exactly once.

    Instances are not hashable, matching the behavior of mutable containers,
    because their entries may themselves contain unhashable keys.
    """

    __slots__ = ("_entries",)
    __hash__ = None

    def __init__(self, entries: Iterable[tuple[Any, Any]] | None = None) -> None:
        self._entries: list[tuple[Any, Any]] = list(entries) if entries is not None else []

    def add(self, key: Any, value: Any) -> None:
        """Append a new ``(key, value)`` entry, preserving any duplicates."""
        self._entries.append((key, value))

    @property
    def entries(self) -> tuple[tuple[Any, Any], ...]:
        """Return all entries, in order, including duplicates."""
        return tuple(self._entries)

    def __iter__(self) -> Iterator[Any]:
        seen: set[int] = set()
        for key, _ in self._entries:
            try:
                key_id = hash(key)
            except TypeError:
                # Unhashable keys cannot collide with anything and have no
                # meaningful dict iteration position anyway; still emit them
                # so that no entry is hidden.
                yield key
            else:
                if key_id not in seen:
                    seen.add(key_id)
                    yield key

    def __len__(self) -> int:
        return len(self._entries)

    def __getitem__(self, key: Any) -> Any:
        for candidate, value in self._entries:
            if candidate == key:
                return value

        raise KeyError(key)

    def keys(self) -> list[Any]:
        """Return one copy of every key, in first-seen order."""
        return list(self)

    def values(self) -> list[Any]:
        """Return the value of every entry, in order, including duplicates."""
        return [value for _, value in self._entries]

    def items(self) -> list[tuple[Any, Any]]:
        """Return every entry, in order, including duplicates."""
        return list(self._entries)

    def __contains__(self, key: object) -> bool:
        return any(candidate == key for candidate, _ in self._entries)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CBORMap):
            return self._entries == other._entries

        return NotImplemented

    def __ne__(self, other: object) -> bool:
        if isinstance(other, CBORMap):
            return self._entries != other._entries

        return NotImplemented

    @recursive_repr()
    def __repr__(self) -> str:
        return f"CBORMap({self._entries!r})"

    @property
    def dict_compatible(self) -> bool:
        """``True`` if converting to a :class:`dict` would not lose entries."""
        return not _collect_map_conflicts(self, (), set())

    def dict_conflicts(self) -> tuple[MapConflict, ...]:
        """
        Recursively find every entry that cannot survive a conversion to an
        ordinary :class:`dict`.

        :return: all detected :class:`MapConflict` records, in entry order
        """
        return tuple(_collect_map_conflicts(self, (), set()))

    def to_dict(self) -> dict[Any, Any]:
        """
        Recursively convert this map (and any nested maps) to plain Python
        :class:`dict` objects.

        :raises CBORMapConflictError: if any entry would be silently dropped
            or merged, or if any key is unhashable
        """
        conflicts = _collect_map_conflicts(self, (), set())
        if conflicts:
            raise CBORMapConflictError(conflicts)

        return _to_plain(self, {})


def _collect_map_conflicts(
    value: Any, path: tuple[Any, ...], seen_ids: set[int]
) -> list[MapConflict]:
    value_id = id(value)
    if value_id in seen_ids:
        return []

    conflicts: list[MapConflict] = []
    if isinstance(value, CBORMap):
        seen_ids.add(value_id)
        groups: dict[int, list[tuple[Any, int]]] = {}
        for index, (key, item) in enumerate(value._entries):
            try:
                key_hash = hash(key)
            except TypeError:
                # The key cannot be used as a Python dict key at all (e.g.
                # lists, maps or sets containing unhashable members).
                conflicts.append(
                    MapConflict(path + (key,), key, "unhashable", index)
                )
            else:
                group = groups.setdefault(key_hash, [])
                for previous_key, _ in group:
                    if previous_key == key:
                        reason = (
                            "duplicate"
                            if type(previous_key) is type(key)
                            else "type_collision"
                        )
                        conflicts.append(
                            MapConflict(path + (key,), key, reason, index)
                        )
                        break
                else:
                    group.append((key, index))

            conflicts.extend(
                _collect_map_conflicts(item, path + (key,), seen_ids)
            )
    elif isinstance(value, CBORTag):
        seen_ids.add(value_id)
        conflicts.extend(_collect_map_conflicts(value.value, path, seen_ids))
    elif isinstance(value, (list, tuple)):
        seen_ids.add(value_id)
        for index, item in enumerate(value):
            conflicts.extend(
                _collect_map_conflicts(item, path + (index,), seen_ids)
            )

    return conflicts


def _to_plain(value: Any, memo: dict[int, Any]) -> Any:
    value_id = id(value)
    if value_id in memo:
        return memo[value_id]

    if isinstance(value, CBORMap):
        result: dict[Any, Any] = {}
        memo[value_id] = result
        for key, item in value._entries:
            result[key] = _to_plain(item, memo)

        return result
    elif isinstance(value, CBORTag):
        result_tag = CBORTag(value.tag, _to_plain(value.value, memo))
        memo[value_id] = result_tag
        return result_tag
    elif isinstance(value, list):
        result_list: list[Any] = []
        memo[value_id] = result_list
        result_list.extend(_to_plain(item, memo) for item in value)
        return result_list
    elif isinstance(value, tuple):
        result_tuple = tuple(_to_plain(item, memo) for item in value)
        memo[value_id] = result_tuple
        return result_tuple
    else:
        return value


class UndefinedType:
    __slots__ = ()

    def __new__(cls: type[UndefinedType]) -> UndefinedType:
        try:
            return undefined
        except NameError:
            return super().__new__(cls)

    def __repr__(self) -> str:
        return "undefined"

    def __bool__(self) -> bool:
        return False


class BreakMarkerType:
    __slots__ = ()

    def __new__(cls: type[BreakMarkerType]) -> BreakMarkerType:
        try:
            return break_marker
        except NameError:
            return super().__new__(cls)

    def __repr__(self) -> str:
        return "break_marker"

    def __bool__(self) -> bool:
        return True


#: Represents the "undefined" value.
undefined = UndefinedType()
break_marker = BreakMarkerType()
