from __future__ import annotations

import re
import struct
import sys
from codecs import getincrementaldecoder
from collections.abc import Callable, Mapping, Sequence
from datetime import date, datetime, timedelta, timezone
from io import BytesIO
from typing import IO, TYPE_CHECKING, Any, Literal, TypeVar, cast, overload

from ._types import (
    CBORDecodeEOF,
    CBORDecodeError,
    CBORDecodeValueError,
    CBORSimpleValue,
    CBORTag,
    FrozenDict,
    break_marker,
    undefined,
)

if TYPE_CHECKING:
    from decimal import Decimal
    from email.message import Message
    from fractions import Fraction
    from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
    from uuid import UUID

T = TypeVar("T")

timestamp_re = re.compile(
    r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)" r"(?:\.(\d{1,6})\d*)?(?:Z|([+-])(\d\d):(\d\d))$"
)
incremental_utf8_decoder = getincrementaldecoder("utf-8")

#: Interpret the tag with its built-in semantic decoder (or via ``tag_hook``
#: when no built-in decoder exists).
TAG_ALLOW = "allow"
#: Keep the tag as a :class:`~cbor2.CBORTag` value. The payload is still fully
#: decoded, with nested tags subject to the same policy.
TAG_PRESERVE = "preserve"
#: Refuse the tag by raising :class:`~cbor2.CBORDecodeError` before any
#: semantic object is constructed.
TAG_REJECT = "reject"

#: Structural tags that mutate the decoder's reference machinery. They can
#: only be explicitly allowed or rejected; preserving them as an opaque shell
#: would leave later references pointing at the wrong objects.
STRUCTURAL_TAGS = frozenset({25, 28, 29, 256})

TagAction = Literal["allow", "preserve", "reject"]


class TagPolicy:
    """
    Explicit admission policy for CBOR semantic tags (major type 6).

    The policy is consulted for every tag *before* its built-in semantic
    decoder runs, so a rejected tag never triggers construction of the
    potentially expensive semantic object (``datetime``, ``Decimal``,
    ``set``, ...) and unknown tags never reach an unauthorized custom
    handler.

    Three actions are available per tag:

    * :data:`TAG_ALLOW` – normal interpretation, including ``tag_hook`` for
      tags without a built-in decoder
    * :data:`TAG_PRESERVE` – keep the raw :class:`~cbor2.CBORTag`; the
      payload is still decoded and nested tags stay subject to the policy
    * :data:`TAG_REJECT` – raise :class:`~cbor2.CBORDecodeError`

    A plain mapping of tag numbers to actions may be passed instead of a
    :class:`TagPolicy`; tags missing from the mapping then default to
    :data:`TAG_PRESERVE`. A callable taking the tag number and returning an
    action is also accepted.

    Structural tags 25 (string reference), 28 (shareable), 29 (shared
    reference) and 256 (string reference namespace) can only be allowed or
    rejected – they cannot be preserved.
    """

    __slots__ = ("rules", "default_action")

    def __init__(
        self,
        rules: Mapping[int, TagAction] | None = None,
        default_action: TagAction = TAG_PRESERVE,
    ):
        """
        :param rules: mapping of tag numbers to actions
        :param default_action:
            action applied to any tag that does not appear in ``rules``
        """
        self.rules: dict[int, TagAction] = {}
        if rules:
            for tagnum, action in rules.items():
                self._validate_tag(tagnum)
                self._validate_action(action)
                if tagnum in STRUCTURAL_TAGS and action == TAG_PRESERVE:
                    raise ValueError(
                        f"structural tag {tagnum} cannot be preserved; it must be explicitly "
                        "allowed or rejected"
                    )

                self.rules[tagnum] = action

        self._validate_action(default_action)
        self.default_action = default_action

    @staticmethod
    def _validate_tag(tagnum: Any) -> None:
        if isinstance(tagnum, bool) or not isinstance(tagnum, int) or tagnum not in range(2**64):
            raise ValueError("tag numbers must be non-negative integers less than 2**64")

    @staticmethod
    def _validate_action(action: Any) -> None:
        if action not in (TAG_ALLOW, TAG_PRESERVE, TAG_REJECT):
            raise ValueError(
                f"invalid tag action {action!r} (must be {TAG_ALLOW!r}, {TAG_PRESERVE!r} or "
                f"{TAG_REJECT!r})"
            )

    def decide(self, tagnum: int) -> TagAction:
        """Return the action that applies to ``tagnum``."""
        action = self.rules.get(tagnum, self.default_action)
        if action == TAG_PRESERVE and tagnum in STRUCTURAL_TAGS:
            raise CBORDecodeError(
                f"structural tag {tagnum} has no explicit policy; it must be allowed or "
                "rejected, not preserved"
            )

        return action

    @classmethod
    def safe(cls) -> "TagPolicy":
        """
        A conservative preset that only admits basic CBOR data plus the
        self-describe CBOR tag (55799, which is a transparent wrapper).

        The structural tags (25, 28, 29, 256) are rejected explicitly, and
        every other tag is preserved as a :class:`~cbor2.CBORTag` so that
        unknown tags survive as data instead of triggering a semantic
        conversion or a custom handler.
        """
        return cls(
            {
                25: TAG_REJECT,
                28: TAG_REJECT,
                29: TAG_REJECT,
                256: TAG_REJECT,
                55799: TAG_ALLOW,
            },
            default_action=TAG_PRESERVE,
        )


TagPolicyInput = TagPolicy | Callable[[int], TagAction] | Mapping[int, TagAction] | None


def _coerce_tag_policy(
    tag_policy: TagPolicyInput,
) -> TagPolicy | Callable[[int], TagAction] | None:
    if tag_policy is None or isinstance(tag_policy, TagPolicy):
        return tag_policy
    elif callable(tag_policy):
        # A user supplied decision function taking the tag number.
        return tag_policy
    elif isinstance(tag_policy, Mapping):
        return TagPolicy(tag_policy)
    else:
        raise ValueError(
            "tag_policy must be a TagPolicy, a mapping of tag numbers to actions, a callable "
            "or None"
        )


class CBORDecoder:
    """
    The CBORDecoder class implements a fully featured `CBOR`_ decoder with
    several extensions for handling shared references, big integers, rational
    numbers and so on. Typically the class is not used directly, but the
    :func:`load` and :func:`loads` functions are called to indirectly construct
    and use the class.

    When the class is constructed manually, the main entry points are
    :meth:`decode` and :meth:`decode_from_bytes`.

    .. _CBOR: https://cbor.io/
    """

    __slots__ = (
        "_tag_hook",
        "_object_hook",
        "_tag_policy",
        "_share_index",
        "_shareables",
        "_fp",
        "_fp_read",
        "_immutable",
        "_str_errors",
        "_stringref_namespace",
        "_max_depth",
        "_decode_depth",
    )

    _fp: IO[bytes]
    _fp_read: Callable[[int], bytes]
    _str_errors: str

    def __init__(
        self,
        fp: IO[bytes],
        tag_hook: Callable[[CBORDecoder, CBORTag], Any] | None = None,
        object_hook: Callable[[CBORDecoder, dict[Any, Any]], Any] | None = None,
        str_errors: str = "strict",
        read_size: int = 1,
        *,
        max_depth: int = 400,
        tag_policy: TagPolicyInput = None,
    ):
        """
        :param fp:
            the file to read from (any file-like object opened for reading in binary
            mode)
        :param tag_hook:
            callable that takes 2 arguments: the decoder instance, and the
            :class:`.CBORTag` to be decoded. This callback is invoked for any tags
            for which there is no built-in decoder. The return value is substituted
            for the :class:`.CBORTag` object in the deserialized output
        :param object_hook:
            callable that takes 2 arguments: the decoder instance, and a
            dictionary. This callback is invoked for each deserialized
            :class:`dict` object. The return value is substituted for the dict in
            the deserialized output.
        :param str_errors:
            determines how to handle unicode decoding errors (see the `Error Handlers`_
            section in the standard library documentation for details)
        :param read_size:
            the minimum number of bytes to read at a time.
            Setting this to a higher value like 4096 improves performance,
            but is likely to read past the end of the CBOR value, advancing the stream
            position beyond the decoded data. This only matters if you need to reuse the
            stream after decoding.
            Ignored in the pure Python implementation, but included for API compatibility.
        :param max_depth:
            the maximum allowed container nesting depth
        :param tag_policy:
            an explicit admission policy for semantic tags. A :class:`TagPolicy`,
            a mapping of tag numbers to actions (``"allow"``, ``"preserve"`` or
            ``"reject"``) or a callable taking a tag number and returning an
            action. When ``None`` (the default), all built-in semantic tags keep
            their default behavior and unknown tags are passed to ``tag_hook``

        .. _Error Handlers: https://docs.python.org/3/library/codecs.html#error-handlers

        """
        self.fp = fp
        self.tag_hook = tag_hook
        self.object_hook = object_hook
        self.tag_policy = tag_policy
        self.str_errors = str_errors
        self._share_index: int | None = None
        self._shareables: list[object] = []
        self._stringref_namespace: list[str | bytes] | None = None
        self._immutable = False
        self._max_depth = max_depth
        self._decode_depth = 0

    @property
    def immutable(self) -> bool:
        """
        Used by decoders to check if the calling context requires an immutable
        type.  Object_hook or tag_hook should raise an exception if this flag
        is set unless the result can be safely used as a dict key.
        """
        return self._immutable

    @property
    def fp(self) -> IO[bytes]:
        return self._fp

    @fp.setter
    def fp(self, value: IO[bytes]) -> None:
        try:
            if not callable(value.read):
                raise ValueError("fp.read is not callable")
        except AttributeError:
            raise ValueError("fp object has no read method")
        else:
            self._fp = value
            self._fp_read = value.read

    @property
    def tag_hook(self) -> Callable[[CBORDecoder, CBORTag], Any] | None:
        return self._tag_hook

    @tag_hook.setter
    def tag_hook(self, value: Callable[[CBORDecoder, CBORTag], Any] | None) -> None:
        if value is None or callable(value):
            self._tag_hook = value
        else:
            raise ValueError("tag_hook must be None or a callable")

    @property
    def object_hook(self) -> Callable[[CBORDecoder, dict[Any, Any]], Any] | None:
        return self._object_hook

    @object_hook.setter
    def object_hook(self, value: Callable[[CBORDecoder, dict[Any, Any]], Any] | None) -> None:
        if value is None or callable(value):
            self._object_hook = value
        else:
            raise ValueError("object_hook must be None or a callable")

    @property
    def tag_policy(
        self,
    ) -> TagPolicy | Callable[[int], TagAction] | None:
        return self._tag_policy

    @tag_policy.setter
    def tag_policy(
        self,
        value: TagPolicyInput,
    ) -> None:
        self._tag_policy = _coerce_tag_policy(value)

    @property
    def str_errors(self) -> str:
        return self._str_errors

    @str_errors.setter
    def str_errors(self, value: str) -> None:
        if value == "error":
            self._str_errors = "strict"
        elif value in ("strict", "error", "replace", "backslashreplace", "surrogateescape"):
            self._str_errors = value
        else:
            raise ValueError(
                f"invalid str_errors value {value!r} (must be 'strict', 'error', 'replace', "
                f"'backslashreplace' or 'surrogateescape')"
            )

    def set_shareable(self, value: T) -> T:
        """
        Set the shareable value for the last encountered shared value marker,
        if any. If the current shared index is ``None``, nothing is done.

        :param value: the shared value
        :returns: the shared value to permit chaining
        """
        if self._share_index is not None:
            self._shareables[self._share_index] = value

        return value

    def _stringref_namespace_add(self, string: str | bytes, length: int) -> None:
        if self._stringref_namespace is not None:
            next_index = len(self._stringref_namespace)
            if next_index < 24:
                is_referenced = length >= 3
            elif next_index < 256:
                is_referenced = length >= 4
            elif next_index < 65536:
                is_referenced = length >= 5
            elif next_index < 4294967296:
                is_referenced = length >= 7
            else:
                is_referenced = length >= 11

            if is_referenced:
                self._stringref_namespace.append(string)

    def read(self, amount: int) -> bytes:
        """
        Read bytes from the data stream.

        :param int amount: the number of bytes to read
        """
        data = self._fp_read(amount)
        if len(data) < amount:
            raise CBORDecodeEOF(
                f"premature end of stream (expected to read {amount} bytes, got {len(data)} "
                "instead)"
            )

        return data

    def decode(self, immutable: bool = False, unshared: bool = False) -> Any:
        """
        Decode the next value from the stream.

        :raises CBORDecodeError: if there is any problem decoding the stream

        """
        if self._decode_depth > self._max_depth:
            raise CBORDecodeError(f"maximum container nesting depth ({self._max_depth}) exceeded")

        if immutable:
            old_immutable = self._immutable
            self._immutable = True
        if unshared:
            old_index = self._share_index
            self._share_index = None

        self._decode_depth += 1
        try:
            initial_byte = self.read(1)[0]
            major_type = initial_byte >> 5
            subtype = initial_byte & 31
            decoder = major_decoders[major_type]
            return decoder(self, subtype)
        finally:
            if immutable:
                self._immutable = old_immutable
            if unshared:
                self._share_index = old_index

            self._decode_depth -= 1
            assert self._decode_depth >= 0
            if self._decode_depth == 0:
                self._shareables.clear()
                self._share_index = None

    def decode_from_bytes(self, buf: bytes) -> object:
        """
        Wrap the given bytestring as a file and call :meth:`decode` with it as
        the argument.

        This method was intended to be used from the ``tag_hook`` hook when an
        object needs to be decoded separately from the rest but while still
        taking advantage of the shared value registry.
        """
        with BytesIO(buf) as fp:
            old_fp = self.fp
            self.fp = fp
            retval = self.decode()
            self.fp = old_fp
            return retval

    @overload
    def _decode_length(self, subtype: int) -> int: ...

    @overload
    def _decode_length(self, subtype: int, allow_indefinite: Literal[True]) -> int | None: ...

    def _decode_length(self, subtype: int, allow_indefinite: bool = False) -> int | None:
        if subtype < 24:
            return subtype
        elif subtype == 24:
            return self.read(1)[0]
        elif subtype == 25:
            return cast(int, struct.unpack(">H", self.read(2))[0])
        elif subtype == 26:
            return cast(int, struct.unpack(">L", self.read(4))[0])
        elif subtype == 27:
            return cast(int, struct.unpack(">Q", self.read(8))[0])
        elif subtype == 31 and allow_indefinite:
            return None
        else:
            raise CBORDecodeValueError(f"unknown unsigned integer subtype 0x{subtype:x}")

    def decode_uint(self, subtype: int) -> int:
        # Major tag 0
        return self.set_shareable(self._decode_length(subtype))

    def decode_negint(self, subtype: int) -> int:
        # Major tag 1
        return self.set_shareable(-self._decode_length(subtype) - 1)

    def decode_bytestring(self, subtype: int) -> bytes:
        # Major tag 2
        length = self._decode_length(subtype, allow_indefinite=True)
        if length is None:
            # Indefinite length
            buf: list[bytes] = []
            while True:
                initial_byte = self.read(1)[0]
                if initial_byte == 0xFF:
                    result = b"".join(buf)
                    break
                elif initial_byte >> 5 == 2:
                    length = self._decode_length(initial_byte & 0x1F)
                    if length is None or length > sys.maxsize:
                        raise CBORDecodeValueError(
                            f"invalid length for indefinite bytestring chunk 0x{length:x}"
                        )
                    value = self.read(length)
                    buf.append(value)
                else:
                    raise CBORDecodeValueError(
                        "non-bytestring found in indefinite length bytestring"
                    )
        else:
            if length > sys.maxsize:
                raise CBORDecodeValueError(f"invalid length for bytestring 0x{length:x}")
            elif length <= 65536:
                result = self.read(length)
            else:
                # Read large bytestrings 65536 (2 ** 16) bytes at a time
                left = length
                buffer = bytearray()
                while left:
                    chunk_size = min(left, 65536)
                    buffer.extend(self.read(chunk_size))
                    left -= chunk_size

                result = bytes(buffer)

            self._stringref_namespace_add(result, length)

        return self.set_shareable(result)

    def decode_string(self, subtype: int) -> str:
        # Major tag 3
        length = self._decode_length(subtype, allow_indefinite=True)
        if length is None:
            # Indefinite length
            # NOTE: It may seem redundant to repeat this code to handle UTF-8
            # strings but there is a reason to do this separately to
            # byte-strings. Specifically, the CBOR spec states (in sec. 2.2):
            #
            #     Text strings with indefinite lengths act the same as byte
            #     strings with indefinite lengths, except that all their chunks
            #     MUST be definite-length text strings.  Note that this implies
            #     that the bytes of a single UTF-8 character cannot be spread
            #     between chunks: a new chunk can only be started at a
            #     character boundary.
            #
            # This precludes using the indefinite bytestring decoder above as
            # that would happily ignore UTF-8 characters split across chunks.
            buf: list[str] = []
            while True:
                initial_byte = self.read(1)[0]
                if initial_byte == 0xFF:
                    result = "".join(buf)
                    break
                elif initial_byte >> 5 == 3:
                    length = self._decode_length(initial_byte & 0x1F)
                    if length is None or length > sys.maxsize:
                        raise CBORDecodeValueError(
                            f"invalid length for indefinite string chunk 0x{length:x}"
                        )

                    try:
                        value = self.read(length).decode("utf-8", self._str_errors)
                    except UnicodeDecodeError as exc:
                        raise CBORDecodeValueError("error decoding unicode string") from exc

                    buf.append(value)
                else:
                    raise CBORDecodeValueError("non-string found in indefinite length string")
        else:
            if length > sys.maxsize:
                raise CBORDecodeValueError(f"invalid length for string 0x{length:x}")

            if length <= 65536:
                try:
                    result = self.read(length).decode("utf-8", self._str_errors)
                except UnicodeDecodeError as exc:
                    raise CBORDecodeValueError("error decoding unicode string") from exc
            else:
                # Read and decode large text strings 65536 (2 ** 16) bytes at a time
                codec = incremental_utf8_decoder(self._str_errors)
                left = length
                result = ""
                while left:
                    chunk_size = min(left, 65536)
                    final = left <= chunk_size
                    try:
                        result += codec.decode(self.read(chunk_size), final)
                    except UnicodeDecodeError as exc:
                        raise CBORDecodeValueError("error decoding unicode string") from exc

                    left -= chunk_size

            self._stringref_namespace_add(result, length)

        return self.set_shareable(result)

    def decode_array(self, subtype: int) -> Sequence[Any]:
        # Major tag 4
        length = self._decode_length(subtype, allow_indefinite=True)
        if length is None:
            # Indefinite length
            items: list[Any] = []
            if not self._immutable:
                self.set_shareable(items)
            while True:
                value = self.decode(unshared=True)
                if value is break_marker:
                    break
                else:
                    items.append(value)
        else:
            if length > sys.maxsize:
                raise CBORDecodeValueError(f"invalid length for array 0x{length:x}")

            items = []
            if not self._immutable:
                self.set_shareable(items)

            for index in range(length):
                items.append(self.decode(unshared=True))

        if self._immutable:
            items_tuple = tuple(items)
            self.set_shareable(items_tuple)
            return items_tuple

        return items

    def decode_map(self, subtype: int) -> Mapping[Any, Any]:
        # Major tag 5
        length = self._decode_length(subtype, allow_indefinite=True)
        if length is None:
            # Indefinite length
            dictionary: dict[Any, Any] = {}
            self.set_shareable(dictionary)
            while True:
                key = self.decode(immutable=True, unshared=True)
                if key is break_marker:
                    break
                else:
                    dictionary[key] = self.decode(unshared=True)
        else:
            dictionary = {}
            self.set_shareable(dictionary)
            for _ in range(length):
                key = self.decode(immutable=True, unshared=True)
                dictionary[key] = self.decode(unshared=True)

        if self._object_hook:
            dictionary = self._object_hook(self, dictionary)
            self.set_shareable(dictionary)
        elif self._immutable:
            frozen_dict = FrozenDict(dictionary)
            self.set_shareable(dictionary)
            return frozen_dict

        return dictionary

    def decode_semantic(self, subtype: int) -> Any:
        # Major tag 6
        tagnum = self._decode_length(subtype)
        tag_policy = self._tag_policy
        if tag_policy is not None:
            # The admission decision is made here, before any built-in
            # semantic object is constructed.
            action = tag_policy(tagnum) if callable(tag_policy) else tag_policy.decide(tagnum)
            if action == TAG_REJECT:
                raise CBORDecodeError(f"semantic tag {tagnum} is not permitted by the tag policy")
            elif action == TAG_PRESERVE:
                # Keep the raw tag, but fully decode the payload (with nested
                # tags still subject to the policy) instead of skipping it.
                tag = CBORTag(tagnum, None)
                self.set_shareable(tag)
                tag.value = self.decode(unshared=True)
                return self.set_shareable(tag)
            elif action != TAG_ALLOW:
                raise CBORDecodeError(
                    f"tag policy returned invalid action {action!r} for tag {tagnum}"
                )

        if semantic_decoder := semantic_decoders.get(tagnum):
            return semantic_decoder(self)

        tag = CBORTag(tagnum, None)
        self.set_shareable(tag)
        tag.value = self.decode(unshared=True)
        if self._tag_hook:
            tag = self._tag_hook(self, tag)

        return self.set_shareable(tag)

    def decode_special(self, subtype: int) -> Any:
        # Simple value
        if subtype < 20:
            # XXX Set shareable?
            return CBORSimpleValue(subtype)

        # Major tag 7
        try:
            return special_decoders[subtype](self)
        except KeyError as e:
            raise CBORDecodeValueError(
                f"Undefined Reserved major type 7 subtype 0x{subtype:x}"
            ) from e

    #
    # Semantic decoders (major tag 6)
    #
    def decode_epoch_date(self) -> date:
        # Semantic tag 100
        value = self.decode()
        return self.set_shareable(date.fromordinal(value + 719163))

    def decode_date_string(self) -> date:
        # Semantic tag 1004
        value = self.decode()
        return self.set_shareable(date.fromisoformat(value))

    def decode_datetime_string(self) -> datetime:
        # Semantic tag 0
        value = self.decode()
        match = timestamp_re.match(value)
        if match:
            (
                year,
                month,
                day,
                hour,
                minute,
                second,
                secfrac,
                offset_sign,
                offset_h,
                offset_m,
            ) = match.groups()
            if secfrac is None:
                microsecond = 0
            else:
                microsecond = int(f"{secfrac:<06}")

            if offset_h:
                if offset_sign == "-":
                    sign = -1
                else:
                    sign = 1
                hours = int(offset_h) * sign
                minutes = int(offset_m) * sign
                tz = timezone(timedelta(hours=hours, minutes=minutes))
            else:
                tz = timezone.utc

            return self.set_shareable(
                datetime(
                    int(year),
                    int(month),
                    int(day),
                    int(hour),
                    int(minute),
                    int(second),
                    microsecond,
                    tz,
                )
            )
        else:
            raise CBORDecodeValueError(f"invalid datetime string: {value!r}")

    def decode_epoch_datetime(self) -> datetime:
        # Semantic tag 1
        value = self.decode()

        try:
            tmp = datetime.fromtimestamp(value, timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise CBORDecodeValueError("error decoding datetime from epoch") from exc

        return self.set_shareable(tmp)

    def decode_positive_bignum(self) -> int:
        # Semantic tag 2
        from binascii import hexlify

        value = self.decode()
        if not isinstance(value, bytes):
            raise CBORDecodeValueError("invalid bignum value " + str(value))

        return self.set_shareable(int(hexlify(value), 16))

    def decode_negative_bignum(self) -> int:
        # Semantic tag 3
        return self.set_shareable(-self.decode_positive_bignum() - 1)

    def decode_fraction(self) -> Decimal:
        # Semantic tag 4
        from decimal import Decimal

        try:
            exp, sig = self.decode()
        except (TypeError, ValueError) as e:
            raise CBORDecodeValueError("Incorrect tag 4 payload") from e
        tmp = Decimal(sig).as_tuple()
        return self.set_shareable(Decimal((tmp.sign, tmp.digits, exp)))

    def decode_bigfloat(self) -> Decimal:
        # Semantic tag 5
        from decimal import Decimal

        try:
            exp, sig = self.decode()
        except (TypeError, ValueError) as e:
            raise CBORDecodeValueError("Incorrect tag 5 payload") from e

        return self.set_shareable(Decimal(sig) * (2 ** Decimal(exp)))

    def decode_stringref(self) -> str | bytes:
        # Semantic tag 25
        if self._stringref_namespace is None:
            raise CBORDecodeValueError("string reference outside of namespace")

        index: int = self.decode()
        try:
            value = self._stringref_namespace[index]
        except IndexError:
            raise CBORDecodeValueError(f"string reference {index} not found")

        return value

    def decode_shareable(self) -> object:
        # Semantic tag 28
        old_index = self._share_index
        self._share_index = len(self._shareables)
        self._shareables.append(None)
        try:
            return self.decode()
        finally:
            self._share_index = old_index

    def decode_sharedref(self) -> Any:
        # Semantic tag 29
        value = self.decode(unshared=True)
        try:
            shared = self._shareables[value]
        except IndexError:
            raise CBORDecodeValueError(f"shared reference {value} not found")

        if shared is None:
            raise CBORDecodeValueError(f"shared value {value} has not been initialized")
        else:
            return shared

    def decode_complex(self) -> complex:
        # Semantic tag 43000
        inputval = self.decode(immutable=True, unshared=True)
        try:
            value = complex(*inputval)
        except TypeError as exc:
            if not isinstance(inputval, tuple):
                raise CBORDecodeValueError(
                    "error decoding complex: input value was not a tuple"
                ) from None

            raise CBORDecodeValueError("error decoding complex") from exc

        return self.set_shareable(value)

    def decode_rational(self) -> Fraction:
        # Semantic tag 30
        from fractions import Fraction

        inputval = self.decode(immutable=True, unshared=True)
        try:
            value = Fraction(*inputval)
        except (TypeError, ZeroDivisionError) as exc:
            if not isinstance(inputval, tuple):
                raise CBORDecodeValueError(
                    "error decoding rational: input value was not a tuple"
                ) from None

            raise CBORDecodeValueError("error decoding rational") from exc

        return self.set_shareable(value)

    def decode_regexp(self) -> re.Pattern[str]:
        # Semantic tag 35
        try:
            value = re.compile(self.decode())
        except re.error as exc:
            raise CBORDecodeValueError("error decoding regular expression") from exc

        return self.set_shareable(value)

    def decode_mime(self) -> Message:
        # Semantic tag 36
        from email.parser import Parser

        try:
            value = Parser().parsestr(self.decode())
        except TypeError as exc:
            raise CBORDecodeValueError("error decoding MIME message") from exc

        return self.set_shareable(value)

    def decode_uuid(self) -> UUID:
        # Semantic tag 37
        from uuid import UUID

        try:
            value = UUID(bytes=self.decode())
        except (TypeError, ValueError) as exc:
            raise CBORDecodeValueError("error decoding UUID value") from exc

        return self.set_shareable(value)

    def decode_stringref_namespace(self) -> Any:
        # Semantic tag 256
        old_namespace = self._stringref_namespace
        self._stringref_namespace = []
        try:
            return self.decode()
        finally:
            # Restore the enclosing namespace even if the payload was
            # rejected by the tag policy, so a reused decoder never keeps a
            # namespace it no longer owns.
            self._stringref_namespace = old_namespace

    def decode_set(self) -> set[Any] | frozenset[Any]:
        # Semantic tag 258
        if self._immutable:
            return self.set_shareable(frozenset(self.decode(immutable=True)))
        else:
            return self.set_shareable(set(self.decode(immutable=True)))

    def decode_ipaddress(self) -> IPv4Address | IPv6Address | CBORTag:
        # Semantic tag 260
        from ipaddress import ip_address

        buf = self.decode()
        if not isinstance(buf, bytes) or len(buf) not in (4, 6, 16):
            raise CBORDecodeValueError(f"invalid ipaddress value {buf!r}")
        elif len(buf) in (4, 16):
            return self.set_shareable(ip_address(buf))
        elif len(buf) == 6:
            # MAC address
            return self.set_shareable(CBORTag(260, buf))

        raise CBORDecodeValueError(f"invalid ipaddress value {buf!r}")

    def decode_ipnetwork(self) -> IPv4Network | IPv6Network:
        # Semantic tag 261
        from ipaddress import ip_network

        net_map = self.decode()
        if isinstance(net_map, Mapping) and len(net_map) == 1:
            for net in net_map.items():
                try:
                    return self.set_shareable(ip_network(net, strict=False))
                except (TypeError, ValueError):
                    break

        raise CBORDecodeValueError(f"invalid ipnetwork value {net_map!r}")

    def decode_self_describe_cbor(self) -> Any:
        # Semantic tag 55799
        return self.decode()

    #
    # Special decoders (major tag 7)
    #

    def decode_simple_value(self) -> CBORSimpleValue:
        # XXX Set shareable?
        return CBORSimpleValue(self.read(1)[0])

    def decode_float16(self) -> float:
        return self.set_shareable(cast(float, struct.unpack(">e", self.read(2))[0]))

    def decode_float32(self) -> float:
        return self.set_shareable(cast(float, struct.unpack(">f", self.read(4))[0]))

    def decode_float64(self) -> float:
        return self.set_shareable(cast(float, struct.unpack(">d", self.read(8))[0]))


major_decoders: dict[int, Callable[[CBORDecoder, int], Any]] = {
    0: CBORDecoder.decode_uint,
    1: CBORDecoder.decode_negint,
    2: CBORDecoder.decode_bytestring,
    3: CBORDecoder.decode_string,
    4: CBORDecoder.decode_array,
    5: CBORDecoder.decode_map,
    6: CBORDecoder.decode_semantic,
    7: CBORDecoder.decode_special,
}

special_decoders: dict[int, Callable[[CBORDecoder], Any]] = {
    20: lambda self: False,
    21: lambda self: True,
    22: lambda self: None,
    23: lambda self: undefined,
    24: CBORDecoder.decode_simple_value,
    25: CBORDecoder.decode_float16,
    26: CBORDecoder.decode_float32,
    27: CBORDecoder.decode_float64,
    31: lambda self: break_marker,
}

semantic_decoders: dict[int, Callable[[CBORDecoder], Any]] = {
    0: CBORDecoder.decode_datetime_string,
    1: CBORDecoder.decode_epoch_datetime,
    2: CBORDecoder.decode_positive_bignum,
    3: CBORDecoder.decode_negative_bignum,
    4: CBORDecoder.decode_fraction,
    5: CBORDecoder.decode_bigfloat,
    25: CBORDecoder.decode_stringref,
    28: CBORDecoder.decode_shareable,
    29: CBORDecoder.decode_sharedref,
    30: CBORDecoder.decode_rational,
    35: CBORDecoder.decode_regexp,
    36: CBORDecoder.decode_mime,
    37: CBORDecoder.decode_uuid,
    100: CBORDecoder.decode_epoch_date,
    256: CBORDecoder.decode_stringref_namespace,
    258: CBORDecoder.decode_set,
    260: CBORDecoder.decode_ipaddress,
    261: CBORDecoder.decode_ipnetwork,
    1004: CBORDecoder.decode_date_string,
    43000: CBORDecoder.decode_complex,
    55799: CBORDecoder.decode_self_describe_cbor,
}


def loads(
    s: bytes | bytearray | memoryview,
    tag_hook: Callable[[CBORDecoder, CBORTag], Any] | None = None,
    object_hook: Callable[[CBORDecoder, dict[Any, Any]], Any] | None = None,
    str_errors: Literal["strict", "error", "replace"] = "strict",
    read_size: int = 1,
    *,
    max_depth: int = 400,
    tag_policy: TagPolicyInput = None,
) -> Any:
    """
    Deserialize an object from a bytestring.

    :param bytes s:
        the bytestring to deserialize
    :param tag_hook:
        callable that takes 2 arguments: the decoder instance, and the :class:`.CBORTag`
        to be decoded. This callback is invoked for any tags for which there is no
        built-in decoder. The return value is substituted for the :class:`.CBORTag`
        object in the deserialized output
    :param object_hook:
        callable that takes 2 arguments: the decoder instance, and a dictionary. This
        callback is invoked for each deserialized :class:`dict` object. The return value
        is substituted for the dict in the deserialized output.
    :param str_errors:
        determines how to handle unicode decoding errors (see the `Error Handlers`_
        section in the standard library documentation for details)
    :param read_size:
        the minimum number of bytes to read at a time.
        Setting this to a higher value like 4096 improves performance.
        Ignored in the pure Python implementation, but included for API compatibility.
    :param max_depth:
        the maximum allowed container nesting depth
    :param tag_policy:
        an explicit admission policy for semantic tags (a :class:`TagPolicy`,
        a mapping of tag numbers to actions or a callable). When ``None``,
        the default semantic tag behavior is used
    :return:
        the deserialized object

    .. _Error Handlers: https://docs.python.org/3/library/codecs.html#error-handlers

    """
    with BytesIO(s) as fp:
        return CBORDecoder(
            fp,
            tag_hook=tag_hook,
            object_hook=object_hook,
            str_errors=str_errors,
            read_size=read_size,
            max_depth=max_depth,
            tag_policy=tag_policy,
        ).decode()


def load(
    fp: IO[bytes],
    tag_hook: Callable[[CBORDecoder, CBORTag], Any] | None = None,
    object_hook: Callable[[CBORDecoder, dict[Any, Any]], Any] | None = None,
    str_errors: Literal["strict", "error", "replace"] = "strict",
    read_size: int = 1,
    *,
    max_depth: int = 400,
    tag_policy: TagPolicyInput = None,
) -> Any:
    """
    Deserialize an object from an open file.

    :param fp:
        the file to read from (any file-like object opened for reading in binary mode)
    :param tag_hook:
        callable that takes 2 arguments: the decoder instance, and the :class:`.CBORTag`
        to be decoded. This callback is invoked for any tags for which there is no
        built-in decoder. The return value is substituted for the :class:`.CBORTag`
        object in the deserialized output
    :param object_hook:
        callable that takes 2 arguments: the decoder instance, and a dictionary. This
        callback is invoked for each deserialized :class:`dict` object. The return value
        is substituted for the dict in the deserialized output.
    :param str_errors:
        determines how to handle unicode decoding errors (see the `Error Handlers`_
        section in the standard library documentation for details)
    :param read_size:
        the minimum number of bytes to read at a time.
        Setting this to a higher value like 4096 improves performance,
        but is likely to read past the end of the CBOR value, advancing the stream
        position beyond the decoded data. This only matters if you need to reuse the
        stream after decoding.
        Ignored in the pure Python implementation, but included for API compatibility.
    :param max_depth:
        the maximum allowed container nesting depth
    :param tag_policy:
        an explicit admission policy for semantic tags (a :class:`TagPolicy`,
        a mapping of tag numbers to actions or a callable). When ``None``,
        the default semantic tag behavior is used
    :return:
        the deserialized object

    .. _Error Handlers: https://docs.python.org/3/library/codecs.html#error-handlers

    """
    return CBORDecoder(
        fp,
        tag_hook=tag_hook,
        object_hook=object_hook,
        str_errors=str_errors,
        read_size=read_size,
        max_depth=max_depth,
        tag_policy=tag_policy,
    ).decode()
