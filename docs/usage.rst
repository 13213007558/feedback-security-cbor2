Basic usage
===========

.. py:currentmodule:: cbor2

Serializing and deserializing with cbor2 is pretty straightforward::

    from cbor2 import dump, dumps, load, loads

    # Serialize an object as a bytestring
    data = dumps(['hello', 'world'])

    # Deserialize a bytestring
    obj = loads(data)

    # Efficiently deserialize from a file
    with open('input.cbor', 'rb') as fp:
        obj = load(fp)

    # Efficiently serialize an object to a file
    with open('output.cbor', 'wb') as fp:
        dump(obj, fp)

Some data types, however, require extra considerations, as detailed below.

Date/time handling
------------------

The CBOR specification does not support naïve datetimes (that is, datetimes where ``tzinfo`` is
missing). When the encoder encounters such a datetime, it needs to know which timezone it belongs
to. To this end, you can specify a default timezone by passing a :class:`~datetime.tzinfo` instance
to :func:`dump`/:func:`dumps` call as the ``timezone`` argument.
Decoded datetimes are always timezone aware.

By default, datetimes are serialized in a manner that retains their timezone offsets. You can
optimize the data stream size by passing ``datetime_as_timestamp=False`` to
:func:`dump`/:func:`dumps`, but this causes the timezone offset
information to be lost.

In versions prior to 4.2 the encoder would convert a ``datetime.date`` object into a
``datetime.datetime`` prior to writing. This can cause confusion on decoding so this has been
disabled by default in the next version. The behaviour can be re-enabled as follows::

    from cbor2 import dumps
    from datetime import date, timezone

    # Serialize dates as datetimes
    encoded = dumps(date(2019, 10, 28), timezone=timezone.utc, date_as_datetime=True)

A default timezone offset must be provided also.

Cyclic (recursive) data structures
----------------------------------

If the encoder encounters a shareable object (ie. list or dict) that it has seen before, it will
by default raise :exc:`CBOREncodeError` indicating that a cyclic reference has been
detected and value sharing was not enabled. CBOR has, however, an extension specification that
allows the encoder to reference a previously encoded value without processing it again. This makes
it possible to serialize such cyclic references, but value sharing has to be enabled by passing
``value_sharing=True`` to :func:`dump`/:func:`dumps`.

.. warning:: Support for value sharing is rare in other CBOR implementations, so think carefully
    whether you want to enable it. It also causes some line overhead, as all potentially shareable
    values must be tagged as such.

String references
-----------------

When ``string_referencing=True`` is passed to
:func:`dump`/:func:`dumps`, if the encoder would encode a string that
it has previously encoded and where a reference would be shorter than the encoded string, it
instead encodes a reference to the nth sufficiently long string already encoded.

.. warning:: Support for string referencing is rare in other CBOR implementations, so think carefully
    whether you want to enable it.

Performance tuning
------------------

By default, the decoder only reads the exact amount of bytes it needs. But this can negatively
impact the performance due to the potentially large number of individual read operations.
To make it faster, you can pass a different ``read_size`` parameter (say, 4096), to :func:`load`,
:func:`loads` or :class:`CBORDecoder`.

.. warning:: If the input stream contains data other than the CBOR stream, that data (or parts of)
    may be lost.

Tag support
-----------

In addition to all standard CBOR tags, this library supports many extended tags:

===== ======================================== ====================================================
Tag   Semantics                                Python type(s)
===== ======================================== ====================================================
0     Standard date/time string                datetime.date / datetime.datetime
1     Epoch-based date/time                    datetime.date / datetime.datetime
2     Positive bignum                          int / long
3     Negative bignum                          int / long
4     Decimal fraction                         decimal.Decimal
5     Bigfloat                                 decimal.Decimal
25    String reference                         str / bytes
28    Mark shared value                        N/A
29    Reference shared value                   N/A
30    Rational number                          fractions.Fraction
35    Regular expression                       re.Pattern (result of ``re.compile(...)``)
36    MIME message                             email.message.Message
37    Binary UUID                              uuid.UUID
256   String reference namespace               N/A
258   Set of unique items                      set
260   Network address                          :class:`ipaddress.IPv4Address` (or IPv6)
261   Network prefix                           :class:`ipaddress.IPv4Network` (or IPv6)
43000 Single complex number                    complex
55799 Self-Described CBOR                      object
===== ======================================== ====================================================

Arbitary tags can be represented with the :class:`CBORTag` class.

If you want to write a file that is detected as CBOR by the Unix ``file`` utility, wrap your data in
a :class:`CBORTag` object like so::

    from cbor2 import dump, CBORTag

    with open('output.cbor', 'wb') as fp:
        dump(CBORTag(55799, obj), fp)

This will be ignored on decode and the original data content will be returned.

Embedded CBOR documents (tag 24)
---------------------------------

Some protocols carry a second, self-contained CBOR document inside a CBOR byte string using
`tag 24 (encoded CBOR data item)`_. By default such a tag is decoded like any other tag, leaving
the raw byte string untouched::

    >>> loads(bytes.fromhex("d8184101"))
    CBORTag(24, b'\\x01')

When the bytes come from an untrusted peer you can opt in to validating them by passing
``embedded_validation=True`` to :func:`load`, :func:`loads` or :class:`CBORDecoder`::

    >>> from cbor2 import EmbeddedCBOR
    >>> loads(bytes.fromhex("d8184101"), embedded_validation=True)
    EmbeddedCBOR(b'\\x01', 1)

With validation enabled, every tag 24 payload must be a single definite-length byte string that
contains exactly one complete CBOR data item. Empty payloads, truncated data and any trailing
bytes after the first data item are rejected, and the error message identifies the nesting level
of the offending document.

Each embedded document is decoded in a fresh reference namespace:

* outer shared references (tags 28/29) and string references (tags 25/256) cannot be borrowed
  inside an embedded document, and
* indexes created inside an embedded document do not leak back into the enclosing document.

The caller's ``tag_hook``, ``object_hook``, ``str_errors`` and ``max_depth`` settings are applied
recursively to embedded documents. Two global budgets protect the whole decode and are not
replenished when entering a new document:

* ``max_embedded_depth`` limits how many tag 24 documents may be nested inside one another, and
* ``max_embedded_bytes`` limits the cumulative number of tag 24 payload bytes processed (payloads
  of nested and sibling documents all count toward the same total).

A successful result is an :class:`EmbeddedCBOR` that retains the original payload bytes alongside
the decoded value. Note that this only means the bytes form a single, well-formed CBOR data item;
parsing is not a cryptographic signature check and must not be treated as proof of authenticity.

.. _tag 24 (encoded CBOR data item): https://www.rfc-editor.org/rfc/rfc8949.html#name-encoded-cbor-data-item

Use Cases
---------

Here are some things that the cbor2 library could be (and in some cases, is being) used for:

- Experimenting with network protocols based on CBOR encoding
- Designing new data storage formats
- Submitting binary documents to ElasticSearch without base64 encoding overhead
- Storing and validating file metadata in a secure backup system
- RPC which supports Decimals with low overhead
