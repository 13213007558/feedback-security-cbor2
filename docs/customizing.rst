Customizing encoding and decoding
=================================

.. py:currentmodule:: cbor2

Both the encoder and decoder can be customized to support a wider range of types.

On the encoder side, this is accomplished by passing a callback as the ``default`` constructor
argument. This callback will receive an object that the encoder could not serialize on its own.
The callback should then return a value that the encoder can serialize on its own, although the
return value is allowed to contain objects that also require the encoder to use the callback, as
long as it won't result in an infinite loop.

On the decoder side, you have two options: ``tag_hook`` and ``object_hook``. The former is called
by the decoder to process any semantic tags that have no predefined decoders. The latter is called
for any newly decoded ``dict`` objects, and is mostly useful for implementing a JSON compatible
custom type serialization scheme. Unless your requirements restrict you to JSON compatible types
only, it is recommended to use ``tag_hook`` for this purpose.

Using the CBOR tags for custom types
------------------------------------

The most common way to use ``default`` is to call :meth:`CBOREncoder.encode`
to add a custom tag in the data stream, with the payload as the value::

    class Point:
        def __init__(self, x, y):
            self.x = x
            self.y = y

    def default_encoder(encoder, value):
        # Tag number 4000 was chosen arbitrarily
        encoder.encode(CBORTag(4000, [value.x, value.y]))

The corresponding ``tag_hook`` would be::

    def tag_hook(decoder, tag, shareable_index=None):
        if tag.tag != 4000:
            return tag

        # tag.value is now the [x, y] list we serialized before
        return Point(*tag.value)

Using dicts to carry custom types
---------------------------------

The same could be done with ``object_hook``, except less efficiently::

    def default_encoder(encoder, value):
        encoder.encode(dict(typename='Point', x=value.x, y=value.y))

    def object_hook(decoder, value):
        if value.get('typename') != 'Point':
            return value

        return Point(value['x'], value['y'])

You should make sure that whatever way you decide to use for telling apart your "specially marked"
dicts from arbitrary data dicts won't mistake on for the other.

Explicit tag admission policies
-------------------------------

``tag_hook`` only sees tags that have no built-in decoder: tags such as ``0``/``1`` (dates),
``2``/``3`` (big numbers), ``4``/``5`` (decimals) or ``258`` (sets) are converted into Python
objects automatically, before any hook runs. When decoding CBOR from an untrusted source you may
want to decide per tag whether it is interpreted, kept as raw data or refused altogether. The
pure Python decoder accepts a ``tag_policy`` for this::

    from cbor2 import loads, TagPolicy, TAG_ALLOW, TAG_PRESERVE, TAG_REJECT

    policy = TagPolicy(
        {
            0: TAG_ALLOW,      # interpret datetime strings
            1: TAG_REJECT,     # refuse epoch datetimes (no datetime object is built)
            258: TAG_PRESERVE, # keep the raw CBORTag instead of building a set
        },
        default_action=TAG_PRESERVE,
    )

The three actions are:

* ``TAG_ALLOW`` – run the normal built-in decoder, or invoke ``tag_hook`` when no built-in decoder
  exists for the tag
* ``TAG_PRESERVE`` – keep a :class:`CBORTag` whose payload is still fully decoded (nested tags
  remain subject to the same policy)
* ``TAG_REJECT`` – raise :class:`CBORDecodeError` before any semantic object is constructed

The decision is made before the built-in semantic conversion runs, so a rejected date, decimal or
big number never triggers the corresponding constructor. Preserved tags still parse their complete
payload and remain usable (and hashable) as map keys. A plain ``{tag: action}`` mapping or a
callable ``tag_number -> action`` can be passed in place of a :class:`TagPolicy`; a bare mapping
defaults to ``TAG_PRESERVE`` for tags it does not mention.

The structural tags 25 (string reference), 28 (shareable), 29 (shared reference) and 256 (string
reference namespace) change how later values in the stream are resolved, so they cannot be
preserved as an empty shell. They must be explicitly allowed or rejected; otherwise a
:class:`CBORDecodeError` is raised. If a policy rejection aborts a decode, the decoder's shared
value and string reference registries are restored to their enclosing state.

A ready-made conservative configuration is available through :meth:`TagPolicy.safe`. It admits
only basic CBOR data and the self-describe tag (55799), explicitly rejects the structural tags, and
preserves every other tag – including unknown ones – as data instead of invoking a custom handler::

    >>> loads(unhexlify('d917706548656c6c6f'), tag_policy=TagPolicy.safe())
    CBORTag(6000, 'Hello')

When ``tag_policy`` is not given (the default), every built-in semantic tag keeps its historical
behavior and unknown tags are still passed to ``tag_hook``.

Value sharing with custom types
-------------------------------

In order to properly encode and decode cyclic references with custom types, some special care has
to be taken. Suppose you have a custom type as below, where every child object contains a reference
to its parent and the parent contains a list of children::

    from cbor2 import dumps, loads, shareable_encoder, CBORTag


    class MyType:
        def __init__(self, parent=None):
            self.parent = parent
            self.children = []
            if parent:
                self.parent.children.append(self)

This would not normally be serializable, as it would lead to an endless loop (in the worst case)
and raise some exception (in the best case). Now, enter CBOR's extension tags 28 and 29. These tags
make it possible to add special markers into the data stream which can be later referenced and
substituted with the object marked earlier.

To do this, in ``default`` hooks used with the encoder you will need to use the
:meth:`shareable_encoder` decorator on your ``default`` hook function. It will
automatically automatically add the object to the shared values registry on the encoder and prevent
it from being serialized twice (instead writing a reference to the data stream)::

    @shareable_encoder
    def default_encoder(encoder, value):
        # The state has to be serialized separately so that the decoder would have a chance to
        # create an empty instance before the shared value references are decoded
        serialized_state = encoder.encode_to_bytes(value.__dict__)
        encoder.encode(CBORTag(3000, serialized_state))

On the decoder side, you will need to initialize an empty instance for shared value lookup before
the object's state (which may contain references to it) is decoded.
This is done with the :meth:`CBORDecoder.set_shareable` method::

    def tag_hook(decoder, tag, shareable_index=None):
        # Return all other tags as-is
        if tag.tag != 3000:
            return tag

        # Create a raw instance before initializing its state to make it possible for cyclic
        # references to work
        instance = MyType.__new__(MyType)
        decoder.set_shareable(shareable_index, instance)

        # Separately decode the state of the new object and then apply it
        state = decoder.decode_from_bytes(tag.value)
        instance.__dict__.update(state)
        return instance

You could then verify that the cyclic references have been restored after deserialization::

    parent = MyType()
    child1 = MyType(parent)
    child2 = MyType(parent)
    serialized = dumps(parent, default=default_encoder, value_sharing=True)

    new_parent = loads(serialized, tag_hook=tag_hook)
    assert new_parent.children[0].parent is new_parent
    assert new_parent.children[1].parent is new_parent

Decoding Tagged items as keys
-----------------------------

Since the CBOR specification allows any type to be used as a key in the mapping type, the decoder
provides a flag that indicates it is expecting an immutable (and by implication hashable) type. If
your custom class cannot be used this way you can raise an exception if this flag is set::

    def tag_hook(decoder, tag, shareable_index=None):
        if tag.tag != 3000:
            return tag

        if decoder.immutable:
            raise CBORDecodeException('MyType cannot be used as a key or set member')

        return MyType(*tag.value)

An example where the data could be used as a dict key::

    from collections import namedtuple

    Pair = namedtuple('Pair', 'first second')

    def tag_hook(decoder, tag, shareable_index=None):
        if tag.tag != 4000:
            return tag

        return Pair(*tag.value)

The ``object_hook`` can check for the immutable flag in the same way.
