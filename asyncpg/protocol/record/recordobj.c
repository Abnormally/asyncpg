/* Big parts of this file are copied (with modifications) from
   CPython/Objects/tupleobject.c.

   Portions Copyright (c) PSF (and other CPython copyright holders).
   Portions Copyright (c) 2016-present MagicStack Inc.
   License: PSFL v2; see CPython/LICENSE for details.
*/

#include "recordobj.h"

#ifdef _PyObject_GC_IS_TRACKED
    #define _ApgObject_GC_IS_TRACKED _PyObject_GC_IS_TRACKED
#elif PyObject_GC_IsTracked
    #define _ApgObject_GC_IS_TRACKED PyObject_GC_IsTracked
#endif

static PyObject * record_iter(PyObject *);
static PyObject * record_new_items_iter(PyObject *);

static ApgRecordObject *free_list[ApgRecord_MAXSAVESIZE];
static int numfree[ApgRecord_MAXSAVESIZE];

static size_t MAX_RECORD_SIZE = (
    ((size_t)PY_SSIZE_T_MAX - sizeof(ApgRecordObject) - sizeof(PyObject *))
    / sizeof(PyObject *)
);


PyObject *
ApgRecord_New(PyTypeObject *type, PyObject *desc, Py_ssize_t size)
{
    ApgRecordObject *o;
    Py_ssize_t i;

    if (size < 0 || desc == NULL || !ApgRecordDesc_CheckExact(desc)) {
        PyErr_BadInternalCall();
        return NULL;
    }

    if (type == &ApgRecord_Type) {
        if (size < ApgRecord_MAXSAVESIZE && (o = free_list[size]) != NULL) {
            free_list[size] = (ApgRecordObject *) o->ob_item[0];
            numfree[size]--;
            _Py_NewReference((PyObject *)o);
        }
        else {
            /* Check for overflow */
            if ((size_t)size > MAX_RECORD_SIZE) {
                return PyErr_NoMemory();
            }
            o = PyObject_GC_NewVar(ApgRecordObject, &ApgRecord_Type, size);
            if (o == NULL) {
                return NULL;
            }
        }

        PyObject_GC_Track(o);
    } else {
        assert(PyType_IsSubtype(type, &ApgRecord_Type));

        if ((size_t)size > MAX_RECORD_SIZE) {
            return PyErr_NoMemory();
        }
        o = (ApgRecordObject *)type->tp_alloc(type, size);

        #ifdef _ApgObject_GC_IS_TRACKED
        if (!_ApgObject_GC_IS_TRACKED(o)) {
            PyErr_SetString(
                PyExc_TypeError,
                "record subclass is not tracked by GC"
            );
            return NULL;
        }
        #endif
    }

    for (i = 0; i < size; i++) {
        o->ob_item[i] = NULL;
    }

    Py_INCREF(desc);
    o->desc = (ApgRecordDescObject*)desc;
    o->self_hash = -1;
    return (PyObject *) o;
}


static void
record_dealloc(ApgRecordObject *o)
{
    Py_ssize_t i;
    Py_ssize_t len = Py_SIZE(o);

    PyObject_GC_UnTrack(o);

    o->self_hash = -1;

    Py_CLEAR(o->desc);

    Py_TRASHCAN_SAFE_BEGIN(o)
    if (len > 0) {
        i = len;
        while (--i >= 0) {
            Py_CLEAR(o->ob_item[i]);
        }

        if (len < ApgRecord_MAXSAVESIZE &&
            numfree[len] < ApgRecord_MAXFREELIST &&
            ApgRecord_CheckExact(o))
        {
            o->ob_item[0] = (PyObject *) free_list[len];
            numfree[len]++;
            free_list[len] = o;
            goto done; /* return */
        }
    }
    Py_TYPE(o)->tp_free((PyObject *)o);
done:
    Py_TRASHCAN_SAFE_END(o)
}


static int
record_traverse(ApgRecordObject *o, visitproc visit, void *arg)
{
    Py_ssize_t i;

    Py_VISIT(o->desc);

    for (i = Py_SIZE(o); --i >= 0;) {
        if (o->ob_item[i] != NULL) {
            Py_VISIT(o->ob_item[i]);
        }
    }

    return 0;
}


static Py_ssize_t
record_length(ApgRecordObject *o)
{
    return Py_SIZE(o);
}


#if PY_VERSION_HEX >= 0x03080000

#if SIZEOF_PY_UHASH_T > 4
#define _PyHASH_XXPRIME_1 ((Py_uhash_t)11400714785074694791ULL)
#define _PyHASH_XXPRIME_2 ((Py_uhash_t)14029467366897019727ULL)
#define _PyHASH_XXPRIME_5 ((Py_uhash_t)2870177450012600261ULL)
#define _PyHASH_XXROTATE(x) ((x << 31) | (x >> 33))  /* Rotate left 31 bits */
#else
#define _PyHASH_XXPRIME_1 ((Py_uhash_t)2654435761UL)
#define _PyHASH_XXPRIME_2 ((Py_uhash_t)2246822519UL)
#define _PyHASH_XXPRIME_5 ((Py_uhash_t)374761393UL)
#define _PyHASH_XXROTATE(x) ((x << 13) | (x >> 19))  /* Rotate left 13 bits */
#endif

static Py_hash_t
record_hash(ApgRecordObject *v)
{
    Py_uhash_t acc = _PyHASH_XXPRIME_5;
    size_t i, len = (size_t)Py_SIZE(v);
    PyObject **els = v->ob_item;
    for (i = 0; i < len; i++) {
        Py_uhash_t lane = (Py_uhash_t)PyObject_Hash(els[i]);
        if (lane == (Py_uhash_t)-1) {
            return -1;
        }
        acc += lane * _PyHASH_XXPRIME_2;
        acc = _PyHASH_XXROTATE(acc);
        acc *= _PyHASH_XXPRIME_1;
    }

    /* Add input length, mangled to keep the historical value of hash(()). */
    acc += len ^ (_PyHASH_XXPRIME_5 ^ 3527539UL);

    if (acc == (Py_uhash_t)-1) {
        return 1546275796;
    }
    return (Py_hash_t)acc;
}

#else

#ifndef _PyHASH_MULTIPLIER
    /* Prime multiplier used in string and various other hashes. */
    /* https://github.com/python/cpython/blob/f453221c8b80e0570066a9375337f208d50e6406/Include/pyhash.h */
    #define _PyHASH_MULTIPLIER 1000003UL  /* 0xf4243 */
#endif

static Py_hash_t
record_hash(ApgRecordObject *v)
{
    Py_uhash_t x;  /* Unsigned for defined overflow behavior. */
    Py_hash_t y;
    Py_ssize_t len;
    PyObject **p;
    Py_uhash_t mult;

    if (v->self_hash != -1) {
        return v->self_hash;
    }

    len = Py_SIZE(v);
    mult = _PyHASH_MULTIPLIER;

    x = 0x345678UL;
    p = v->ob_item;
    while (--len >= 0) {
        y = PyObject_Hash(*p++);
        if (y == -1) {
            return -1;
        }
        x = (x ^ (Py_uhash_t)y) * mult;
        /* the cast might truncate len; that doesn't change hash stability */
        mult += (Py_uhash_t)(82520UL + (size_t)len + (size_t)len);
    }
    x += 97531UL;
    if (x == (Py_uhash_t)-1) {
        x = (Py_uhash_t)-2;
    }
    v->self_hash = (Py_hash_t)x;
    return (Py_hash_t)x;
}

#endif


static PyObject *
record_richcompare(PyObject *v, PyObject *w, int op)
{
    Py_ssize_t i;
    Py_ssize_t vlen, wlen;
    int v_is_tuple = 0;
    int w_is_tuple = 0;
    int v_is_record = 0;
    int w_is_record = 0;
    int comp;

    if (PyTuple_Check(v)) {
        v_is_tuple = 1;
    }
    else if (ApgRecord_CheckExact(v)) {
        v_is_record = 1;
    }
    else if (!ApgRecord_Check(v)) {
        Py_RETURN_NOTIMPLEMENTED;
    }

    if (PyTuple_Check(w)) {
        w_is_tuple = 1;
    }
    else if (ApgRecord_CheckExact(w)) {
        w_is_record = 1;
    }
    else if (!ApgRecord_Check(w)) {
        Py_RETURN_NOTIMPLEMENTED;
    }


#define V_ITEM(i) \
    (v_is_tuple ? \
        PyTuple_GET_ITEM(v, i) \
        : (v_is_record ? ApgRecord_GET_ITEM(v, i) : PySequence_GetItem(v, i)))
#define W_ITEM(i) \
    (w_is_tuple ? \
        PyTuple_GET_ITEM(w, i) \
        : (w_is_record ? ApgRecord_GET_ITEM(w, i) : PySequence_GetItem(w, i)))

    vlen = Py_SIZE(v);
    wlen = Py_SIZE(w);

    if (op == Py_EQ && vlen != wlen) {
        /* Checking if v == w, but len(v) != len(w): return False */
        Py_RETURN_FALSE;
    }

    if (op == Py_NE && vlen != wlen) {
        /* Checking if v != w, and len(v) != len(w): return True */
        Py_RETURN_TRUE;
    }

    /* Search for the first index where items are different.
     * Note that because tuples are immutable, it's safe to reuse
     * vlen and wlen across the comparison calls.
     */
    for (i = 0; i < vlen && i < wlen; i++) {
        comp = PyObject_RichCompareBool(V_ITEM(i), W_ITEM(i), Py_EQ);
        if (comp < 0) {
            return NULL;
        }
        if (!comp) {
            break;
        }
    }

    if (i >= vlen || i >= wlen) {
        /* No more items to compare -- compare sizes */
        int cmp;
        switch (op) {
            case Py_LT: cmp = vlen <  wlen; break;
            case Py_LE: cmp = vlen <= wlen; break;
            case Py_EQ: cmp = vlen == wlen; break;
            case Py_NE: cmp = vlen != wlen; break;
            case Py_GT: cmp = vlen >  wlen; break;
            case Py_GE: cmp = vlen >= wlen; break;
            default: return NULL; /* cannot happen */
        }
        if (cmp) {
            Py_RETURN_TRUE;
        }
        else {
            Py_RETURN_FALSE;
        }
    }

    /* We have an item that differs -- shortcuts for EQ/NE */
    if (op == Py_EQ) {
        Py_RETURN_FALSE;
    }
    if (op == Py_NE) {
        Py_RETURN_TRUE;
    }

    /* Compare the final item again using the proper operator */
    return PyObject_RichCompare(V_ITEM(i), W_ITEM(i), op);

#undef V_ITEM
#undef W_ITEM
}


static PyObject *
record_item(ApgRecordObject *o, Py_ssize_t i)
{
    if (i < 0 || i >= Py_SIZE(o)) {
        PyErr_SetString(PyExc_IndexError, "record index out of range");
        return NULL;
    }
    Py_INCREF(o->ob_item[i]);
    return o->ob_item[i];
}


typedef enum item_by_name_result {
    APG_ITEM_FOUND = 0,
    APG_ERROR = -1,
    APG_ITEM_NOT_FOUND = -2
} item_by_name_result_t;


/* Lookup a record value by its name.  Return 0 on success, -2 if the
 * value was not found (with KeyError set), and -1 on all other errors.
 */
static item_by_name_result_t
record_item_by_name(ApgRecordObject *o, PyObject *item, PyObject **result)
{
    PyObject *mapped;
    PyObject *val;
    Py_ssize_t i;

    mapped = PyObject_GetItem(o->desc->mapping, item);
    if (mapped == NULL) {
        goto noitem;
    }

    if (!PyIndex_Check(mapped)) {
        Py_DECREF(mapped);
        goto error;
    }

    i = PyNumber_AsSsize_t(mapped, PyExc_IndexError);
    Py_DECREF(mapped);

    if (i < 0) {
        if (PyErr_Occurred())
            PyErr_Clear();
        goto error;
    }

    val = record_item(o, i);
    if (val == NULL) {
        PyErr_Clear();
        goto error;
    }

    *result = val;

    return APG_ITEM_FOUND;

noitem:
    PyErr_SetObject(PyExc_KeyError, item);
    return APG_ITEM_NOT_FOUND;

error:
    PyErr_SetString(PyExc_RuntimeError, "invalid record descriptor");
    return APG_ERROR;
}


static PyObject *
record_subscript(ApgRecordObject* o, PyObject* item)
{
    if (PyIndex_Check(item)) {
        Py_ssize_t i = PyNumber_AsSsize_t(item, PyExc_IndexError);
        if (i == -1 && PyErr_Occurred())
            return NULL;
        if (i < 0) {
            i += Py_SIZE(o);
        }
        return record_item(o, i);
    }
    else if (PySlice_Check(item)) {
        Py_ssize_t start, stop, step, slicelength, cur, i;
        PyObject* result;
        PyObject* it;
        PyObject **src, **dest;

        if (PySlice_GetIndicesEx(
                item,
                Py_SIZE(o),
                &start, &stop, &step, &slicelength) < 0)
        {
            return NULL;
        }

        if (slicelength <= 0) {
            return PyTuple_New(0);
        }
        else {
            result = PyTuple_New(slicelength);
            if (!result) return NULL;

            src = o->ob_item;
            dest = ((PyTupleObject *)result)->ob_item;
            for (cur = start, i = 0; i < slicelength; cur += step, i++) {
                it = src[cur];
                Py_INCREF(it);
                dest[i] = it;
            }

            return result;
        }
    }
    else {
        PyObject* result;

        if (record_item_by_name(o, item, &result) < 0)
            return NULL;
        else
            return result;
    }
}

#ifndef _PyUnicodeWriter_Dealloc

/* Single character Unicode strings in the Latin-1 range are being
   shared as well. */
static PyObject *unicode_latin1[256] = {NULL};

#define _PyUnicode_UTF8(op)                             \
    (((PyCompactUnicodeObject*)(op))->utf8)
#define PyUnicode_UTF8(op)                              \
    (assert(_PyUnicode_CHECK(op)),                      \
     assert(PyUnicode_IS_READY(op)),                    \
     PyUnicode_IS_COMPACT_ASCII(op) ?                   \
         ((char*)((PyASCIIObject*)(op) + 1)) :          \
         _PyUnicode_UTF8(op))
#define _PyUnicode_UTF8_LENGTH(op)                      \
    (((PyCompactUnicodeObject*)(op))->utf8_length)
#define PyUnicode_UTF8_LENGTH(op)                       \
    (assert(_PyUnicode_CHECK(op)),                      \
     assert(PyUnicode_IS_READY(op)),                    \
     PyUnicode_IS_COMPACT_ASCII(op) ?                   \
         ((PyASCIIObject*)(op))->length :               \
         _PyUnicode_UTF8_LENGTH(op))
#define _PyUnicode_WSTR(op)                             \
    (((PyASCIIObject*)(op))->wstr)
#define _PyUnicode_WSTR_LENGTH(op)                      \
    (((PyCompactUnicodeObject*)(op))->wstr_length)
#define _PyUnicode_LENGTH(op)                           \
    (((PyASCIIObject *)(op))->length)
#define _PyUnicode_STATE(op)                            \
    (((PyASCIIObject *)(op))->state)
#define _PyUnicode_HASH(op)                             \
    (((PyASCIIObject *)(op))->hash)
#define _PyUnicode_KIND(op)                             \
    (assert(_PyUnicode_CHECK(op)),                      \
     ((PyASCIIObject *)(op))->state.kind)
#define _PyUnicode_GET_LENGTH(op)                       \
    (assert(_PyUnicode_CHECK(op)),                      \
     ((PyASCIIObject *)(op))->length)
#define _PyUnicode_DATA_ANY(op)                         \
    (((PyUnicodeObject*)(op))->data.any)

#undef PyUnicode_READY
#define PyUnicode_READY(op)                             \
    (assert(_PyUnicode_CHECK(op)),                      \
     (PyUnicode_IS_READY(op) ?                          \
      0 :                                               \
      _PyUnicode_Ready(op)))

#define _PyUnicode_SHARE_UTF8(op)                       \
    (assert(_PyUnicode_CHECK(op)),                      \
     assert(!PyUnicode_IS_COMPACT_ASCII(op)),           \
     (_PyUnicode_UTF8(op) == PyUnicode_DATA(op)))
#define _PyUnicode_SHARE_WSTR(op)                       \
    (assert(_PyUnicode_CHECK(op)),                      \
     (_PyUnicode_WSTR(unicode) == PyUnicode_DATA(op)))

/* true if the Unicode object has an allocated UTF-8 memory block
   (not shared with other data) */
#define _PyUnicode_HAS_UTF8_MEMORY(op)                  \
    ((!PyUnicode_IS_COMPACT_ASCII(op)                   \
      && _PyUnicode_UTF8(op)                            \
      && _PyUnicode_UTF8(op) != PyUnicode_DATA(op)))

/* true if the Unicode object has an allocated wstr memory block
   (not shared with other data) */
#define _PyUnicode_HAS_WSTR_MEMORY(op)                  \
    ((_PyUnicode_WSTR(op) &&                            \
      (!PyUnicode_IS_READY(op) ||                       \
       _PyUnicode_WSTR(op) != PyUnicode_DATA(op))))

/* Generic helper macro to convert characters of different types.
   from_type and to_type have to be valid type names, begin and end
   are pointers to the source characters which should be of type
   "from_type *".  to is a pointer of type "to_type *" and points to the
   buffer where the result characters are written to. */
#define _PyUnicode_CONVERT_BYTES(from_type, to_type, begin, end, to) \
    do {                                                \
        to_type *_to = (to_type *)(to);                \
        const from_type *_iter = (from_type *)(begin);  \
        const from_type *_end = (from_type *)(end);     \
        Py_ssize_t n = (_end) - (_iter);                \
        const from_type *_unrolled_end =                \
            _iter + _Py_SIZE_ROUND_DOWN(n, 4);          \
        while (_iter < (_unrolled_end)) {               \
            _to[0] = (to_type) _iter[0];                \
            _to[1] = (to_type) _iter[1];                \
            _to[2] = (to_type) _iter[2];                \
            _to[3] = (to_type) _iter[3];                \
            _iter += 4; _to += 4;                       \
        }                                               \
        while (_iter < (_end))                          \
            *_to++ = (to_type) *_iter++;                \
    } while (0)

#ifdef MS_WINDOWS
    /* On Windows, overallocate by 50% is the best factor */
    #define OVERALLOCATE_FACTOR 2
#else
    /* On Linux, overallocate by 25% is the best factor */
    #define OVERALLOCATE_FACTOR 4
#endif

#if (SIZEOF_LONG == 8)
    #define UCS1_ASCII_CHAR_MASK 0x8080808080808080UL
#elif (SIZEOF_LONG == 4)
    #define UCS1_ASCII_CHAR_MASK 0x80808080UL
#endif

/* The empty Unicode object is shared to improve performance. */
static PyObject *unicode_empty = NULL;

#define _Py_INCREF_UNICODE_EMPTY()                      \
    do {                                                \
        if (unicode_empty != NULL)                      \
            Py_INCREF(unicode_empty);                   \
        else {                                          \
            unicode_empty = PyUnicode_New(0, 0);        \
            if (unicode_empty != NULL) {                \
                Py_INCREF(unicode_empty);               \
                assert(_PyUnicode_CheckConsistency(unicode_empty, 1)); \
            }                                           \
        }                                               \
    } while (0)

#define _Py_RETURN_UNICODE_EMPTY()                      \
    do {                                                \
        _Py_INCREF_UNICODE_EMPTY();                     \
        return unicode_empty;                           \
    } while (0)

#define MASK_ASCII 0xFFFFFF80
#define MASK_UCS1 0xFFFFFF00
#define MASK_UCS2 0xFFFF0000

#define MAX_CHAR_ASCII 0x7f
#define MAX_CHAR_UCS1  0xff
#define MAX_CHAR_UCS2  0xffff
#define MAX_CHAR_UCS4  0x10ffff

Py_UCS4
ucs1lib_find_max_char(const Py_UCS1 *begin, const Py_UCS1 *end)
{
    const unsigned char *p = (const unsigned char *) begin;
    const unsigned char *aligned_end =
            (const unsigned char *) _Py_ALIGN_DOWN(end, SIZEOF_LONG);

    while (p < end) {
        if (_Py_IS_ALIGNED(p, SIZEOF_LONG)) {
            /* Help register allocation */
            const unsigned char *_p = p;
            while (_p < aligned_end) {
                unsigned long value = *(unsigned long *) _p;
                if (value & UCS1_ASCII_CHAR_MASK)
                    return 255;
                _p += SIZEOF_LONG;
            }
            p = _p;
            if (p == end)
                break;
        }
        if (*p++ & 0x80)
            return 255;
    }
    return 127;
}

Py_UCS4
abn_find_max_char(const Py_UCS4 *p, const Py_UCS4 *unrolled_end, const Py_UCS4 *end, Py_UCS4 mask_limit, Py_UCS4 max_char_limit, long type)
{
    if (type == sizeof (Py_UCS2)) {
        #define STRINGLIB_CHAR Py_UCS2
    } else {
        #define STRINGLIB_CHAR Py_UCS4
    }

    Py_UCS4 mask = MASK_ASCII;
    Py_UCS4 max_char = MAX_CHAR_ASCII;

    while (p < unrolled_end) {
        STRINGLIB_CHAR bits = p[0] | p[1] | p[2] | p[3];
        if (bits & mask) {
            if (mask == mask_limit) {
                /* Limit reached */
                #undef STRINGLIB_CHAR
                return max_char_limit;
            }
            if (mask == MASK_ASCII) {
                max_char = MAX_CHAR_UCS1;
                mask = MASK_UCS1;
            }
            else {
                /* mask can't be MASK_UCS2 because of mask_limit above */
                assert(mask == MASK_UCS1);
                max_char = MAX_CHAR_UCS2;
                mask = MASK_UCS2;
            }
            /* We check the new mask on the same chars in the next iteration */
            continue;
        }
        p += 4;
    }

    #undef STRINGLIB_CHAR

    while (p < end) {
        if (p[0] & mask) {
            if (mask == mask_limit) {
                /* Limit reached */
                return max_char_limit;
            }
            if (mask == MASK_ASCII) {
                max_char = MAX_CHAR_UCS1;
                mask = MASK_UCS1;
            }
            else {
                /* mask can't be MASK_UCS2 because of mask_limit above */
                assert(mask == MASK_UCS1);
                max_char = MAX_CHAR_UCS2;
                mask = MASK_UCS2;
            }
            /* We check the new mask on the same chars in the next iteration */
            continue;
        }
        p++;
    }

    return max_char;
}

Py_UCS4
ucs2lib_find_max_char(const Py_UCS2 *begin, const Py_UCS2 *end)
{
    Py_ssize_t n = end - begin;
    const Py_UCS4 *p = begin;
    const Py_UCS4 *unrolled_end = begin + _Py_SIZE_ROUND_DOWN(n, 4);

    return abn_find_max_char(&p, &unrolled_end, end, MASK_UCS1, MAX_CHAR_UCS2, sizeof (Py_UCS2));
}

Py_UCS4
ucs4lib_find_max_char(const Py_UCS4 *begin, const Py_UCS4 *end)
{
    Py_ssize_t n = end - begin;
    const Py_UCS4 *p = begin;
    const Py_UCS4 *unrolled_end = begin + _Py_SIZE_ROUND_DOWN(n, 4);

    return abn_find_max_char(&p, &unrolled_end, end, MASK_UCS2, MAX_CHAR_UCS4, sizeof (Py_UCS4));
}

Py_UCS4
_PyUnicode_FindMaxChar(PyObject *unicode, Py_ssize_t start, Py_ssize_t end)
{
    enum PyUnicode_Kind kind;
    void *startptr, *endptr;

    assert(PyUnicode_IS_READY(unicode));
    assert(0 <= start);
    assert(end <= PyUnicode_GET_LENGTH(unicode));
    assert(start <= end);

    if (start == 0 && end == PyUnicode_GET_LENGTH(unicode))
        return PyUnicode_MAX_CHAR_VALUE(unicode);

    if (start == end)
        return 127;

    if (PyUnicode_IS_ASCII(unicode))
        return 127;

    kind = PyUnicode_KIND(unicode);
    startptr = PyUnicode_DATA(unicode);
    endptr = (char *)startptr + end * kind;
    startptr = (char *)startptr + start * kind;
    switch(kind) {
    case PyUnicode_1BYTE_KIND:
        return ucs1lib_find_max_char(startptr, endptr);
    case PyUnicode_2BYTE_KIND:
        return ucs2lib_find_max_char(startptr, endptr);
    case PyUnicode_4BYTE_KIND:
        return ucs4lib_find_max_char(startptr, endptr);
    default:
        assert(0);
        return 0;
    }
}

static inline void
_PyUnicodeWriter_Update(_PyUnicodeWriter *writer)
{
    writer->maxchar = PyUnicode_MAX_CHAR_VALUE(writer->buffer);
    writer->data = PyUnicode_DATA(writer->buffer);

    if (!writer->readonly) {
        writer->kind = PyUnicode_KIND(writer->buffer);
        writer->size = PyUnicode_GET_LENGTH(writer->buffer);
    }
    else {
        /* use a value smaller than PyUnicode_1BYTE_KIND() so
           _PyUnicodeWriter_PrepareKind() will copy the buffer. */
        writer->kind = PyUnicode_WCHAR_KIND;
        assert(writer->kind <= PyUnicode_1BYTE_KIND);

        /* Copy-on-write mode: set buffer size to 0 so
         * _PyUnicodeWriter_Prepare() will copy (and enlarge) the buffer on
         * next write. */
        writer->size = 0;
    }
}

void
_PyUnicodeWriter_Init(_PyUnicodeWriter *writer)
{
    memset(writer, 0, sizeof(*writer));

    /* ASCII is the bare minimum */
    writer->min_char = 127;

    /* use a value smaller than PyUnicode_1BYTE_KIND() so
       _PyUnicodeWriter_PrepareKind() will copy the buffer. */
    writer->kind = PyUnicode_WCHAR_KIND;
    assert(writer->kind <= PyUnicode_1BYTE_KIND);
}

// Initialize _PyUnicodeWriter with initial buffer
static inline void
_PyUnicodeWriter_InitWithBuffer(_PyUnicodeWriter *writer, PyObject *buffer)
{
    memset(writer, 0, sizeof(*writer));
    writer->buffer = buffer;
    _PyUnicodeWriter_Update(writer);
    writer->min_length = writer->size;
}

static int
_copy_characters(PyObject *to, Py_ssize_t to_start,
                 PyObject *from, Py_ssize_t from_start,
                 Py_ssize_t how_many, int check_maxchar)
{
    unsigned int from_kind, to_kind;
    void *from_data, *to_data;

    assert(0 <= how_many);
    assert(0 <= from_start);
    assert(0 <= to_start);
    assert(PyUnicode_Check(from));
    assert(PyUnicode_IS_READY(from));
    assert(from_start + how_many <= PyUnicode_GET_LENGTH(from));

    assert(PyUnicode_Check(to));
    assert(PyUnicode_IS_READY(to));
    assert(to_start + how_many <= PyUnicode_GET_LENGTH(to));

    if (how_many == 0)
        return 0;

    from_kind = PyUnicode_KIND(from);
    from_data = PyUnicode_DATA(from);
    to_kind = PyUnicode_KIND(to);
    to_data = PyUnicode_DATA(to);

#ifdef Py_DEBUG
    if (!check_maxchar
        && PyUnicode_MAX_CHAR_VALUE(from) > PyUnicode_MAX_CHAR_VALUE(to))
    {
        const Py_UCS4 to_maxchar = PyUnicode_MAX_CHAR_VALUE(to);
        Py_UCS4 ch;
        Py_ssize_t i;
        for (i=0; i < how_many; i++) {
            ch = PyUnicode_READ(from_kind, from_data, from_start + i);
            assert(ch <= to_maxchar);
        }
    }
#endif

    if (from_kind == to_kind) {
        if (check_maxchar
            && !PyUnicode_IS_ASCII(from) && PyUnicode_IS_ASCII(to))
        {
            /* Writing Latin-1 characters into an ASCII string requires to
               check that all written characters are pure ASCII */
            Py_UCS4 max_char;
            max_char = ucs1lib_find_max_char(from_data,
                                             (Py_UCS1*)from_data + how_many);
            if (max_char >= 128)
                return -1;
        }
        memcpy((char*)to_data + to_kind * to_start,
                  (char*)from_data + from_kind * from_start,
                  to_kind * how_many);
    }
    else if (from_kind == PyUnicode_1BYTE_KIND
             && to_kind == PyUnicode_2BYTE_KIND)
    {
        _PyUnicode_CONVERT_BYTES(
            Py_UCS1, Py_UCS2,
            PyUnicode_1BYTE_DATA(from) + from_start,
            PyUnicode_1BYTE_DATA(from) + from_start + how_many,
            PyUnicode_2BYTE_DATA(to) + to_start
            );
    }
    else if (from_kind == PyUnicode_1BYTE_KIND
             && to_kind == PyUnicode_4BYTE_KIND)
    {
        _PyUnicode_CONVERT_BYTES(
            Py_UCS1, Py_UCS4,
            PyUnicode_1BYTE_DATA(from) + from_start,
            PyUnicode_1BYTE_DATA(from) + from_start + how_many,
            PyUnicode_4BYTE_DATA(to) + to_start
            );
    }
    else if (from_kind == PyUnicode_2BYTE_KIND
             && to_kind == PyUnicode_4BYTE_KIND)
    {
        _PyUnicode_CONVERT_BYTES(
            Py_UCS2, Py_UCS4,
            PyUnicode_2BYTE_DATA(from) + from_start,
            PyUnicode_2BYTE_DATA(from) + from_start + how_many,
            PyUnicode_4BYTE_DATA(to) + to_start
            );
    }
    else {
        assert (PyUnicode_MAX_CHAR_VALUE(from) > PyUnicode_MAX_CHAR_VALUE(to));

        if (!check_maxchar) {
            if (from_kind == PyUnicode_2BYTE_KIND
                && to_kind == PyUnicode_1BYTE_KIND)
            {
                _PyUnicode_CONVERT_BYTES(
                    Py_UCS2, Py_UCS1,
                    PyUnicode_2BYTE_DATA(from) + from_start,
                    PyUnicode_2BYTE_DATA(from) + from_start + how_many,
                    PyUnicode_1BYTE_DATA(to) + to_start
                    );
            }
            else if (from_kind == PyUnicode_4BYTE_KIND
                     && to_kind == PyUnicode_1BYTE_KIND)
            {
                _PyUnicode_CONVERT_BYTES(
                    Py_UCS4, Py_UCS1,
                    PyUnicode_4BYTE_DATA(from) + from_start,
                    PyUnicode_4BYTE_DATA(from) + from_start + how_many,
                    PyUnicode_1BYTE_DATA(to) + to_start
                    );
            }
            else if (from_kind == PyUnicode_4BYTE_KIND
                     && to_kind == PyUnicode_2BYTE_KIND)
            {
                _PyUnicode_CONVERT_BYTES(
                    Py_UCS4, Py_UCS2,
                    PyUnicode_4BYTE_DATA(from) + from_start,
                    PyUnicode_4BYTE_DATA(from) + from_start + how_many,
                    PyUnicode_2BYTE_DATA(to) + to_start
                    );
            }
            else {
                assert(0);
                return -1;
            }
        }
        else {
            const Py_UCS4 to_maxchar = PyUnicode_MAX_CHAR_VALUE(to);
            Py_UCS4 ch;
            Py_ssize_t i;

            for (i=0; i < how_many; i++) {
                ch = PyUnicode_READ(from_kind, from_data, from_start + i);
                if (ch > to_maxchar)
                    return -1;
                PyUnicode_WRITE(to_kind, to_data, to_start + i, ch);
            }
        }
    }
    return 0;
}

void
_PyUnicode_FastCopyCharacters(
    PyObject *to, Py_ssize_t to_start,
    PyObject *from, Py_ssize_t from_start, Py_ssize_t how_many)
{
    (void)_copy_characters(to, to_start, from, from_start, how_many, 0);
}

static PyObject*
resize_compact(PyObject *unicode, Py_ssize_t length)
{
    Py_ssize_t char_size;
    Py_ssize_t struct_size;
    Py_ssize_t new_size;
    int share_wstr;
    PyObject *new_unicode;
#ifdef Py_DEBUG
    Py_ssize_t old_length = _PyUnicode_LENGTH(unicode);
#endif

    assert(unicode_modifiable(unicode));
    assert(PyUnicode_IS_READY(unicode));
    assert(PyUnicode_IS_COMPACT(unicode));

    char_size = PyUnicode_KIND(unicode);
    if (PyUnicode_IS_ASCII(unicode))
        struct_size = sizeof(PyASCIIObject);
    else
        struct_size = sizeof(PyCompactUnicodeObject);
    share_wstr = _PyUnicode_SHARE_WSTR(unicode);

    if (length > ((PY_SSIZE_T_MAX - struct_size) / char_size - 1)) {
        PyErr_NoMemory();
        return NULL;
    }
    new_size = (struct_size + (length + 1) * char_size);

    if (_PyUnicode_HAS_UTF8_MEMORY(unicode)) {
        PyObject_DEL(_PyUnicode_UTF8(unicode));
        _PyUnicode_UTF8(unicode) = NULL;
        _PyUnicode_UTF8_LENGTH(unicode) = 0;
    }
    _Py_DEC_REFTOTAL;
    _Py_ForgetReference(unicode);

    new_unicode = (PyObject *)PyObject_REALLOC(unicode, new_size);
    if (new_unicode == NULL) {
        _Py_NewReference(unicode);
        PyErr_NoMemory();
        return NULL;
    }
    unicode = new_unicode;
    _Py_NewReference(unicode);

    _PyUnicode_LENGTH(unicode) = length;
    if (share_wstr) {
        _PyUnicode_WSTR(unicode) = PyUnicode_DATA(unicode);
        if (!PyUnicode_IS_ASCII(unicode))
            _PyUnicode_WSTR_LENGTH(unicode) = length;
    }
    else if (_PyUnicode_HAS_WSTR_MEMORY(unicode)) {
        PyObject_DEL(_PyUnicode_WSTR(unicode));
        _PyUnicode_WSTR(unicode) = NULL;
        if (!PyUnicode_IS_ASCII(unicode))
            _PyUnicode_WSTR_LENGTH(unicode) = 0;
    }
#ifdef Py_DEBUG
    unicode_fill_invalid(unicode, old_length);
#endif
    PyUnicode_WRITE(PyUnicode_KIND(unicode), PyUnicode_DATA(unicode),
                    length, 0);
    assert(_PyUnicode_CheckConsistency(unicode, 0));
    return unicode;
}

int
_PyUnicodeWriter_PrepareInternal(_PyUnicodeWriter *writer,
                                 Py_ssize_t length, Py_UCS4 maxchar)
{
    Py_ssize_t newlen;
    PyObject *newbuffer;

    assert(maxchar <= MAX_UNICODE);

    /* ensure that the _PyUnicodeWriter_Prepare macro was used */
    assert((maxchar > writer->maxchar && length >= 0)
           || length > 0);

    if (length > PY_SSIZE_T_MAX - writer->pos) {
        PyErr_NoMemory();
        return -1;
    }
    newlen = writer->pos + length;

    maxchar = Py_MAX(maxchar, writer->min_char);

    if (writer->buffer == NULL) {
        assert(!writer->readonly);
        if (writer->overallocate
            && newlen <= (PY_SSIZE_T_MAX - newlen / OVERALLOCATE_FACTOR)) {
            /* overallocate to limit the number of realloc() */
            newlen += newlen / OVERALLOCATE_FACTOR;
        }
        if (newlen < writer->min_length)
            newlen = writer->min_length;

        writer->buffer = PyUnicode_New(newlen, maxchar);
        if (writer->buffer == NULL)
            return -1;
    }
    else if (newlen > writer->size) {
        if (writer->overallocate
            && newlen <= (PY_SSIZE_T_MAX - newlen / OVERALLOCATE_FACTOR)) {
            /* overallocate to limit the number of realloc() */
            newlen += newlen / OVERALLOCATE_FACTOR;
        }
        if (newlen < writer->min_length)
            newlen = writer->min_length;

        if (maxchar > writer->maxchar || writer->readonly) {
            /* resize + widen */
            maxchar = Py_MAX(maxchar, writer->maxchar);
            newbuffer = PyUnicode_New(newlen, maxchar);
            if (newbuffer == NULL)
                return -1;
            _PyUnicode_FastCopyCharacters(newbuffer, 0,
                                          writer->buffer, 0, writer->pos);
            Py_DECREF(writer->buffer);
            writer->readonly = 0;
        }
        else {
            newbuffer = resize_compact(writer->buffer, newlen);
            if (newbuffer == NULL)
                return -1;
        }
        writer->buffer = newbuffer;
    }
    else if (maxchar > writer->maxchar) {
        assert(!writer->readonly);
        newbuffer = PyUnicode_New(writer->size, maxchar);
        if (newbuffer == NULL)
            return -1;
        _PyUnicode_FastCopyCharacters(newbuffer, 0,
                                      writer->buffer, 0, writer->pos);
        Py_SETREF(writer->buffer, newbuffer);
    }
    _PyUnicodeWriter_Update(writer);
    return 0;

#undef OVERALLOCATE_FACTOR
}

int
_PyUnicodeWriter_PrepareKindInternal(_PyUnicodeWriter *writer,
                                     enum PyUnicode_Kind kind)
{
    Py_UCS4 maxchar;

    /* ensure that the _PyUnicodeWriter_PrepareKind macro was used */
    assert(writer->kind < kind);

    switch (kind)
    {
    case PyUnicode_1BYTE_KIND: maxchar = 0xff; break;
    case PyUnicode_2BYTE_KIND: maxchar = 0xffff; break;
    case PyUnicode_4BYTE_KIND: maxchar = 0x10ffff; break;
    default:
        assert(0 && "invalid kind");
        return -1;
    }

    return _PyUnicodeWriter_PrepareInternal(writer, 0, maxchar);
}

static inline int
_PyUnicodeWriter_WriteCharInline(_PyUnicodeWriter *writer, Py_UCS4 ch)
{
    assert(ch <= MAX_UNICODE);
    if (_PyUnicodeWriter_Prepare(writer, 1, ch) < 0)
        return -1;
    PyUnicode_WRITE(writer->kind, writer->data, writer->pos, ch);
    writer->pos++;
    return 0;
}

int
_PyUnicodeWriter_WriteChar(_PyUnicodeWriter *writer, Py_UCS4 ch)
{
    return _PyUnicodeWriter_WriteCharInline(writer, ch);
}

int
_PyUnicodeWriter_WriteStr(_PyUnicodeWriter *writer, PyObject *str)
{
    Py_UCS4 maxchar;
    Py_ssize_t len;

    if (PyUnicode_READY(str) == -1)
        return -1;
    len = PyUnicode_GET_LENGTH(str);
    if (len == 0)
        return 0;
    maxchar = PyUnicode_MAX_CHAR_VALUE(str);
    if (maxchar > writer->maxchar || len > writer->size - writer->pos) {
        if (writer->buffer == NULL && !writer->overallocate) {
            assert(_PyUnicode_CheckConsistency(str, 1));
            writer->readonly = 1;
            Py_INCREF(str);
            writer->buffer = str;
            _PyUnicodeWriter_Update(writer);
            writer->pos += len;
            return 0;
        }
        if (_PyUnicodeWriter_PrepareInternal(writer, len, maxchar) == -1)
            return -1;
    }
    _PyUnicode_FastCopyCharacters(writer->buffer, writer->pos,
                                  str, 0, len);
    writer->pos += len;
    return 0;
}

int
_PyUnicodeWriter_WriteSubstring(_PyUnicodeWriter *writer, PyObject *str,
                                Py_ssize_t start, Py_ssize_t end)
{
    Py_UCS4 maxchar;
    Py_ssize_t len;

    if (PyUnicode_READY(str) == -1)
        return -1;

    assert(0 <= start);
    assert(end <= PyUnicode_GET_LENGTH(str));
    assert(start <= end);

    if (end == 0)
        return 0;

    if (start == 0 && end == PyUnicode_GET_LENGTH(str))
        return _PyUnicodeWriter_WriteStr(writer, str);

    if (PyUnicode_MAX_CHAR_VALUE(str) > writer->maxchar)
        maxchar = _PyUnicode_FindMaxChar(str, start, end);
    else
        maxchar = writer->maxchar;
    len = end - start;

    if (_PyUnicodeWriter_Prepare(writer, len, maxchar) < 0)
        return -1;

    _PyUnicode_FastCopyCharacters(writer->buffer, writer->pos,
                                  str, start, len);
    writer->pos += len;
    return 0;
}

static PyObject*
get_latin1_char(unsigned char ch)
{
    PyObject *unicode = unicode_latin1[ch];
    if (!unicode) {
        unicode = PyUnicode_New(1, ch);
        if (!unicode)
            return NULL;
        PyUnicode_1BYTE_DATA(unicode)[0] = ch;
        assert(_PyUnicode_CheckConsistency(unicode, 1));
        unicode_latin1[ch] = unicode;
    }
    Py_INCREF(unicode);
    return unicode;
}

PyObject*
_PyUnicode_FromASCII(const char *buffer, Py_ssize_t size)
{
    const unsigned char *s = (const unsigned char *)buffer;
    PyObject *unicode;
    if (size == 1) {
#ifdef Py_DEBUG
        assert((unsigned char)s[0] < 128);
#endif
        return get_latin1_char(s[0]);
    }
    unicode = PyUnicode_New(size, 127);
    if (!unicode)
        return NULL;
    memcpy(PyUnicode_1BYTE_DATA(unicode), s, size);
    assert(_PyUnicode_CheckConsistency(unicode, 1));
    return unicode;
}

int
_PyUnicodeWriter_WriteASCIIString(_PyUnicodeWriter *writer,
                                  const char *ascii, Py_ssize_t len)
{
    if (len == -1)
        len = strlen(ascii);

    assert(ucs1lib_find_max_char((const Py_UCS1*)ascii, (const Py_UCS1*)ascii + len) < 128);

    if (writer->buffer == NULL && !writer->overallocate) {
        PyObject *str;

        str = _PyUnicode_FromASCII(ascii, len);
        if (str == NULL)
            return -1;

        writer->readonly = 1;
        writer->buffer = str;
        _PyUnicodeWriter_Update(writer);
        writer->pos += len;
        return 0;
    }

    if (_PyUnicodeWriter_Prepare(writer, len, 127) == -1)
        return -1;

    switch (writer->kind)
    {
    case PyUnicode_1BYTE_KIND:
    {
        const Py_UCS1 *str = (const Py_UCS1 *)ascii;
        Py_UCS1 *data = writer->data;

        memcpy(data + writer->pos, str, len);
        break;
    }
    case PyUnicode_2BYTE_KIND:
    {
        _PyUnicode_CONVERT_BYTES(
            Py_UCS1, Py_UCS2,
            ascii, ascii + len,
            (Py_UCS2 *)writer->data + writer->pos);
        break;
    }
    case PyUnicode_4BYTE_KIND:
    {
        _PyUnicode_CONVERT_BYTES(
            Py_UCS1, Py_UCS4,
            ascii, ascii + len,
            (Py_UCS4 *)writer->data + writer->pos);
        break;
    }
    default:
        assert(0);
    }

    writer->pos += len;
    return 0;
}

/* Copy an ASCII or latin1 char* string into a Python Unicode string.

   WARNING: The function doesn't copy the terminating null character and
   doesn't check the maximum character (may write a latin1 character in an
   ASCII string). */
static void
unicode_write_cstr(PyObject *unicode, Py_ssize_t index,
                   const char *str, Py_ssize_t len)
{
    enum PyUnicode_Kind kind = PyUnicode_KIND(unicode);
    void *data = PyUnicode_DATA(unicode);
    const char *end = str + len;

    switch (kind) {
    case PyUnicode_1BYTE_KIND: {
        assert(index + len <= PyUnicode_GET_LENGTH(unicode));
#ifdef Py_DEBUG
        if (PyUnicode_IS_ASCII(unicode)) {
            Py_UCS4 maxchar = ucs1lib_find_max_char(
                (const Py_UCS1*)str,
                (const Py_UCS1*)str + len);
            assert(maxchar < 128);
        }
#endif
        memcpy((char *) data + index, str, len);
        break;
    }
    case PyUnicode_2BYTE_KIND: {
        Py_UCS2 *start = (Py_UCS2 *)data + index;
        Py_UCS2 *ucs2 = start;
        assert(index <= PyUnicode_GET_LENGTH(unicode));

        for (; str < end; ++ucs2, ++str)
            *ucs2 = (Py_UCS2)*str;

        assert((ucs2 - start) <= PyUnicode_GET_LENGTH(unicode));
        break;
    }
    default: {
        Py_UCS4 *start = (Py_UCS4 *)data + index;
        Py_UCS4 *ucs4 = start;
        assert(kind == PyUnicode_4BYTE_KIND);
        assert(index <= PyUnicode_GET_LENGTH(unicode));

        for (; str < end; ++ucs4, ++str)
            *ucs4 = (Py_UCS4)*str;

        assert((ucs4 - start) <= PyUnicode_GET_LENGTH(unicode));
    }
    }
}

int
_PyUnicodeWriter_WriteLatin1String(_PyUnicodeWriter *writer,
                                   const char *str, Py_ssize_t len)
{
    Py_UCS4 maxchar;

    maxchar = ucs1lib_find_max_char((const Py_UCS1*)str, (const Py_UCS1*)str + len);
    if (_PyUnicodeWriter_Prepare(writer, len, maxchar) == -1)
        return -1;
    unicode_write_cstr(writer->buffer, writer->pos, str, len);
    writer->pos += len;
    return 0;
}

static PyObject*
unicode_result_ready(PyObject *unicode)
{
    Py_ssize_t length;

    length = PyUnicode_GET_LENGTH(unicode);
    if (length == 0) {
        if (unicode != unicode_empty) {
            Py_DECREF(unicode);
            _Py_RETURN_UNICODE_EMPTY();
        }
        return unicode_empty;
    }

    if (length == 1) {
        void *data = PyUnicode_DATA(unicode);
        int kind = PyUnicode_KIND(unicode);
        Py_UCS4 ch = PyUnicode_READ(kind, data, 0);
        if (ch < 256) {
            PyObject *latin1_char = unicode_latin1[ch];
            if (latin1_char != NULL) {
                if (unicode != latin1_char) {
                    Py_INCREF(latin1_char);
                    Py_DECREF(unicode);
                }
                return latin1_char;
            }
            else {
                assert(_PyUnicode_CheckConsistency(unicode, 1));
                Py_INCREF(unicode);
                unicode_latin1[ch] = unicode;
                return unicode;
            }
        }
    }

    assert(_PyUnicode_CheckConsistency(unicode, 1));
    return unicode;
}

PyObject *
_PyUnicodeWriter_Finish(_PyUnicodeWriter *writer)
{
    PyObject *str;

    if (writer->pos == 0) {
        Py_CLEAR(writer->buffer);
        _Py_RETURN_UNICODE_EMPTY();
    }

    str = writer->buffer;
    writer->buffer = NULL;

    if (writer->readonly) {
        assert(PyUnicode_GET_LENGTH(str) == writer->pos);
        return str;
    }

    if (PyUnicode_GET_LENGTH(str) != writer->pos) {
        PyObject *str2;
        str2 = resize_compact(str, writer->pos);
        if (str2 == NULL) {
            Py_DECREF(str);
            return NULL;
        }
        str = str2;
    }

    assert(_PyUnicode_CheckConsistency(str, 1));
    return unicode_result_ready(str);
}

void
_PyUnicodeWriter_Dealloc(_PyUnicodeWriter *writer)
{
    Py_CLEAR(writer->buffer);
}

#endif

static PyObject *
record_repr(ApgRecordObject *v)
{
    Py_ssize_t i, n;
    PyObject *keys_iter;
    _PyUnicodeWriter writer;

    n = Py_SIZE(v);
    if (n == 0) {
        return PyUnicode_FromString("<Record>");
    }

    keys_iter = PyObject_GetIter(v->desc->keys);
    if (keys_iter == NULL) {
        return NULL;
    }

    i = Py_ReprEnter((PyObject *)v);
    if (i != 0) {
        Py_DECREF(keys_iter);
        return i > 0 ? PyUnicode_FromString("<Record ...>") : NULL;
    }

    _PyUnicodeWriter_Init(&writer);
    writer.overallocate = 1;
    writer.min_length = 12; /* <Record a=1> */

    if (_PyUnicodeWriter_WriteASCIIString(&writer, "<Record ", 8) < 0) {
        goto error;
    }

    for (i = 0; i < n; ++i) {
        PyObject *key;
        PyObject *key_repr;
        PyObject *val_repr;

        if (i > 0) {
            if (_PyUnicodeWriter_WriteChar(&writer, ' ') < 0) {
                goto error;
            }
        }

        if (Py_EnterRecursiveCall(" while getting the repr of a record")) {
            goto error;
        }
        val_repr = PyObject_Repr(v->ob_item[i]);
        Py_LeaveRecursiveCall();
        if (val_repr == NULL) {
            goto error;
        }

        key = PyIter_Next(keys_iter);
        if (key == NULL) {
            Py_DECREF(val_repr);
            PyErr_SetString(PyExc_RuntimeError, "invalid record mapping");
            goto error;
        }

        key_repr = PyObject_Str(key);
        Py_DECREF(key);
        if (key_repr == NULL) {
            Py_DECREF(val_repr);
            goto error;
        }

        if (_PyUnicodeWriter_WriteStr(&writer, key_repr) < 0) {
            Py_DECREF(key_repr);
            Py_DECREF(val_repr);
            goto error;
        }
        Py_DECREF(key_repr);

        if (_PyUnicodeWriter_WriteChar(&writer, '=') < 0) {
            Py_DECREF(val_repr);
            goto error;
        }

        if (_PyUnicodeWriter_WriteStr(&writer, val_repr) < 0) {
            Py_DECREF(val_repr);
            goto error;
        }
        Py_DECREF(val_repr);
    }

    writer.overallocate = 0;
    if (_PyUnicodeWriter_WriteChar(&writer, '>') < 0) {
        goto error;
    }

    Py_DECREF(keys_iter);
    Py_ReprLeave((PyObject *)v);
    return _PyUnicodeWriter_Finish(&writer);

error:
    Py_DECREF(keys_iter);
    _PyUnicodeWriter_Dealloc(&writer);
    Py_ReprLeave((PyObject *)v);
    return NULL;
}



static PyObject *
record_values(PyObject *o, PyObject *args)
{
    return record_iter(o);
}


static PyObject *
record_keys(PyObject *o, PyObject *args)
{
    if (!ApgRecord_Check(o)) {
        PyErr_BadInternalCall();
        return NULL;
    }

    return PyObject_GetIter(((ApgRecordObject*)o)->desc->keys);
}


static PyObject *
record_items(PyObject *o, PyObject *args)
{
    if (!ApgRecord_Check(o)) {
        PyErr_BadInternalCall();
        return NULL;
    }

    return record_new_items_iter(o);
}


static int
record_contains(ApgRecordObject *o, PyObject *arg)
{
    if (!ApgRecord_Check(o)) {
        PyErr_BadInternalCall();
        return -1;
    }

    return PySequence_Contains(o->desc->mapping, arg);
}


static PyObject *
record_get(ApgRecordObject* o, PyObject* args)
{
    PyObject *key;
    PyObject *defval = Py_None;
    PyObject *val = NULL;
    int res;

    if (!PyArg_UnpackTuple(args, "get", 1, 2, &key, &defval))
        return NULL;

    res = record_item_by_name(o, key, &val);
    if (res == APG_ITEM_NOT_FOUND) {
        PyErr_Clear();
        Py_INCREF(defval);
        val = defval;
    }

    return val;
}


static PySequenceMethods record_as_sequence = {
    (lenfunc)record_length,                          /* sq_length */
    0,                                               /* sq_concat */
    0,                                               /* sq_repeat */
    (ssizeargfunc)record_item,                       /* sq_item */
    0,                                               /* sq_slice */
    0,                                               /* sq_ass_item */
    0,                                               /* sq_ass_slice */
    (objobjproc)record_contains,                     /* sq_contains */
};


static PyMappingMethods record_as_mapping = {
    (lenfunc)record_length,                          /* mp_length */
    (binaryfunc)record_subscript,                    /* mp_subscript */
    0                                                /* mp_ass_subscript */
};


static PyMethodDef record_methods[] = {
    {"values",          (PyCFunction)record_values, METH_NOARGS},
    {"keys",            (PyCFunction)record_keys, METH_NOARGS},
    {"items",           (PyCFunction)record_items, METH_NOARGS},
    {"get",             (PyCFunction)record_get, METH_VARARGS},
    {NULL,              NULL}           /* sentinel */
};


PyTypeObject ApgRecord_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "asyncpg.Record",
    .tp_basicsize = sizeof(ApgRecordObject) - sizeof(PyObject *),
    .tp_itemsize = sizeof(PyObject *),
    .tp_dealloc = (destructor)record_dealloc,
    .tp_repr = (reprfunc)record_repr,
    .tp_as_sequence = &record_as_sequence,
    .tp_as_mapping = &record_as_mapping,
    .tp_hash = (hashfunc)record_hash,
    .tp_getattro = PyObject_GenericGetAttr,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC | Py_TPFLAGS_BASETYPE,
    .tp_traverse = (traverseproc)record_traverse,
    .tp_richcompare = record_richcompare,
    .tp_iter = record_iter,
    .tp_methods = record_methods,
    .tp_free = PyObject_GC_Del,
};


/* Record Iterator */


typedef struct {
    PyObject_HEAD
    Py_ssize_t it_index;
    ApgRecordObject *it_seq; /* Set to NULL when iterator is exhausted */
} ApgRecordIterObject;


static void
record_iter_dealloc(ApgRecordIterObject *it)
{
    PyObject_GC_UnTrack(it);
    Py_CLEAR(it->it_seq);
    PyObject_GC_Del(it);
}


static int
record_iter_traverse(ApgRecordIterObject *it, visitproc visit, void *arg)
{
    Py_VISIT(it->it_seq);
    return 0;
}


static PyObject *
record_iter_next(ApgRecordIterObject *it)
{
    ApgRecordObject *seq;
    PyObject *item;

    assert(it != NULL);
    seq = it->it_seq;
    if (seq == NULL)
        return NULL;
    assert(ApgRecord_Check(seq));

    if (it->it_index < Py_SIZE(seq)) {
        item = ApgRecord_GET_ITEM(seq, it->it_index);
        ++it->it_index;
        Py_INCREF(item);
        return item;
    }

    it->it_seq = NULL;
    Py_DECREF(seq);
    return NULL;
}


static PyObject *
record_iter_len(ApgRecordIterObject *it)
{
    Py_ssize_t len = 0;
    if (it->it_seq) {
        len = Py_SIZE(it->it_seq) - it->it_index;
    }
    return PyLong_FromSsize_t(len);
}


PyDoc_STRVAR(record_iter_len_doc,
             "Private method returning an estimate of len(list(it)).");


static PyMethodDef record_iter_methods[] = {
    {"__length_hint__", (PyCFunction)record_iter_len, METH_NOARGS,
        record_iter_len_doc},
    {NULL,              NULL}           /* sentinel */
};


PyTypeObject ApgRecordIter_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "RecordIterator",
    .tp_basicsize = sizeof(ApgRecordIterObject),
    .tp_dealloc = (destructor)record_iter_dealloc,
    .tp_getattro = PyObject_GenericGetAttr,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_traverse = (traverseproc)record_iter_traverse,
    .tp_iter = PyObject_SelfIter,
    .tp_iternext = (iternextfunc)record_iter_next,
    .tp_methods = record_iter_methods,
};


static PyObject *
record_iter(PyObject *seq)
{
    ApgRecordIterObject *it;

    if (!ApgRecord_Check(seq)) {
        PyErr_BadInternalCall();
        return NULL;
    }
    it = PyObject_GC_New(ApgRecordIterObject, &ApgRecordIter_Type);
    if (it == NULL)
        return NULL;
    it->it_index = 0;
    Py_INCREF(seq);
    it->it_seq = (ApgRecordObject *)seq;
    PyObject_GC_Track(it);
    return (PyObject *)it;
}


/* Record Items Iterator */


typedef struct {
    PyObject_HEAD
    Py_ssize_t it_index;
    PyObject *it_key_iter;
    ApgRecordObject *it_seq; /* Set to NULL when iterator is exhausted */
} ApgRecordItemsObject;


static void
record_items_dealloc(ApgRecordItemsObject *it)
{
    PyObject_GC_UnTrack(it);
    Py_CLEAR(it->it_key_iter);
    Py_CLEAR(it->it_seq);
    PyObject_GC_Del(it);
}


static int
record_items_traverse(ApgRecordItemsObject *it, visitproc visit, void *arg)
{
    Py_VISIT(it->it_key_iter);
    Py_VISIT(it->it_seq);
    return 0;
}


static PyObject *
record_items_next(ApgRecordItemsObject *it)
{
    ApgRecordObject *seq;
    PyObject *key;
    PyObject *val;
    PyObject *tup;

    assert(it != NULL);
    seq = it->it_seq;
    if (seq == NULL) {
        return NULL;
    }
    assert(ApgRecord_Check(seq));
    assert(it->it_key_iter != NULL);

    key = PyIter_Next(it->it_key_iter);
    if (key == NULL) {
        /* likely it_key_iter had less items than seq has values */
        goto exhausted;
    }

    if (it->it_index < Py_SIZE(seq)) {
        val = ApgRecord_GET_ITEM(seq, it->it_index);
        ++it->it_index;
        Py_INCREF(val);
    }
    else {
        /* it_key_iter had more items than seq has values */
        Py_DECREF(key);
        goto exhausted;
    }

    tup = PyTuple_New(2);
    if (tup == NULL) {
        Py_DECREF(val);
        Py_DECREF(key);
        goto exhausted;
    }

    PyTuple_SET_ITEM(tup, 0, key);
    PyTuple_SET_ITEM(tup, 1, val);
    return tup;

exhausted:
    Py_CLEAR(it->it_key_iter);
    Py_CLEAR(it->it_seq);
    return NULL;
}


static PyObject *
record_items_len(ApgRecordItemsObject *it)
{
    Py_ssize_t len = 0;
    if (it->it_seq) {
        len = Py_SIZE(it->it_seq) - it->it_index;
    }
    return PyLong_FromSsize_t(len);
}


PyDoc_STRVAR(record_items_len_doc,
             "Private method returning an estimate of len(list(it())).");


static PyMethodDef record_items_methods[] = {
    {"__length_hint__", (PyCFunction)record_items_len, METH_NOARGS,
        record_items_len_doc},
    {NULL,              NULL}           /* sentinel */
};


PyTypeObject ApgRecordItems_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "RecordItemsIterator",
    .tp_basicsize = sizeof(ApgRecordItemsObject),
    .tp_dealloc = (destructor)record_items_dealloc,
    .tp_getattro = PyObject_GenericGetAttr,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_traverse = (traverseproc)record_items_traverse,
    .tp_iter = PyObject_SelfIter,
    .tp_iternext = (iternextfunc)record_items_next,
    .tp_methods = record_items_methods,
};


static PyObject *
record_new_items_iter(PyObject *seq)
{
    ApgRecordItemsObject *it;
    PyObject *key_iter;

    if (!ApgRecord_Check(seq)) {
        PyErr_BadInternalCall();
        return NULL;
    }

    key_iter = PyObject_GetIter(((ApgRecordObject*)seq)->desc->keys);
    if (key_iter == NULL) {
        return NULL;
    }

    it = PyObject_GC_New(ApgRecordItemsObject, &ApgRecordItems_Type);
    if (it == NULL)
        return NULL;

    it->it_key_iter = key_iter;
    it->it_index = 0;
    Py_INCREF(seq);
    it->it_seq = (ApgRecordObject *)seq;
    PyObject_GC_Track(it);

    return (PyObject *)it;
}


PyTypeObject *
ApgRecord_InitTypes(void)
{
    if (PyType_Ready(&ApgRecord_Type) < 0) {
        return NULL;
    }

    if (PyType_Ready(&ApgRecordDesc_Type) < 0) {
        return NULL;
    }

    if (PyType_Ready(&ApgRecordIter_Type) < 0) {
        return NULL;
    }

    if (PyType_Ready(&ApgRecordItems_Type) < 0) {
        return NULL;
    }

    return &ApgRecord_Type;
}


/* ----------------- */


static void
record_desc_dealloc(ApgRecordDescObject *o)
{
    PyObject_GC_UnTrack(o);
    Py_CLEAR(o->mapping);
    Py_CLEAR(o->keys);
    PyObject_GC_Del(o);
}


static int
record_desc_traverse(ApgRecordDescObject *o, visitproc visit, void *arg)
{
    Py_VISIT(o->mapping);
    Py_VISIT(o->keys);
    return 0;
}


PyTypeObject ApgRecordDesc_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "RecordDescriptor",
    .tp_basicsize = sizeof(ApgRecordDescObject),
    .tp_dealloc = (destructor)record_desc_dealloc,
    .tp_getattro = PyObject_GenericGetAttr,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_traverse = (traverseproc)record_desc_traverse,
    .tp_iter = PyObject_SelfIter,
};


PyObject *
ApgRecordDesc_New(PyObject *mapping, PyObject *keys)
{
    ApgRecordDescObject *o;

    if (!mapping || !keys || !PyTuple_CheckExact(keys)) {
        PyErr_BadInternalCall();
        return NULL;
    }

    o = PyObject_GC_New(ApgRecordDescObject, &ApgRecordDesc_Type);
    if (o == NULL) {
        return NULL;
    }

    Py_INCREF(mapping);
    o->mapping = mapping;

    Py_INCREF(keys);
    o->keys = keys;

    PyObject_GC_Track(o);
    return (PyObject *) o;
}
