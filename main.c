#define null 0
#define true 1
#define false 0
#define bool int
#define i8  __int8
#define u8  unsigned __int8
#define i16 __int16
#define u16 unsigned __int16
#define i32 __int32
#define u32 unsigned __int32
#define i64 __int64
#define u64 unsigned __int64

#define U32_MAX 0xffffffff
#define U8_MAX 0xff
#define I16_MAX 32767
#define I16_MIN -32768

#define max(a, b)  ((a) > (b)? (a) : (b))
#define min(a, b)  ((a) > (b)? (b) : (a))

#include <stdarg.h>
#include "fake_winapi.h" // our substitute for windows.h

Handle stdout;
Handle process_heap;

void main();
void program_entry() {
    stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    process_heap = GetProcessHeap();
    main();
    ExitProcess(0);
}

void printf(u8* string, ...);
#define assert(x)        ((x)? (null) : (printf("assert(%s) failed, %s:%u\n", #x, __FILE__, (u64) __LINE__), ExitProcess(-1), null))
#define panic(x, ...)    (printf("Panic at %s:%u: ", __FILE__, (u64) __LINE__), printf(x, __VA_ARGS__), ExitThread(-1))
#define unimplemented()  (printf("Reached unimplemented code at %s:%u\n", __FILE__, (u64) __LINE__), ExitProcess(-1), null)

u64 round_to_next(u64 value, u64 step) {
    value += step - 1;
    value /= step;
    value *= step;
    return value;
}

// Memory

void* alloc(u64 size) {
    return HeapAlloc(process_heap, 0, size);
}
void* realloc(void* mem, u64 size) {
    return HeapReAlloc(process_heap, 0, mem, size);
}
bool free(void* mem) {
    return HeapFree(process_heap, 0, mem);
}

void mem_copy(u8* from, u8* to, u64 count) {
    while (count >= 8) {
        *((u64*) to) = *((u64*) from);
        from += 8;
        to += 8;
        count -= 8;
    }

    while (count >= 1) {
        *to = *from;
        from += 1;
        to += 1;
        count -= 1;
    }
}

void mem_clear(u8* ptr, u64 count) {
    while (count >= 8) {
        *((u64*) ptr) = 0;
        ptr += 8;
        count -= 8;
    }

    while (count >= 1) {
        *ptr = 0;
        ptr += 1;
        count -= 1;
    }
}

void u32_fill(u32* ptr, u64 count, u32 value) {
    for (u64 i = 0; i < count; i += 1) {
        *ptr = value;
        ptr += 1;
    }
}

// Stretchy buffers

typedef struct Buf_Header {
    u64 length;
    u64 capacity;
    u8 buffer[0];
} Buf_Header;

#define BUF_HEADER_SIZE 16

#define _buf_header(b)     ((Buf_Header*) ((u8*) b - BUF_HEADER_SIZE))
#define buf_length(b)      ((b)? _buf_header(b)->length : 0)
#define buf_bytes(b)       ((b)? _buf_header(b)->length * sizeof(*(b)) : 0)
#define buf_capacity(b)    ((b)? _buf_header(b)->capacity : 0)
#define _buf_fits(b, n)    (buf_length(b) + (n) <= buf_capacity(b))
#define _buf_fit(b, n)     (_buf_fits(b, n)? 0 : ((b) = _buf_grow(b, buf_length(b) + (n), sizeof(*(b)))))
#define buf_push(b, x)     (_buf_fit(b, 1), (b)[buf_length(b)] = (x), _buf_header(b)->length += 1)
#define buf_pop(b)         (assert(!buf_empty(b)), _buf_header(b)->length -= 1, *((b) + buf_length(b)))
#define buf_free(b)        ((b)? (free(_buf_header(b)), (b) = null) : (0))
#define buf_end(b)         ((b)? ((b) + buf_length(b)) : null)
#define buf_empty(b)       (buf_length(b) <= 0)
#define buf_clear(b)       ((b)? (_buf_header(b)->length = 0, null) : null)

#define buf_foreach(t, x, b)  for (t* x = (b); x != buf_end(b); x += 1)

void* _buf_grow(void* buf, u64 new_len, u64 element_size) {
    Buf_Header* new_header;

    if (buf == null) {
        u64 new_capacity = 64;
        if (new_capacity < new_len) {
            new_capacity = new_len;
        }
        u64 new_bytes = new_capacity*element_size + BUF_HEADER_SIZE;

        new_header = (Buf_Header*) alloc(new_bytes);
        new_header->length = 0;
        new_header->capacity = new_capacity;

    } else {
        u64 new_capacity = 1 + 2*buf_capacity(buf);
        if (new_capacity < new_len) {
            new_capacity = new_len;
        }
        u64 new_bytes = new_capacity*element_size + BUF_HEADER_SIZE;

        Buf_Header* old_header = _buf_header(buf);
        new_header = (Buf_Header*) realloc(old_header, new_bytes);
        new_header->capacity = new_capacity;
    }

    return new_header->buffer;
}

// Appends a c-string onto a stretchy buffer. Does not push the null terminator!
void str_push_cstr(u8** buf, u8* cstr) {
    u32 cstr_length = 0;
    for (u8* t = cstr; *t != 0; t += 1) {
        cstr_length += 1;
    }

    _buf_fit(*buf, cstr_length);
    u64* buf_length = &_buf_header(*buf)->length;
    mem_copy(cstr, *buf + *buf_length, cstr_length);
    *buf_length += cstr_length;
}

void str_push_str(u8** buf, u8* str, u64 length) {
    _buf_fit(*buf, length);
    u64* buf_length = &_buf_header(*buf)->length;
    mem_copy(str, *buf + *buf_length, length);
    *buf_length += length;
}

void str_push_zeroes(u8** buf, u64 length) {
    _buf_fit(*buf, length);
    u64* buf_length = &_buf_header(*buf)->length;
    mem_clear(*buf + *buf_length, length);
    *buf_length += length;
}

// NB only works on u8* buffers!
#define str_push_type(b, type, value) (_buf_fit(b, sizeof(type)), *((type*) ((b) + buf_length(b))) = (type) (value), _buf_header(b)->length += sizeof(type))


// Arenas
// Pointers remain valid throughout entire lifetime, but you can't remove individual
// elements, only append to the end. 
// We also have functions to use arenas as stack allocators.

enum {
    ARENA_PAGE_SIZE = 8 * 1024 * 1024,
    ARENA_ALIGN = 16,
};

typedef struct Arena Arena;
typedef struct Arena_Page Arena_Page;
typedef struct Arena_Stack_Frame Arena_Stack_Frame;

struct Arena_Stack_Frame {
    Arena_Stack_Frame* parent;
    Arena_Page* head;
    u64 head_used;
};

struct Arena {
    Arena_Page* current_page;
    Arena_Stack_Frame frame;
};

struct Arena_Page {
    Arena_Page* previous;
    Arena_Page* next;
    u64 used;
    u8 data[0];
};

#define arena_insert(a, e) (arena_insert_with_size((a), &(e), sizeof((e))))

void arena_make_space(Arena* arena, u64 size) {
    if (arena->current_page == null) {
        Arena_Page* page = (Arena_Page*) alloc(sizeof(Arena_Page) + ARENA_PAGE_SIZE);
        page->used = 0;
        page->previous = null;
        page->next = null;
        arena->current_page = page;
    }

    u64 free_space = ARENA_PAGE_SIZE - arena->current_page->used;

    u8* start = ((u8*) arena->current_page) + sizeof(Arena_Page) + arena->current_page->used;

    u64 ARENA_ALIGN_offset = ((u64) start) % ARENA_ALIGN;
    if (ARENA_ALIGN_offset != 0) {
        ARENA_ALIGN_offset = ARENA_ALIGN - ARENA_ALIGN_offset;
    }

    if (size + ARENA_ALIGN_offset > free_space) {
        if (arena->current_page->next == null) {
            Arena_Page* page = (Arena_Page*) alloc(sizeof(Arena_Page) + ARENA_PAGE_SIZE);
            page->used = 0;
            page->next = null;

            page->previous = arena->current_page;
            arena->current_page->next = page;

            arena->current_page = page;
        } else {
            arena->current_page = arena->current_page->next;
            assert(arena->current_page->used == 0);
        }
    }
}

u8* arena_alloc(Arena* arena, u64 size) {
    assert(size < ARENA_PAGE_SIZE);

    arena_make_space(arena, size);

    u8* ptr = ((u8*) arena->current_page) + sizeof(Arena_Page) + arena->current_page->used;
    u64 ARENA_ALIGN_offset = ((u64) ptr) % ARENA_ALIGN;
    if (ARENA_ALIGN_offset != 0) {
        ARENA_ALIGN_offset = ARENA_ALIGN - ARENA_ALIGN_offset;
        ptr += ARENA_ALIGN_offset;
    }

    arena->current_page->used += size + ARENA_ALIGN_offset;

    return ptr;
}

void* arena_insert_with_size(Arena* arena, void* element, u64 size) {
    u8* ptr = arena_alloc(arena, size); 
    mem_copy((u8*) element, ptr, size);
    return (void*) ptr;
}

void arena_stack_push(Arena* arena) {
    Arena_Stack_Frame new_frame = {0};
    new_frame.head = arena->current_page;
    new_frame.head_used = arena->current_page? arena->current_page->used : 0;
    new_frame.parent = arena_insert_with_size(arena, &arena->frame, sizeof(Arena_Stack_Frame));
    arena->frame = new_frame;
}

void arena_stack_pop(Arena* arena) {
    while (arena->current_page != arena->frame.head) {
        arena->current_page->used = 0;
        if (arena->current_page->previous == null) {
            break;
        } else {
            arena->current_page = arena->current_page->previous;
        }
    }

    if (arena->current_page != null) {
        arena->current_page->used = arena->frame.head_used;
    }

    arena->frame = *arena->frame.parent;
}

// String interning

const u32 STRING_TABLE_NO_MATCH = U32_MAX;

u32 string_table_search_with_length(u8* table, u8* string, u32 length) {
    assert(length <= 0xff); // String table doesn't support strings longer than 255 bytes

    u64 i = 0;
    u64 table_length = buf_length(table);
    while (i < table_length) {
        u8 entry_length = table[i];

        if (entry_length == length) {
            bool match = true;
            for (u8 j = 0; j < entry_length; j += 1) {
                if (table[i + j + 1] != string[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }

        i += entry_length + 2;

    }

    return STRING_TABLE_NO_MATCH;
}

u32 string_table_search(u8* table, u8* string) {
    u32 length = 0;
    for (u8* t = string; *t != '\0'; t += 1) {
        length += 1;
    }

    return string_table_search_with_length(table, string, length);
}

u32 string_table_canonicalize(u8** table, u8* string, u32 length) {
    u32 index;

    index = string_table_search_with_length(*table, string, length);
    if (index != STRING_TABLE_NO_MATCH) {
        return index;
    }

    index = buf_length(*table);
    buf_push(*table, (u8) length);
    str_push_str(table, string, length);
    buf_push(*table, 0);

    return index;
}

// NB when inserting into the string table, old pointer may get invalidated as we reallocate!
// Returns a null terminated string
u8* string_table_access(u8* table, u32 index) {
    u64 table_length = buf_length(table);
    assert(index < table_length);

    u32 string_length = table[index];
    assert(table[index + string_length + 1] == 0); // Invalid string index

    return &table[index + 1];
}


// Printing

void print(u8* buffer, u32 buffer_length) {
    u32 written = 0;
    i32 success = WriteFile(stdout, buffer, buffer_length, &written, null);
    if (!success || written != buffer_length) {
        u32 error_code = GetLastError();
        ExitProcess(error_code);
    }
}

u8* printf_buf; // Heh, this is gnarly af.

void printf_integer(u64 value, u8 base);

void printf(u8* string, ...) {
    buf_free(printf_buf);

    va_list args = {0};
    va_start(args, string);

    for (u8* t = string; *t != '\0'; t += 1) {
        if (*t != '%') {
            buf_push(printf_buf, *t);
        } else {
            u8 type = *(t + 1);

            switch (type) {

            case 'i': {
                i64 value = va_arg(args, i64);
                if (value < 0) {
                    buf_push(printf_buf, '-');
                    value = -value;
                }
                printf_integer(value, 10);
            } break;

            case 'u': {
                u64 value = va_arg(args, u64);
                printf_integer(value, 10);
            } break;

            case 'c': {
                u8 value = va_arg(args, u8);

                if (value >= 0x20) {
                    buf_push(printf_buf, value);
                } else {
                    buf_push(printf_buf, '\\');

                    switch (value) {

                    case '\n': buf_push(printf_buf, 'n'); break;
                    case '\r': buf_push(printf_buf, 'r'); break;
                    case '\t': buf_push(printf_buf, 't'); break;

                    default: {
                        buf_push(printf_buf, 'x');

                        u8 hi = (value & 0xf0) >> 4;
                        if (hi > 9)  buf_push(printf_buf, 'a' + hi);
                        else         buf_push(printf_buf, '0' + hi);
                        u8 lo = (value & 0x0f);
                        if (lo > 9)  buf_push(printf_buf, 'a' + lo);
                        else         buf_push(printf_buf, '0' + lo);
                    } break;

                    }
                }

            } break;

            case 'x': {
                buf_push(printf_buf, '0');
                buf_push(printf_buf, 'x');
                u64 value = va_arg(args, u64);
                printf_integer(value, 16);
            } break;

            case 's': {
                u8* other_string = va_arg(args, u8*);
                str_push_cstr(&printf_buf, other_string);
            } break;

            case 'z': {
                u64 length = va_arg(args, u64);
                u8* other_string = va_arg(args, u8*);
                str_push_str(&printf_buf, other_string, length);
            } break;

            case '%': {
                buf_push(printf_buf, '%');
            } break;

            default: {
                buf_push(printf_buf, type);
                buf_push(printf_buf, '?');
            } break;

            }

            t += 1;
        }
    }

    va_end(args);

    print(printf_buf, buf_length(printf_buf));
}

void printf_integer(u64 value, u8 base) {
    u64 start_index = buf_length(printf_buf);
    u64 length = 0;
    do {
        u8 digit = value % base;
        value = value / base;

        if (digit <= 9) {
            digit = '0' + digit;
        } else {
            digit = 'a' + (digit - 10);
        }
        buf_push(printf_buf, digit);

        length += 1;
    } while (value != 0);

    for (u64 i = 0; i < length/2; i += 1) {
        u64 a = start_index + i;
        u64 b = start_index + length - i - 1;
        u8 temp = printf_buf[b];
        printf_buf[b] = printf_buf[a];
        printf_buf[a] = temp;
    }
}

// IO stuff

bool read_entire_file(u8* file_name, u8** contents, u32* length) {
    Handle file = CreateFileA(file_name, GENERIC_READ, 0, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
    if (file == INVALID_HANDLE_VALUE) {
        u32 error_code = GetLastError();
        //printf("Couldn't open file \"%s\" for reading: %x\n", file_name, error_code);
        return false;
    }

    i64 file_size;
    if (!GetFileSizeEx(file, &file_size)) {
        u32 error_code = GetLastError();
        //printf("Couldn't get file size for \"%s\": %x\n", file_name, error_code);
        return false;
    }

    *contents = alloc(file_size);

    u32 read = 0;
    i32 success = ReadFile(file, *contents, file_size, &read, null);
    if (!success || read != file_size) {
        u32 error_code = GetLastError();
        //printf("Couldn't read from \"%s\": %x\n", file_name, error_code);
        free(*contents);
        *contents = null;
        return false;
    }

    *length = file_size;

    CloseHandle(file);

    return true;
}

bool write_entire_file(u8* file_name, u8* contents, u32 length) {
    Handle file = CreateFileA(file_name, GENERIC_WRITE, 0, null, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, null);
    if (file == INVALID_HANDLE_VALUE) {
        u32 error_code = GetLastError();
        //printf("Couldn't create/open file \"%s\" for writing: %x\n", file_name, error_code);
        return false;
    }

    u32 written = 0;
    i32 success = WriteFile(file, contents, length, &written, null);
    if (!success || written != length) {
        u32 error_code = GetLastError();
        //printf("Couldn't write to file \"%s\": %x", file_name, error_code);
        return false;
    }

    CloseHandle(file);

    return true;
}


typedef struct File_Pos {
    u32 line;
} File_Pos;


#define BRACKET_CURLY_CLOSE  0
#define BRACKET_ROUND_CLOSE  1
#define BRACKET_SQUARE_CLOSE 2
#define BRACKET_OPEN   4
#define BRACKET_CURLY_OPEN    (BRACKET_CURLY_CLOSE  | BRACKET_OPEN)
#define BRACKET_ROUND_OPEN    (BRACKET_ROUND_CLOSE  | BRACKET_OPEN)
#define BRACKET_SQUARE_OPEN   (BRACKET_SQUARE_CLOSE | BRACKET_OPEN)
const u8 BRACKET_NAMES[8] = { '}', ')', ']', 0, '{', '(', '[', 0 };

typedef struct Token {
    enum {
        token_end_of_stream = 0,

        token_identifier,
        token_literal,

        token_operator,
        token_bracket,

        token_arrow,
        token_semicolon,
        token_comma,
        token_colon,

        token_keyword_var,
        token_keyword_fn,
    } kind;

    union {
        u32 identifier_string_table_index;
        u64 literal_value;
        u8 operator_symbol;
        struct {
            u8 kind;
            i16 offset_to_matching;
        } bracket;
    };

    File_Pos pos;
} Token;

typedef u8 Type;
enum Type_Kind {
    type_invalid = 0,

    type_unsolidified_int,
    type_u8,
    type_u16,
    type_u32,
    type_u64,
    type_i8,
    type_i16,
    type_i32,
    type_i64,
};
#define PRIMITIVE_TYPE_COUNT 10

void init_primitive_type_names(u32* names, u8** string_table) {
    names[type_unsolidified_int] = string_table_canonicalize(string_table, "<int>", 5);

    names[type_u8]  = string_table_canonicalize(string_table, "u8",  2);
    names[type_u16] = string_table_canonicalize(string_table, "u16", 3);
    names[type_u32] = string_table_canonicalize(string_table, "u32", 3);
    names[type_u64] = string_table_canonicalize(string_table, "u64", 3);
    names[type_i8]  = string_table_canonicalize(string_table, "i8",  2);
    names[type_i16] = string_table_canonicalize(string_table, "i16", 3);
    names[type_i32] = string_table_canonicalize(string_table, "i32", 3);
    names[type_i64] = string_table_canonicalize(string_table, "i64", 3);
}

u8* type_name(Type t) {
    switch (t) {
        case type_invalid: return "<invalid type>";
        case type_unsolidified_int: return "<int>";
        case type_u8:  return "u8";
        case type_u16: return "u16";
        case type_u32: return "u32";
        case type_u64: return "u64";
        case type_i8:  return "i8";
        case type_i16: return "i16";
        case type_i32: return "i32";
        case type_i64: return "i64";
        default: assert(false); return null;
    }
}

bool type_can_solidify_to(Type type) {
    switch (type) {
        case type_u8:  return true;
        case type_u16: return true;
        case type_u32: return true;
        case type_u64: return true;
        case type_i8:  return true;
        case type_i16: return true;
        case type_i32: return true;
        case type_i64: return true;

        case type_invalid: return false;
        case type_unsolidified_int: return false;
        default: assert(false);
    }
    return false;
}

bool type_is_signed(Type type) {
    switch (type) {
        case type_u8:  return false;
        case type_u16: return false;
        case type_u32: return false;
        case type_u64: return false;
        case type_i8:  return true;
        case type_i16: return true;
        case type_i32: return true;
        case type_i64: return true;

        case type_invalid: return false;
        case type_unsolidified_int: return false;
        default: assert(false);
    }
    return false;
}

u8 type_size_of(Type type) {
    switch (type) {
        case type_u8:  return 1;
        case type_u16: return 2;
        case type_u32: return 4;
        case type_u64: return 8;
        case type_i8:  return 1;
        case type_i16: return 2;
        case type_i32: return 4;
        case type_i64: return 8;

        case type_invalid: return 0;
        case type_unsolidified_int: return 0;
        default: assert(false); return 0;
    }
}


u64 SIZE_MASKS[9] = {
    0x0000000000000000,
    0x00000000000000ff,
    0x000000000000ffff,
    0x0000000000ffffff,
    0x00000000ffffffff,
    0x000000ffffffffff,
    0x0000ffffffffffff,
    0x00ffffffffffffff,
    0xffffffffffffffff
};

u64 type_mask(u8 size) {
    assert(size <= 8);
    return SIZE_MASKS[size];
}


enum {
    binary_add,
    binary_sub,
    binary_mul,
    binary_div,
};

#define EXPR_FLAG_UNRESOLVED 0x01

typedef struct Expr Expr;
struct Expr {
    enum {
        expr_variable,
        expr_literal,
        expr_binary,
        expr_call,
    } kind;
    u8 flags;

    Type type;

    union {
        union { u32 index; u32 unresolved_name; } variable; // discriminated by EXPR_FLAG_UNRESOLVED
        u32 literal_index;

        struct { u8 op; Expr* left; Expr* right; } binary;

        struct {
            union { u32 unresolved_name; u32 func_index; }; // discriminated by EXPR_FLAG_UNRESOLVED
            Expr** params; // Pointer to an array of pointers to expressions! (*[*Expr] as opposed to **[Expr])
            u32 param_count;
        } call;
    };

    File_Pos pos;
};

typedef struct Stmt {
    enum {
        stmt_assignment,
    } kind;

    union {
        struct { u32 var; Expr* expr; } assignment;
    };

    File_Pos pos;
} Stmt;


typedef u16 Local;

typedef enum Local_Kind {
    local_temporary = 0,
    local_variable  = 1,
    local_literal   = 2,
} Local_Kind;

Local new_local(Local_Kind kind, u32 index) {
    assert(index <= 0x3fff);
    assert(kind < 4);
    return (Local) (index | (kind << 14));
}

Local_Kind local_kind(Local local) {
    return (Local_Kind) ((local >> 14) & 3);
}

u32 local_index(Local local) {
    return (u32) (local & 0x3fff);
}


#define OP_KIND_BINARY_FLAG 0x80
enum Op_Kind {
    op_end_of_function = 0,
    op_reset_temporaries,

    op_call,

    // 'binary'
    op_set = 0 | OP_KIND_BINARY_FLAG,
    op_add = 1 | OP_KIND_BINARY_FLAG,
    op_sub = 2 | OP_KIND_BINARY_FLAG,
    op_mul = 3 | OP_KIND_BINARY_FLAG,
    op_div = 4 | OP_KIND_BINARY_FLAG,
};

typedef struct Op_Call_Param {
    Local local;
    u8 size;
} Op_Call_Param;

// TODO optimize
// For some 'Op's (especially op_call), we need a lot of data to specify the operation.
// Other operations, suchs as binary operations, can probably be specified in 8/16 bytes.
// Maybe having a multiple-op setup would make sense, where the parts of a operation are split
// into more pieces. This would give more efficient memory usage if we have many small but
// only a few large ops.
// With this in mind, can we do "variable sized" structs, i.e. we overwrite the later part
// of the struct with the start of the next struct in cases where only the first parts of
// the struct are needed? This might be a cleaner approach.
// Regardless, this kind of optimization can only be done once we have a really clear idea of
// what needs to go into an 'Op'.
typedef struct Op {
    u8 kind;
    Type type;
        
    // NB (Morten, 07.04.18) In general, we rely on 'Op's being well formed. We have some assertions
    // to ensure that e.g. 'Local's are valid.

    union {
        struct {
            Local source;
            Local target;
        } binary;

        struct {
            Local target;
            u32 func_index;
            Op_Call_Param* params;
        } call;
    };
} Op;


typedef struct Var {
    u32 name;
    u32 declared_before_stmt;
    File_Pos declaration_pos;
    Type type;
} Var;


typedef struct Func {
    u32 name;

    // All pointers are to arena alocations!

    // first var is output, second n are params, then normal local variables
    Var* vars;
    u32 var_count; // var_count = output + params + locals, length of vars

    Var* params; // pointer into 'vars'
    u32 param_count;
    Type return_type;

    u64* literals;
    u32 literal_count;

    Stmt* stmts;
    u32 stmt_count;

    Op* ops;
    u32 op_count;
    u32 max_tmps;

    u32 bytecode_start;
} Func;



typedef struct Fixup {
    // Fixups which rely on information about adresses in the final executable go here,
    // other kinds of fixups can have their own struct

    u64 text_location;

    enum {
        fixup_imported_function,
        fixup_data,
    } kind;

    union {
        struct {
            u32 function;
            u32 dll;
        } imported;

        u32 data_offset;
    };
} Fixup;

typedef struct Stack_Fixup {
    u64 text_location;
    u32 stack_item_index;
} Stack_Fixup;

typedef struct Stack_Item {
    Local local;
    u8 size;

    u32 offset; // only set once we sort items after writing all instructions for a function
} Stack_Item;

typedef struct Call_Fixup {
    u64 text_location;
    u32 func_index;
} Call_Fixup;


// Data needed to generate import table
typedef struct Import_Function {
    u8* name; // c-str
    u16 hint;
} Import_Function;

typedef struct DynlibImport {
    u8* name; // c-str
    Import_Function* functions; // stretchy-buffer
} DynlibImport;


#define REG_COUNT 4 // eax, ecx, edx, ebx
#define REG_BAD 255

enum Reg_Names {
    reg_rax = 0,
    reg_rcx = 1,
    reg_rdx = 2,
    reg_rbx = 3,
};
u8* reg_names[REG_COUNT] = { "eax", "ecx", "edx", "ebx" };

typedef struct Reg {
    bool used;
    u32 alloc_time;
    Local local;
    u8 size;
} Reg;


#define PRINT_GENERATED_INSTRUCTIONS
#define NO_STACK_SPACE_ALLOCATED U32_MAX

// NB regarding memory allocation.
// For short-lived objects, we allocate in the 'stack' arena, which we push/pop.
// For permanent objects, we stick them in the 'arena' arena, which we should never really push/pop
// We also use a bunch of stretchy-buffers, though some of those we might be able to replace with arena allocations
typedef struct Context {
    Arena arena, stack; // arena is for permanent storage, stack for temporary

    u8* string_table; // stretchy-buffer string table
    u32 primitive_type_names[PRIMITIVE_TYPE_COUNT]; // indices to string table

    // AST & intermediate representation
    Func* funcs; // stretchy-buffer

    // These are only for temporary use, we copy to arena buffers & clear
    Stmt* tmp_stmts; // stretchy-buffer
    Var* tmp_vars; // stretchy-buffer
    u64* tmp_literals; // stretchy-buffer
    Op* tmp_ops; // stretchy-buffer, linearized for of stmts

    // Low level representation
    u8* bytecode;
    u8* bytecode_data;
    Fixup* fixups;
    DynlibImport* dlls;

    // Used during codegen
    Reg regs[REG_COUNT];

    Stack_Fixup* stack_fixups; // stretchy-buffer
    Stack_Item* stack_items; // stretchy-buffer
    Call_Fixup* call_fixups; // stretchy-buffer

    u32 time; // incremented with each emitted instruction
} Context;

void token_print(u8* string_table, Token* t) {
    switch (t->kind) {
        case token_end_of_stream: {
            printf("end of file");
        } break;

        case token_identifier: {
            u32 index = t->identifier_string_table_index;
            u8* name = string_table_access(string_table, index);
            printf("\"%s\"", name);
        } break;
        case token_literal: {
            printf("%u", t->literal_value);
        } break;

        case token_operator: {
            u8 operator = t->operator_symbol;
            printf("%c", operator);
        } break;
        case token_bracket: {
            printf("%c", BRACKET_NAMES[t->bracket.kind]);
        } break;

        case token_semicolon: {
            printf(";");
        } break;
        case token_comma: {
            printf(",");
        } break;
        case token_colon: {
            printf(":");
        } break;
        case token_arrow: {
            printf("->");
        } break;

        case token_keyword_var: {
            printf("keyword var");
        } break;
        case token_keyword_fn: {
            printf("keyword fn");
        } break;

        default: assert(false);
    }
}

void expr_print(Context* context, Func* func, Expr* expr) {
    switch (expr->kind) {
        case expr_variable: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u8* name = string_table_access(context->string_table, expr->variable.unresolved_name);
                printf("<unresolved %s>", name);
            } else {
                Var* var = &func->vars[expr->variable.index];
                u8* name = string_table_access(context->string_table, var->name);
                printf("%s", name);
            }
        } break;

        case expr_literal: {
            printf("%u", func->literals[expr->literal_index]);
        } break;

        case expr_binary: {
            printf("(");
            expr_print(context, func, expr->binary.left);
            switch (expr->binary.op) {
                case binary_add: printf(" + "); break;
                case binary_sub: printf(" - "); break;
                case binary_mul: printf(" * "); break;
                case binary_div: printf(" / "); break;
                default: assert(false);
            }
            expr_print(context, func, expr->binary.right);
            printf(")");
        } break;

        case expr_call: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u8* name = string_table_access(context->string_table, expr->call.unresolved_name);
                printf("<unresolved %s>", name);
            } else {
                Func* callee = &context->funcs[expr->call.func_index];
                u8* name = string_table_access(context->string_table, callee->name);
                printf("%s", name);
            }

            printf("(");
            for (u32 i = 0; i < expr->call.param_count; i += 1) {
                if (i != 0) printf(", ");
                expr_print(context, func, expr->call.params[i]);
            }
            printf(")");
        } break;

        default: assert(false);
    }
}

void stmt_print(Context* context, Func* func, Stmt* stmt) {
    switch (stmt->kind) {
        case stmt_assignment: {
            Var* var = &func->vars[stmt->assignment.var];
            u8* name = string_table_access(context->string_table, var->name);
            printf("%s = ", name);
            expr_print(context, func, stmt->assignment.expr);
        } break;

        default: assert(false);
    }
}

void local_print(Context* context, Func* func, Local local) {
    u32 index = local_index(local);

    switch (local_kind(local)) {
        case local_variable: {
            Var* var = &func->vars[index];
            u8* name = string_table_access(context->string_table, var->name);
            printf("%s", name);
        } break;

        case local_temporary: {
            printf("$%u", (u64) index);
        } break;

        case local_literal: {
            printf("%u", func->literals[index]);
        } break;

        default: assert(false);
    }
}



void op_print(Context* context, Func* func, Op* op) {
    if (op->kind & OP_KIND_BINARY_FLAG) {
        printf("(%s", type_name(op->type));

        switch (op->kind) {
            case op_set: printf(") set "); break;
            case op_add: printf(") add "); break;
            case op_sub: printf(") sub "); break;
            case op_mul: printf(") mul "); break;
            case op_div: printf(") div "); break;
            default: assert(false);
        }

        local_print(context, func, op->binary.target);
        printf(", ");
        local_print(context, func, op->binary.source);
    } else switch (op->kind) {
        case op_reset_temporaries: {
            printf("reset temporaries");
        } break;

        case op_call: {
            Func* callee = context->funcs + op->call.func_index;
            u8* name = string_table_access(context->string_table, callee->name);

            printf("(%s) set ", type_name(op->type));
            local_print(context, func, op->call.target);
            printf(", (call %s with ", name);

            for (u32 p = 0; p < callee->param_count; p += 1) {
                if (p != 0) printf(", ");
                local_print(context, func, op->call.params[p].local);
                printf(" (%u)", (u64) (op->call.params[p].size*8));
            }

            printf(")");

        } break;

        default: assert(false);
    }
}

u32 find_var(Func* func, u32 name) {
    for (u32 i = 0; i < func->var_count; i += 1) {
        if (func->vars[i].name == name) {
            return i;
        }
    }
    return U32_MAX;
}

u32 find_func(Context* context, u32 name) {
    u32 length = buf_length(context->funcs);
    for (u32 i = 0; i < length; i += 1) {
        if (context->funcs[i].name == name) {
            return i;
        }
    }
    return U32_MAX;
}

Type parse_type(Context* context, Token* t, u32* length) {
    if (t->kind != token_identifier) { goto invalid; }

    Type id = type_invalid;
    for (u32 i = 0; i < PRIMITIVE_TYPE_COUNT; i += 1) {
        if (context->primitive_type_names[i] == t->identifier_string_table_index) {
            id = i;
            break;
        }
    }

    if (id == type_invalid) { goto invalid; }

    *length = 1;
    return id;

    invalid:
    printf("Expected type, but got ");
    token_print(context->string_table, t);
    printf(" (Line %u)\n", (u64) t->pos.line);
    *length = 1;
    return type_invalid;
}

bool parse_parameter_declaration_list(Context* context, Func* func, Token* t, u32 length) {
    u32 i = 0;
    while (i < length) {
        u32 start = i;
        while (i < length && t[i].kind != token_comma) { i += 1; }
        u32 end = i;
        i += 1; // Skip the comma

        u32 length = end - start;
        if (length < 1 || t[start].kind != token_identifier) {
            printf("Expected parameter name, but got ");
            token_print(context->string_table, &t[start]);
            printf(" (Line %u)\n", (u64) t[start].pos.line);
            return false;
        }
        u32 name_index = t[start].identifier_string_table_index;

        if (length < 2) {
            u8* name = string_table_access(context->string_table, name_index);
            printf("Expected ': type' after parameter '%s', but found nothing (Line %u)\n", name, (u64) t[start + 1].pos.line);
            return false;
        }

        if (t[start + 1].kind != token_colon) {
            u8* name = string_table_access(context->string_table, name_index);
            printf("Expected ': type' after parameter '%s', but got ", name);
            for (u32 j = start + 1;  j < end; j += 1) {
                token_print(context->string_table, &t[j]);
            }
            printf(" (Line %u)\n", (u64) t[start + 1].pos.line);
            return false;
        }

        u32 type_length = 0;
        Type type = parse_type(context, &t[start + 2], &type_length);
        if (type == type_invalid) {
            return false;
        }

        if (type_length != length - 2) {
            printf("Unexpected token after type: ");
            token_print(context->string_table, &t[start + 2 + type_length]);
            printf(" (Line %u)\n", (u64) t[start + 2 + type_length].pos.line);
            return false;
        }

        Var var = {0};
        var.name = name_index;
        var.declaration_pos = t->pos;
        var.type = type;
        buf_push(context->tmp_vars, var);
        func->param_count += 1;
    }

    return true;
}

Expr* parse_expr(Context* context, Token* t, u32 length);

bool parse_call_parameter_list(
    Context* context, Token* t, u32 length,
    Expr*** out_exprs,
    u32* out_count
)
{
    // This will probably allocate to much memory, but at least it will allways allocate enough
    Expr** exprs = (Expr**) arena_alloc(&context->arena, length);
    u32 count = 0;

    u32 i = 0;
    while (i < length) {
        u32 start = i;
        while (i < length && t[i].kind != token_comma) { i += 1; }
        u32 end = i;
        i += 1; // Skip the comma

        Expr* expr = parse_expr(context, &t[start], end - start);
        if (expr == null) {
            return false;
        }

        exprs[count] = expr;
        count += 1;
    }

    *out_count = count;
    *out_exprs = exprs;

    return true;
}

Expr* parse_expr(Context* context, Token* t, u32 length) {
    if (length == 0) {
        printf("Expected expression but found nothing (Line %u)\n", (u64) t->pos.line);
        return null;
    }

    u32 op_pos = U32_MAX;
    u8 op_precedence = U8_MAX;

    for (u32 i = 0; i < length; i += 1) {
        if (t[i].kind == token_bracket) {
            switch (t[i].bracket.kind) {
                case BRACKET_SQUARE_OPEN:
                case BRACKET_SQUARE_CLOSE:
                case BRACKET_CURLY_OPEN:
                case BRACKET_CURLY_CLOSE:
                {
                    printf("Can't have square or curly brackets in expressions (Line %u)\n",  (u64) t->pos.line);
                    return null;
                } break;

                case BRACKET_ROUND_CLOSE: {
                    printf("Unmatched parenthesis in expression (Line %u)\n",  (u64) t->pos.line);
                    return null;
                } break;

                case BRACKET_ROUND_OPEN: {
                    // Skip ahead to closing bracket
                    i += t[i].bracket.offset_to_matching;
                    if (i >= length) {
                        printf("Unclosed parenthesis in expression (Line %u)\n",  (u64) t->pos.line);
                        return null;
                    }
                } break;

                default: assert(false);
            }
        }

        if (t[i].kind == token_operator) {
            u8 precedence;
            switch (t[i].operator_symbol) {
                case '+': precedence = 1; break;
                case '-': precedence = 1; break;
                case '*': precedence = 2; break;
                case '/': precedence = 2; break;
                case '=': precedence = 3; break;
                default: assert(false);
            }

            if (precedence <= op_precedence) {
                op_precedence = precedence;
                op_pos = i;
            }
        }
    }

    bool brackets_enclosed =
        t[0].kind == token_bracket &&
        t[0].bracket.kind == BRACKET_ROUND_OPEN &&
        t[0].bracket.offset_to_matching == length - 1;
    if (brackets_enclosed) {
        assert(
            t[length - 1].kind == token_bracket &&
            t[length - 1].bracket.kind == BRACKET_ROUND_CLOSE
        );
        return parse_expr(context, t + 1, length - 2);
    }


    // We didnt find an operator
    if (op_pos == U32_MAX) {
        switch (t->kind) {
            case token_literal: {
                if (length != 1) {
                    printf("Unexpected token(s) after %u: ", t->literal_value);
                    for (u32 i = 1; i < length; i += 1) {
                        if (i > 1) printf(", ");
                        token_print(context->string_table, &t[i]);
                    }
                    printf(" (Line %u)\n", (u64) t->pos.line);
                    return null;

                } else {
                    u32 literal_index = buf_length(context->tmp_literals);
                    buf_push(context->tmp_literals, t->literal_value);

                    Expr* expr = arena_insert(&context->arena, ((Expr) {0}));
                    expr->kind = expr_literal;
                    expr->literal_index = literal_index;
                    expr->pos = t->pos;
                    return expr;
                }
            } break;

            case token_identifier: {
                u32 name_index = t->identifier_string_table_index;

                if (length == 1) {
                    Expr* expr = arena_insert(&context->arena, ((Expr) {0}));
                    expr->variable.unresolved_name = name_index;
                    expr->flags |= EXPR_FLAG_UNRESOLVED;
                    expr->pos = t->pos;
                    return expr;
                    
                // More than one token, we must have a function
                } else {
                    bool proper_brackets =
                        t[1].kind == token_bracket &&
                        t[1].bracket.kind == BRACKET_ROUND_OPEN &&
                        t[1].bracket.offset_to_matching == length - 2;

                    if (!proper_brackets) {
                        u8* name = string_table_access(context->string_table, name_index);
                        printf("Expected parentheses after function '%s', surounding arguments. Got the following tokens instead: ", name);
                        for (u32 i = 1; i < length; i += 1) {
                            if (i > 1) printf(", ");
                            token_print(context->string_table, &t[i]);
                        }
                        printf(" (Starting on line %u)\n", (u64) t[1].pos.line);
                        return null;
                    }
                    assert(
                        t[length - 1].kind == token_bracket &&
                        t[length - 1].bracket.kind == BRACKET_ROUND_CLOSE
                    );

                    Expr* expr = arena_insert(&context->arena, ((Expr) {0}));
                    expr->kind = expr_call;
                    expr->call.unresolved_name = t[0].identifier_string_table_index;
                    expr->flags |= EXPR_FLAG_UNRESOLVED;
                    expr->pos = t->pos;

                    bool result = parse_call_parameter_list(
                        context, &t[2], length - 3,
                        &expr->call.params,
                        &expr->call.param_count
                    );
                    if (!result) return null;

                    return expr;
                }
            } break;

            case token_operator:
            case token_semicolon:
            case token_arrow:
            case token_bracket:
            case token_comma:
            case token_colon:
            case token_keyword_var:
            case token_keyword_fn:
            {
                printf("Expected literal or variable, but got ");
                token_print(context->string_table, t);
                printf(" (Line %u)\n", (u64) t->pos.line);
                return null;
            }

            default: {
                assert(false);
                return null;
            } break;
        }
    
    // We did find an operator
    } else {
        u8 binary_op;
        Token* op_token = t + op_pos;
        switch (op_token->operator_symbol) {
            case '+': binary_op = binary_add; break;
            case '-': binary_op = binary_sub; break;
            case '*': binary_op = binary_mul; break;
            case '/': binary_op = binary_div; break;
            default: {
                printf("Expected binary operator, but got %c (Line %u)\n", op_token->operator_symbol, (u64) op_token->pos.line);
                return null;
            } break;
        }

        Expr* left  = parse_expr(context, t, op_pos);
        Expr* right = parse_expr(context, t + op_pos + 1, length - op_pos - 1);

        if (left == null || right == null) { return null; }

        Expr* expr = arena_insert(&context->arena, ((Expr) {0}));
        expr->kind = expr_binary;
        expr->binary.op = binary_op;
        expr->binary.left = left;
        expr->binary.right = right;
        expr->pos = left->pos;
        return expr;
    }
}

// This parsing function returns length via a pointer, rather than taking it as a parameter
bool parse_function(Context* context, Token* t, u32* length) {
    assert(t->kind == token_keyword_fn);

    Token* start = t;
    File_Pos declaration_pos = t->pos;

    // Estimate size of function, so we still print reasonable errors on bad function declarations
    *length = 1;
    for (Token* u = t + 1; !(u->kind == token_end_of_stream || u->kind == token_keyword_fn); u += 1) {
        *length += 1;
    }

    // Name
    t += 1;
    if (t->kind != token_identifier) {
        printf("Expected function name, but found ");
        token_print(context->string_table, t);
        printf(" (Line %u)\n", (u64) t->pos.line);

        return false;
    }
    u32 name_index = t->identifier_string_table_index;


    buf_clear(context->tmp_vars); // NB we will these while parsing, and then copy them into the arena
    buf_clear(context->tmp_stmts);
    buf_clear(context->tmp_literals);


    buf_push(context->funcs, ((Func) {0}));
    Func* func = context->funcs + buf_length(context->funcs) - 1;
    func->name = name_index;

    Var output_var = {0};
    output_var.name = string_table_canonicalize(&context->string_table, "output", 6);
    buf_push(context->tmp_vars, output_var);

    buf_push(context->tmp_literals, (u64) 0);

    // Parameter list
    t += 1;
    if (t->kind != token_bracket || t->bracket.kind != BRACKET_ROUND_OPEN) {
        u8* name = string_table_access(context->string_table, name_index);
        printf("Expected a open parenthesis '(' to after 'fn %s', but got ", name);
        token_print(context->string_table, t);
        printf(" (Line %u)\n", (u64) t->pos.line);
        return false;
    }

    Token* parameter_start = t + 1;
    u32 parameter_length = t->bracket.offset_to_matching - 1;
    t = t + t->bracket.offset_to_matching;
    if (!parse_parameter_declaration_list(context, func, parameter_start, parameter_length)) {
        // We already printed an error in parse_parameter_declaration_list
        return false;
    }

    // Return type
    t += 1;
    if (t->kind != token_arrow) {
        // TODO Infer '-> void'. But we don't have a void type yet!
        unimplemented();
    } else {
        t += 1;

        u32 type_length = 0;
        func->return_type = parse_type(context, t, &type_length);
        if (func->return_type == type_invalid) {
            return false;
        }

        t += type_length;
    }

    context->tmp_vars[0].type = func->return_type;

    // Body
    if (t->kind != token_bracket || t->bracket.kind != BRACKET_CURLY_OPEN) {
        u8* name = string_table_access(context->string_table, name_index);
        printf("Expected an open curly brace '{' after 'fn %s ...', but found ", name);
        token_print(context->string_table, t);
        printf(" (Line %u)\n", (u64) t->pos.line);
        return false;
    }

    Token* body = t + 1;
    u32 body_length = t->bracket.offset_to_matching - 1;
    t = t + t->bracket.offset_to_matching;

    *length = (u32) (t - start) + 1;

    bool body_valid = true;

    for (u32 i = 0; i < body_length; i += 1) {
        u32 stmt_start = i;
        u32 equals_position = U32_MAX;
        while (i < body_length && body[i].kind != token_semicolon) {
            if (body[i].kind == token_operator && body[i].operator_symbol == '=') {
                equals_position = i - stmt_start;
            }
            i += 1;
        }
        u32 stmt_length = i - stmt_start;
        if (stmt_length == 0) { continue; }

        if (i == body_length) {
            printf("No semicolon at end of statement starting on line %u\n", (u64) body[stmt_start].pos.line);
            body_valid = false;
        }

        switch (body[stmt_start].kind) {
            case token_keyword_var: {
                if (stmt_length < 2 || body[stmt_start + 1].kind != token_identifier) {
                    printf("Expecetd identifier after 'var', but found ");
                    token_print(context->string_table, &body[stmt_start + 1]);
                    printf(" (Line %u)\n", (u64) body[stmt_start + 1].pos.line);
                    body_valid = false;
                    break;
                }

                u32 name_index = body[stmt_start + 1].identifier_string_table_index;

                bool redeclaration = false;
                buf_foreach(Var, v, context->tmp_vars) {
                    if (v->name == name_index) {
                        u8* name = string_table_access(context->string_table, name_index);
                        printf(
                            "Redeclaration of variable %s on line %u. First delcaration on line %u\n",
                            name, (u64) body[stmt_start + 1].pos.line, (u64) v->declaration_pos.line
                        );
                        redeclaration = true;
                        body_valid = false;
                    }
                }
                if (redeclaration) break;

                buf_push(context->tmp_vars, ((Var) {
                    .name = body[stmt_start + 1].identifier_string_table_index,
                    .declaration_pos = body[stmt_start].pos.line,
                }));
                Var* var = buf_end(context->tmp_vars) - 1;
                var->declared_before_stmt = buf_length(context->tmp_stmts);

                if (stmt_length == 2) break;

                if (stmt_length > 2 && body[stmt_start + 2].kind != token_colon) {
                    u8* name = string_table_access(context->string_table, name_index);
                    printf("Expected 'var %s: type', but got ", name);
                    token_print(context->string_table, &body[stmt_start + 2]);
                    printf(" (Line %u)\n", body[stmt_start].pos.line);
                    body_valid = false;
                    break;
                }

                u32 type_length = 0;
                var->type = parse_type(context, &body[stmt_start + 3], &type_length);

                if (var->type == type_invalid) {
                    body_valid = false;
                    break;
                }

                if (type_length + 3 != min(equals_position, stmt_length)) {
                    printf("Unexpected token after type: ");
                    token_print(context->string_table, &body[stmt_start + 3 + type_length]);
                    printf(" (Line %u)\n", (u64) body[stmt_start + 3 + type_length].pos.line);
                    return false;
                }

                if (equals_position != U32_MAX) {
                    Expr* expr = parse_expr(context, &body[stmt_start + equals_position + 1], stmt_length - equals_position - 1);
                    if (expr == null) {
                        body_valid = false;
                        break;
                    }

                    Stmt stmt = {0};
                    stmt.kind = stmt_assignment;
                    stmt.assignment.var = buf_length(context->tmp_vars) - 1;
                    stmt.assignment.expr = expr;
                    stmt.pos = body[stmt_start].pos;
                    buf_push(context->tmp_stmts, stmt);
                }
            } break;

            case token_identifier:
            case token_literal:
            case token_operator:
            case token_bracket:
            case token_comma:
            case token_colon:
            case token_arrow:
            {
                if (stmt_length < 1 || body[stmt_start].kind != token_identifier) {
                    printf("Expected identifier, but got ");
                    token_print(context->string_table, &body[stmt_start]);
                    printf(" (Line %u)\n", (u64) body[stmt_start].pos.line);
                    body_valid = false;
                    break;
                }

                u32 name_index = body[stmt_start].identifier_string_table_index;

                u32 var_index = U32_MAX;
                for (u32 i = 0; i < buf_length(context->tmp_vars); i += 1) {
                    if (context->tmp_vars[i].name == name_index) {
                        var_index = i;
                        break;
                    }
                }

                if (var_index == U32_MAX) {
                    u8* name = string_table_access(context->string_table, name_index);
                    printf(
                        "Assignment to undeclared variable '%s' (Line %u)\n",
                        name, (u64) body[stmt_start].pos.line
                    );
                    break;
                }

                if (equals_position != 1) {
                    printf("Expected equals sign '=' following %s, but got ");
                    token_print(context->string_table, &body[stmt_start + 1]);
                    printf(" (Line %u)\n", (u64) body[stmt_start + 1].pos.line);
                    body_valid = false;
                    break;
                }

                Expr* expr = parse_expr(context, &body[stmt_start + 2], stmt_length - 2);
                if (expr == null) {
                    body_valid = false;
                    break;
                }

                Stmt stmt = {0};
                stmt.kind = stmt_assignment;
                stmt.assignment.var = var_index;
                stmt.assignment.expr = expr;
                stmt.pos = body[stmt_start].pos;
                buf_push(context->tmp_stmts, stmt);
            } break;

            case token_keyword_fn: {
                printf("Can't declare a function inside another function (Line %u)\n", (u64) body[i].pos.line);
                body_valid = false;
            } break;

            case token_semicolon: assert(false);
            default: assert(false);
        }

        if (equals_position == U32_MAX) {
            printf("Invalid statement, ");
            continue;
        }
    }

    // Copy data out of temporary buffers into permanent arena storage
    func->stmt_count = buf_length(context->tmp_stmts);
    func->stmts = (Stmt*) arena_alloc(&context->arena, buf_bytes(context->tmp_stmts));
    mem_copy((u8*) context->tmp_stmts, (u8*) func->stmts, buf_bytes(context->tmp_stmts));

    func->literal_count = buf_length(context->tmp_literals);
    func->literals = (u64*) arena_alloc(&context->arena, buf_bytes(context->tmp_literals));
    mem_copy((u8*) context->tmp_literals, (u8*) func->literals, buf_bytes(context->tmp_literals));

    func->var_count = buf_length(context->tmp_vars);
    func->vars = (Var*) arena_alloc(&context->arena, buf_bytes(context->tmp_vars));
    mem_copy((u8*) context->tmp_vars, (u8*) func->vars, buf_bytes(context->tmp_vars));
    func->params = func->vars + 1;

    return body_valid;
}

bool build_ast(Context* context, u8* path) {
    u8* file;
    u32 file_length;
    if (!read_entire_file(path, &file, &file_length)) {
        printf("Couldn't load %s\n", path);
        return false;
    }

    bool valid = true;

    u32 keyword_var = string_table_canonicalize(&context->string_table, "var", 3);
    u32 keyword_fn  = string_table_canonicalize(&context->string_table, "fn", 2);
    init_primitive_type_names(context->primitive_type_names, &context->string_table);

    // Lex
    arena_stack_push(&context->stack); // pop at end of lexing

    typedef struct Bracket_Info Bracket_Info;
    struct Bracket_Info {
        u8 our_char;
        u8 needed_match;
        u32 our_line;
        u32 token_position;
        Bracket_Info* previous;
    };

    Bracket_Info* bracket_match = null;
    bool all_brackets_matched = true;


    Token* tokens = null;
    File_Pos file_pos = {0};
    file_pos.line = 1;

    #define LOWERCASE \
    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': case 'g': case 'h': case 'i': case 'j': case 'k': case 'l': case 'm': \
    case 'n': case 'o': case 'p': case 'q': case 'r': case 's': case 't': case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
    #define UPPERCASE \
    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': case 'G': case 'H': case 'I': case 'J': case 'K': case 'L': case 'M': \
    case 'N': case 'O': case 'P': case 'Q': case 'R': case 'S': case 'T': case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z':
    #define DIGIT \
    case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9':
    #define SPACE \
    case ' ': case '\t':

    for (u32 i = 0; i < file_length;) switch (file[i]) {
        LOWERCASE UPPERCASE case '_': {
            u32 first = i;
            u32 last = i;

            for (; i < file_length; i += 1) {
                switch (file[i]) {
                LOWERCASE UPPERCASE DIGIT case '_': { last = i; } break;
                default: goto done_with_identifier;
                }
            }
            done_with_identifier:

            u32 length = last - first + 1;
            u8* identifier = &file[first];

            u32 string_table_index = string_table_canonicalize(&context->string_table, identifier, length);

            if (string_table_index == keyword_var) {
                buf_push(tokens, ((Token) { token_keyword_var, .pos = file_pos }));
            } else if (string_table_index == keyword_fn) {
                buf_push(tokens, ((Token) { token_keyword_fn,  .pos = file_pos }));
            } else {
                buf_push(tokens, ((Token) { token_identifier, .identifier_string_table_index = string_table_index, .pos = file_pos }));
            }
        } break;

        DIGIT {
            u32 first = i;
            u32 last = i;
            bool overflow = false;
            
            u64 value = 0;

            for (; i < file_length; i += 1) {
                switch (file[i]) {
                DIGIT {
                    last = i;

                    u64 previous_value = value;

                    u64 digit = file[i] - '0';
                    value *= 10;
                    value += digit;

                    if (value < previous_value) {
                        overflow = true;
                    }

                } break;
                default: goto done_with_literal;
                }
            }
            done_with_literal:

            if (overflow) {
                printf(
                    "Integer literal %z is to large. Wrapped around to %u. (Line %u)\n",
                    (u64) (last - first + 1), &file[first], value, (u64) file_pos.line
                );
            }

            buf_push(tokens, ((Token) { token_literal, .literal_value = value, .pos = file_pos }));
        } break;

        case '+': case '-':
        case '*': case '/':
        case '=':
        {
            if (i + 1 < file_length && file[i + 1] == '>') {
                buf_push(tokens, ((Token) { token_arrow, .pos = file_pos }));
                i += 2;
            } else {
                u8 symbol = file[i];
                buf_push(tokens, ((Token) { token_operator, .operator_symbol = symbol, .pos = file_pos }));
                i += 1;
            }
        } break;

        case '{': case '}':
        case '(': case ')':
        case '[': case ']':
        {
            u8 kind;
            u8 our_char = file[i];
            switch (file[i]) {
                case '{': kind = BRACKET_CURLY_OPEN;   break;
                case '}': kind = BRACKET_CURLY_CLOSE;  break;
                case '(': kind = BRACKET_ROUND_OPEN;   break;
                case ')': kind = BRACKET_ROUND_CLOSE;  break;
                case '[': kind = BRACKET_SQUARE_OPEN;  break;
                case ']': kind = BRACKET_SQUARE_CLOSE; break;
            }
            i += 1;

            i16 offset;

            if (all_brackets_matched) {
                if (kind & BRACKET_OPEN) {
                    Bracket_Info* info = arena_insert(&context->stack, ((Bracket_Info) {0}));
                    info->our_char = our_char;
                    info->our_line = file_pos.line;
                    info->needed_match = kind & (~BRACKET_OPEN);
                    info->token_position = buf_length(tokens);
                    info->previous = bracket_match;
                    bracket_match = info;
                    offset = 0;
                } else {
                    if (bracket_match == null) {
                        printf(
                            "Found a closing bracket '%c' before any opening brackets were found (Line %u)\n",
                            our_char, (u64) file_pos.line
                        );
                        all_brackets_matched = false;
                    } else if (bracket_match->needed_match != kind) {
                        printf(
                            "Found a closing bracket '%c', which doesn't match the previous '%c' (Line %u and %u)\n",
                            our_char, bracket_match->our_char, (u64) bracket_match->our_line, (u64) file_pos.line
                        );
                        all_brackets_matched = false;
                    } else {
                        u32 open_position = bracket_match->token_position;
                        u32 close_position = buf_length(tokens);
                        u32 unsigned_offset = close_position - open_position;
                        assert(unsigned_offset <= I16_MAX);
                        offset = -((i16) unsigned_offset);
                        tokens[open_position].bracket.offset_to_matching = -offset;
                        bracket_match = bracket_match->previous;
                    }
                }
            }

            buf_push(tokens, ((Token) {
                token_bracket,
                .bracket.kind = kind,
                .bracket.offset_to_matching = offset,
                .pos = file_pos,
            }));
        } break;

        case '#': {
            for (; i < file_length; i += 1) if (file[i] == '\n' || file[i] == '\r') break;
        } break;

        case ',': {
            i += 1;
            buf_push(tokens, ((Token) { token_comma, .pos = file_pos }));
        } break;
        case ':': {
            i += 1;
            buf_push(tokens, ((Token) { token_colon, .pos = file_pos }));
        } break;
        case ';': {
            i += 1;
            buf_push(tokens, ((Token) { token_semicolon, .pos = file_pos }));
        } break;

        case '\n':
        case '\r': {
            i += 1;
            if (i < file_length && file[i] + file[i - 1] == '\n' + '\r') {
                i += 1;
            }

            file_pos.line += 1;
        } break;

        SPACE {
            i += 1;
        } break;

        default: {
            printf("Unexpected character: %c (Line %u)\n", file[i], (u64) file_pos.line);
            valid = false;
            i += 1;
        } break;
    }
    buf_push(tokens, ((Token) { token_end_of_stream, .pos = file_pos }));


    if (all_brackets_matched && bracket_match != null) {
        all_brackets_matched = false;
        printf("Unclosed bracket '%c' (Line %u)\n", bracket_match->our_char, (u64) bracket_match->our_line);
    }

    arena_stack_pop(&context->stack);

    if (!all_brackets_matched) {
        return false;
    }

    /*
    printf("%u tokens:\n", (u64) buf_length(tokens));
    for (Token* t = tokens; t->kind != token_end_of_stream; t += 1) {
        printf("  ");
        token_print(string_table, t);
        printf(" (Line %u)\n", (u64) t->pos.line);
    }
    */

    // Parse
    Token* t = tokens;
    while (t->kind != token_end_of_stream) switch (t->kind) {
        case token_keyword_fn: {
            u32 length = 0;
            valid &= parse_function(context, t, &length);
            t += length;
        } break;

        case token_identifier:
        case token_literal:
        case token_operator:
        case token_bracket:
        case token_semicolon:
        case token_comma:
        case token_colon:
        case token_keyword_var:
        {
            printf("Found invalid token at global scope: ");
            token_print(context->string_table, t);
            printf(" (Line %u)\n", (u64) t->pos.line);

            t += 1;
            while (t->kind != token_semicolon && t->kind != token_end_of_stream) { t += 1; }
        } break;

        default: assert(false);
    }



    free(file);

    if (!valid) {
        printf("Encountered errors while lexing / parsing, exiting compiler!\n");
        return false;
    } else {
        return true;
    }
}

bool expr_find_types(Context* context, Func* func, u32 stmt, Expr* expr, Type solidify_to) {
    switch (expr->kind) {
        case expr_literal: {
            if (type_can_solidify_to(solidify_to)) {
                expr->type = solidify_to;

                u64 mask = type_mask(type_size_of(expr->type));
                u64 value = func->literals[expr->literal_index];

                if (value != (value & mask)) {
                    printf(
                        "Warning: Literal %u won't fit fully into a %s and will be masked! (Line %u)\n",
                        (u64) value, type_name(expr->type), (u64) expr->pos.line
                    );
                }
            } else {
                expr->type = type_unsolidified_int;
            }
        } break;

        case expr_variable: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u32 var_index = find_var(func, expr->variable.unresolved_name);
                if (var_index == U32_MAX) {
                    u8* var_name = string_table_access(context->string_table, expr->variable.unresolved_name);
                    u8* func_name = string_table_access(context->string_table, func->name);
                    printf(
                        "Can't find variable '%s' in function '%s' (Line %u)\n",
                        var_name, func_name, (u64) expr->pos.line
                    );
                    return false;
                }

                Var* var = &func->vars[var_index];
                if (var->declared_before_stmt > stmt) {
                    u8* var_name = string_table_access(context->string_table, expr->variable.unresolved_name);
                    printf(
                        "Can't use variable %s on line %u before its declaration on line %u\n",
                        var_name, (u64) expr->pos.line, (u64) var->declaration_pos.line
                    );
                    return false;
                }

                expr->variable.index = var_index;
                expr->flags &= ~EXPR_FLAG_UNRESOLVED;
            }

            expr->type = func->vars[expr->variable.index].type;
        } break;

        case expr_binary: {
            if (!expr_find_types(context, func, stmt, expr->binary.left, solidify_to))  return false;
            if (!expr_find_types(context, func, stmt, expr->binary.right, solidify_to)) return false;

            assert(expr->binary.left->type != type_unsolidified_int);
            assert(expr->binary.left->type != type_unsolidified_int);

            if (expr->binary.left->type != expr->binary.right->type) {
                printf(
                    "Types don't match: %s vs %s (Line %u)\n",
                    type_name(expr->binary.left->type),
                    type_name(expr->binary.right->type),
                    (u64) expr->pos.line
                );

                expr->type = type_invalid;
                return false;
            } else {
                expr->type = expr->binary.left->type;
            }
        } break;

        case expr_call: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u32 func_index = find_func(context, expr->call.unresolved_name);
                if (func_index == U32_MAX) {
                    u8* name = string_table_access(context->string_table, expr->call.unresolved_name);
                    printf("Can't find function '%s' (Line %u)\n", name, (u64) expr->pos.line);
                    return false;
                }

                expr->call.func_index = func_index;
                expr->flags &= ~EXPR_FLAG_UNRESOLVED;
            }

            Func* callee = &context->funcs[expr->call.func_index];
            expr->type = callee->return_type;

            if (expr->call.param_count != callee->param_count) {
                u8* name = string_table_access(context->string_table, callee->name);
                printf(
                    "Function '%s' takes %u parameters, but %u were given (Line %u)\n",
                    name, (u64) callee->param_count, (u64) expr->call.param_count, (u64) expr->pos.line
                );
                return false;
            }

            for (u32 p = 0; p < expr->call.param_count; p += 1) {
                Type expected = callee->params[p].type;

                if (!expr_find_types(context, func, stmt, expr->call.params[p], expected)) {
                    return false;
                }

                Type actual = expr->call.params[p]->type;
                if (expected != actual) {
                    u8* func_name = string_table_access(context->string_table, callee->name);
                    printf(
                        "Invalid type for parameter %u to %s: Expected %s but got %s (Line %u)\n",
                        (u64) (p + 1), func_name,
                        type_name(expected), type_name(actual),
                        (u64) expr->pos.line
                    );

                    return false;
                }
            }
        } break;

        default: assert(false);
    }

    return true;
}

bool typecheck(Context* context) {
    bool valid = true;

    for (u32 f = 0; f < buf_length(context->funcs); f += 1) {
        Func* func = context->funcs + f;

        for (u32 i = 0; i < func->stmt_count; i += 1) {
            Stmt* stmt = func->stmts + i;
            switch (stmt->kind) {
                case stmt_assignment: {
                    Var* var = &func->vars[stmt->assignment.var];
                    Expr* expr = stmt->assignment.expr;

                    bool left = true;
                    bool right = expr_find_types(context, func, i, expr, var->type);
                    if (!(left && right)) { valid = false; break; }

                    if (var->type != stmt->assignment.expr->type) {
                        printf(
                            "Types on left and right side of assignment don't match: %s vs %s (Line %u)\n",
                            type_name(var->type), type_name(stmt->assignment.expr->type), (u64) stmt->pos.line
                        );
                        valid = false;
                    }
                } break;

                default: assert(false);
            }
        }
    }

    return valid;
}



void expr_linearize_recursive(Context* context, Expr* expr, u32 tmp) {
    assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));

    switch (expr->kind) {
        case expr_variable: {
            Op op = {0};
            op.type = expr->type;
            op.kind = op_set;
            op.binary.target = new_local(local_temporary, tmp);
            op.binary.source = new_local(local_variable, expr->variable.index);
            buf_push(context->tmp_ops, op);
        } break;

        case expr_literal: {
            Op op = {0};
            op.type = expr->type;
            op.kind = op_set;
            op.binary.target = new_local(local_temporary, tmp);
            op.binary.source = new_local(local_literal, expr->literal_index);
            buf_push(context->tmp_ops, op);
        } break;

        case expr_binary: {
            expr_linearize_recursive(context, expr->binary.left, tmp);

            Op op = {0};
            op.type = expr->type;
            op.binary.target = new_local(local_temporary, tmp);

            bool right_may_be_literal =
                (expr->binary.op == binary_add || expr->binary.op == binary_sub) &&
                type_size_of(expr->type) < 4;

            switch (expr->binary.op) {
                case binary_add: op.kind = op_add; break;
                case binary_sub: op.kind = op_sub; break;
                case binary_mul: op.kind = op_mul; break;
                case binary_div: op.kind = op_div; break;
                default: assert(false);
            }

            // The `expr_binary` case is the fallthrough case. This case works for all kinds of
            // expressions. We handle some expressions differently though, which results in
            // less temporaries allocated.
            if (right_may_be_literal) {
                switch (expr->binary.right->kind) {
                    case expr_literal: {
                        op.binary.source = new_local(local_literal, expr->binary.right->literal_index);
                    } break;
                    case expr_variable: {
                        op.binary.source = new_local(local_variable, expr->binary.right->variable.index);
                    } break;

                    // for more complex expression kinds
                    case expr_binary:
                    case expr_call:
                    {
                        right_may_be_literal = false; // oof, messy control flow
                    } break;

                    default: assert(false);
                }
            }

            if (!right_may_be_literal) {
                expr_linearize_recursive(context, expr->binary.right, tmp + 1);
                op.binary.source = new_local(local_temporary, tmp + 1);
            }

            buf_push(context->tmp_ops, op);
        } break;

        case expr_call: {
            u32 result_tmp = tmp;

            // This is just a more complex case of the code for linearizing a binary expression.
            Op_Call_Param* call_params = (Op_Call_Param*) arena_alloc(&context->arena, sizeof(Op_Call_Param) * expr->call.param_count);
            for (u32 p = 0; p < expr->call.param_count; p += 1) {
                Expr* param = expr->call.params[p];

                call_params[p].size = type_size_of(param->type);

                switch (param->kind)  {
                    case expr_literal: {
                        call_params[p].local = new_local(local_literal, param->literal_index);
                    } break;

                    case expr_variable: {
                        call_params[p].local = new_local(local_variable, param->variable.index);
                    } break;

                    case expr_binary:
                    case expr_call:
                    {
                        call_params[p].local = new_local(local_temporary, tmp);
                        expr_linearize_recursive(context, param, tmp);
                        tmp += 1;
                    } break;

                    default: assert(false);
                }
            }

            Op op = {0};
            op.kind = op_call;
            op.type = expr->type;
            op.call.func_index = expr->call.func_index;
            op.call.target = new_local(local_temporary, result_tmp);
            op.call.params = call_params;
            buf_push(context->tmp_ops, op);
        } break;

        default: assert(false);
    }
}

void local_decrement_temporary(Local* local, u32 fallback_var) {
    if (local_kind(*local) == local_temporary) {
        u32 index = local_index(*local);
        if (index == 0) {
            *local = new_local(local_variable, fallback_var);
        } else {
            *local = new_local(local_temporary, index - 1);
        }
    }
}

void linearize_assignment(Context* context, Func* func, u32 var, Expr* root) {
    // TODO Optimize
    // * Summing constants
    // * Reorganizing trees so as many right branches are leaves. We only need temporaries if we
    //   have non-leaf expressions on right branches (Draw it up, it makes sense!).
    //
    // TODO TODO TODO Cleanup
    // There are three loops below which go through all locals we have, and do some checks/transforms on them. They are
    // very repetitive, but probably tricky to refactor. Adding to complexity, one of them distinguishes between source
    // and target locals :/

    u32 initial_op_count = buf_length(context->tmp_ops);

    expr_linearize_recursive(context, root, 0);

    // Try replacing temporary $0 with our variable.
    // If we write to $0 after reading from 'var' we need $0
    bool need_temporary_0 = false;
    bool has_assigned_to_0 = false;
    for (u32 i = initial_op_count; i < buf_length(context->tmp_ops); i += 1) {
        Op* op = context->tmp_ops + i;

        if (op->kind & OP_KIND_BINARY_FLAG) {
            if (local_kind(op->binary.source) == local_variable && local_index(op->binary.source) == var) {
                if (has_assigned_to_0) {
                    need_temporary_0 = true;
                    break;
                }
            }
            if (local_kind(op->binary.target) == local_temporary && local_index(op->binary.target) == 0) {
                has_assigned_to_0 = true;
            }
        } else switch (op->kind) {
            case op_end_of_function: break;
            case op_reset_temporaries: break;
            case op_call: {
                u32 param_count = context->funcs[op->call.func_index].param_count;
                for (u32 p = 0; p < param_count; p += 1) {
                    if (local_kind(op->call.params[p].local) == local_variable && local_index(op->call.params[p].local) == var) {
                        if (has_assigned_to_0) {
                            need_temporary_0 = true;
                            break;
                        }
                    }
                }

                if (local_kind(op->call.target) == local_temporary && local_index(op->call.target) == 0) {
                    has_assigned_to_0 = true;
                }
            } break;
            default: assert(false);
        }
    }

    if (need_temporary_0) {
        // Move the temporary $0 into our variable
        Type type = func->vars[var].type;
        buf_push(context->tmp_ops, ((Op) {
            .kind = op_set,
            .binary = {
                .source = new_local(local_temporary, 0),
                .target = new_local(local_variable, var),
            },
            .type = type,
        }));
    } else { 
        for (u32 i = initial_op_count; i < buf_length(context->tmp_ops); i += 1) {
            Op* op = context->tmp_ops + i;

            if (op->kind & OP_KIND_BINARY_FLAG) {
                local_decrement_temporary(&op->binary.source, var);
                local_decrement_temporary(&op->binary.target, var);
            } else switch (op->kind) {
                case op_end_of_function: break;
                case op_reset_temporaries: break;
                case op_call: {
                    u32 param_count = context->funcs[op->call.func_index].param_count;
                    for (u32 p = 0; p < param_count; p += 1) {
                        local_decrement_temporary(&op->call.params[p].local, var);
                    }
                    local_decrement_temporary(&op->call.target, var);
                } break;
                default: assert(false);
            }
        }

        // By removing temporary $0 we might convert 'set $0, x' to 'set x, x' as the first instruction
        Op* first = context->tmp_ops + initial_op_count;
        if (first->kind == op_set && first->binary.source == first->binary.target) {
            // NB this is buf_remove
            for (u32 i = initial_op_count; i < buf_length(context->tmp_ops) - 1; i += 1) {
                context->tmp_ops[i] = context->tmp_ops[i + 1];
            }
            buf_pop(context->tmp_ops);
        }
    }
    
    // Figure out how many temporaries we ended up using
    bool used_temporaries = false;

    for (u32 i = initial_op_count; i < buf_length(context->tmp_ops); i += 1) {
        Op* op = &context->tmp_ops[i];
        if (!(op->kind & OP_KIND_BINARY_FLAG)) continue;

        for (u32 i = initial_op_count; i < buf_length(context->tmp_ops); i += 1) {
            Op* op = context->tmp_ops + i;

            if (op->kind & OP_KIND_BINARY_FLAG) {
                if (local_kind(op->binary.source) == local_temporary) {
                    used_temporaries = true;
                    func->max_tmps = max(local_index(op->binary.source) + 1, func->max_tmps);
                }
                if (local_kind(op->binary.target) == local_temporary) {
                    used_temporaries = true;
                    func->max_tmps = max(local_index(op->binary.target) + 1, func->max_tmps);
                }
            } else switch (op->kind) {
                case op_end_of_function: break;
                case op_reset_temporaries: break;
                case op_call: {
                    u32 param_count = context->funcs[op->call.func_index].param_count;
                    for (u32 p = 0; p < param_count; p += 1) {
                        if (local_kind(op->call.params[p].local) == local_temporary) {
                            used_temporaries = true;
                            func->max_tmps = max(local_index(op->call.params[p].local) + 1, func->max_tmps);
                        }
                    }
                    if (local_kind(op->call.target) == local_temporary) {
                        used_temporaries = true;
                        func->max_tmps = max(local_index(op->call.target) + 1, func->max_tmps);
                    }
                } break;
                default: assert(false);
            }
        }
    }

    if (used_temporaries) {
        buf_push(context->tmp_ops, ((Op) { op_reset_temporaries }));
    }
}

void build_intermediate(Context* context) {
    // Linearize statements
    buf_foreach (Func, func, context->funcs) {
        assert(buf_empty(context->tmp_ops));

        for (u32 s = 0; s < func->stmt_count; s += 1) {
            Stmt* stmt = &func->stmts[s];

            switch (stmt->kind) {
                case stmt_assignment: {
                    linearize_assignment(context, func, stmt->assignment.var, stmt->assignment.expr);
                } break;

                default: assert(false);
            }
        }

        buf_push(context->tmp_ops, ((Op) { op_end_of_function }));

        func->op_count = buf_length(context->tmp_ops) - 1;
        func->ops = (Op*) arena_alloc(&context->arena, buf_bytes(context->tmp_ops));
        mem_copy((u8*) context->tmp_ops, (u8*) func->ops, buf_bytes(context->tmp_ops));

        buf_clear(context->tmp_ops);

        #if 1
        u8* name = string_table_access(context->string_table, func->name);
        printf("%s has %u operations:\n", name, (u64) func->op_count);
        for (u32 i = 0; i < func->op_count; i += 1) {
            printf("  ");
            op_print(context, func, &func->ops[i]);
            printf("\n");
        }
        #endif
    }
}

void eval_ops(Context* context) {
    arena_stack_push(&context->stack);

    u32 output_value = 0;

    typedef struct Stack_Frame Stack_Frame;
    struct Stack_Frame {
        Func* func;
        u64* var_values;
        u64* tmp_values;
        Op* current_op;
        Stack_Frame* parent;
        Local call_result_into;
    };

    u32 main_func_index = find_func(context, string_table_search(context->string_table, "main")); 
    if (main_func_index == STRING_TABLE_NO_MATCH) {
        panic("No main function");
    }
    Func* main_func = context->funcs + main_func_index;
    Stack_Frame* frame = arena_insert(&context->stack, ((Stack_Frame) { main_func }));


    u32 var_bytes = sizeof(u64) * frame->func->var_count;
    frame->var_values = (u64*) arena_alloc(&context->stack, var_bytes);
    mem_clear((u8*) frame->var_values, var_bytes);

    u32 tmp_bytes = sizeof(u64) * frame->func->max_tmps;
    frame->tmp_values = (u64*) arena_alloc(&context->stack, tmp_bytes);
    mem_clear((u8*) frame->tmp_values, tmp_bytes);

    while (1) {
        if (frame->current_op == null) {
            frame->current_op = frame->func->ops;
        }

        bool break_into_call = false;

        Op* last_op = frame->func->ops + frame->func->op_count;
        while (frame->current_op != last_op && !break_into_call) {
            Op* op = frame->current_op;
            frame->current_op += 1;

            if (op->kind & OP_KIND_BINARY_FLAG) {
                u64* left;
                switch (local_kind(op->binary.target)) {
                    case local_temporary: left = frame->tmp_values + local_index(op->binary.target); break;
                    case local_variable:  left = frame->var_values + local_index(op->binary.target); break;
                    case local_literal: assert(false);
                    default: assert(false);
                }

                u64 right;
                switch (local_kind(op->binary.source)) {
                    case local_temporary: {
                        right = frame->tmp_values[local_index(op->binary.source)];
                    } break;
                    case local_variable: {
                        right = frame->var_values[local_index(op->binary.source)];
                    } break;

                    case local_literal: {
                        right = frame->func->literals[local_index(op->binary.source)];
                    } break;

                    default: assert(false);
                }

                u64 mask = type_mask(type_size_of(op->type));

                *left &= mask;
                right &= mask;

                switch (op->kind) {
                    case op_set: *left = right; break;
                    case op_add: *left = *left + right; break;
                    case op_sub: *left = *left - right; break;
                    case op_mul: *left = *left * right; break;
                    case op_div: *left = *left / right; break;

                    default: assert(false);
                }

                *left &= mask;

                // TODO we need different arithmetic here. Keep in mind we want signed integer overflow to be defined!
                if (type_is_signed(op->type)) unimplemented();

            // Other operators
            } else switch (op->kind) {
                case op_reset_temporaries: break;

                case op_call: {
                    Func* callee = context->funcs + op->call.func_index;
                    Stack_Frame* next_frame = arena_insert(&context->stack, ((Stack_Frame) {
                        .func = callee,
                        .parent = frame,
                        .call_result_into = op->call.target,
                    }));

                    u64 var_bytes = sizeof(u64) * callee->var_count;
                    next_frame->var_values = (u64*) arena_alloc(&context->stack, var_bytes);
                    mem_clear((u8*) next_frame->var_values, var_bytes);

                    u64 tmp_bytes = sizeof(u64) * callee->max_tmps;
                    next_frame->tmp_values = (u64*) arena_alloc(&context->stack, tmp_bytes);
                    mem_clear((u8*) next_frame->tmp_values, tmp_bytes);

                    for (u32 p = 0; p < callee->param_count; p += 1) {
                        u64 our_value;

                        Local param = op->call.params[p].local;
                        switch (local_kind(param)) {
                            case local_temporary: our_value = *(frame->tmp_values + local_index(param)); break;
                            case local_variable:  our_value = *(frame->var_values + local_index(param)); break;
                            case local_literal:   our_value = frame->func->literals[local_index(param)]; break;
                            default: assert(false);
                        }

                        next_frame->var_values[p + 1] = our_value; // + 1 to skip output
                    }

                    frame = next_frame;
                    break_into_call = true;
                } break;

                default: assert(false);
            }
        }

        if (!break_into_call) {
            if (frame->parent != null) {
                u64 output_value = frame->var_values[0];

                Local target = frame->call_result_into;
                frame = frame->parent;

                u64* target_value;
                switch (local_kind(target)) {
                    case local_temporary: target_value = frame->tmp_values + local_index(target); break;
                    case local_variable:  target_value = frame->var_values + local_index(target); break;
                    case local_literal:   assert(false);
                    default: assert(false);
                }
                *target_value = output_value;
            } else {
                break;
            }
        }
    }

    {
        printf("Evaluated intermediate bytecode:\n");
        u8* name = string_table_access(context->string_table, frame->func->name);
        printf("  fn %s:\n", name);

        for (u32 i = 0; i < frame->func->var_count; i += 1) {
            Var* var = &frame->func->vars[i];
            u8* name = string_table_access(context->string_table, var->name);
            u32 value = frame->var_values[i];

            printf("    %s = %u\n", name, (u64) value);
        }
    }

    arena_stack_pop(&context->stack);
}


void write_lit(Context* context, u8 size, u64 lit) {
    switch (size) {
        default: assert(false);

        #define CASE_N(n)\
        case n:\
            buf_push(context->bytecode, lit & 0xff);\
            lit = lit >> 8; // fallthrough!

        CASE_N(8)
        CASE_N(7)
        CASE_N(6)
        CASE_N(5)
        CASE_N(4)
        CASE_N(3)
        CASE_N(2)
        CASE_N(1)

        #undef CASE_N
    }
}

void write_mov_reg_to_reg(Context* context, u8 size, u8 from_reg, u8 to_reg) {
    assert(to_reg < 8 && from_reg < 8); // otherwise we need to encode registers using rex.{r, x, b}

    switch (size) {
        case 1: {
            buf_push(context->bytecode, 0x88);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, 0x89);
        } break;
        case 4: {
            buf_push(context->bytecode, 0x89);
        } break;
        case 8: {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0x89);
        } break;
        default: assert(false);
    }

    buf_push(context->bytecode, 0xc0 | (from_reg << 3) | to_reg);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov%u %s, %s\n", (u64) (size*8), reg_names[to_reg], reg_names[from_reg]);
    #endif
}

void write_mov_lit_to_reg(Context* context, u8 size, u64 lit, u8 to_reg) {
    assert(to_reg < 8); // otherwise we need to encode registers using rex.{r, x, b}

    switch (size) {
        case 1: {
            buf_push(context->bytecode, 0xb0 | to_reg);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, 0xb8 | to_reg);
        } break;
        case 4: {
            buf_push(context->bytecode, 0xb8 | to_reg);
        } break;
        case 8: {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0xb8 | to_reg);
        } break;
        default: assert(false);
    }

    write_lit(context, size, lit);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov%u %s, %u\n", (u64) (size*8), reg_names[to_reg], type_mask(size) & lit);
    #endif
}

void write_mov_reg_to_stack(Context* context, u8 size, u8 from_reg, u32 stack_item_index) {
    assert(from_reg < 8); // otherwise we need to encode registers using rex.{r, x, b}

    switch (size) {
        case 1: {
            buf_push(context->bytecode, 0x88);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, 0x89);
        } break;
        case 4: {
            buf_push(context->bytecode, 0x89);
        } break;
        case 8: {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0x89);
        } break;
        default: assert(false);
    }

    buf_push(context->bytecode, 0x44 | (from_reg << 3)); // 0x44 is x+imm8, 0x84 is x+imm32
    buf_push(context->bytecode, 0x24); // x is rsp

    buf_push(context->bytecode, 0x00);

    Stack_Fixup stack_fixup = {0};
    stack_fixup.text_location = buf_length(context->bytecode) - sizeof(u8);
    stack_fixup.stack_item_index = stack_item_index;
    buf_push(context->stack_fixups, stack_fixup);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov%u [stack %u], %s\n", (u64) (size*8), (u64) stack_item_index, reg_names[from_reg]);
    #endif
}

void write_mov_stack_to_reg(Context* context, u8 size, u32 stack_item_index, u8 to_reg) {
    assert(to_reg < 8); // otherwise we need to encode registers using rex.{r, x, b}

    switch (size) {
        case 1: {
            buf_push(context->bytecode, 0x8a);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, 0x8b);
        } break;
        case 4: {
            buf_push(context->bytecode, 0x8b);
        } break;
        case 8: {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0x8b);
        } break;
        default: assert(false);
    }

    buf_push(context->bytecode, 0x44 | (to_reg << 3)); // 0x44 is x+imm8, 0x84 is x+imm32
    buf_push(context->bytecode, 0x24); // x is rsp

    buf_push(context->bytecode, 0x00);
    Stack_Fixup stack_fixup = {0};
    stack_fixup.text_location = buf_length(context->bytecode) - sizeof(u8);
    stack_fixup.stack_item_index = stack_item_index;
    buf_push(context->stack_fixups, stack_fixup);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov%u %s, [stack %u]\n", (u64) (size*8), reg_names[to_reg], (u64) stack_item_index);
    #endif
}

void write_add_or_sub_lit_to_reg(Context* context, u8 size, bool add, u64 lit, u8 to_reg) {
    assert(to_reg < 8);

    switch (size) {
        case 1: {
            buf_push(context->bytecode, 0x80);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, 0x81);
        } break;
        case 4: {
            buf_push(context->bytecode, 0x81);
        } break;
        case 8: {
            panic("Can't add/sub a 64-bit literal on x64!\n");
        } break;
        default: assert(false);
    }
    buf_push(context->bytecode, (add? 0xc0 : 0xe8) | to_reg);
    write_lit(context, size, lit);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("%s%u %s, %u\n", add? "add" : "sub", (u64) (size*8), reg_names[to_reg], type_mask(size) & lit);
    #endif
}

void write_add_or_sub_reg_to_reg(Context* context, u8 size, bool add, u8 from_reg, u8 to_reg) {
    assert(from_reg < 8 && to_reg < 8);

    switch (size) {
        case 1: {
            buf_push(context->bytecode, add? 0x00 : 0x28);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, add? 0x01 : 0x29);
        } break;
        case 4: {
            buf_push(context->bytecode, add? 0x01 : 0x29);
        } break;
        case 8: {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, add? 0x01 : 0x29);
        } break;
        default: assert(false);
    }

    buf_push(context->bytecode, 0xc0 | (from_reg << 3) | to_reg);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("%s%u %s, %s\n", add? "add" : "sub", (u64) (size*8), reg_names[to_reg], reg_names[from_reg]);
    #endif
}

void write_unsigned_mul(Context* context, u8 size, u8 by_reg) {
    // remainder goes in rdx, multiplies rax by the value in the given register

    assert(by_reg < 8);
    assert(!context->regs[reg_rdx].used);

    switch (size) {
        case 1: {
            buf_push(context->bytecode, 0xf6);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, 0xf7);
        } break;
        case 4: {
            buf_push(context->bytecode, 0xf7);
        } break;
        case 8: {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0xf7);
        } break;
        default: assert(false);
    }
    buf_push(context->bytecode, 0xe0 | by_reg);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mul%u %s\n", (u64) (size*8), reg_names[by_reg]);
    #endif
}


u32 local_stack_item_index(Context* context, u8 size, Local local, bool allocate) {
    Local_Kind kind = local_kind(local);
    assert(kind != local_literal);

    u32 index = NO_STACK_SPACE_ALLOCATED;

    for (u32 i = 0; i < buf_length(context->stack_items); i += 1) {
        Stack_Item* stack_item = &context->stack_items[i];
        if (stack_item->local == local) {
            switch (kind) {
                case local_temporary: {
                    stack_item->size = max(stack_item->size, size);
                } break;
                case local_variable: {
                    assert(stack_item->size == size);
                } break;
                default: assert(false);
            }
            assert(stack_item->size == size);
            index = i;
            break;
        }
    }

    if (index == NO_STACK_SPACE_ALLOCATED && allocate) {
        index = buf_length(context->stack_items);
        buf_push(context->stack_items, ((Stack_Item) { .local = local, .size = size }));
    }

    return index;
}

void reg_deallocate(Context* context, u8 reg) {
    // TODO check if we need to deallocate the register at all, or if we can get away
    // with just overwriting it!
    // To do this, we need info about the last use of a certain variable/temporary.
    // To do this, we can just read ahead in the current ops list. Might not be terribly fast though...

    if (!context->regs[reg].used) return;
    context->regs[reg].used = false;

    Local local = context->regs[reg].local;
    u8 size = context->regs[reg].size;
    u32 stack_item_index = local_stack_item_index(context, size, local, true);
    write_mov_reg_to_stack(context, size, reg, stack_item_index);
}

void reg_allocate_into(Context* context, u8 size, Local local, u8 reg) {
    if (context->regs[reg].used && context->regs[reg].local == local) {
        return;
    }

    reg_deallocate(context, reg);

    u8 old_reg = REG_BAD;
    for (u32 r = 0; r < REG_COUNT; r += 1) {
        if (context->regs[r].used && context->regs[r].local == local) {
            old_reg = r;
            break;
        }
    }

    if (old_reg == REG_BAD) {
        u32 stack_item_index = local_stack_item_index(context, size, local, false);
        if (stack_item_index == NO_STACK_SPACE_ALLOCATED) {
            unimplemented(); // Is this case even legal? Doesn't it imply we are using an uninitialized variable
        } else {
            write_mov_stack_to_reg(context, size, stack_item_index, reg);
        }
    } else {
        write_mov_reg_to_reg(context, size, old_reg, reg);
        context->regs[old_reg].used = false;
    }

    context->regs[reg].used = true;
    context->regs[reg].alloc_time = context->time;
    context->regs[reg].local = local;
    context->regs[reg].size = size;
}

u8 reg_allocate(Context* context, u8 size, Local local) {
    bool deallocate = true;
    bool reallocate = true;

    u8 reg = REG_BAD;
    u32 oldest_time = context->time;
    for (u32 rp = REG_COUNT; rp > 0; rp -= 1) {
        u32 r = rp - 1;

        // Reallocate a old register
        if (context->regs[r].alloc_time < oldest_time) {
            oldest_time = context->regs[r].alloc_time;
            reg = r;

            reallocate = true;
            deallocate = true;
        }

        // Or better, use a unused register
        if (!context->regs[r].used) {
            oldest_time = 0; // makes sure we don't try to reallocate in the 'if' above
            reg = r;

            reallocate = true;
            deallocate = false;
        }

        // Or even better, use a register we allready allocated for this
        if (context->regs[r].used && context->regs[r].local == local) {
            reg = r;

            reallocate = false;
            deallocate = false;

            break;
        }
    }
    assert(reg != REG_BAD);

    // Deallocate old contents of register if needed
    if (deallocate) {
        reg_deallocate(context, reg);
    }

    // Reallocate regsiter
    if (reallocate) {
        context->regs[reg].used = true;
        context->regs[reg].alloc_time = context->time;
        context->regs[reg].local = local;
        context->regs[reg].size = size;

        u32 stack_item_index = local_stack_item_index(context, size, local, false);
        if (stack_item_index != NO_STACK_SPACE_ALLOCATED) {
            write_mov_stack_to_reg(context, size, stack_item_index, reg);
        }
    }

    return reg;
}

void op_write_machinecode(Context* context, Func* func, Op* op) {
    // Binary operators
    if (op->kind & OP_KIND_BINARY_FLAG) {
        u8 type_size = type_size_of(op->type);

        // Figure out special requirements
        // These requirements might seem a bit funky, but they reflect the way x64
        // instructions are set up.
        bool left_must_be_eax = false;
        bool clobbers_edx = false;

        switch (op->kind) {
            case op_set: break;
            case op_add: break;
            case op_sub: break;

            case op_mul: {
                left_must_be_eax = true;
                clobbers_edx = true;
                assert(local_kind(op->binary.source) != local_literal);
            } break;

            case op_div: {
                // Probably can be same as op_mul though, need to verify once we implement division properly
                unimplemented();
            } break;

            default: assert(false);
        }

        // Allocate registers based on requirements
        u8 left_reg, right_reg;
        u64 right_literal;
        bool use_right_literal;

        if (left_must_be_eax) {
            left_reg = reg_rax;
            reg_allocate_into(context, type_size, op->binary.target, left_reg);
        } else {
            left_reg = reg_allocate(context, type_size, op->binary.target);
        }

        if (local_kind(op->binary.source) == local_literal) {
            use_right_literal = true;
            right_literal = func->literals[local_index(op->binary.source)];
        } else {
            use_right_literal = false;
            right_reg = reg_allocate(context, type_size, op->binary.source);
        }

        if (clobbers_edx) {
            // Note that we still can use edx as a right reg in the instruction generated
            // below, because we only read from it and deallocating does not overwrite!
            assert(left_reg != 2);
            reg_deallocate(context, 2);
        }

        if (!use_right_literal) {
            assert(left_reg != right_reg);
        }

        // Generate opcodes
        switch (op->kind) {
            case op_set: {
                if (use_right_literal) {
                    write_mov_lit_to_reg(context, type_size, right_literal, left_reg);
                } else {
                    write_mov_reg_to_reg(context, type_size, right_reg, left_reg);
                }
            } break;

            case op_add: {
                if (use_right_literal) {
                    write_add_or_sub_lit_to_reg(context, type_size, true, right_literal, left_reg);
                } else {
                    write_add_or_sub_reg_to_reg(context, type_size, true, right_reg, left_reg);
                }
            } break;

            case op_sub: {
                if (use_right_literal) {
                    write_add_or_sub_lit_to_reg(context, type_size, false, right_literal, left_reg);
                } else {
                    write_add_or_sub_reg_to_reg(context, type_size, false, right_reg, left_reg);
                }
            } break;

            case op_mul: {
                assert(left_reg == reg_rax);
                assert(!use_right_literal);
                write_unsigned_mul(context, type_size, right_reg);
            } break;

            case op_div: {
                assert(left_reg == reg_rax);
                assert(!use_right_literal);
                unimplemented();
            } break;

            default: assert(false);
        }

    // Other operators
    } else switch (op->kind) {
        case op_reset_temporaries: {
            for (u32 r = 0; r < REG_COUNT; r += 1) {
                if (context->regs[r].used && local_kind(context->regs[r].local) == local_temporary) {
                    context->regs[r] = (Reg) {0};
                }
            }
        } break;

        case op_call: {
            // TODO calling convention: Which registers do we need to deallocate
           
            // TODO we can avoid deallocating and reallocating here, if we deallocate
            // after punching in parameters
            for (u32 r = 0; r < REG_COUNT; r += 1) {
                reg_deallocate(context, r);
            }

            Func* callee = &context->funcs[op->call.func_index];
            for (u32 p = 0; p < callee->param_count; p += 1) {
                Local param_local = op->call.params[p].local;
                u8 param_size = op->call.params[p].size;

                if (p < 4) {
                    u8 param_reg;
                    switch (p) {
                        case 0: param_reg = reg_rcx; break;
                        case 1: param_reg = reg_rdx; break;
                        case 2: unimplemented(); break; // r8
                        case 3: unimplemented(); break; // r9
                    }

                    if (local_kind(param_local) == local_literal) {
                        u64 literal = func->literals[local_index(param_local)];
                        write_mov_lit_to_reg(context, param_size, literal, param_reg);
                    } else {
                        reg_allocate_into(context, param_size, param_local, param_reg);
                        context->regs[param_reg].used = false;
                    }
                } else {
                    // TODO Parameters go on the stack
                    unimplemented();
                }

                // TODO we need to reserve stack space for parameters, even if we only
                // pass parameters via registers.
            }

            buf_push(context->bytecode, 0xe8);
            buf_push(context->bytecode, 0xde);
            buf_push(context->bytecode, 0xad);
            buf_push(context->bytecode, 0xbe);
            buf_push(context->bytecode, 0xef);

            Call_Fixup fixup = {0};
            fixup.text_location = buf_length(context->bytecode) - sizeof(i32);
            fixup.func_index = op->call.func_index;
            buf_push(context->call_fixups, fixup);

            #ifdef PRINT_GENERATED_INSTRUCTIONS
            u8* name = string_table_access(context->string_table, context->funcs[op->call.func_index].name);
            printf("call %s\n", name);
            #endif

            assert(!context->regs[reg_rax].used);
            context->regs[reg_rax] = (Reg) {
                .used = true,
                .alloc_time = context->time,
                .local = op->call.target,
                .size = type_size_of(op->type)
            };
        } break;

        default: assert(false);
    }
}

void build_machinecode(Context* context) {
    arena_stack_push(&context->stack);

    u32 main_func_index = find_func(context, string_table_search(context->string_table, "main")); 
    if (main_func_index == STRING_TABLE_NO_MATCH) {
        panic("No main function");
    }
    Func* main_func = context->funcs + main_func_index;


    buf_foreach (Func, func, context->funcs) {
        buf_clear(context->stack_fixups);
        buf_clear(context->stack_items);
        mem_clear((u8*) context->regs, sizeof(Reg) * REG_COUNT);

        func->bytecode_start = buf_length(context->bytecode);

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        u8* name = string_table_access(context->string_table, func->name);
        printf("; --- fn %s ---\n", name);
        #endif

        // TODO calling convention
        // We need preserve non-volatile registers if we change them
        // That code must go here
        // For now we don't need to because we clobber all registers when calling anything

        for (u32 p = 0; p < func->param_count; p += 1) {
            u32 var_index = p + 1; // + 1 because first var is output
            Local local = new_local(local_variable, var_index);

            u8 size = type_size_of(func->params[p].type);

            if (p < 4) {
                switch (p) {
                    case 0: context->regs[reg_rcx] = (Reg) { .used = true, .local = local, .size = size }; break;
                    case 1: context->regs[reg_rdx] = (Reg) { .used = true, .local = local, .size = size }; break;
                    case 2: unimplemented(); break; // r8
                    case 3: unimplemented(); break; // r9
                }
            } else {
                // TODO Parameters go on stack!
                // All parameters will have preallocated stack space, which we should probably use while we are at it.
                // This means punching negative values into 'func->stack_offsets', because the preallocated space is
                // on the other side of rsp from the rest of our stack space.
                unimplemented();
            }
        }

        // TODO don't generate sub rsp if we don't use the stack
        // sub rsp, stack frame size
        buf_push(context->bytecode, 0x48);
        buf_push(context->bytecode, 0x83);
        buf_push(context->bytecode, 0xec);
        buf_push(context->bytecode, 0x00);
        u64 stack_frame_size_text_location = buf_length(context->bytecode) - sizeof(u8);
        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("sub rsp, stack_frame_size\n");
        #endif


        for (u32 i = 0; i < func->op_count; i += 1) {
            Op* op = &func->ops[i];
            context->time += 1;
            op_write_machinecode(context, func, op);
        }

        for (u32 i = 0; i < buf_length(context->stack_items); i += 1) {
            u32 min = buf_length(context->stack_items) - 1;
            u8 size = U8_MAX;
            for (u32 j = i; j < buf_length(context->stack_items); j += 1) {
                u8 s = context->stack_items[j].size;
                if (s < size) {
                    min = j;
                    size = s;
                }
            }

            Stack_Item temp = context->stack_items[i];
            context->stack_items[i] = context->stack_items[min];
            context->stack_items[min] = temp;
        }

        u32 stack_offset = 0; // TODO stack space for function parameters!

        for (u32 i = 0; i < buf_length(context->stack_items); i += 1) {
            Stack_Item* stack_item = &context->stack_items[i];
            stack_offset = round_to_next(stack_offset, stack_item->size);
            stack_item->offset = stack_offset;
            stack_offset += stack_item->size;
        }

        u32 stack_size = ((stack_offset + 7) & (~0x0f)) + 8; // Aligns so last nibble is 8
        // If this assertion trips, we have to encode stack size as a imm32 in the add/sub
        // instructions setting up the stack frame.
        // While we are at it, me might want to figure out a way of removing the add/sub
        // instructions completely when we do not use the stack at all!
        assert((stack_size & 0x7f) == stack_size);

        for (u32 i = 0; i < buf_length(context->stack_fixups); i += 1) {
            Stack_Fixup* f = &context->stack_fixups[i];

            u8 old_value = context->bytecode[f->text_location];
            assert(old_value == 0x00);

            Stack_Item* stack_item = &context->stack_items[f->stack_item_index];
            u32 adjusted_offset = stack_item->offset;

            // Eventually, this assertion will trip. We then need to encode disp32 instead of always encoding disp8
            // The assert checks for signed values, not sure if that is needed...
            // We also have to fix write_mov_stack_to_reg so the functions still match.
            assert((adjusted_offset & 0x7f) == adjusted_offset);

            context->bytecode[f->text_location] = (u8) adjusted_offset;
        }

        // TODO calling convention
        // How do we pass return values?
        // This needs to be the same as how we do return value reading in 'op_call' bytecode
        if (func != main_func) {
            Local output_var = new_local(local_variable, 0);
            u8 output_size = (u8) type_size_of(func->vars[0].type);
            reg_allocate_into(context, output_size, output_var, reg_rax);
        }

        // add rsp, stack frame size
        buf_push(context->bytecode, 0x48);
        buf_push(context->bytecode, 0x83);
        buf_push(context->bytecode, 0xc4);
        buf_push(context->bytecode, stack_size);
        context->bytecode[stack_frame_size_text_location] = stack_size; // fixes up initial 'sub rsp, ...'

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("add rsp, stack_frame_size (stack_frame_size is %u)\n", (u64) stack_size);
        #endif

        // TODO this 'if' is only for testing purposes!!
        if (func != main_func) {
            buf_push(context->bytecode, 0xc3);
            #ifdef PRINT_GENERATED_INSTRUCTIONS
            printf("ret\n");
            #endif
        }
    }

    // Move output into .data+0
    {
        u8 output_reg = reg_allocate(context, 4, new_local(local_variable, 0));

        buf_push(context->bytecode, 0x88);
        buf_push(context->bytecode, 0x05 | (output_reg << 3));
        buf_push(context->bytecode, 0xde);
        buf_push(context->bytecode, 0xad);
        buf_push(context->bytecode, 0xbe);
        buf_push(context->bytecode, 0xef);

        Fixup fixup = {0};
        fixup.text_location = buf_length(context->bytecode) - sizeof(i32);
        fixup.kind = fixup_data;
        fixup.data_offset = 0;
        buf_push(context->fixups, fixup);
    }

    // Call fixups
    buf_foreach (Call_Fixup, fixup, context->call_fixups) {
        i32* target = (i32*) (context->bytecode + fixup->text_location);
        assert(*target == 0xefbeadde);

        u32 jump_to = context->funcs[fixup->func_index].bytecode_start;
        u32 jump_from = fixup->text_location + sizeof(i32);

        *target = ((i32) jump_to) - ((i32) jump_from);
    }

    DynlibImport kernel32 = {0};
    kernel32.name = "KERNEL32.DLL";
    buf_push(kernel32.functions, ((Import_Function){"GetStdHandle", 0x2d5}));
    buf_push(kernel32.functions, ((Import_Function){"WriteFile", 0x619}));
    buf_push(kernel32.functions, ((Import_Function){"ExitProcess", 0x162}));
    buf_push(context->dlls, kernel32);

    str_push_str(&context->bytecode_data, "_i\n\0", 4);

    Fixup fixup = {0};

    // sub rsp,58h  
    buf_push(context->bytecode, 0x48);
    buf_push(context->bytecode, 0x83);
    buf_push(context->bytecode, 0xec);
    buf_push(context->bytecode, 0x58);

    //lea rax,[0cc3000h]  
    buf_push(context->bytecode, 0x48);
    buf_push(context->bytecode, 0x8d);
    buf_push(context->bytecode, 0x05);
    buf_push(context->bytecode, 0xde);
    buf_push(context->bytecode, 0xad);
    buf_push(context->bytecode, 0xbe);
    buf_push(context->bytecode, 0xef);
    fixup.text_location = buf_length(context->bytecode) - sizeof(i32);
    fixup.kind = fixup_data;
    fixup.data_offset = 0;
    buf_push(context->fixups, fixup);
    // mov qword ptr [rsp+38h],rax  
    buf_push(context->bytecode, 0x48);
    buf_push(context->bytecode, 0x89);
    buf_push(context->bytecode, 0x44);
    buf_push(context->bytecode, 0x24);
    buf_push(context->bytecode, 0x38);

    // GetStdHandle()
    // mov ecx, 0xfffffff5   (param)
    buf_push(context->bytecode, 0xb9);
    buf_push(context->bytecode, 0xf5);
    buf_push(context->bytecode, 0xff);
    buf_push(context->bytecode, 0xff);
    buf_push(context->bytecode, 0xff);
    // call qword ptr [rip + 0x0f9b]  
    buf_push(context->bytecode, 0xff);
    buf_push(context->bytecode, 0x15);
    buf_push(context->bytecode, 0xde);
    buf_push(context->bytecode, 0xad);
    buf_push(context->bytecode, 0xbe);
    buf_push(context->bytecode, 0xef);

    fixup.text_location = buf_length(context->bytecode) - sizeof(i32);
    fixup.kind = fixup_imported_function;
    fixup.imported.dll = 0;
    fixup.imported.function = 0;
    buf_push(context->fixups, fixup);

    // mov qword ptr [rsp+40h],rax  
    buf_push(context->bytecode, 0x48);
    buf_push(context->bytecode, 0x89);
    buf_push(context->bytecode, 0x44);
    buf_push(context->bytecode, 0x24);
    buf_push(context->bytecode, 0x40);
    
    // This is space for the `bytes_written` pointer which is returned
    // mov dword ptr [rsp+30h],0  
    buf_push(context->bytecode, 0xc7);
    buf_push(context->bytecode, 0x44);
    buf_push(context->bytecode, 0x24);
    buf_push(context->bytecode, 0x30);
    buf_push(context->bytecode, 0x00);
    buf_push(context->bytecode, 0x00);
    buf_push(context->bytecode, 0x00);
    buf_push(context->bytecode, 0x00);
    
    // WriteFile()
    // mov qword ptr [rsp+20h],0  
    buf_push(context->bytecode, 0x48);
    buf_push(context->bytecode, 0xc7);
    buf_push(context->bytecode, 0x44);
    buf_push(context->bytecode, 0x24);
    buf_push(context->bytecode, 0x20);
    buf_push(context->bytecode, 0x00);
    buf_push(context->bytecode, 0x00);
    buf_push(context->bytecode, 0x00);
    buf_push(context->bytecode, 0x00);
    // lea r9,[rsp+30h]  
    buf_push(context->bytecode, 0x4c);
    buf_push(context->bytecode, 0x8d);
    buf_push(context->bytecode, 0x4c);
    buf_push(context->bytecode, 0x24);
    buf_push(context->bytecode, 0x30);
    // mov r8d,3  
    buf_push(context->bytecode, 0x41);
    buf_push(context->bytecode, 0xb8);
    buf_push(context->bytecode, 0x03);
    buf_push(context->bytecode, 0x00);
    buf_push(context->bytecode, 0x00);
    buf_push(context->bytecode, 0x00);
    // mov rdx,qword ptr [rsp+38h]  
    buf_push(context->bytecode, 0x48);
    buf_push(context->bytecode, 0x8b);
    buf_push(context->bytecode, 0x54);
    buf_push(context->bytecode, 0x24);
    buf_push(context->bytecode, 0x38);
    // mov rcx,qword ptr [rsp+40h]  
    buf_push(context->bytecode, 0x48);
    buf_push(context->bytecode, 0x8b);
    buf_push(context->bytecode, 0x4c);
    buf_push(context->bytecode, 0x24);
    buf_push(context->bytecode, 0x40);
    // call        qword ptr [rip + buf_push(context->bytecode, 0x0f72]  
    buf_push(context->bytecode, 0xff);
    buf_push(context->bytecode, 0x15);
    buf_push(context->bytecode, 0xde);
    buf_push(context->bytecode, 0xad);
    buf_push(context->bytecode, 0xbe);
    buf_push(context->bytecode, 0xef);

    fixup.text_location = buf_length(context->bytecode) - sizeof(i32);
    fixup.kind = fixup_imported_function;
    fixup.imported.dll = 0;
    fixup.imported.function = 1;
    buf_push(context->fixups, fixup);

    // ExitProcess()
    // xor ecx,ecx  
    buf_push(context->bytecode, 0x33);
    buf_push(context->bytecode, 0xc9);
    // call qword ptr [rip + 0x0f72]  
    buf_push(context->bytecode, 0xff);
    buf_push(context->bytecode, 0x15);
    buf_push(context->bytecode, 0xde);
    buf_push(context->bytecode, 0xad);
    buf_push(context->bytecode, 0xbe);
    buf_push(context->bytecode, 0xef);

    fixup.text_location = buf_length(context->bytecode) - sizeof(i32);
    fixup.kind = fixup_imported_function;
    fixup.imported.dll = 0;
    fixup.imported.function = 2;
    buf_push(context->fixups, fixup);

    // xor eax,eax  
    buf_push(context->bytecode, 0x33);
    buf_push(context->bytecode, 0xc0);

    // Reset stack
    // add rsp,58h  
    buf_push(context->bytecode, 0x48);
    buf_push(context->bytecode, 0x83);
    buf_push(context->bytecode, 0xc4);
    buf_push(context->bytecode, 0x58);
    // ret
    buf_push(context->bytecode, 0xc3);

    arena_stack_pop(&context->stack);
}

typedef struct COFF_Header {
    u8 signature[4];

    u16 machine;
    u16 section_count;
    u32 timestamp; // Unix timestamp from creation time. Used as a unique key for DLLs

    u32 pointer_to_symbol_table; // Deprecated
    u32 number_of_symbols; // Deprecated

    u16 size_of_optional_header;
    u16 flags; // "characteristics"
} COFF_Header;

const u16 COFF_MACHINE_AMD64 = 0x8664;

const u16 COFF_FLAGS_EXECUTABLE_IMAGE    = 0x0002;
const u16 COFF_FLAGS_LARGE_ADDRESS_AWARE = 0x0020;

typedef struct Image_Header {
    u16 magic;

    u8 major_linker_version;
    u8 minor_linker_version;

    u32 size_of_code;               // Sum of size of all .text sections
    u32 size_of_initialized_data;   // Sum of .data sections
    u32 size_of_uninitialized_data; // Sum of .bss section

    u32 entry_point;  // Address relative to image base
    u32 base_of_code; // Address relative to image base

    u64 image_base; // Preferred first memory address. Default is 0x00400000

    u32 section_alignment;
    u32 file_alignment;

    u16 major_os_version; // Required os version
    u16 minor_os_version;
    u16 major_image_version;
    u16 minor_image_version;

    u16 major_subsystem_version;
    u16 minor_subsystem_version;
    u32 win32_version_value; // Must be 0

    u32 size_of_image;
    u32 size_of_headers;

    u32 checksum; // Not checked for contexts
    u16 subsystem;
    u16 dll_flags;
    u64 stack_reserve;
    u64 stack_commit;
    u64 heap_reserve;
    u64 heap_commit;
    u32 loader_flags; // Must be 0

    u32 number_of_rva_and_sizes;

    struct {
        u32 virtual_address;
        u32 size;
    } data_directories[16];
} Image_Header;

const u16 IMAGE_PE64 = 0x020b; // "PE32+". We only allow this
const u16 IMAGE_SUBSYSTEM_WINDOWS_GUI = 2;
const u16 IMAGE_SUBSYSTEM_WINDOWS_CONSOLE = 3;

const u16 IMAGE_DLL_FLAGS_64_BIT_VA             = 0x0020;
const u16 IMAGE_DLL_FLAGS_DYNAMIC_BASE          = 0x0040; // Can be relocated at load
const u16 IMAGE_DLL_FLAGS_NX_COMPAT             = 0x0100;
const u16 IMAGE_DLL_FLAGS_NO_SEH                = 0x0400; // No structured exception handling
const u16 IMAGE_DLL_FLAGS_TERMINAL_SERVER_AWARE = 0x8000;

typedef struct Section_Header {
    u8 name[8];
    u32 virtual_size;
    u32 virtual_address;
    u32 size_of_raw_data;
    u32 pointer_to_raw_data;
    u32 unused[3]; // Not used in executable files
    u32 flags;
} Section_Header;

const u32 SECTION_FLAGS_CODE               = 0x00000020;
const u32 SECTION_FLAGS_INITIALIZED_DATA   = 0x00000040;
const u32 SECTION_FLAGS_UNINITIALIZED_DATA = 0x00000080;
const u32 SECTION_FLAGS_NOT_CACHED         = 0x04000000;
const u32 SECTION_FLAGS_NOT_PAGED          = 0x08000000;
const u32 SECTION_FLAGS_SHARED             = 0x10000000;
const u32 SECTION_FLAGS_EXECUTE            = 0x20000000;
const u32 SECTION_FLAGS_READ               = 0x40000000;
const u32 SECTION_FLAGS_WRITE              = 0x80000000;


void write_executable(u8* path, Context* context) {
    enum { section_count = 4 }; // So we can use it as an array length
    u64 in_file_alignment = 0x200;
    u64 in_memory_alignment = 0x1000;
    u64 dos_prepend_size = 200;
    u64 total_header_size = dos_prepend_size + sizeof(COFF_Header) + sizeof(Image_Header) + section_count*sizeof(Section_Header);

    u64 text_length = buf_length(context->bytecode);
    u64 data_length = buf_length(context->bytecode_data);

    // NB pdata is completly messed up. It is supposed to be pointing to some
    // unwind info, which we deleted by accident. We have to figure out how to
    // generate that info. We can't test that without first having some codegen
    // though...
    u8 pdata[12]  = { 0x0, 0x10, 0x0, 0x0, 0xa5, 0x10, 0x0, 0x0, 0x10, 0x21, 0x0, 0x0 };
    u64 pdata_length = 12;
    struct { u32 begin; u32 end; u32 rva; } *pdata_info = (void*) pdata;

    // Figure out placement and final size
    u64 header_space = round_to_next(total_header_size, in_file_alignment);

    u64 text_file_start  = header_space;
    u64 data_file_start  = text_file_start  + round_to_next(text_length,  in_file_alignment);
    u64 pdata_file_start = data_file_start  + round_to_next(data_length,  in_file_alignment);
    u64 idata_file_start = pdata_file_start + round_to_next(pdata_length, in_file_alignment);

    u64 text_memory_start  = round_to_next(total_header_size, in_memory_alignment);
    u64 data_memory_start  = text_memory_start  + round_to_next(text_length,  in_memory_alignment);
    u64 pdata_memory_start = data_memory_start  + round_to_next(data_length,  in_memory_alignment);
    u64 idata_memory_start = pdata_memory_start + round_to_next(pdata_length, in_memory_alignment);

    // Verify that fixups are not bogus data, so we don't have to do that later...
    for (u64 i = 0; i < buf_length(context->fixups); i += 1) {
        Fixup* fixup = &context->fixups[i];

        if (fixup->text_location >= text_length) {
            panic("Can't apply fixup at %x which is beyond end of text section at %x\n", fixup->text_location, text_length);
        }

        i32 text_value = *((u32*) (context->bytecode + fixup->text_location));
        if (text_value != 0xefbeadde) {
            panic("All fixup override locations should be set to {0xde 0xad 0xbe 0xef} as a sentinel. Found %x instead\n", text_value);
        }

        switch (fixup->kind) {
            case fixup_imported_function: {
                u32 l = fixup->imported.dll;
                u32 f = fixup->imported.function;

                if (l > buf_length(context->dlls)) {
                    panic(
                        "Function fixup refers to invalid library %u. There are only %u dlls.\n",
                        (u64) l, (u64) buf_length(context->dlls)
                    );
                } else if (f > buf_length(context->dlls[l].functions)) {
                    panic(
                        "Function fixup refers to invalid function %u in library %u. There are only %u functions.\n",
                        (u64) f, (u64) l, (u64) buf_length(context->dlls[l].functions)
                    );
                }
            } break;

            case fixup_data: {
                assert(fixup->data_offset < data_length);
            } break;

            default: assert(false);
        }
    }

    // Build idata
    u8* idata = null;
    typedef struct Import_Entry {
        u32 lookup_table_address;
        u32 timestamp;
        u32 forwarder_chain;
        u32 name_address;
        u32 address_table_address;
    } Import_Entry;

    u64 idata_import_offset = buf_length(idata);
    str_push_zeroes(&idata, (buf_length(context->dlls) + 1) * sizeof(Import_Entry));
    for (u64 i = 0; i < buf_length(context->dlls); i += 1) {
        DynlibImport* library = &context->dlls[i];

        u64 table_size = sizeof(u64) * (1 + buf_length(library->functions));
        u64 address_table_start = buf_length(idata);
        u64 lookup_table_start = address_table_start + table_size;

        str_push_zeroes(&idata, 2*table_size); // Make space for the address & lookup table

        u64 name_table_start = buf_length(idata);
        str_push_cstr(&idata, library->name);
        buf_push(idata, 0);

        for (u64 j = 0; j < buf_length(library->functions); j += 1) {
            u64 function_name_address = idata_memory_start + buf_length(idata);
            if ((function_name_address & 0x7fffffff) != function_name_address) {
                panic("Import data will be invalid, because it has functions at to high rvas: %x!", function_name_address);
            }

            u8* name = library->functions[j].name;
            u16 hint = library->functions[j].hint;

            buf_push(idata, (u8) (hint & 0xff));
            buf_push(idata, (u8) ((hint >> 8) & 0xff));
            str_push_cstr(&idata, name);
            buf_push(idata, 0);
            if (buf_length(idata) & 1) { buf_push(idata, 0); } // align

            *((u64*) (idata + address_table_start + sizeof(u64)*j)) = function_name_address;
            *((u64*) (idata + lookup_table_start  + sizeof(u64)*j)) = function_name_address;
        }

        // Write into the space we prefilled before the loop
        Import_Entry* entry = (void*) (idata + idata_import_offset + i*sizeof(Import_Entry));
        entry->address_table_address = idata_memory_start + address_table_start;
        entry->lookup_table_address  = idata_memory_start + lookup_table_start;
        entry->name_address          = idata_memory_start + name_table_start;

        // Apply fixups for this library
        for (u64 k = 0; k < buf_length(context->fixups); k += 1) {
            Fixup* fixup = &context->fixups[k];
            if (fixup->kind != fixup_imported_function || fixup->imported.dll != i) { continue; }

            u32 function = fixup->imported.function;
            u64 function_address = idata_memory_start + address_table_start + sizeof(u64)*function;

            i32* text_value = (i32*) (context->bytecode + fixup->text_location);
            *text_value = function_address;
            *text_value -= (text_memory_start + fixup->text_location + sizeof(i32)); // make relative
        }
    }
    u64 idata_length = buf_length(idata);

    // Knowing idata size, we can compute final size
    u64 file_image_size   = idata_file_start   + round_to_next(idata_length, in_file_alignment);
    u64 memory_image_size = idata_memory_start + round_to_next(idata_length, in_memory_alignment);

    // Apply data & function fixups
    for (u64 i = 0; i < buf_length(context->fixups); i += 1) {
        Fixup* fixup = &context->fixups[i];
        i32* text_value = (u32*) (context->bytecode + fixup->text_location);

        switch (fixup->kind) {
            case fixup_imported_function: break;

            case fixup_data: {
                *text_value = data_memory_start + fixup->data_offset;
                *text_value -= (text_memory_start + fixup->text_location + sizeof(i32)); // make relative
            } break;

            default: assert(false);
        }
    }

    // Allocate space and fill in the image
    u8* output_file = alloc(file_image_size);
    mem_clear(output_file, file_image_size);

    u8 dos_prepend[200] = {
        0x4d, 0x5a, 0x90, 0x0, 0x3, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0xff, 0xff, 0x0, 0x0, 0xb8,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, // <- dos_prepend_size goes in these four bytes
        0xe, 0x1f, 0xba, 0xe, 0x0, 0xb4, 0x9, 0xcd, 0x21, 0xb8, 0x1, 0x4c, 0xcd, 0x21, 0x54, 0x68,
        0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e,
        0x6f, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f,
        0x53, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x2e, 0xd, 0xd, 0xa, 0x24, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x11, 0xba, 0x1, 0xc7, 0x55, 0xdb, 0x6f, 0x94, 0x55, 0xdb, 0x6f, 0x94, 0x55, 0xdb,
        0x6f, 0x94, 0x26, 0xb9, 0x6e, 0x95, 0x56, 0xdb, 0x6f, 0x94, 0x55, 0xdb, 0x6e, 0x94, 0x56,
        0xdb, 0x6f, 0x94, 0xb2, 0xbf, 0x6b, 0x95, 0x54, 0xdb, 0x6f, 0x94, 0xb2, 0xbf, 0x6d, 0x95,
        0x54, 0xdb, 0x6f, 0x94, 0x52, 0x69, 0x63, 0x68, 0x55, 0xdb, 0x6f, 0x94, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    };
    mem_copy(dos_prepend, output_file, dos_prepend_size);
    *((u32*) (output_file + 60)) = dos_prepend_size;


    COFF_Header coff = {0};
    Image_Header image = {0};
    Section_Header section_headers[section_count] = {0};

    mem_copy("PE\0\0", coff.signature, 4);
    coff.machine = COFF_MACHINE_AMD64;
    image.magic = IMAGE_PE64;
    coff.flags = COFF_FLAGS_EXECUTABLE_IMAGE | COFF_FLAGS_LARGE_ADDRESS_AWARE;
    image.subsystem = IMAGE_SUBSYSTEM_WINDOWS_CONSOLE;
    coff.size_of_optional_header = sizeof(Image_Header);
    image.major_os_version = 6;
    image.minor_os_version = 0;
    image.major_subsystem_version = 6;
    image.minor_subsystem_version = 0;
    image.dll_flags =
        IMAGE_DLL_FLAGS_TERMINAL_SERVER_AWARE |
        IMAGE_DLL_FLAGS_NX_COMPAT |
        IMAGE_DLL_FLAGS_DYNAMIC_BASE |
        //IMAGE_DLL_FLAGS_NO_SEH |
        IMAGE_DLL_FLAGS_64_BIT_VA;
    image.file_alignment = in_file_alignment;
    image.section_alignment = in_memory_alignment;
    image.size_of_headers = header_space;
    coff.section_count = section_count;

    image.size_of_code = text_length;
    image.size_of_initialized_data = data_length + idata_length + pdata_length;
    image.size_of_uninitialized_data = 0;

    u32 main_func_index = find_func(context, string_table_search(context->string_table, "main")); 
    if (main_func_index == STRING_TABLE_NO_MATCH) {
        panic("No main function");
    }
    u32 main_bytecode_start = context->funcs[main_func_index].bytecode_start;
    image.entry_point = text_memory_start + main_bytecode_start;

    image.base_of_code = text_memory_start;
    image.size_of_image = memory_image_size;
    image.image_base = 0x00400000;

    image.stack_reserve = 0x100000;
    image.stack_commit  = 0x100000;
    image.heap_reserve  = 0x100000;
    image.heap_commit   = 0x100000;

    image.number_of_rva_and_sizes = 16;
    image.data_directories[1].virtual_address = idata_memory_start + idata_import_offset;
    image.data_directories[1].size = (buf_length(context->dlls) + 1)*sizeof(Import_Entry);
    image.data_directories[3].virtual_address = pdata_memory_start;
    image.data_directories[3].size = pdata_length;

    Section_Header* text_header = &section_headers[0];
    mem_copy(".text", text_header->name, 5);
    text_header->flags = SECTION_FLAGS_EXECUTE | SECTION_FLAGS_READ | SECTION_FLAGS_CODE;
    text_header->virtual_size = text_length;
    text_header->virtual_address = text_memory_start;
    text_header->size_of_raw_data = round_to_next(text_length, in_file_alignment);
    text_header->pointer_to_raw_data = text_file_start;

    Section_Header* data_header = &section_headers[1];
    mem_copy(".data", data_header->name, 5);
    data_header->flags = SECTION_FLAGS_READ | SECTION_FLAGS_WRITE | SECTION_FLAGS_INITIALIZED_DATA;
    data_header->virtual_size = data_length;
    data_header->virtual_address = data_memory_start;
    data_header->size_of_raw_data = round_to_next(data_length, in_file_alignment);
    data_header->pointer_to_raw_data = data_file_start;

    Section_Header* pdata_header = &section_headers[2];
    mem_copy(".pdata", pdata_header->name, 6);
    pdata_header->flags = SECTION_FLAGS_READ | SECTION_FLAGS_INITIALIZED_DATA;
    pdata_header->virtual_size = pdata_length;
    pdata_header->virtual_address = pdata_memory_start;
    pdata_header->size_of_raw_data = round_to_next(pdata_length, in_file_alignment);
    pdata_header->pointer_to_raw_data = pdata_file_start;

    Section_Header* idata_header = &section_headers[3];
    mem_copy(".idata", idata_header->name, 6);
    idata_header->flags = SECTION_FLAGS_READ | SECTION_FLAGS_WRITE | SECTION_FLAGS_INITIALIZED_DATA;
    idata_header->virtual_size = idata_length;
    idata_header->virtual_address = idata_memory_start;
    idata_header->size_of_raw_data = round_to_next(idata_length, in_file_alignment);
    idata_header->pointer_to_raw_data = idata_file_start;


    // Write headers
    u64 header_offset = dos_prepend_size;

    mem_copy((u8*) &coff, output_file + header_offset, sizeof(COFF_Header));
    header_offset += sizeof(COFF_Header);

    mem_copy((u8*) &image, output_file + header_offset, sizeof(Image_Header));
    header_offset += sizeof(Image_Header);

    mem_copy((u8*) section_headers, output_file + header_offset, section_count * sizeof(Section_Header));

    // Write data
    mem_copy(context->bytecode, output_file + text_file_start,  text_length);
    mem_copy(context->bytecode_data, output_file + data_file_start,  data_length);
    mem_copy(pdata,    output_file + pdata_file_start, pdata_length);
    mem_copy(idata,    output_file + idata_file_start, idata_length);

    bool success = write_entire_file(path, output_file, file_image_size);
    // TODO proper error handling for file write failure
    assert(success);

    buf_free(idata);
}

void print_executable_info(u8* path) {
    // NB this is only testing code!!!!!!!!!!!!!!!!!!!!!!
    // No overflow checking here!

    u8* file;
    u32 file_length;
    if (!read_entire_file(path, &file, &file_length)) {
        printf("Couldn't load %s\n", path);
        return;
    }

    printf("  %s file size: %u\n", path, (u64) file_length);
    if (file_length > 78 + 38) {
        // Grab the message from the dos stub for fun
        printf("  ");
        print(file + 78, 38);
        printf(", nice!\n");
    }

    /*
    // Only used for printing, not a good idea..
    struct {
        u8 dos_header[60];
        u32 offset_to_coff_header;
        u8 dos_stub[136];

        COFF_Header    coff;
        Image_Header   image;
        Section_Header sections[4];
    } * header = (void*) file;

    {
        printf("\n\n\n");
        printf("struct Full_Header* header = (void*) output_file;\n\n");

        printf("header->offset_to_coff_header = %u;\n\n", header->offset_to_coff_header);

        for (u32 i = 0; i < 64; i += 1) {
            printf("header->dos_header[%u] = %x;\n", i, header->dos_header[i]);
        }
        for (u32 i = 0; i < 136; i += 1) {
            printf("header->dos_stub[%u] = %x;\n", i, header->dos_stub[i]);
        }
        printf("\n");

        printf("header->coff.signature[0] = %u;\n", header->coff.signature[0]);
        printf("header->coff.signature[1] = %u;\n", header->coff.signature[1]);
        printf("header->coff.signature[2] = %u;\n", header->coff.signature[2]);
        printf("header->coff.signature[3] = %u;\n", header->coff.signature[3]);
        printf("header->coff.machine = %u;\n", header->coff.machine);
        printf("header->coff.section_count = %u;\n", header->coff.section_count);
        printf("header->coff.timestamp = %u;\n", header->coff.timestamp);
        printf("header->coff.pointer_to_symbol_table = %u;\n", header->coff.pointer_to_symbol_table);
        printf("header->coff.number_of_symbols = %u;\n", header->coff.number_of_symbols);
        printf("header->coff.size_of_optional_header = %u;\n", header->coff.size_of_optional_header);
        printf("header->coff.flags = %u;\n", header->coff.flags);

        printf("\n");
        printf("header->image.magic = %u;\n", header->image.magic);
        printf("header->image.major_linker_version = %u;\n", header->image.major_linker_version);
        printf("header->image.minor_linker_version = %u;\n", header->image.minor_linker_version);
        printf("header->image.size_of_code = %u;\n", header->image.size_of_code);
        printf("header->image.size_of_initialized_data = %u;\n", header->image.size_of_initialized_data);
        printf("header->image.size_of_uninitialized_data = %u;\n", header->image.size_of_uninitialized_data);
        printf("header->image.entry_point = %u;\n", header->image.entry_point);
        printf("header->image.base_of_code = %u;\n", header->image.base_of_code);
        printf("header->image.image_base = %u;\n", header->image.image_base);
        printf("header->image.section_alignment = %u;\n", header->image.section_alignment);
        printf("header->image.file_alignment = %u;\n", header->image.file_alignment);
        printf("header->image.major_os_version = %u;\n", header->image.major_os_version);
        printf("header->image.minor_os_version = %u;\n", header->image.minor_os_version);
        printf("header->image.major_image_version = %u;\n", header->image.major_image_version);
        printf("header->image.minor_image_version = %u;\n", header->image.minor_image_version);
        printf("header->image.major_subsystem_version = %u;\n", header->image.major_subsystem_version);
        printf("header->image.minor_subsystem_version = %u;\n", header->image.minor_subsystem_version);
        printf("header->image.win32_version_value = %u;\n", header->image.win32_version_value);
        printf("header->image.size_of_image = %u;\n", header->image.size_of_image);
        printf("header->image.size_of_headers = %u;\n", header->image.size_of_headers);
        printf("header->image.checksum = %u;\n", header->image.checksum);
        printf("header->image.subsystem = %u;\n", header->image.subsystem);
        printf("header->image.dll_flags = %u;\n", header->image.dll_flags);
        printf("header->image.stack_reserve = %u;\n", header->image.stack_reserve);
        printf("header->image.stack_commit = %u;\n", header->image.stack_commit);
        printf("header->image.heap_reserve = %u;\n", header->image.heap_reserve);
        printf("header->image.heap_commit = %u;\n", header->image.heap_commit);
        printf("header->image.loader_flags = %u;\n", header->image.loader_flags);
        printf("header->image.number_of_rva_and_sizes = %u;\n", header->image.number_of_rva_and_sizes);

        printf("\n");
        for (u32 i = 0; i < 16; i += 1) {
            printf("header->image.data_directories[%u].virtual_address = %u;\n", i, header->image.data_directories[i].virtual_address);
            printf("header->image.data_directories[%u].size = %u;\n", i, header->image.data_directories[i].size);
        }

        printf("\n");

        for (u32 i = 0; i < 4; i += 1) {
            printf("{\n");
            Section_Header* s = &(header->sections[i]);
            printf("    Section_Header* s = &header->sections[%u];\n", i);
            printf("\n");
            printf("    s->name[0] = %u;\n", s->name[0]);
            printf("    s->name[1] = %u;\n", s->name[1]);
            printf("    s->name[2] = %u;\n", s->name[2]);
            printf("    s->name[3] = %u;\n", s->name[3]);
            printf("    s->name[4] = %u;\n", s->name[4]);
            printf("    s->name[5] = %u;\n", s->name[5]);
            printf("    s->name[6] = %u;\n", s->name[6]);
            printf("    s->name[7] = %u;\n", s->name[7]);
            printf("    s->virtual_size = %u;\n", s->virtual_size);
            printf("    s->virtual_address = %u;\n", s->virtual_address);
            printf("    s->size_of_raw_data = %u;\n", s->size_of_raw_data);
            printf("    s->pointer_to_raw_data = %u;\n", s->pointer_to_raw_data);
            printf("    s->flags = %u;\n", s->flags);
            printf("\n");

            u8* raw_data = file + s->pointer_to_raw_data;
            printf("    u8 raw_data[%u] = { ", s->size_of_raw_data);
            for (u32 i = 0; i < s->size_of_raw_data; i += 1) {
                if (i == 0) {
                    printf("%x", raw_data[i]);
                } else {
                    printf(", %x", raw_data[i]);
                }
            }
            printf(" };\n");

            printf("    for (u32 i = 0; i < s->size_of_raw_data; i += 1) {\n");
            printf("        output_file[s->pointer_to_raw_data + i] = raw_data[i];\n");
            printf("    }\n");

            printf("}\n\n");
        }
    }
    printf("\n\n\n");
    */

    u32 coff_header_offset = *((u32*) (file + 0x3c));
    COFF_Header* coff_header = (void*) (file + coff_header_offset);

    printf("  Section count: %u\n", (u64) coff_header->section_count);
    printf("  Header size: %u\n", (u64) coff_header->size_of_optional_header);

    Image_Header* image_header = (void*) (coff_header + 1);

    printf("  Linker version: %u %u\n", (u64) image_header->major_linker_version, (u64) image_header->minor_linker_version);
    printf("  .text is %u, .data is %u, .bss is %u\n", (u64) image_header->size_of_code, (u64) image_header->size_of_initialized_data, (u64) image_header->size_of_uninitialized_data);
    printf("  Entry %x, base %x\n", image_header->entry_point, image_header->base_of_code);
    printf("  Subsystem: %x\n", image_header->subsystem);
    printf("  Stack: %x,%x\n", image_header->stack_reserve, image_header->stack_commit);

    Section_Header* section_header = (void*) (image_header + 1);
    for (u32 i = 0; i < coff_header->section_count; i += 1) {
        u32 end = (u32) (((u8*) section_header) - file);
        if (end > file_length) {
            printf("  Sections run off end of file\n");
            return;
        }

        printf("  Section %s\n", section_header->name);

        section_header += 1;
    }

    free(file);
}

void print_crap(Context* context) {
    printf("%u functions:\n", (u64) buf_length(context->funcs));
    for (u32 f = 0; f < buf_length(context->funcs); f += 1) {
        Func* func = context->funcs + f;

        u8* name = string_table_access(context->string_table, func->name);
        printf("  fn %s\n", name);

        printf("    %u variables: ", (u64) func->var_count);
        for (u32 v = 0; v < func->var_count; v += 1) {
            Var* var = func->vars + v;
            u8* name = string_table_access(context->string_table, var->name);

            if (v == 0) {
                printf("%s", name);
            } else {
                printf(", %s", name);
            }
        }
        printf("\n");

        printf("    %u statements:\n", (u64) func->stmt_count);
        for (u32 s = 0; s < func->stmt_count; s += 1) {
            printf("      ");
            stmt_print(context, func, func->stmts + s);
            printf("\n");
        }
    }
}

void main() {
    //print_executable_info("build/tiny.exe");

    Context context = {0};
    bool success;

    success = build_ast(&context, "W:/small/asm2/code.txt");
    if (!success) { return; } // We print errors from inside build_context/typecheck
    success = typecheck(&context);
    if (!success) { return; }
    print_crap(&context);
    build_intermediate(&context);
    eval_ops(&context);
    build_machinecode(&context);
    write_executable("out.exe", &context);

    printf("Running generated executable:\n");
    STARTUPINFO startup_info = {0};
    startup_info.size = sizeof(STARTUPINFO);
    PROCESSINFO process_info = {0};
    bool result = CreateProcessA("out.exe", "", null, null, false, 0, null, null, &startup_info, &process_info);
    if (!result) {
        printf("Failed to start generated executable\n");
        return;
    }
    WaitForSingleObject(process_info.process, 0xffffffff);
}


// win32 functions are __stdcall, but that is ignored in x64
//
// First four parameters go in registers, depending on type:
//      rcx  xmm0
//      rdx  xmm1
//      r8   xmm2
//      r9   xmm3
// Larger types are passed as pointers to caller-allocated memory
// Caller-allocated memory must be 16-byte alligned
// Values are returned in rax or xmm0 if they fit
//
// Voltatile registers can be overwritten by the callee, invalidating their previous
// values. Nonvolatile registers must remain constant across function calls.
// Volatile         rax rcx rdx  r8  r9 r10 r11
// Nonvoltatile     rbx rbp rdi rsi rsp r12 r13 r14 r15
//
// Caller must allocate stack space for all passed parameters, even though the first
// four parameters always go in registers rather than on the stack. Space for at least
// four parameters must be allocated!
//
// The stack grows downwards
// rsp points to the bottom of the stack
// rsp must be 16 byte aligned when 'call' is executed
//
// call pushes return rip (8 bytes)
