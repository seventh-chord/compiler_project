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

#define U8_MAX 0xff
#define U16_MAX 0xffff
#define U32_MAX 0xffffffff

#define I8_MAX 127
#define I8_MIN -128
#define I16_MAX 32767
#define I16_MIN -32768
#define I32_MAX 2147483647
#define I32_MIN -2147483648

#define max(a, b)  ((a) > (b)? (a) : (b))
#define min(a, b)  ((a) > (b)? (b) : (a))

#include <stdarg.h>
#include "winapi.h" // our substitute for windows.h

Handle stdout;
Handle process_heap;
i64 perf_frequency;

void printf(u8* string, ...);
void printf_flush();



#ifdef DEBUG
#define trap_or_exit()   (DebugBreak(), ExitProcess(-1))
#else
#define trap_or_exit()   (ExitProcess(-1))
#endif

#define assert(x)        ((x)? (null) : (printf("assert(%s) failed, %s:%u\n", #x, __FILE__, (u64) __LINE__), printf_flush(), trap_or_exit(), null))
#define panic(x, ...)    (printf("Panic at %s:%u: ", __FILE__, (u64) __LINE__), printf(x, __VA_ARGS__), printf_flush(), trap_or_exit())
#define unimplemented()  (printf("Reached unimplemented code at %s:%u\n", __FILE__, (u64) __LINE__), printf_flush(), trap_or_exit(), null)


void main();
void program_entry() {
    stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    process_heap = GetProcessHeap();
    QueryPerformanceFrequency(&perf_frequency);
    main();
    printf_flush();
    ExitProcess(0);
}

u64 round_to_next(u64 value, u64 step) {
    value += step - 1;
    value /= step;
    value *= step;
    return value;
}

i64 perf_time() {
    i64 result = 0;
    QueryPerformanceCounter(&result);
    return result;
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

bool mem_cmp(u8* a, u8* b, u64 count) {
    while (count >= 8) {
        if (*((u64*) a) != *((u64*) b)) {
            return false;
        }

        a += 8;
        b += 8;
        count -= 8;
    }

    while (count >= 1) {
        if (*a != *b) {
            return false;
        }

        a += 1;
        b += 1;
        count -= 1;
    }

    return true;
}

bool str_cmp(u8* a, u8* b) {
    while (1) {
        if (*a != *b) {
            return false;
        }

        if (*a == 0 || *b == 0) {
            break;
        }

        a += 1;
        b += 1;
    }
    
    return true;
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
        u64 new_capacity = max(64, new_len);
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

    if (cstr_length == 0) return;

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

void str_push_integer(u8** buf, u8 bytes, u64 value) {
    assert(bytes <= 8);
    _buf_fit(*buf, bytes);
    u64* buf_length = &_buf_header(*buf)->length;
    for (u8 i = 0; i < bytes; i += 1) {
        *(*buf + *buf_length + i) = value & 0xff;
        value = value >> 8;
    }
    *buf_length += bytes;
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

    u64 align_offset = ((u64) start) % ARENA_ALIGN;
    if (align_offset != 0) {
        align_offset = ARENA_ALIGN - align_offset;
    }

    if (size + align_offset > free_space) {
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
    u64 align_offset = ((u64) ptr) % ARENA_ALIGN;
    if (align_offset != 0) {
        align_offset = ARENA_ALIGN - align_offset;
        ptr += align_offset;
    }

    arena->current_page->used += size + align_offset;

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

void printf_flush() {
    #ifdef DEBUG
    buf_push(printf_buf, '\0');
    OutputDebugStringA(printf_buf);
    #else
    print(printf_buf, buf_length(printf_buf));
    #endif

    buf_clear(printf_buf);
}

void printf(u8* string, ...) {
    bool flush = false;

    va_list args = {0};
    va_start(args, string);

    for (u8* t = string; *t != '\0'; t += 1) {
        if (*t != '%') {
            if (*t == '\n') {
                flush = true;
            }
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
                    assert(other_string != null);
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

    if (buf_length(printf_buf) > 10000 || flush) {
        printf_flush();
    }
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

u8* long_bracket_name(u8 kind) {
    switch (kind) {
        case BRACKET_CURLY_CLOSE:  case BRACKET_CURLY_OPEN:  return "curly bracket";
        case BRACKET_SQUARE_CLOSE: case BRACKET_SQUARE_OPEN: return "square bracket";
        case BRACKET_ROUND_CLOSE:  case BRACKET_ROUND_OPEN:  return "parenthesis";
        default: assert(false);
    }
    return null;
}

typedef struct Token {
    enum {
        token_end_of_stream = 0,

        token_identifier,
        token_literal,
        token_string,

        token_operator,
        token_bracket,

        token_arrow,
        token_semicolon,
        token_comma,
        token_colon,
        token_tick,
        token_at,

        token_keyword_extern,
        token_keyword_var,
        token_keyword_fn,
    } kind;

    union {
        u32 identifier_string_table_index;
        u64 literal_value;
        struct {
            u8* bytes; // null-terminated
            u64 length;
        } string;
        u8 operator_symbol;
        struct {
            u8 kind;
            i16 offset_to_matching;
        } bracket;
    };

    File_Pos pos;
} Token;



typedef struct Var {
    u32 name;
    u32 type_index;
    File_Pos declaration_pos;
} Var;


typedef enum Primitive {
    primitive_invalid = 0,

    primitive_void,
    primitive_pointer,
    primitive_array, // followed by a 64 bit integer in the type buf

    primitive_unsolidified_int,
    primitive_u8,
    primitive_u16,
    primitive_u32,
    primitive_u64,
    primitive_i8,
    primitive_i16,
    primitive_i32,
    primitive_i64,

    PRIMITIVE_COUNT,
} Primitive;

void init_primitive_names(u32* names, u8** string_table) {
    names[primitive_unsolidified_int] = string_table_canonicalize(string_table, "<int>", 5);

    names[primitive_void] = string_table_canonicalize(string_table, "void", 4);
    names[primitive_u8]   = string_table_canonicalize(string_table, "u8",   2);
    names[primitive_u16]  = string_table_canonicalize(string_table, "u16",  3);
    names[primitive_u32]  = string_table_canonicalize(string_table, "u32",  3);
    names[primitive_u64]  = string_table_canonicalize(string_table, "u64",  3);
    names[primitive_i8]   = string_table_canonicalize(string_table, "i8",   2);
    names[primitive_i16]  = string_table_canonicalize(string_table, "i16",  3);
    names[primitive_i32]  = string_table_canonicalize(string_table, "i32",  3);
    names[primitive_i64]  = string_table_canonicalize(string_table, "i64",  3);
}

u8* primitive_name(Primitive primitive) {
    switch (primitive) {
        case primitive_invalid: return "<invalid>";
        case primitive_void: return "void";
        case primitive_pointer: return "pointer";
        case primitive_unsolidified_int: return "<int>";
        case primitive_array: return "array";

        case primitive_u8:  return "u8";
        case primitive_u16: return "u16";
        case primitive_u32: return "u32";
        case primitive_u64: return "u64";
        case primitive_i8:  return "i8";
        case primitive_i16: return "i16";
        case primitive_i32: return "i32";
        case primitive_i64: return "i64";

        default: assert(false);
    }

    return null;
}

enum { POINTER_SIZE = 8 };

u8 primitive_size_of(Primitive primitive) {
    switch (primitive) {
        case primitive_u8:  return 1;
        case primitive_u16: return 2;
        case primitive_u32: return 4;
        case primitive_u64: return 8;
        case primitive_i8:  return 1;
        case primitive_i16: return 2;
        case primitive_i32: return 4;
        case primitive_i64: return 8;
        case primitive_void: return 0;
        case primitive_pointer: return POINTER_SIZE;
        case primitive_invalid: return 0;
        case primitive_unsolidified_int: return 0;
        case primitive_array: panic("You should be using type_size_of!"); return 0;
        default: assert(false); return 0;
    }
}

bool primitive_is_compound(Primitive primitive) {
    switch (primitive) {
        case primitive_array: return true;

        case primitive_u8:  return false;
        case primitive_u16: return false;
        case primitive_u32: return false;
        case primitive_u64: return false;
        case primitive_i8:  return false;
        case primitive_i16: return false;
        case primitive_i32: return false;
        case primitive_i64: return false;
        case primitive_void: return false;
        case primitive_pointer: return false;
        case primitive_invalid: return false;
        case primitive_unsolidified_int: return false;
        default: assert(false); return false;
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
u64 size_mask(u8 size) {
    assert(size <= 8);
    return SIZE_MASKS[size];
}


#define EXPR_FLAG_UNRESOLVED 0x01
#define EXPR_FLAG_ASSIGNABLE 0x02

enum Expr_Kind {
    expr_variable,
    expr_literal,
    expr_compound_literal,
    expr_binary,
    expr_call,
    expr_cast,
    expr_address_of,
    expr_dereference,
    expr_subscript,
};

typedef struct Expr Expr;
struct Expr {
    u8 kind;
    u8 flags;

    union {
        union { u32 index; u32 unresolved_name; } variable; // discriminated by EXPR_FLAG_UNRESOLVED
        u64 literal_value;

        struct {
            Expr** content; // *[*Expr]
            u32 count;
        } compound_literal;

        struct {
            enum {
                binary_add,
                binary_sub,
                binary_mul,
                binary_div,
            } op;

            Expr* left;
            Expr* right;
        } binary;

        struct {
            union {
                u32 unresolved_name;
                u32 func_index;
            }; // discriminated by EXPR_FLAG_UNRESOLVED

            u32 param_count;
            Expr** params; // Pointer to an array of pointers to expressions! (*[*Expr] as opposed to **[Expr])
        } call;

        Expr* cast_from;
        Expr* dereference_from;
        Expr* address_from;

        struct {
            Expr* array;
            Expr* index;
        } subscript;
    };

    u32 type_index;
    File_Pos pos;
};

typedef struct Stmt {
    enum {
        stmt_declaration,
        stmt_expr,
        stmt_assignment,
    } kind;

    union {
        struct { u32 var_index; } declaration;
        Expr* expr;
        struct { Expr* left; Expr* right; } assignment;
    };

    File_Pos pos;
} Stmt;


typedef struct Local {
    enum {
        local_temporary = 0,
        local_variable = 1,
        local_literal = 2,
    } kind;
    bool as_reference;
    u64 value;
} Local;

bool local_cmp(Local* a, Local* b) {
    return a->kind == b->kind && a->as_reference == b->as_reference && a->value == b->value;
}


typedef enum Op_Kind {
    op_end_of_function = 0,
    op_reset_temporary,

    op_call,
    op_cast,
    
    // 'binary'
    op_set,
    op_add,
    op_sub,
    op_mul,
    op_div,
    op_address_of,
} Op_Kind;

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
    u8 primitive;
        
    // NB (Morten, 07.04.18) In general, we rely on 'Op's being well formed. We have some assertions
    // to ensure that e.g. 'Local's are valid.

    union {
        u32 temporary;

        struct {
            Local source;
            Local target;
        } binary;

        struct {
            Local target;
            u32 func_index;
            Op_Call_Param* params;
        } call;

        struct {
            Local local;
            u8 old_primitive;
        } cast;

        struct {
            Local other;
            Local offset;
            u32 var_index;
        } member;
    };
} Op;

typedef struct Tmp {
    u64 size; // size of the largest thing we ever store here
    bool currently_allocated;
} Tmp;


typedef struct Mem_Item {
    u64 size;
    u32 offset;
} Mem_Item;

typedef struct Mem_Layout {
    u64 total_bytes;

    // NB pointers point to same number of members as vars/tmps in the coresponding 'Func'
    Mem_Item* vars;
    Mem_Item* tmps;
} Mem_Layout;



typedef struct Import_Index {
    // names are string table indices
    u32 library;
    u32 function;
} Import_Index;

typedef struct Library_Import {
    // names are string table indices
    u32 lib_name; // c-str
    // TODO make this a hashtable (?)
    u32* function_names; // stretchy-buffer

    // We find these in 'parse_library'
    u8* dll_name;
    u32* function_hints;
} Library_Import;

typedef struct Fixup {
    // Fixups which rely on information about adresses in the final executable go here,
    // other kinds of fixups can have their own struct

    u64 text_location;

    enum {
        fixup_imported_function,
        fixup_data,
    } kind;

    union {
        Import_Index import_index;
        u32 data_offset;
    };
} Fixup;

typedef struct Call_Fixup {
    u64 text_location;
    u32 func_index;
} Call_Fixup;



typedef struct Func {
    u32 name;

    enum {
        func_kind_normal, // use '.body'
        func_kind_imported, // use '.import_info'
    } kind;

    struct {
        bool has_output;
        u32 output_type_index;

        struct {
            u32 type_index;
            u32 var_index;
        } *params;
        u32 param_count;
    } signature;

    union {
        struct {
            Import_Index index;
        } import_info;

        struct {
            Var* vars;
            u32 var_count;
            u32 output_var_index;

            bool* in_scope_map; // internal

            Tmp* tmps;
            u32 tmp_count;

            Mem_Layout mem_layout; // used for eval_ops
            Mem_Layout stack_layout; // for machinecode generations

            Stmt* stmts;
            u32 stmt_count;

            Op* ops;
            u32 op_count;

            u32 bytecode_start;
        } body;
    };
} Func;


typedef enum Reg {
    reg_rax, reg_rcx, reg_rdx, reg_rbx,
    reg_rsp, reg_rbp, reg_rsi, reg_rdi,
    reg_r8,  reg_r9,  reg_r10, reg_r11,
    reg_r12, reg_r13, reg_r14, reg_r15,
    REG_COUNT,
    reg_invalid = U8_MAX,
} Reg;

u8* reg_names[REG_COUNT] = {
    "rax", "rcx", "rdx", "rbx",
    "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11",
    "r12", "r13", "r14", "r15"
};

//#define PRINT_GENERATED_INSTRUCTIONS



// NB regarding memory allocation.
// For short-lived objects, we allocate in the 'stack' arena, which we push/pop.
// For permanent objects, we stick them in the 'arena' arena, which we should never really push/pop
// We also use a bunch of stretchy-buffers, though some of those we might be able to replace with arena allocations
typedef struct Context {
    Arena arena, stack; // arena is for permanent storage, stack for temporary

    u8* string_table; // stretchy-buffer string table
    u32 primitive_names[PRIMITIVE_COUNT]; // indices to string table

    // AST & intermediate representation
    Func* funcs; // stretchy-buffer

    // These are only for temporary use, we copy to arena buffers & clear
    Stmt* tmp_stmts; // stretchy-buffer
    Var* tmp_vars; // stretchy-buffer
    Op* tmp_ops; // stretchy-buffer, linearized from of stmts
    Tmp* tmp_tmps; // stretchy-buffer, also built during op generation

    // NB the first 'PRIMITIVE_COUNT' elements are the respective primitives, which
    // simplifies refering directly to primitives: A type index of 'primitive_i64' points
    // to 'primitive_i64'
    u8* type_buf; // stretchy-buffer of chained 'Primitive's

    // Low level representation
    u8* bytecode;
    u8* bytecode_data;
    Fixup* fixups;

    Library_Import* imports; // stretchy-buffer
    Call_Fixup* call_fixups; // stretchy-buffer
} Context;


// NB This currently just assumes we are trying to import a function. In the future we might want to support importing
// other items, though we probably want to find an example of that first, so we know what we are doing!
Import_Index add_import(Context* context, u32 library_name, u32 function_name) {
    Import_Index index = {0};

    Library_Import* import = null;
    for (u32 i = 0; i < buf_length(context->imports); i += 1) {
        if (library_name == context->imports[i].lib_name) {
            index.library = i;
            import = &context->imports[i];
            break;
        }
    }
    if (import == null) {
        index.library = buf_length(context->imports);

        Library_Import new = {0};
        new.lib_name = library_name;
        buf_push(context->imports, new);

        import = buf_end(context->imports) - 1;
    }

    for (u32 i = 0; i < buf_length(import->function_names); i += 1) {
        u32 other_function_name = import->function_names[i];
        if (other_function_name == function_name) {
            index.function = i;
            return index;
        }
    }

    index.function = buf_length(import->function_names);
    buf_push(import->function_names, function_name);
    return index;
}

bool type_cmp(Context* context, u32 a, u32 b) {
    while (1) {
        Primitive a_primitive = context->type_buf[a];
        Primitive b_primitive = context->type_buf[b];
        a += 1;
        b += 1;

        if (a_primitive != b_primitive) {
            return false;
        }

        bool a_ptr = a_primitive == primitive_pointer;
        bool b_ptr = b_primitive == primitive_pointer;

        if (!a_ptr && !b_ptr) {
            break;
        } else if (a_ptr && b_ptr) {
            // NB this is a bit of a hack to make '[N]Foo == 'Foo
            Primitive a_primitive = context->type_buf[a];
            Primitive b_primitive = context->type_buf[b];
            if (a_primitive == primitive_array && b_primitive != primitive_array) {
                a += sizeof(u64) + 1;
            }
            if (b_primitive == primitive_array && a_primitive != primitive_array) {
                b += sizeof(u64) + 1;
            }
            continue;
        } else {
            return false;
        }
    }

    return true;
}

u64 type_size_of(Context* context, u32 type_index) {
    u64 array_multiplier = 1;
    u64 size = 0;

    while (1) {
        Primitive primitive = context->type_buf[type_index];
        type_index += 1;

        if (primitive == primitive_array) {
            u64 array_size = *((u64*) &context->type_buf[type_index]);
            type_index += sizeof(u64);

            array_multiplier *= array_size;
        } else {
            size = primitive_size_of(primitive);
            break;
        }
    }

    return size * array_multiplier;
}

u32 type_duplicate(Context* context, u32 type_index) {
    u32 new = buf_length(context->type_buf);

    u32 i = type_index;
    while (1) {
        Primitive p = context->type_buf[i];
        buf_push(context->type_buf, p);

        i += 1;

        if (p == primitive_pointer) {

        } else if (p == primitive_array) {
            for (u32 j = 0; j < sizeof(u64); j += 1) {
                buf_push(context->type_buf, context->type_buf[i + j]);
            }
            i += sizeof(u64);
        } else {
            break;
        }
    }

    return new;
}


void print_type(Context* context, u32 type_index) {
    u32 i = type_index;
    while (1) {
        Primitive p = context->type_buf[i];
        i += 1;

        bool keep_going = false;

        switch (p) {
            case primitive_invalid:          printf("<invalid>"); break;
            case primitive_void:             printf("void"); break;
            case primitive_unsolidified_int: printf("<int>"); break;

            case primitive_pointer: {
                printf("'");
                keep_going = true;
            } break;

            case primitive_array: {
                u64 size = *((u64*) (context->type_buf + i));
                i += sizeof(u64);

                printf("[%u]", size);

                keep_going = true;
            } break;

            case primitive_u8:  printf("u8");  break;
            case primitive_u16: printf("u16"); break;
            case primitive_u32: printf("u32"); break;
            case primitive_u64: printf("u64"); break;
            case primitive_i8:  printf("i8");  break;
            case primitive_i16: printf("i16"); break;
            case primitive_i32: printf("i32"); break;
            case primitive_i64: printf("i64"); break;

            default: assert(false);
        }

        if (!keep_going) break;
    }
}

void print_token(u8* string_table, Token* t) {
    switch (t->kind) {
        case token_end_of_stream: {
            printf("end of file");
        } break;

        case token_identifier: {
            u32 index = t->identifier_string_table_index;
            u8* name = string_table_access(string_table, index);
            printf("%s", name);
        } break;
        case token_literal: {
            printf("%u", t->literal_value);
        } break;
        case token_string: {
            printf("\"%z\"", t->string.length, t->string.bytes);
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

        case token_tick: {
            printf("'");
        } break;

        case token_at: {
            printf("@");
        } break;

        case token_keyword_extern: {
            printf("keyword extern");
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

void print_expr(Context* context, Func* func, Expr* expr) {
    switch (expr->kind) {
        case expr_variable: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u8* name = string_table_access(context->string_table, expr->variable.unresolved_name);
                printf("<unresolved %s>", name);
            } else {
                Var* var = &func->body.vars[expr->variable.index];
                u8* name = string_table_access(context->string_table, var->name);
                printf("%s", name);
            }
        } break;

        case expr_literal: {
            printf("%u", expr->literal_value);
        } break;

        case expr_compound_literal: {
            print_type(context, expr->type_index);
            printf(" { ");
            for (u32 i = 0; i < expr->compound_literal.count; i += 1) {
                if (i != 0) printf(", ");
                print_expr(context, func, expr->compound_literal.content[i]);
            }
            printf(" }");
        } break;

        case expr_binary: {
            printf("(");
            print_expr(context, func, expr->binary.left);
            switch (expr->binary.op) {
                case binary_add: printf(" + "); break;
                case binary_sub: printf(" - "); break;
                case binary_mul: printf(" * "); break;
                case binary_div: printf(" / "); break;
                default: assert(false);
            }
            print_expr(context, func, expr->binary.right);
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
                print_expr(context, func, expr->call.params[i]);
            }
            printf(")");
        } break;

        case expr_cast: {
            print_type(context, expr->type_index);
            printf("(");
            print_expr(context, func, expr->cast_from);
            printf(")");
        } break;

        case expr_address_of: {
            printf("@");
            print_expr(context, func, expr->address_from);
        } break;

        case expr_dereference: {
            printf("'");
            print_expr(context, func, expr->dereference_from);
        } break;

        case expr_subscript: {
            print_expr(context, func, expr->subscript.array);
            printf("[");
            print_expr(context, func, expr->subscript.index);
            printf("]");
        } break;

        default: assert(false);
    }
}

void print_stmt(Context* context, Func* func, Stmt* stmt) {
    switch (stmt->kind) {
        case stmt_assignment: {
            print_expr(context, func, stmt->assignment.left);
            printf(" = ");
            print_expr(context, func, stmt->assignment.right);
            printf(";");
        } break;

        case stmt_expr: {
            print_expr(context, func, stmt->expr);
            printf(";");
        } break;

        case stmt_declaration: {
            Var* var = &func->body.vars[stmt->declaration.var_index];
            u8* name = string_table_access(context->string_table, var->name);
            printf("var %s;", name);
        } break;

        default: assert(false);
    }
}

void print_local(Context* context, Func* func, Local local) {
    u8* pointer_star;
    if (local.as_reference) {
        pointer_star = "*";
    } else {
        pointer_star = "";
    }

    switch (local.kind) {
        case local_variable: {
            Var* var = &func->body.vars[local.value];
            u8* name = string_table_access(context->string_table, var->name);
            printf("%s%s", pointer_star, name);
        } break;

        case local_temporary: {
            printf("%s$%u", pointer_star, (u64) local.value);
        } break;

        case local_literal: {
            printf("%s%u", pointer_star, local.value);
        } break;

        default: assert(false);
    }
}

void print_op(Context* context, Func* func, Op* op) {
    switch (op->kind) {
        case op_reset_temporary: {
            printf("reset $%u", (u64) op->temporary);
        } break;

        case op_set:
        case op_add:
        case op_sub:
        case op_mul:
        case op_div:
        {
            u8* op_name;
            switch (op->kind) {
                case op_set: op_name = "set"; break;
                case op_add: op_name = "add"; break;
                case op_sub: op_name = "sub"; break;
                case op_mul: op_name = "mul"; break;
                case op_div: op_name = "div"; break;
                default: assert(false);
            }

            printf("(%s) %s ", primitive_name(op->primitive), op_name);

            print_local(context, func, op->binary.target);
            printf(", ");
            print_local(context, func, op->binary.source);
        } break;

        case op_address_of: {
            printf("address of ");
            print_local(context, func, op->binary.target);
            printf(", ");
            print_local(context, func, op->binary.source);
        } break;

        case op_call: {
            Func* callee = context->funcs + op->call.func_index;
            u8* name = string_table_access(context->string_table, callee->name);

            printf("(%s) set ", primitive_name(op->primitive));
            print_local(context, func, op->call.target);

            if (callee->signature.param_count > 0) {
                printf(", (call %s with ", name);

                for (u32 p = 0; p < callee->signature.param_count; p += 1) {
                    if (p != 0) printf(", ");
                    print_local(context, func, op->call.params[p].local);
                    printf(" (u%u)", (u64) (op->call.params[p].size*8));
                }

                printf(")");
            } else {
                printf(", (call %s)", name);
            }
        } break;

        case op_cast: {
            printf("cast ");
            print_local(context, func, op->cast.local);
            printf(" (from %s to %s)", primitive_name(op->cast.old_primitive), primitive_name(op->primitive));
        } break;

        default: assert(false);
    }
}


u32 find_var(Func* func, u32 name) {
    for (u32 i = 0; i < func->body.var_count; i += 1) {
        if (func->body.vars[i].name == name) {
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

u32 parse_type(Context* context, Token* t, u32 length) {
    u32 start = buf_length(context->type_buf);
    u32 type_length = 0;

    bool done = false;

    for (u32 i = 0; i < length; i += 1) {
        if (done) {
            printf("Unexpected token after type: ");
            print_token(context->string_table, &t[i]);
            printf(" (Line %u)\n", (u64) t[i].pos.line);
            return U32_MAX;
        }

        switch (t[i].kind) {
            case token_identifier: {
                Primitive primitive = primitive_invalid;
                for (u32 p = 0; p < PRIMITIVE_COUNT; p += 1) {
                    if (context->primitive_names[p] == t[i].identifier_string_table_index) {
                        primitive = p;
                        break;
                    }
                }

                if (primitive != primitive_invalid) {
                    if (type_length == 0) {
                        start = primitive; // because we have entries for all primitives at start of context->type_buf
                    } else {
                        buf_push(context->type_buf, primitive);
                        type_length += 1;
                    }

                    done = true;
                } else {
                    u8* name = string_table_access(context->string_table, t[i].identifier_string_table_index);
                    printf("Not a valid type: %s (Line %u)\n", name, (u64) t[i].pos.line);
                    return U32_MAX;
                }
            } break;

            case token_tick: {
                buf_push(context->type_buf, primitive_pointer);
                type_length += 1;
            } break;

            case token_bracket: {
                if (
                    i + 3 >= length ||
                    t[i].kind != token_bracket ||
                    t[i].bracket.kind != BRACKET_SQUARE_OPEN ||
                    t[i + 1].kind != token_literal ||
                    t[i + 2].kind != token_bracket ||
                    t[i + 2].bracket.kind != BRACKET_SQUARE_CLOSE
                ) {
                    printf("Unexpected token in type: ");
                    print_token(context->string_table, &t[i]);
                    printf(" (Line %u)\n", (u64) t[i].pos.line);
                    return U32_MAX;
                }

                buf_push(context->type_buf, primitive_array);

                u64 array_size = t[i + 1].literal_value;
                for (u32 i = 0; i < sizeof(u64); i += 1) {
                    buf_push(context->type_buf, (u8) (array_size & 0xff));
                    array_size = array_size >> 8;
                }

                type_length += 9;
                i += 2;
            } break;

            case token_literal:
            case token_string:
            case token_operator:
            case token_arrow:
            case token_semicolon:
            case token_comma:
            case token_colon:
            case token_at:
            case token_keyword_var:
            case token_keyword_fn:
            case token_keyword_extern:
            {
                printf("Unexpected token in type: ");
                print_token(context->string_table, &t[i]);
                printf(" (Line %u)\n", (u64) t[i].pos.line);
                return U32_MAX;
            } break;

            default: assert(false);
        }
    }

    return start;
}

bool parse_parameter_declaration_list(Context* context, Func* func, Token* t, u32 length) {
    assert(func->signature.params == null);
    assert(func->signature.param_count == 0);

    if (length == 0) {
        return true;
    }

    // Count parameters
    func->signature.param_count = 1;
    for (u32 i = 0; i < length; i += 1) {
        if (t[i].kind == token_comma && i + 1 < length) {
            func->signature.param_count += 1;
        }
        if (t[i].kind == token_bracket && (t[i].bracket.kind & BRACKET_OPEN)) {
            i += t[i].bracket.offset_to_matching;
        }
    }

    u64 signature_param_bytes = func->signature.param_count * sizeof(*func->signature.params);
    func->signature.params = (void*) arena_alloc(&context->arena, signature_param_bytes);
    mem_clear((u8*) func->signature.params, signature_param_bytes);

    // Parse parameters
    u32 i = 0;
    for (u32 n = 0; n < func->signature.param_count; n += 1) {
        u32 start = i;
        while (i < length && t[i].kind != token_comma) { i += 1; }
        u32 end = i;
        i += 1; // Skip the comma

        u32 length = end - start;
        if (length < 1 || t[start].kind != token_identifier) {
            printf("Expected parameter name, but got ");
            print_token(context->string_table, &t[start]);
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
                print_token(context->string_table, &t[j]);
            }
            printf(" (Line %u)\n", (u64) t[start + 1].pos.line);
            return false;
        }

        u32 type_index = parse_type(context, &t[start + 2], length - 2);
        if (type_index == U32_MAX) {
            return false;
        }

        func->signature.params[n].var_index = buf_length(context->tmp_vars);
        func->signature.params[n].type_index = type_index;

        Var var = {0};
        var.name = name_index;
        var.declaration_pos = t->pos;
        var.type_index = type_index;
        buf_push(context->tmp_vars, var);
    }

    return true;
}

Expr* parse_expr(Context* context, Token* t, u32 length);

bool parse_comma_separated_expr_list(
    Context* context, Token* t, u32 length,
    Expr*** out_exprs,
    u32* out_count
)
{
    *out_count = 0;
    *out_exprs = null;

    if (length == 0) {
        return true;
    }

    // Figure out how many exprs we need to allocate
    *out_count = 1;
    for (u32 i = 0; i < length; i += 1) {
        if (t[i].kind == token_comma && i + 1 < length) {
            *out_count += 1;
        }
        if (t[i].kind == token_bracket && (t[i].bracket.kind & BRACKET_OPEN)) {
            i += t[i].bracket.offset_to_matching;
        }
    }

    // This will probably allocate to much memory, but at least it will allways allocate enough
    *out_exprs = (Expr**) arena_alloc(&context->arena, *out_count * sizeof(Expr));

    u32 i = 0;
    u32 e = 0;
    while (i < length) {
        u32 start = i;
        while (i < length) {
            if (t[i].kind == token_comma) {
                break;
            }
            if (t[i].kind == token_bracket && (t[i].bracket.kind & BRACKET_OPEN)) {
                i += t[i].bracket.offset_to_matching;
            }
            i += 1;
        }
        u32 end = i;
        i += 1; // Skip the comma

        Expr* expr = parse_expr(context, &t[start], end - start);
        if (expr == null) {
            return false;
        }

        (*out_exprs)[e] = expr;
        e += 1;
    }

    assert(e == *out_count);

    return true;
}

Expr* parse_expr(Context* context, Token* t, u32 length) {
    if (length == 0) {
        printf("Expected expression but found nothing (Line %u)\n", (u64) t->pos.line);
        return null;
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

    u32 op_pos = U32_MAX;
    u8 op_precedence = U8_MAX;

    for (u32 i = 0; i < length; i += 1) {
        if (t[i].kind == token_bracket) {
            if (t[i].bracket.kind & BRACKET_OPEN) {
                // Skip ahead to closing bracket
                i += t[i].bracket.offset_to_matching;
                if (i >= length) {
                    printf("Unclosed %s in expression (Line %u)\n",  long_bracket_name(t[i].bracket.kind), (u64) t->pos.line);
                    return null;
                }
            } else {
                printf("Unopened %s in expression (Line %u)\n",  long_bracket_name(t[i].bracket.kind), (u64) t->pos.line);
                return null;
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

    // We didnt find an operator
    if (op_pos == U32_MAX) {
        bool array_subscript = t[length - 1].kind == token_bracket && t[length - 1].bracket.kind == BRACKET_SQUARE_CLOSE;
        
        if (array_subscript) {
            i32 open_bracket = (length - 1) + t[length - 1].bracket.offset_to_matching;
            if (open_bracket < 0 || open_bracket >= length) {
                printf("The parser is hosed and I don't wanna fix it right now\n"); // TODO hmmm
                return null;
            }

            Expr* array = parse_expr(context, t, open_bracket);
            Expr* index = parse_expr(context, &t[open_bracket + 1], length - open_bracket - 2);

            Expr* expr = arena_insert(&context->arena, ((Expr) {0}));
            expr->kind = expr_subscript;
            expr->subscript.array = array;
            expr->subscript.index = index;
            expr->pos = array->pos;
            return expr;
        }

        bool compound_literal = 
            t[0].kind == token_identifier || // type name
            (t[0].kind == token_bracket && t[0].bracket.kind == BRACKET_SQUARE_OPEN); // start of array literal

        u32 compound_literal_type_length, compound_literal_content_start, compound_literal_content_length;

        if (compound_literal) {
            // We might just have a variable, look ahead for a curly brace
            u32 bracket_at = U32_MAX;
            for (u32 i = 1; i < length; i += 1) {
                if (t[i].kind == token_bracket && t[i].bracket.kind == BRACKET_CURLY_OPEN) {
                    bracket_at = i;
                    break;
                }
            }

            if (bracket_at == U32_MAX) {
                compound_literal = false;
            } else {
                u32 closing_bracket = bracket_at + t[bracket_at].bracket.offset_to_matching;
                if (closing_bracket + 1 != length) {
                    printf("Unexpected tokens after compound literal: ");
                    for (u32 i = closing_bracket + 1; i < length; i += 1) {
                        print_token(context->string_table, &t[i]);
                    }
                    printf(" (Line %u)\n", t[closing_bracket].pos.line);
                    return null;
                }

                compound_literal_type_length = bracket_at;
                compound_literal_content_start = bracket_at + 1;
                compound_literal_content_length = length - bracket_at - 2;
            }
        }

        if (compound_literal) {
            Expr* expr = arena_insert(&context->arena, ((Expr) {0}));
            expr->kind = expr_compound_literal;
            expr->pos = t->pos;

            expr->type_index = parse_type(context, t, compound_literal_type_length);
            if (expr->type_index == U32_MAX) return null;

            bool result = parse_comma_separated_expr_list(
                context,
                t + compound_literal_content_start,
                compound_literal_content_length,
                &expr->compound_literal.content,
                &expr->compound_literal.count
            );
            if (!result) return null;

            return expr;
        }

        switch (t->kind) {
            case token_literal: {
                if (length != 1) {
                    printf("Unexpected token(s) after %u: ", t->literal_value);
                    for (u32 i = 1; i < length; i += 1) {
                        if (i > 1) printf(", ");
                        print_token(context->string_table, &t[i]);
                    }
                    printf(" (Line %u)\n", (u64) t->pos.line);
                    return null;

                } else {
                    Expr* expr = arena_insert(&context->arena, ((Expr) {0}));
                    expr->kind = expr_literal;
                    expr->literal_value = t->literal_value;
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
                            print_token(context->string_table, &t[i]);
                        }
                        printf(" (Starting on line %u)\n", (u64) t[1].pos.line);
                        return null;
                    }
                    assert(
                        t[length - 1].kind == token_bracket &&
                        t[length - 1].bracket.kind == BRACKET_ROUND_CLOSE
                    );

                    u32 name_index = t[0].identifier_string_table_index;

                    Primitive cast_primitive = primitive_invalid;
                    for (u32 i = 0; i < PRIMITIVE_COUNT; i += 1) {
                        if (context->primitive_names[i] == name_index) {
                            cast_primitive = i;
                            break;
                        }
                    }

                    if (cast_primitive != primitive_invalid) {
                        Expr* cast_from = parse_expr(context, t + 2, length - 3);
                        if (cast_from == null) return null;

                        Expr* expr = arena_insert(&context->arena, ((Expr) {0}));
                        expr->kind = expr_cast;
                        expr->cast_from = cast_from;
                        expr->pos = t->pos;
                        expr->type_index = cast_primitive; // because we have entries for all primitives at start of context->type_buf
                        return expr;

                    } else { // Parse as a normal function call
                        Expr* expr = arena_insert(&context->arena, ((Expr) {0}));
                        expr->kind = expr_call;
                        expr->call.unresolved_name = name_index;
                        expr->flags |= EXPR_FLAG_UNRESOLVED;
                        expr->pos = t->pos;

                        bool result = parse_comma_separated_expr_list(
                            context, &t[2], length - 3,
                            &expr->call.params,
                            &expr->call.param_count
                        );
                        if (!result) return null;

                        return expr;
                    }
                }
            } break;

            case token_tick: {
                Expr* sub_expr = parse_expr(context, t + 1, length - 1);
                if (sub_expr == null) return null;

                Expr* expr = arena_insert(&context->arena, ((Expr) {0}));
                expr->kind = expr_dereference;
                expr->address_from = sub_expr;
                expr->pos = t->pos;
                return expr;
            } break;

            case token_at: {
                Expr* sub_expr = parse_expr(context, t + 1, length - 1);
                if (sub_expr == null) return null;

                Expr* expr = arena_insert(&context->arena, ((Expr) {0}));
                expr->kind = expr_address_of;
                expr->address_from = sub_expr;
                expr->pos = t->pos;
                return expr;
            } break;

            case token_string:
            case token_operator:
            case token_semicolon:
            case token_arrow:
            case token_bracket:
            case token_comma:
            case token_colon:
            case token_keyword_var:
            case token_keyword_fn:
            case token_keyword_extern:
            {
                printf("Expected literal or variable, but got ");
                print_token(context->string_table, t);
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
Func* parse_function(Context* context, Token* t, u32* length) {
    assert(t->kind == token_keyword_fn);
    bool valid = true;

    Token* start = t;
    File_Pos declaration_pos = t->pos;

    // Estimate size of function, so we still print reasonable errors on bad function declarations
    // NB This assumes functions with bodies at the moment, maybe that is bad?
    *length = 1;
    for (Token* u = t + 1; !(u->kind == token_end_of_stream || u->kind == token_keyword_fn); u += 1) {
        *length += 1;
    }

    // Name
    t += 1;
    if (t->kind != token_identifier) {
        printf("Expected function name, but found ");
        print_token(context->string_table, t);
        printf(" (Line %u)\n", (u64) t->pos.line);

        return null;
    }
    u32 name_index = t->identifier_string_table_index;

    buf_foreach (Func, func, context->funcs) {
        if (func->name == name_index) {
            u8* name = string_table_access(context->string_table, name_index);
            printf("Second definition of function %s on line %u\n", name, (u64) declaration_pos.line);
            valid = false;
        }
    }


    // NB we use these while parsing, and then copy them into the memory arena
    buf_clear(context->tmp_vars); 
    buf_clear(context->tmp_stmts);

    buf_push(context->funcs, ((Func) {0}));
    Func* func = buf_end(context->funcs) - 1;
    func->name = name_index;

    // Parameter list
    t += 1;
    if (t->kind != token_bracket || t->bracket.kind != BRACKET_ROUND_OPEN) {
        u8* name = string_table_access(context->string_table, name_index);
        printf("Expected a open parenthesis '(' to after 'fn %s', but got ", name);
        print_token(context->string_table, t);
        printf(" (Line %u)\n", (u64) t->pos.line);
        return null;
    }

    Token* parameter_start = t + 1;
    u32 parameter_length = t->bracket.offset_to_matching - 1;
    t = t + t->bracket.offset_to_matching;
    if (!parse_parameter_declaration_list(context, func, parameter_start, parameter_length)) {
        // We already printed an error in parse_parameter_declaration_list
        return null;
    }

    // Return type
    t += 1;

    Token* return_type_start = t;
    while (t->kind != token_end_of_stream) {
        if (t->kind == token_semicolon || (t->kind == token_bracket && t->bracket.kind == BRACKET_CURLY_OPEN)) {
            break;
        } else {
            t += 1;
        }
    }
    u32 return_type_length = (u32) (t - return_type_start);

    if (return_type_length > 0) {
        return_type_start += 1;
        return_type_length -= 1;

        u32 output_type_index = parse_type(context, return_type_start, return_type_length);
        if (output_type_index == U32_MAX) {
            return null;
        }

        func->signature.has_output = true;
        func->signature.output_type_index = output_type_index;
        func->body.output_var_index = buf_length(context->tmp_vars);

        Var output_var = {0};
        output_var.name = string_table_canonicalize(&context->string_table, "output", 6);
        output_var.type_index = output_type_index;
        buf_push(context->tmp_vars, output_var);
    } else {
        func->signature.has_output = false;
        func->signature.output_type_index = primitive_void;
        func->body.output_var_index = U32_MAX;
    }

    // Functions without a body
    if (t->kind == token_semicolon) {
        func->kind = func_kind_imported;

    // Body
    } else {
        func->kind = func_kind_normal;

        if (t->kind != token_bracket || t->bracket.kind != BRACKET_CURLY_OPEN) {
            u8* name = string_table_access(context->string_table, name_index);
            printf("Expected an open curly brace '{' after 'fn %s ...', but found ", name);
            print_token(context->string_table, t);
            printf(" (Line %u)\n", (u64) t->pos.line);
            return null;
        }

        Token* body = t + 1;
        u32 body_length = t->bracket.offset_to_matching - 1;
        t = t + t->bracket.offset_to_matching;

        *length = (u32) (t - start) + 1;

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
                valid = false;
            }

            switch (body[stmt_start].kind) {
                case token_keyword_var: {
                    if (stmt_length < 2 || body[stmt_start + 1].kind != token_identifier) {
                        printf("Expected identifier after 'var', but found ");
                        print_token(context->string_table, &body[stmt_start + 1]);
                        printf(" (Line %u)\n", (u64) body[stmt_start + 1].pos.line);
                        valid = false;
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
                            valid = false;
                        }
                    }
                    if (redeclaration) break;

                    u32 var_index = buf_length(context->tmp_vars);
                    buf_push(context->tmp_vars, ((Var) {0}));
                    Var* var = &context->tmp_vars[var_index];
                    var->name = name_index;

                    if (stmt_length > 2 && body[stmt_start + 2].kind != token_colon) {
                        u8* name = string_table_access(context->string_table, name_index);
                        printf("Expected 'var %s: type', but got ", name);
                        print_token(context->string_table, &body[stmt_start + 2]);
                        printf(" (Line %u)\n", body[stmt_start].pos.line);
                        valid = false;
                        break;
                    }

                    u32 type_length = min(equals_position, stmt_length) - 3;
                    var->type_index = parse_type(context, &body[stmt_start + 3], type_length);

                    if (var->type_index == U32_MAX) {
                        valid = false;
                        break;
                    }

                    Stmt stmt = {0};
                    stmt.kind = stmt_declaration;
                    stmt.declaration.var_index = var_index;
                    stmt.pos = body[stmt_start].pos;
                    buf_push(context->tmp_stmts, stmt);

                    if (equals_position != U32_MAX) {
                        Expr* right = parse_expr(context, &body[stmt_start + equals_position + 1], stmt_length - equals_position - 1);
                        if (right == null) {
                            valid = false;
                            break;
                        }

                        Expr* left = arena_insert(&context->arena, ((Expr) {0}));
                        left->kind = expr_variable;
                        left->variable.index = var_index;
                        left->type_index = var->type_index;
                        left->pos = body[stmt_start].pos;

                        Stmt stmt = {0};
                        stmt.kind = stmt_assignment;
                        stmt.assignment.left = left;
                        stmt.assignment.right = right;
                        stmt.pos = body[stmt_start].pos;
                        buf_push(context->tmp_stmts, stmt);
                    }
                } break;

                case token_identifier:
                case token_literal:
                case token_string:
                case token_operator:
                case token_bracket:
                case token_comma:
                case token_colon:
                case token_arrow:
                case token_tick:
                case token_at:
                {
                    Stmt stmt = {0};
                    stmt.pos = body[stmt_start].pos;

                    if (equals_position == U32_MAX) {
                        Expr* expr = parse_expr(context, &body[stmt_start], stmt_length);

                        if (expr == null) {
                            valid = false;
                            break;
                        }

                        stmt.kind = stmt_expr;
                        stmt.expr = expr;
                    } else {
                        Expr* left = parse_expr(context, &body[stmt_start], equals_position);
                        Expr* right = parse_expr(context, &body[stmt_start + equals_position + 1], stmt_length - equals_position - 1);

                        if (left == null || right == null) {
                            valid = false;
                            break;
                        }

                        stmt.kind = stmt_assignment;
                        stmt.assignment.left = left;
                        stmt.assignment.right = right;
                    }

                    buf_push(context->tmp_stmts, stmt);
                } break;

                case token_keyword_fn: {
                    printf("Can't declare a function inside another function (Line %u)\n", (u64) body[i].pos.line);
                    valid = false;
                } break;

                case token_keyword_extern: {
                    printf("Can't declare an extern block inside a function (Line %u)\n", (u64) body[i].pos.line);
                    valid = false;
                } break;

                case token_semicolon: assert(false);
                default: assert(false);
            }
        }
    }

    // Copy data out of temporary buffers into permanent arena storage
    func->body.stmt_count = buf_length(context->tmp_stmts);
    func->body.stmts = (Stmt*) arena_alloc(&context->arena, buf_bytes(context->tmp_stmts));
    mem_copy((u8*) context->tmp_stmts, (u8*) func->body.stmts, buf_bytes(context->tmp_stmts));

    func->body.var_count = buf_length(context->tmp_vars);
    func->body.vars = (Var*) arena_alloc(&context->arena, buf_bytes(context->tmp_vars));
    mem_copy((u8*) context->tmp_vars, (u8*) func->body.vars, buf_bytes(context->tmp_vars));

    func->body.in_scope_map = (bool*) arena_alloc(&context->arena, sizeof(bool) * func->body.var_count);

    if (!valid) {
        return null;
    } else {
        return func;
    }
}

bool parse_extern(Context* context, Token* t, u32* length) {
    assert(t->kind == token_keyword_extern);

    Token* start = t;
    File_Pos declaration_pos = t->pos;

    // Estimate size of block, so we still print reasonable errors on bad function declarations
    *length = 1;
    for (Token* u = t + 1; !(u->kind == token_end_of_stream || u->kind == token_keyword_fn); u += 1) {
        *length += 1;
    }

    // Library name
    t += 1;
    if (t->kind != token_string) {
        printf("Expected library name, but got ");
        print_token(context->string_table, t);
        printf(" (Line %u)\n", (u64) t->pos.line);

        return false;
    }
    u8* library_name = t->string.bytes;
    u32 library_name_index = string_table_canonicalize(&context->string_table, t->string.bytes, t->string.length);

    // Body
    t += 1;
    if (t->kind != token_bracket || t->bracket.kind != BRACKET_CURLY_OPEN) {
        printf("Expected an open curly brace '{' after 'extern \"%s\" ...', but found ", library_name);
        print_token(context->string_table, t);
        printf(" (Line %u)\n", (u64) t->pos.line);
        return false;
    }

    Token* body = t + 1;
    u32 body_length = t->bracket.offset_to_matching - 1;
    t = t + t->bracket.offset_to_matching;

    *length = (u32) (t - start) + 1;

    bool valid = true;

    for (u32 i = 0; i < body_length; i += 1) {
        switch (body[i].kind) {
            case token_keyword_fn: {
                u32 length;
                Func* func = parse_function(context, &body[i], &length);

                if (func == null) {
                    valid = false;
                } else if (func->kind != func_kind_imported) {
                    u8* name = string_table_access(context->string_table, func->name);
                    printf(
                        "Function %s has a body, but functions inside 'extern' blocks can't have bodies (Line %u)\n",
                        name, (u64) body[i].pos.line
                    );
                    valid = false;
                } else {
                    Import_Index import_index = add_import(context, library_name_index, func->name);
                    func->import_info.index = import_index;
                }

                i += length - 1;
            } break;

            default: {
                printf("Found invalid token at top level inside 'extern' block: ");
                print_token(context->string_table, &body[i]);
                printf(" (Line %u)\n", (u64) body[i].pos.line);

                i += 1;
                while (i < body_length && body[i].kind != token_semicolon) { i += 1; }
            } break;
        }
        // TODO parse function templates
    }

    return valid;
}

bool build_ast(Context* context, u8* path) {
    u8* file;
    u32 file_length;
    if (!read_entire_file(path, &file, &file_length)) {
        printf("Couldn't load %s\n", path);
        return false;
    }

    bool valid = true;

    u32 keyword_extern = string_table_canonicalize(&context->string_table, "extern", 6);
    u32 keyword_var    = string_table_canonicalize(&context->string_table, "var", 3);
    u32 keyword_fn     = string_table_canonicalize(&context->string_table, "fn", 2);
    init_primitive_names(context->primitive_names, &context->string_table);

    for (u32 t = 0; t < PRIMITIVE_COUNT; t += 1) {
        buf_push(context->type_buf, t);
    }

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
                    LOWERCASE UPPERCASE DIGIT case '_': last = i; break;
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
            } else if (string_table_index == keyword_extern) {
                buf_push(tokens, ((Token) { token_keyword_extern,  .pos = file_pos }));
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

        case '"': {
            i += 1;

            u32 start_index = i;
            u8* start = &file[i];

            bool valid = true;
            for (; i < file_length; i += 1) {
                if (file[i] == '\n' || file[i] == '\r') {
                    valid = false;
                    printf("Strings can not span multiple lines (Line %u)\n", (u64) file_pos.line);
                    break;
                }

                if (file[i] == '"') {
                    break;
                }
            }

            u32 length = i - start_index;
            i += 1;

            u8* arena_pointer = null;
            if (length > 0) {
                arena_pointer = arena_alloc(&context->arena, length + 1);
                arena_pointer[length] = 0;
                mem_copy(start, arena_pointer, length);
            }

            buf_push(tokens, ((Token) {
                token_string,
                .string.bytes = arena_pointer,
                .string.length = length,
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

        case '\'': {
            i += 1;
            buf_push(tokens, ((Token) { token_tick, .pos = file_pos }));
        } break;
        case '@': {
            i += 1;
            buf_push(tokens, ((Token) { token_at, .pos = file_pos }));
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

    #if 0
    printf("%u tokens:\n", (u64) buf_length(tokens));
    for (Token* t = tokens; t->kind != token_end_of_stream; t += 1) {
        printf("  ");
        print_token(string_table, t);
        printf(" (Line %u)\n", (u64) t->pos.line);
    }
    #endif

    // Parse
    Token* t = tokens;
    while (t->kind != token_end_of_stream) switch (t->kind) {
        case token_keyword_fn: {
            u32 length = 0;
            Func* func = parse_function(context, t, &length);

            if (func == null) {
                valid = false;
            } else if (func->kind != func_kind_normal) {
                u8* name = string_table_access(context->string_table, func->name);
                printf(
                    "Function %s does not have a body. Functions without bodies can only be inside 'extern' blocks (Line %u)\n",
                    name, (u64) t->pos.line
                );
                valid = false;
            }

            t += length;
        } break;

        case token_keyword_extern: {
            u32 length = 0;
            valid &= parse_extern(context, t, &length);
            t += length;
        } break;

        default: {
            valid = false;

            printf("Found invalid token at global scope: ");
            print_token(context->string_table, t);
            printf(" (Line %u)\n", (u64) t->pos.line);

            t += 1;
            while (t->kind != token_keyword_fn && t->kind != token_keyword_extern && t->kind != token_end_of_stream) { t += 1; }
        } break;
    }

    free(file);

    if (!valid) {
        printf("Encountered errors while lexing / parsing, exiting compiler!\n");
        return false;
    } else {
        return true;
    }
}

bool typecheck_expr(Context* context, Func* func, Expr* expr, u32 solidify_to) {
    switch (expr->kind) {
        case expr_literal: {
            Primitive solidify_to_primitive = context->type_buf[solidify_to];
            if (solidify_to_primitive == primitive_pointer) {
                solidify_to_primitive = primitive_u64;
            }

            bool can_solidify = solidify_to_primitive >= primitive_u8 && solidify_to_primitive <= primitive_i64;

            if (can_solidify) {
                expr->type_index = solidify_to_primitive;

                u64 mask = size_mask(primitive_size_of(solidify_to_primitive));
                u64 value = expr->literal_value;

                if (value != (value & mask)) {
                    printf(
                        "Warning: Literal %u won't fit fully into a %s and will be masked! (Line %u)\n",
                        (u64) value, primitive_name(solidify_to_primitive), (u64) expr->pos.line
                    );
                }
            } else {
                expr->type_index = primitive_unsolidified_int;
            }
        } break;

        case expr_compound_literal: {
            // The syntax requires you to give a type when creating a compound literal

            Primitive primitive = context->type_buf[expr->type_index];
            if (primitive == primitive_array) {
                u64 expected_child_count = *((u64*) &context->type_buf[expr->type_index + 1]);
                u32 expected_child_type_index = context->type_buf[expr->type_index + 1 + sizeof(u64)];

                if (expr->compound_literal.count != expected_child_count) {
                    printf(
                        "To %s values in compound literal: expected %u, got %u (Line %u)\n",
                        (expr->compound_literal.count > expected_child_count)? "many" : "few",
                        (u64) expected_child_count,
                        (u64) expr->compound_literal.count,
                        (u64) expr->pos.line
                    );
                    return false;
                }

                for (u32 i = 0; i < expr->compound_literal.count; i += 1) {
                    Expr* child = expr->compound_literal.content[i];
                    if (!typecheck_expr(context, func, child, expected_child_type_index)) {
                        return false;
                    }

                    if (!type_cmp(context, expected_child_type_index, child->type_index)) {
                        printf("Invalid type inside compound literal: Expected ");
                        print_type(context, expected_child_type_index);
                        printf(" but got ");
                        print_type(context, child->type_index);
                        printf(" (Line %u)\n", (u64) expr->pos.line);

                        return false;
                    }
                }

            } else {
                printf("Invalid type for compound literal: ");
                print_type(context, expr->type_index);
                printf(" (Line %u)\n", expr->pos.line);
                return false;
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

                if (func->body.in_scope_map[var_index] == false) {
                    Var* var = &func->body.vars[var_index];
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

            expr->type_index = func->body.vars[expr->variable.index].type_index;

            expr->flags |= EXPR_FLAG_ASSIGNABLE;
        } break;

        case expr_binary: {
            if (!typecheck_expr(context, func, expr->binary.left, solidify_to))  return false;
            if (!typecheck_expr(context, func, expr->binary.right, solidify_to)) return false;

            assert(context->type_buf[expr->binary.left->type_index] != primitive_unsolidified_int);
            assert(context->type_buf[expr->binary.left->type_index] != primitive_unsolidified_int);

            // We take one shot at matching the types to each other by chaning what we try solidifying to
            if (!type_cmp(context, expr->binary.left->type_index, expr->binary.right->type_index)) {
                bool left_strong = context->type_buf[expr->binary.left->type_index] != solidify_to;
                bool right_strong = context->type_buf[expr->binary.right->type_index] != solidify_to;

                if (left_strong) {
                    assert(typecheck_expr(context, func, expr->binary.right, expr->binary.left->type_index));
                } else if (right_strong) {
                    assert(typecheck_expr(context, func, expr->binary.left, expr->binary.right->type_index));
                }
            }

            expr->type_index = primitive_invalid;

            Primitive left_primitive = context->type_buf[expr->binary.left->type_index];
            Primitive right_primitive = context->type_buf[expr->binary.right->type_index];

            bool matching_integers =
                left_primitive == right_primitive &&
                left_primitive >= primitive_u8 && left_primitive <= primitive_i64;

            if (matching_integers) {
                expr->type_index = expr->binary.left->type_index;
            } else switch (expr->binary.op) {
                case binary_add: {
                    if (left_primitive == primitive_pointer && right_primitive == primitive_u64) {
                        expr->type_index = expr->binary.left->type_index;
                    }

                    if (left_primitive == primitive_u64 && right_primitive == primitive_pointer) {
                        expr->type_index = expr->binary.right->type_index;
                    }
                } break;

                case binary_sub: {
                    if (left_primitive == primitive_pointer && right_primitive == primitive_u64) {
                        expr->type_index = expr->binary.left->type_index;
                    }
                } break;

                case binary_mul: {} break;
                case binary_div: {} break;

                default: assert(false);
            }

            if (expr->type_index == primitive_invalid) {
                printf("Types don't match: ");
                print_type(context, expr->binary.left->type_index);
                printf(" vs ");
                print_type(context, expr->binary.right->type_index);
                printf(" (Line %u)\n", (u64) expr->pos.line);
                return false;
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
            expr->type_index = callee->signature.output_type_index;

            if (expr->call.param_count != callee->signature.param_count) {
                u8* name = string_table_access(context->string_table, callee->name);
                printf(
                    "Function '%s' takes %u parameters, but %u were given (Line %u)\n",
                    name, (u64) callee->signature.param_count, (u64) expr->call.param_count, (u64) expr->pos.line
                );
                return false;
            }

            for (u32 p = 0; p < expr->call.param_count; p += 1) {
                u32 var_index = callee->signature.params[p].var_index;
                u32 expected_type_index = callee->signature.params[p].type_index;

                if (!typecheck_expr(context, func, expr->call.params[p], expected_type_index)) {
                    return false;
                }

                u32 actual_type_index = expr->call.params[p]->type_index;
                if (!type_cmp(context, expected_type_index, actual_type_index)) {
                    u8* func_name = string_table_access(context->string_table, callee->name);
                    printf("Invalid type for parameter %u to %s: Expected ", (u64) (p + 1), func_name);
                    print_type(context, expected_type_index);
                    printf(" but got ");
                    print_type(context, actual_type_index);
                    printf(" (Line %u)\n", (u64) expr->pos.line);

                    return false;
                }
            }
        } break;

        case expr_cast: {
            Primitive primitive = context->type_buf[expr->type_index];
            assert(primitive >= primitive_u8 && primitive <= primitive_i64);
            typecheck_expr(context, func, expr->cast_from, expr->type_index);
        } break;

        case expr_address_of: {
            if (!typecheck_expr(context, func, expr->address_from, primitive_invalid)) {
                return false;
            }

            if (!(expr->address_from->flags & EXPR_FLAG_ASSIGNABLE)) {
                printf("Can't take address of ");
                print_expr(context, func, expr->address_from);
                printf(" (Line %u)\n", expr->pos.line);
                return false;
            }

            expr->type_index = buf_length(context->type_buf);
            buf_push(context->type_buf, primitive_pointer);
            u32 duped = type_duplicate(context, expr->address_from->type_index);
            assert(duped == expr->type_index + 1);
        } break;

        case expr_dereference: {
            if (!typecheck_expr(context, func, expr->dereference_from, primitive_invalid)) {
                return false;
            }

            u8 child_primitive = context->type_buf[expr->dereference_from->type_index];
            if (child_primitive != primitive_pointer) {
                printf("Can't dereference non-pointer ");
                print_expr(context, func, expr->dereference_from);
                printf(" (Line %u)\n", expr->pos.line);
                return false;
            }

            expr->type_index = expr->dereference_from->type_index + 1;

            expr->flags |= EXPR_FLAG_ASSIGNABLE;
        } break;

        case expr_subscript: {
            if (!typecheck_expr(context, func, expr->subscript.array, primitive_invalid)) {
                return false;
            }

            if (!typecheck_expr(context, func, expr->subscript.index, primitive_u64)) {
                return false;
            }

            bool bad = false;

            u32 array_type_index = expr->subscript.array->type_index;
            if (context->type_buf[array_type_index] == primitive_array) {
                expr->type_index = array_type_index + sizeof(u64) + 1;
                expr->flags |= EXPR_FLAG_ASSIGNABLE;
            } else if (context->type_buf[array_type_index] == primitive_pointer && context->type_buf[array_type_index + 1] == primitive_array) {
                expr->type_index = array_type_index + sizeof(u64) + 2;
                expr->flags |= EXPR_FLAG_ASSIGNABLE;
            } else {
                printf("Can't index a ");
                print_type(context, array_type_index);
                printf(" (Line %u)\n", (u64) expr->pos.line);
                bad = true;
            }

            u32 index_type_index = expr->subscript.index->type_index;
            if (context->type_buf[index_type_index] != primitive_u64) {
                // TODO should we allow other integer types and insert automatic promotions as neccesary here??
                printf("Can only use u64 as an array index, not ");
                print_type(context, index_type_index);
                printf(" (Line %u)\n", (u64) expr->subscript.index->pos.line);
                bad = true;
            }

            if (bad) return false;
        } break;

        default: assert(false);
    }

    return true;
}

bool typecheck(Context* context) {
    bool valid = true;

    for (u32 f = 0; f < buf_length(context->funcs); f += 1) {
        Func* func = context->funcs + f;

        mem_clear((u8*) func->body.in_scope_map, sizeof(bool) * func->body.var_count);

        // output and parameters are allways in scope
        if (func->signature.has_output) {
            func->body.in_scope_map[func->body.output_var_index] = true;
        }
        for (u32 i = 0; i < func->signature.param_count; i += 1) {
            u32 var_index = func->signature.params[i].var_index;
            func->body.in_scope_map[var_index] = true;
        }

        for (u32 i = 0; i < func->body.stmt_count; i += 1) {
            Stmt* stmt = func->body.stmts + i;
            switch (stmt->kind) {
                case stmt_assignment: {
                    if (!typecheck_expr(context, func, stmt->assignment.left, primitive_invalid)) {
                        valid = false;
                        break;
                    }
                    u32 left_type_index = stmt->assignment.left->type_index;

                    if (!typecheck_expr(context, func, stmt->assignment.right, left_type_index)) {
                        valid = false;
                        break;
                    }
                    u32 right_type_index = stmt->assignment.right->type_index;

                    if (!type_cmp(context, left_type_index, right_type_index)) {
                        printf("Types on left and right side of assignment don't match: ");
                        print_type(context, left_type_index);
                        printf(" vs ");
                        print_type(context, right_type_index);
                        printf(" (Line %u)\n", (u64) stmt->pos.line);
                        valid = false;
                        break;
                    }

                    if (!(stmt->assignment.left->flags & EXPR_FLAG_ASSIGNABLE)) {
                        printf("Can't assign to left hand side: ");
                        print_expr(context, func, stmt->assignment.left);
                        printf(" (Line %u)\n", (u64) stmt->pos.line);
                        valid = false;
                        break;
                    }
                } break;

                case stmt_expr: {
                    if (!typecheck_expr(context, func, stmt->expr, primitive_invalid)) {
                        valid = false;
                        break;
                    }
                } break;

                case stmt_declaration: {
                    assert(!func->body.in_scope_map[stmt->declaration.var_index]);
                    func->body.in_scope_map[stmt->declaration.var_index] = true;
                } break;

                default: assert(false);
            }
        }
    }

    return valid;
}


Local intermediate_allocate_temporary(Context* context, u64 size) {
    u32 best_without_growing = U32_MAX;
    u64 best_without_growing_diff = U32_MAX;

    u32 best_with_growing = U32_MAX;
    u64 best_with_growing_diff = U32_MAX;

    for (u32 i = 0; i < buf_length(context->tmp_tmps); i += 1) {
        Tmp* tmp = &context->tmp_tmps[i];
        if (tmp->currently_allocated) continue;

        if (tmp->size >= size) {
            u64 diff = tmp->size - size;
            if (diff < best_without_growing_diff) {
                best_without_growing_diff = diff;
                best_without_growing = i;
            }
        } else {
            u64 diff = size - tmp->size;
            if (diff < best_with_growing_diff) {
                best_with_growing_diff = diff;
                best_with_growing = i;
            }
        }
    }

    u32 index = U32_MAX;

    if (best_without_growing != U32_MAX) {
        index = best_without_growing;
    } else if (best_with_growing != U32_MAX) {
        index = best_with_growing;
        context->tmp_tmps[index].size = size;
    } else {
        index = buf_length(context->tmp_tmps);
        buf_push(context->tmp_tmps, ((Tmp) {
            .size = size,
            .currently_allocated = true,
        }));
    }

    assert(index != U32_MAX);
    assert(context->tmp_tmps[index].size >= size);

    context->tmp_tmps[index].currently_allocated = true;

    Local local = { local_temporary, false, index };
    return local;
}

void intermediate_deallocate_temporary(Context* context, Local local) {
    assert(local.kind == local_temporary);
    assert(context->tmp_tmps[local.value].currently_allocated);
    context->tmp_tmps[local.value].currently_allocated = false;

    Op op = {0};
    op.kind = op_reset_temporary;
    op.temporary = local.value;
    buf_push(context->tmp_ops, op);
}

void intermediate_write_compound_set(Context* context, Local source, Local target, u32 type_index) {
    Primitive primitive = context->type_buf[type_index];

    if (primitive_is_compound(primitive)) {
        assert(source.as_reference);
        assert(target.as_reference);

        if (primitive == primitive_array) {
            u64 array_size = *((u64*) &context->type_buf[type_index + 1]);
            u32 child_type_index = type_index + sizeof(u64) + 1;
            u64 stride = type_size_of(context, child_type_index);

            Local offset_source = intermediate_allocate_temporary(context, POINTER_SIZE);
            Local offset_target = intermediate_allocate_temporary(context, POINTER_SIZE);

            buf_push(context->tmp_ops, ((Op) {
                .kind = op_set,
                .primitive = primitive_pointer,
                .binary = {
                    .source = { source.kind, false, source.value },
                    .target = offset_source,
                },
            }));

            buf_push(context->tmp_ops, ((Op) {
                .kind = op_set,
                .primitive = primitive_pointer,
                .binary = {
                    .source = { target.kind, false, target.value },
                    .target = offset_target,
                },
            }));

            // TODO TODO TODO TODO Once we get control flow, this should be a loop
            for (u64 i = 0; i < array_size; i += 1) {
                offset_source.as_reference = true;
                offset_target.as_reference = true;

                intermediate_write_compound_set(context, offset_source, offset_target, child_type_index);

                offset_source.as_reference = false;
                offset_target.as_reference = false;

                Op op = {0};
                op.kind = op_add;
                op.primitive = primitive_pointer;
                op.binary.source = (Local) { local_literal, false, stride };

                op.binary.target = offset_source;
                buf_push(context->tmp_ops, op);

                op.binary.target = offset_target;
                buf_push(context->tmp_ops, op);
            }

            intermediate_deallocate_temporary(context, offset_source);
            intermediate_deallocate_temporary(context, offset_target);
        } else {
            assert(false);
        }

    } else {
        Op op = {0};
        op.kind = op_set;
        op.primitive = primitive;
        op.binary.source = source;
        op.binary.target = target;
        buf_push(context->tmp_ops, op);
    }
}

void linearize_expr(Context* context, Expr* expr, Local assign_to, bool get_address) {
    Primitive primitive = context->type_buf[expr->type_index];
    assert(assign_to.kind != local_literal);

    switch (expr->kind) {
        case expr_literal:
        case expr_variable:
        {
            Local source;
            switch (expr->kind) {
                case expr_literal:  source = (Local) { local_literal, false, expr->literal_value };  break;
                case expr_variable: source = (Local) { local_variable, false, expr->variable.index }; break;
                default: assert(false);
            }

            if (get_address) {
                assert(expr->kind != expr_literal);

                Op op = {0};
                op.kind = op_address_of;
                op.binary.source = source;
                op.binary.target = assign_to;
                buf_push(context->tmp_ops, op);
            } else {
                assert(!primitive_is_compound(primitive));

                Op op = {0};
                op.kind = op_set;
                op.primitive = primitive;
                op.binary.source = source;
                op.binary.target = assign_to;
                buf_push(context->tmp_ops, op);
            }
        } break;

        case expr_compound_literal: {
            assert(!get_address);
            assert(assign_to.as_reference);
            assert(primitive_is_compound(primitive));

            if (primitive == primitive_array) {
                u64 array_length = *((u64*) &context->type_buf[expr->type_index + 1]);
                assert(array_length == expr->compound_literal.count);

                u32 child_type_index = expr->type_index + 1 + sizeof(u64);
                u64 stride = type_size_of(context, child_type_index);

                Local element_pointer = intermediate_allocate_temporary(context, POINTER_SIZE);
                element_pointer.as_reference = false;

                Op op = {0};
                op.kind = op_set;
                op.primitive = primitive_pointer;
                op.binary.source = (Local) { assign_to.kind, false, assign_to.value };
                op.binary.target = element_pointer;
                buf_push(context->tmp_ops, op);

                for (u32 i = 0; i < array_length; i += 1) {
                    element_pointer.as_reference = false;

                    if (i != 0) {
                        Op op = {0};
                        op.kind = op_add;
                        op.primitive = primitive_pointer;
                        op.binary.source = (Local) { local_literal, false, stride };
                        op.binary.target = element_pointer;
                        buf_push(context->tmp_ops, op);
                    }

                    element_pointer.as_reference = true;

                    linearize_expr(context, expr->compound_literal.content[i], element_pointer, false);
                }

                intermediate_deallocate_temporary(context, element_pointer);
            } else {
                assert(false);
            }

        } break;

        case expr_binary: {
            assert(!get_address);

            linearize_expr(context, expr->binary.left, assign_to, false);

            u64 right_size = type_size_of(context, expr->binary.right->type_index);
            Local right_local = intermediate_allocate_temporary(context, right_size);
            linearize_expr(context, expr->binary.right, right_local, false);

            Op op = {0};
            switch (expr->binary.op) {
                case binary_add: op.kind = op_add; break;
                case binary_sub: op.kind = op_sub; break;
                case binary_mul: op.kind = op_mul; break;
                case binary_div: op.kind = op_div; break;
                default: assert(false);
            }
            op.primitive = primitive;
            op.binary.target = assign_to;
            op.binary.source = right_local;
            buf_push(context->tmp_ops, op);

            intermediate_deallocate_temporary(context, right_local);
        } break;

        case expr_call: {
            assert(!get_address);

            Op_Call_Param* call_params = (Op_Call_Param*) arena_alloc(&context->arena, sizeof(Op_Call_Param) * expr->call.param_count);
            for (u32 p = 0; p < expr->call.param_count; p += 1) {
                Expr* param_expr = expr->call.params[p];

                u64 param_size = type_size_of(context, param_expr->type_index);
                if (param_size > 8) unimplemented(); // TODO by-reference semantics

                Local local = intermediate_allocate_temporary(context, param_size);
                linearize_expr(context, param_expr, local, false);

                call_params[p].size = param_size;
                call_params[p].local = local;
            }

            Op op = {0};
            op.kind = op_call;
            op.primitive = context->type_buf[expr->type_index];
            op.call.func_index = expr->call.func_index;
            op.call.target = assign_to;
            op.call.params = call_params;
            buf_push(context->tmp_ops, op);

            for (u32 i = 0; i < expr->call.param_count; i += 1) {
                intermediate_deallocate_temporary(context, call_params[i].local);
            }
        } break;

        case expr_cast: {
            assert(!get_address);

            linearize_expr(context, expr->cast_from, assign_to, false);

            if (!type_cmp(context, expr->type_index, expr->cast_from->type_index)) {
                Op op = {0};
                op.kind = op_cast;
                op.primitive = primitive;
                op.cast.local = assign_to;
                op.cast.old_primitive = context->type_buf[expr->cast_from->type_index];
                buf_push(context->tmp_ops, op);
            }
        } break;

        case expr_address_of: {
            assert(!get_address);
            linearize_expr(context, expr->address_from, assign_to, true);
        } break;

        case expr_dereference: {
            if (get_address) {
                // Used for lvalues
                linearize_expr(context, expr->dereference_from, assign_to, false);

            } else {
                Local right_local = intermediate_allocate_temporary(context, POINTER_SIZE);
                right_local.as_reference = false;
                linearize_expr(context, expr->dereference_from, right_local, false);
                right_local.as_reference = true;

                if (primitive_is_compound(context->type_buf[expr->type_index])) {
                    assert(assign_to.as_reference);
                }

                intermediate_write_compound_set(context, right_local, assign_to, expr->type_index);

                intermediate_deallocate_temporary(context, right_local);
            }
        } break;

        case expr_subscript: {
            u32 subscript_type_index = expr->subscript.array->type_index;
            u32 child_type_index;
            bool is_pointer;

            if (context->type_buf[subscript_type_index] == primitive_pointer) {
                assert(context->type_buf[subscript_type_index + 1] == primitive_array);
                child_type_index = subscript_type_index + 2 + sizeof(u64);
                is_pointer = true;
            } else {
                assert(context->type_buf[subscript_type_index] == primitive_array);
                child_type_index = subscript_type_index + 1 + sizeof(u64);
                is_pointer = false;
            }

            u64 stride = type_size_of(context, child_type_index);

            Local base_pointer;
            if (get_address) {
                base_pointer = assign_to;
            } else {
                base_pointer = intermediate_allocate_temporary(context, POINTER_SIZE);
            }
            linearize_expr(context, expr->subscript.array, base_pointer, !is_pointer);

            u64 index_size = primitive_size_of(primitive_u64);
            Local offset = intermediate_allocate_temporary(context, index_size);
            linearize_expr(context, expr->subscript.index, offset, false);

            Op op = {0};

            op.kind = op_mul;
            op.primitive = primitive_pointer;
            op.binary.source = (Local) { local_literal, false, stride };
            op.binary.target = offset;
            buf_push(context->tmp_ops, op);

            op.kind = op_add;
            op.primitive = primitive_pointer;
            op.binary.source = offset;
            op.binary.target = base_pointer;
            buf_push(context->tmp_ops, op);

            if (!get_address) {
                if (primitive_is_compound(primitive)) {
                    assert(assign_to.as_reference);
                }

                base_pointer.as_reference = true;
                intermediate_write_compound_set(context, base_pointer, assign_to, child_type_index);
                intermediate_deallocate_temporary(context, base_pointer);
            }

            intermediate_deallocate_temporary(context, offset);
        } break;

        default: assert(false);
    }
}

void linearize_assignment(Context* context, Expr* left, Expr* right) {
    assert(left->flags & EXPR_FLAG_ASSIGNABLE);

    switch (left->kind) {
        case expr_subscript:
        case expr_dereference:
        {
            bool use_pointer_to_right = primitive_is_compound(context->type_buf[left->type_index]);

            Local right_data_local = intermediate_allocate_temporary(context, type_size_of(context, right->type_index));
            Local pointer_to_right_data_local, right_local;
            if (use_pointer_to_right) {
                pointer_to_right_data_local = intermediate_allocate_temporary(context, POINTER_SIZE);

                Op op = {0};
                op.kind = op_address_of;
                op.binary.source = right_data_local;
                op.binary.target = pointer_to_right_data_local;
                buf_push(context->tmp_ops, op);

                pointer_to_right_data_local.as_reference = true;
                right_local = pointer_to_right_data_local;
            } else {
                right_local = right_data_local;
            }

            Local left_local  = intermediate_allocate_temporary(context, POINTER_SIZE);
            linearize_expr(context, left, left_local, true);
            left_local.as_reference = true;

            linearize_expr(context, right, right_local, false);

            intermediate_write_compound_set(context, right_local, left_local, left->type_index);

            intermediate_deallocate_temporary(context, left_local);
            intermediate_deallocate_temporary(context, right_data_local);
            if (use_pointer_to_right) {
                intermediate_deallocate_temporary(context, pointer_to_right_data_local);
            }
        } break;

        case expr_variable: {
            Primitive left_primitive = context->type_buf[left->type_index];
            u64 operand_size = type_size_of(context, left->type_index);

            if (primitive_is_compound(left_primitive)) {
                if (left_primitive == primitive_array) {
                    Local temporary_local = intermediate_allocate_temporary(context, operand_size);
                    Local pointer_to_temporary_local  = intermediate_allocate_temporary(context, POINTER_SIZE);

                    buf_push(context->tmp_ops, ((Op) {
                        .kind = op_address_of,
                        .binary = {
                            .source = temporary_local,
                            .target = pointer_to_temporary_local,
                        },
                    }));
                    pointer_to_temporary_local.as_reference = true;

                    linearize_expr(context, right, pointer_to_temporary_local, false);

                    Local variable_local = { local_variable, false, left->variable.index };
                    Local pointer_to_variable_local  = intermediate_allocate_temporary(context, POINTER_SIZE);

                    buf_push(context->tmp_ops, ((Op) {
                        .kind = op_address_of,
                        .binary = {
                            .source = variable_local,
                            .target = pointer_to_variable_local,
                        },
                    }));
                    pointer_to_variable_local.as_reference = true;

                    intermediate_write_compound_set(context, pointer_to_temporary_local, pointer_to_variable_local, left->type_index);

                    intermediate_deallocate_temporary(context, temporary_local);
                    intermediate_deallocate_temporary(context, pointer_to_temporary_local);
                    intermediate_deallocate_temporary(context, pointer_to_variable_local);
                } else {
                    assert(false);
                }

            } else {
                assert(operand_size <= POINTER_SIZE);

                Local temporary_local = intermediate_allocate_temporary(context, operand_size);
                Local variable_local = { local_variable, false, left->variable.index };

                linearize_expr(context, right, temporary_local, false);
                intermediate_write_compound_set(context, temporary_local, variable_local, left->type_index);

                intermediate_deallocate_temporary(context, temporary_local);
            }
        } break;

        case expr_literal:
        case expr_binary:
        case expr_call:
        case expr_cast:
        case expr_address_of:
        {
            panic("Invalid lexpr\n");
        } break;

        default: assert(false);
    }
}

void build_intermediate(Context* context) {
    // Linearize statements
    buf_foreach (Func, func, context->funcs) {
        assert(buf_empty(context->tmp_ops));

        if (func->kind != func_kind_normal) {
            continue;
        }

        for (u32 s = 0; s < func->body.stmt_count; s += 1) {
            Stmt* stmt = &func->body.stmts[s];

            u32 a = buf_length(context->tmp_ops);

            switch (stmt->kind) {
                case stmt_assignment: linearize_assignment(context, stmt->assignment.left, stmt->assignment.right); break;
                case stmt_expr:       linearize_expr(context, stmt->expr, (Local) {0}, false); break;

                case stmt_declaration: {
                } break;

                default: assert(false);
            }

            u32 b = buf_length(context->tmp_ops);

            buf_foreach (Tmp, tmp, context->tmp_tmps) assert(!tmp->currently_allocated);
        }

        buf_push(context->tmp_ops, ((Op) { op_end_of_function }));

        func->body.op_count = buf_length(context->tmp_ops) - 1;
        func->body.ops = (Op*) arena_alloc(&context->arena, buf_bytes(context->tmp_ops));
        mem_copy((u8*) context->tmp_ops, (u8*) func->body.ops, buf_bytes(context->tmp_ops));

        func->body.tmp_count = buf_length(context->tmp_tmps);
        func->body.tmps = (Tmp*) arena_alloc(&context->arena, buf_bytes(context->tmp_tmps));
        mem_copy((u8*) context->tmp_tmps, (u8*) func->body.tmps, buf_bytes(context->tmp_tmps));

        buf_clear(context->tmp_ops);
        buf_clear(context->tmp_tmps);

        #if 0
        u8* name = string_table_access(context->string_table, func->name);
        printf("%s has %u operations:\n", name, (u64) func->body.op_count);
        for (u32 i = 0; i < func->body.op_count; i += 1) {
            printf("  ");
            print_op(context, func, &func->body.ops[i]);
            printf("\n");
        }
        printf("temps:\n");
        for (u32 t = 0; t < func->body.tmp_count; t += 1) {
            printf("  $%u is %u bytes\n", (u64) t, (u64) func->body.tmps[t].size);
        }
        #endif
    }
}


typedef struct Eval_Stack_Frame Eval_Stack_Frame;
struct Eval_Stack_Frame {
    Func* func;
    Op* current_op;
    Eval_Stack_Frame* parent;
    Local call_result_into;
    u8* local_data;
};

u8* eval_get_local(Eval_Stack_Frame* frame, Local local, bool allow_literal) {
    Mem_Item* item;
    switch (local.kind) {
        case local_variable:  item = &frame->func->body.mem_layout.vars[local.value]; break;
        case local_temporary: item = &frame->func->body.mem_layout.tmps[local.value]; break;
        case local_literal: {
            assert(allow_literal);
            assert(!local.as_reference);
            return (u8*) &local.value;
        } break;
        default: assert(false);
    }

    u8* pointer = frame->local_data + item->offset;
    if (local.as_reference) {
        assert(item->size == POINTER_SIZE);
        pointer = (void*) *((u64*) pointer);
    }

    return pointer;
}

void eval_ops(Context* context) {
    arena_stack_push(&context->stack);


    buf_foreach (Func, func, context->funcs) {
        if (func->kind != func_kind_normal) {
            continue;
        }

        assert(func->body.mem_layout.vars == null && func->body.mem_layout.tmps == null);


        u8* mem_item_data = arena_alloc(&context->arena, sizeof(Mem_Item) * (func->body.var_count + func->body.tmp_count));
        func->body.mem_layout.vars = (Mem_Item*) mem_item_data;
        func->body.mem_layout.tmps = func->body.mem_layout.vars + func->body.var_count;

        u32 offset = 0;

        for (u32 v = 0; v < func->body.var_count; v += 1) {
            u64 size = type_size_of(context, func->body.vars[v].type_index);
            func->body.mem_layout.vars[v].size = size;
            func->body.mem_layout.vars[v].offset = offset;
            offset = round_to_next(offset + size, 8);
        }

        for (u32 t = 0; t < func->body.tmp_count; t += 1) {
            u64 size = func->body.tmps[t].size;
            func->body.mem_layout.tmps[t].size = size;
            func->body.mem_layout.tmps[t].offset = offset;
            offset = round_to_next(offset + size, 8);
        }

        func->body.mem_layout.total_bytes = offset;
    }


    u32 main_func_index = find_func(context, string_table_search(context->string_table, "main")); 
    assert(main_func_index != STRING_TABLE_NO_MATCH);
    Func* main_func = context->funcs + main_func_index;

    Eval_Stack_Frame* frame = arena_insert(&context->stack, ((Eval_Stack_Frame) {0}));
    frame->func = main_func;
    frame->local_data = arena_alloc(&context->stack, frame->func->body.mem_layout.total_bytes);
    mem_clear(frame->local_data, frame->func->body.mem_layout.total_bytes);

    u64 instructions_executed = 0;

    while (1) {
        if (frame->current_op == null) {
            frame->current_op = frame->func->body.ops;
        }

        bool break_into_call = false;

        Op* last_op = frame->func->body.ops + frame->func->body.op_count;
        while (frame->current_op != last_op && !break_into_call) {
            Op* op = frame->current_op;
            frame->current_op += 1;

            #if 0
            printf("(%u) ", (u64) instructions_executed);
            print_op(context, frame->func, op);
            printf("\n");
            #endif
            instructions_executed += 1;

            switch (op->kind) {
                case op_reset_temporary: {
                    Mem_Item* item = &frame->func->body.mem_layout.tmps[op->temporary];
                    mem_clear(frame->local_data + item->offset, item->size);
                } break;

                case op_set: {
                    u8* target_pointer = eval_get_local(frame, op->binary.target, false);
                    u8* source_pointer = eval_get_local(frame, op->binary.source, true);
                    u8 operand_size = primitive_size_of(op->primitive);
                    mem_copy(source_pointer, target_pointer, operand_size);
                } break;

                case op_add:
                case op_sub:
                case op_mul:
                case op_div:
                {
                    u8* target_pointer = eval_get_local(frame, op->binary.target, false);
                    u8* source_pointer = eval_get_local(frame, op->binary.source, true);

                    u8 operand_size = primitive_size_of(op->primitive);
                    u64 mask = size_mask(operand_size);

                    switch (op->primitive) {
                        case primitive_invalid:
                        case primitive_void:
                        case primitive_array:
                        case primitive_unsolidified_int:
                        {
                            assert(false);
                        } break;

                        case primitive_u8:
                        case primitive_u16:
                        case primitive_u32:
                        case primitive_u64:
                        case primitive_pointer:
                        {
                            u64 target = *((u64*) target_pointer) & mask;
                            u64 source = *((u64*) source_pointer) & mask;
                            u64 result;
                            switch (op->kind) {
                                case op_add: result = target + source; break;
                                case op_sub: result = target - source; break;
                                case op_mul: result = target * source; break;
                                case op_div: result = target / source; break;
                                default: assert(false);
                            }
                            mem_copy((u8*) &result, target_pointer, operand_size);
                        } break;

                        case primitive_i8:
                        case primitive_i16:
                        case primitive_i32:
                        case primitive_i64:
                        {
                            unimplemented();
                        } break;

                        default: assert(false);
                    }
                } break;

                case op_address_of: {
                    u8* target_pointer = eval_get_local(frame, op->binary.target, false);
                    u8* source_pointer = eval_get_local(frame, op->binary.source, false);
                    if (op->binary.source.as_reference) assert(false);
                    *((u64*) target_pointer) = (u64) source_pointer;
                } break;

                case op_call: {
                    Func* callee = context->funcs + op->call.func_index;

                    if (callee->kind == func_kind_imported) {
                        u8* name = string_table_access(context->string_table, callee->name);
                        printf("WARNING: Can't call imported function \"%s\" from intermediate mode for now.\n", name);
                        break;
                    }

                    Eval_Stack_Frame* next_frame = arena_insert(&context->stack, ((Eval_Stack_Frame) {0}));
                    next_frame->func = callee;
                    next_frame->parent = frame;
                    next_frame->call_result_into = op->call.target;
                    next_frame->local_data = arena_alloc(&context->stack, next_frame->func->body.mem_layout.total_bytes);
                    mem_clear(next_frame->local_data, next_frame->func->body.mem_layout.total_bytes);

                    for (u32 p = 0; p < callee->signature.param_count; p += 1) {
                        Local param = op->call.params[p].local;
                        u64 param_size = op->call.params[p].size;

                        u32 var_index = callee->signature.params[p].var_index;
                        Local into_variable = { local_variable, false, var_index };

                        u8* our = eval_get_local(frame, param, false);
                        u8* their = eval_get_local(next_frame, into_variable, false);
                        mem_copy(our, their, param_size);
                    }

                    frame = next_frame;
                    break_into_call = true;
                } break;

                case op_cast: {
                    Local local = op->cast.local;
                    u64* value = (u64*) eval_get_local(frame, op->cast.local, false);

                    switch (op->primitive) {
                        case primitive_invalid:
                        case primitive_void:
                        case primitive_unsolidified_int:
                        {
                            panic("Invalid cast to %s\n", primitive_name(op->primitive));
                        } break;

                        case primitive_pointer: break;

                        case primitive_u8:
                        case primitive_u16:
                        case primitive_u32:
                        case primitive_u64:
                        {
                            *value &= size_mask(primitive_size_of(op->cast.old_primitive));
                        } break;

                        case primitive_i8:
                        case primitive_i16:
                        case primitive_i32:
                        case primitive_i64:
                        {
                            unimplemented(); // TODO Sign extend if we up-cast!
                        } break;

                        default: assert(false);
                    }
                } break;

                default: assert(false);
            }
        }

        if (!break_into_call) {
            if (frame->parent != null) {
                if (frame->func->signature.has_output) {
                    Local output_local = { local_variable, false, frame->func->body.output_var_index };
                    Local target_local = frame->call_result_into;

                    u64* output_pointer = (u64*) eval_get_local(frame, output_local, false);
                    u64* target_pointer = (u64*) eval_get_local(frame->parent, target_local, false);
                    *target_pointer = *output_pointer;
                }

                frame = frame->parent;
            } else {
                break;
            }
        }
    }

    {
        printf("Evaluated intermediate bytecode:\n");
        u8* name = string_table_access(context->string_table, frame->func->name);
        printf("  fn %s:\n", name);

        for (u32 i = 0; i < frame->func->body.var_count; i += 1) {
            u32 offset = frame->func->body.mem_layout.vars[i].offset;
            u64 value = *((u64*) (frame->local_data + offset));

            Var* var = &frame->func->body.vars[i];
            u8* name = string_table_access(context->string_table, var->name);

            printf("    %s = %u\n", name, (u64) value);
        }
    }

    arena_stack_pop(&context->stack);
}


enum {
    REX_BASE = 0x40,
    REX_W = 0x08,
    REX_R = 0x04,
    REX_X = 0x02,
    REX_B = 0x01,
};

enum {
    MODRM_REG_OFFSET = 3,
    MODRM_REG_MASK = 0x38,
    MODRM_RM_OFFSET = 0,
    MODRM_RM_MASK = 0x7,
    MODRM_MOD_OFFSET = 6,
    MODRM_MOD_MASK = 0xc0,
};

typedef enum Arithmetic {
    arithmetic_xor,
    arithmetic_add,
    arithmetic_sub,
    ARITHMETIC_COUNT,
} Arithmetic;

u8 ARITHMETIC_OPCODES_BYTE[ARITHMETIC_COUNT] = {
    [arithmetic_xor] = 0x32,
    [arithmetic_add] = 0x02,
    [arithmetic_sub] = 0x2a,
};
u8 ARITHMETIC_OPCODES_INT[ARITHMETIC_COUNT] = {
    [arithmetic_xor] = 0x33,
    [arithmetic_add] = 0x03,
    [arithmetic_sub] = 0x2b,
};
u8* ARITHMETIC_OP_NAMES[ARITHMETIC_COUNT] = {
    [arithmetic_xor] = "xor",
    [arithmetic_add] = "add",
    [arithmetic_sub] = "sub",
};

void instruction_int3(u8** b) {
    buf_push(*b, 0xcc);
}

void instruction_nop(u8** b) {
    buf_push(*b, 0x90);
}

//#define missing_instruction(x) instruction_nop(x)
#define missing_instruction(x) unimplemented()

void instruction_arithmetic_reg_reg(u8** b, Arithmetic arithmetic, Reg a_reg, Reg b_reg, u8 bytes) {
    bool use_small_op = false;
    u8 rex = REX_BASE;
    u8 modrm = 0xc0;

    modrm |= (a_reg << MODRM_REG_OFFSET) & MODRM_REG_MASK;
    if (a_reg > 8) rex |= REX_R;
    assert(a_reg < 16);

    modrm |= (b_reg << MODRM_RM_OFFSET) & MODRM_RM_MASK;
    if (b_reg > 8) rex |= REX_B;
    assert(b_reg < 16);

    switch (bytes) {
        case 1: {
            use_small_op = true;
        } break;
        case 2: {
            buf_push(*b, 0x66);
        } break;
        case 4: {
        } break;
        case 8: {
            rex |= REX_W;
        } break;
        default: assert(false);
    }

    if (rex != REX_BASE) {
        buf_push(*b, rex);
    }

    if (use_small_op) {
        buf_push(*b, ARITHMETIC_OPCODES_BYTE[arithmetic]);
    } else {
        buf_push(*b, ARITHMETIC_OPCODES_INT[arithmetic]);
    }

    buf_push(*b, modrm);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("%s%u %s %s\n", ARITHMETIC_OP_NAMES[arithmetic], (u64) bytes*8, reg_names[a_reg], reg_names[b_reg]);
    #endif
}

// Multiplies/divides reg_rax by reg, storing the result in reg_rax.
// Higher order bits (for mul) or remainder (for div) are stored in reg_rdx or the second byte of reg_rax (for 8-bit mul)
void instruction_mul_or_div_reg(u8** b, bool mul, Reg reg, u8 bytes) {
    u8 rex = REX_BASE;
    u8 opcode = 0xf7;

    u8 modrm;
    if (mul) {
        modrm = 0xe0;
    } else {
        modrm = 0xf0;
    }

    modrm |= ((reg << MODRM_RM_OFFSET) & MODRM_RM_MASK);
    if (reg > 8) rex |= REX_B;
    assert(reg < 16);

    switch (bytes) {
        case 1: opcode -= 1; break;
        case 2: buf_push(*b, 0x66); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    if (rex != REX_BASE) {
        buf_push(*b, rex);
    }
    buf_push(*b, opcode);
    buf_push(*b, modrm);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("%s%u rax, %s\n", mul? "mul" : "div", (u64) bytes*8, reg_names[reg]);
    #endif
}

Mem_Item* get_stack_item(Func* func, Local local) {
    Mem_Item* item;
    switch (local.kind) {
        case local_variable:  item = &func->body.stack_layout.vars[local.value]; break;
        case local_temporary: item = &func->body.stack_layout.tmps[local.value]; break;
        case local_literal: assert(false);
        default: assert(false);
    }
    return item;
}

void instruction_lea_stack_to_reg(u8** b, Func* func, Local local, Reg reg) {
    Mem_Item* item = get_stack_item(func, local);
    u32 offset = item->offset;

    u8 rex = REX_BASE | REX_W;
    u8 modrm = 0;

    modrm |= (reg << MODRM_REG_OFFSET) & MODRM_REG_MASK;
    if (reg > 8) rex |= REX_R;
    assert(reg < 16);

    modrm |= 0x04; // Use SIB with a 32-bit displacement
    if (offset <= I8_MAX) {
        modrm |= 0x40;
    } else {
        modrm |= 0x80;
    }

    buf_push(*b, rex);
    buf_push(*b, 0x8d);
    buf_push(*b, modrm);
    buf_push(*b, 0x24); // SIB which results in 'rsp + offset'
    str_push_integer(b, (offset <= I8_MAX)? sizeof(i8) : sizeof(i32), offset);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("lea %s, [rsp + %u]\n", reg_names[reg], (u64) offset);
    #endif
}

typedef enum Mov_Mode {
    mov_to,
    mov_from,
} Mov_Mode;

void instruction_mov_pointer(u8** b, Mov_Mode mode, Reg pointer_reg, Reg value_reg, u8 bytes) {
    u8 rex = REX_BASE | REX_W;
    u8 opcode;

    if (mode == mov_to) {
        opcode = 0x89;
    } else {
        opcode = 0x8b;
    }

    switch (bytes) {
        case 1: {
            opcode -= 1;
        } break;
        case 2: {
            buf_push(*b, 0x66);
        } break;
        case 4: {
        } break;
        case 8: {
            rex |= REX_W;
        } break;
        default: assert(false);
    }

    u8 modrm = 0x00;

    modrm |= (value_reg << MODRM_REG_OFFSET) & MODRM_REG_MASK;
    if (value_reg > 8) rex |= REX_R;
    assert(value_reg < 16);

    modrm |= (pointer_reg << MODRM_RM_OFFSET) & MODRM_RM_MASK;
    if (pointer_reg > 8) rex |= REX_R;
    assert(pointer_reg < 16);

    if (pointer_reg == reg_rsp || pointer_reg == reg_rbp || pointer_reg == reg_r12 || pointer_reg == reg_r13) {
        panic("Can't encode mov to value pointed to by rsp/rbp direction, as these byte sequences are used to indicate the use of a SIB byte.");
        // TODO there is a table in the intel manual (p. 71) which explains these exceptions. Also see reference/notes.md on modrm/sib, which
        // covers this briefly.
    }

    if (rex != REX_BASE) {
        buf_push(*b, rex);
    }
    buf_push(*b, opcode);
    buf_push(*b, modrm);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    if (mode == mov_to) {
        printf("mov%u [%s], %s\n", (u64) bytes*8, reg_names[pointer_reg], reg_names[value_reg]);
    } else {
        printf("mov%u %s, [%s]\n", (u64) bytes*8, reg_names[value_reg], reg_names[pointer_reg]);
    }
    #endif
}

void instruction_mov_stack(u8** b, Func* func, Mov_Mode mode, Reg reg, Local local, u8 bytes) {
    Mem_Item* item = get_stack_item(func, local);
    u32 offset = item->offset;

    u8 rex = REX_BASE | REX_W;
    u8 modrm = 0;
    u8 opcode;

    if (mode == mov_to) {
        opcode = 0x89;
    } else {
        opcode = 0x8b;
    }

    switch (bytes) {
        case 1: {
            opcode -= 1;
        } break;
        case 2: {
            buf_push(*b, 0x66);
        } break;
        case 4: {
        } break;
        case 8: {
            rex |= REX_W;
        } break;
        default: assert(false);
    }

    modrm |= (reg << MODRM_REG_OFFSET) & MODRM_REG_MASK;
    if (reg > 8) rex |= REX_R;
    assert(reg < 16);

    modrm |= 0x04; // Use SIB with a 32-bit displacement
    if (offset <= I8_MAX) {
        modrm |= 0x40;
    } else {
        modrm |= 0x80;
    }

    if (rex != REX_BASE) {
        buf_push(*b, rex);
    }
    buf_push(*b, opcode);
    buf_push(*b, modrm);
    buf_push(*b, 0x24); // SIB which results in 'rsp + offset'
    str_push_integer(b, (offset <= I8_MAX)? sizeof(i8) : sizeof(i32), offset);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    if (mode == mov_to) {
        printf("mov%u [rsp + %x], %s\n", (u64) bytes*8, (u64) offset, reg_names[reg]);
    } else {
        printf("mov%u %s, [rsp + %x]\n", (u64) bytes*8, reg_names[reg], (u64) offset);
    }
    #endif
}

void instruction_mov_imm_to_reg(u8** b, u64 value, Reg reg, u8 bytes) {
    u8 rex = REX_BASE;
    u8 opcode;

    switch (bytes) {
        case 1: {
            opcode = 0xb0;
        } break;
        case 2: {
            buf_push(*b, 0x66);
            opcode = 0xb8;
        } break;
        case 4: {
            opcode = 0xb8;
        } break;
        case 8: {
            opcode = 0xb8;
            rex |= REX_W;
        } break;
        default: assert(false);
    }

    opcode |= reg & 0x07;
    if (reg > 8) rex |= REX_B;
    assert(reg < 16);

    if (rex != REX_BASE) {
        buf_push(*b, rex);
    }

    buf_push(*b, opcode);

    str_push_integer(b, bytes, value);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov%u %s, %u\n", (u64) bytes*8, reg_names[reg], value);
    #endif
}

void instruction_load_local(u8** b, Func* func, Reg reg, Local local, u8 bytes) {
    if (local.kind == local_literal) {
        assert(!local.as_reference);
        instruction_mov_imm_to_reg(b, local.value, reg, bytes);
    } else if (local.as_reference) {
        instruction_mov_stack(b, func, mov_from, reg, local, POINTER_SIZE);
        instruction_mov_pointer(b, mov_from, reg, reg, bytes);
    } else {
        instruction_mov_stack(b, func, mov_from, reg, local, bytes);
    }
}


void machinecode_for_op(Context* context, Func* func, Op* op) {
    u8 primitive_size = primitive_size_of(op->primitive);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("; ");
    print_op(context, func, op);
    printf("\n");
    #endif

    switch (op->kind) {
        case op_set: {
            instruction_load_local(&context->bytecode, func, reg_rax, op->binary.source, primitive_size);

            if (op->binary.target.as_reference) {
                instruction_mov_stack(&context->bytecode, func, mov_from, reg_rcx, op->binary.target, POINTER_SIZE);
                instruction_mov_pointer(&context->bytecode, mov_to, reg_rcx, reg_rax, primitive_size);
            } else {
                instruction_mov_stack(&context->bytecode, func, mov_to, reg_rax, op->binary.target, primitive_size);
            }
        } break;

        case op_address_of: {
            // TODO neither of these cases currently ever happens, due to how we generate the intermediate bytecode. Once we start
            // optimizing, this might change though...
            if (op->binary.source.as_reference) unimplemented(); // TODO
            if (op->binary.target.as_reference) unimplemented(); // TODO

            instruction_lea_stack_to_reg(&context->bytecode, func, op->binary.source, reg_rax);
            instruction_mov_stack(&context->bytecode, func, mov_to, reg_rax, op->binary.target, POINTER_SIZE);
        } break;

        case op_add:
        case op_sub:
        {
            int kind;
            switch (op->kind) {
                case op_add: kind = arithmetic_add; break;
                case op_sub: kind = arithmetic_sub; break;
                default: assert(false);
            }

            if (op->binary.target.as_reference) {
                instruction_mov_stack(&context->bytecode, func, mov_from, reg_rcx, op->binary.target, POINTER_SIZE);
                instruction_mov_pointer(&context->bytecode, mov_from, reg_rcx, reg_rax, primitive_size);
            } else {
                instruction_mov_stack(&context->bytecode, func, mov_from, reg_rax, op->binary.target, primitive_size);
            }

            instruction_load_local(&context->bytecode, func, reg_rdx, op->binary.source, primitive_size);

            instruction_arithmetic_reg_reg(&context->bytecode, kind, reg_rax, reg_rdx, primitive_size);

            if (op->binary.target.as_reference) {
                instruction_mov_pointer(&context->bytecode, mov_to, reg_rcx, reg_rax, primitive_size);
            } else {
                instruction_mov_stack(&context->bytecode, func, mov_to, reg_rax, op->binary.target, primitive_size);
            }
        } break;

        case op_mul:
        case op_div:
        {
            if (op->binary.target.as_reference) unimplemented(); // TODO

            instruction_mov_stack(&context->bytecode, func, mov_from, reg_rax, op->binary.target, primitive_size);
            instruction_load_local(&context->bytecode, func, reg_rcx, op->binary.source, primitive_size);

            bool mul = op->kind == op_mul;
            instruction_mul_or_div_reg(&context->bytecode, mul, reg_rcx, primitive_size);

            instruction_mov_stack(&context->bytecode, func, mov_to, reg_rax, op->binary.target, primitive_size);
        } break;

        case op_call: {
            Func* callee = &context->funcs[op->call.func_index];

            for (u32 p = 0; p < callee->signature.param_count; p += 1) {
                Local local = op->call.params[p].local;
                u8 size = op->call.params[p].size;

                u8 reg;
                switch (p) {
                    case 0: reg = reg_rcx; break;
                    case 1: reg = reg_rdx; break;
                    case 2: reg = reg_r8; break;
                    case 3: reg = reg_r9; break;
                    default: unimplemented(); // TODO additional parameters go on the stack. We also need more space in that case.
                }

                if (local.kind == local_literal) {
                    unimplemented(); // TODO
                } else if (local.as_reference) {
                    unimplemented(); // TODO
                } else {
                    instruction_mov_stack(&context->bytecode, func, mov_from, reg, local, size);
                }
            }

            // Actually call the function
            switch (callee->kind) {
                case func_kind_normal: {
                    buf_push(context->bytecode, 0xe8);
                    buf_push(context->bytecode, 0xde);
                    buf_push(context->bytecode, 0xad);
                    buf_push(context->bytecode, 0xbe);
                    buf_push(context->bytecode, 0xef);

                    Call_Fixup fixup = {0};
                    fixup.text_location = buf_length(context->bytecode) - sizeof(i32);
                    fixup.func_index = op->call.func_index;
                    buf_push(context->call_fixups, fixup);
                } break;

                case func_kind_imported: {
                    buf_push(context->bytecode, 0xff);
                    buf_push(context->bytecode, 0x15);
                    buf_push(context->bytecode, 0xde);
                    buf_push(context->bytecode, 0xad);
                    buf_push(context->bytecode, 0xbe);
                    buf_push(context->bytecode, 0xef);

                    Fixup fixup = {0};
                    fixup.text_location = buf_length(context->bytecode) - sizeof(i32);
                    fixup.kind = fixup_imported_function;
                    fixup.import_index = callee->import_info.index;
                    buf_push(context->fixups, fixup);
                } break;

                default: assert(false);
            }

            #ifdef PRINT_GENERATED_INSTRUCTIONS
            u8* name = string_table_access(context->string_table, callee->name);
            printf("call %s\n", name);
            #endif

            if (op->primitive != primitive_void) {
                if (op->call.target.as_reference) unimplemented(); // TODO
                instruction_mov_stack(&context->bytecode, func, mov_to, reg_rax, op->call.target, primitive_size);
            }
        } break;

        case op_cast: {
            // TODO zero-extend for signed types!

            u8 new_size = primitive_size;
            u8 old_size = primitive_size_of(op->cast.old_primitive);

            if (new_size > old_size) {
                if (op->cast.local.as_reference) unimplemented(); // TODO
                instruction_mov_stack(&context->bytecode, func, mov_from, reg_rax, op->cast.local, old_size);
                instruction_mov_stack(&context->bytecode, func, mov_to, reg_rax, op->cast.local, new_size);
            }
        } break;

        case op_reset_temporary: break;

        case op_end_of_function: assert(false);
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
    assert(main_func->kind == func_kind_normal); // TODO I'm not sure if this is strictly speaking neccesary!

    buf_foreach (Func, func, context->funcs) {
        if (func->kind != func_kind_normal) continue;

        func->body.bytecode_start = buf_length(context->bytecode);

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        u8* name = string_table_access(context->string_table, func->name);
        printf("; --- fn %s ---\n", name);
        #endif

        // Lay out stack
        assert(func->body.stack_layout.vars == null && func->body.stack_layout.tmps == null);

        u64 mem_item_data_bytes = sizeof(Mem_Item) * (func->body.var_count + func->body.tmp_count);
        u8* mem_item_data = arena_alloc(&context->arena, mem_item_data_bytes);
        mem_clear(mem_item_data, mem_item_data_bytes);

        func->body.stack_layout.vars = (Mem_Item*) mem_item_data;
        func->body.stack_layout.tmps = func->body.stack_layout.vars + func->body.var_count;

        u32 offset = 0;

        // Shadow space for calling other functions
        u32 max_params = U32_MAX;
        for (u32 i = 0; i < func->body.op_count; i += 1) {
            Op* op = &func->body.ops[i];
            if (op->kind == op_call) {
                Func* callee = &context->funcs[op->call.func_index];

                if (max_params == U32_MAX) max_params = 0;
                max_params = max(max_params, callee->signature.param_count);
            }
        }
        if (max_params != U32_MAX) {
            offset += max(max_params, 4)*POINTER_SIZE;
        }

        // Mark parameter variables so they don't get allocated normaly
        for (u32 p = 0; p < func->signature.param_count; p += 1) {
            u32 var_index = func->signature.params[p].var_index;
            func->body.stack_layout.vars[var_index].offset = U32_MAX;
        }

        // Variables
        for (u32 v = 0; v < func->body.var_count; v += 1) {
            Mem_Item* mem_item = &func->body.stack_layout.vars[v];

            if (mem_item->offset == U32_MAX) continue; // Ignore parameters for now

            u64 size = type_size_of(context, func->body.vars[v].type_index);
            offset = (u32) round_to_next(offset, min(size, POINTER_SIZE));
            mem_item->size = size;
            mem_item->offset = offset;
            offset += size;
        }

        // Temporaries
        for (u32 t = 0; t < func->body.tmp_count; t += 1) {
            u64 size = func->body.tmps[t].size;
            offset = (u32) round_to_next(offset, min(size, POINTER_SIZE));

            func->body.stack_layout.tmps[t].size = size;
            func->body.stack_layout.tmps[t].offset = offset;

            offset += size;
        }

        offset = ((offset + 7) & (~0x0f)) + 8; // Aligns so last nibble is 8
        func->body.stack_layout.total_bytes = offset;

        // Parameters
        for (u32 p = 0; p < func->signature.param_count; p += 1) {
            u32 var_index = func->signature.params[p].var_index;
            Mem_Item* mem_item = &func->body.stack_layout.vars[var_index];
            assert(mem_item->offset == U32_MAX);

            u64 size = type_size_of(context, func->body.vars[var_index].type_index);
            assert(size <= POINTER_SIZE);

            mem_item->size = POINTER_SIZE;
            mem_item->offset = func->body.stack_layout.total_bytes + POINTER_SIZE + POINTER_SIZE*p;
        }

        #if 0
        printf("%x total size\n", func->body.stack_layout.total_bytes);
        for (u32 v = 0; v < func->body.var_count; v += 1) {
            Mem_Item* item = &func->body.stack_layout.vars[v];
            Var* var = &func->body.vars[v];
            printf("  %s\t%x, %x\n", string_table_access(context->string_table, var->name), (u32) item->offset, (u64) item->size);
        }
        for (u32 t = 0; t < func->body.tmp_count; t += 1) {
            Mem_Item* item = &func->body.stack_layout.tmps[t];
            printf("  $%u    %x, %x\n", (u64) t, (u32) item->offset, (u64) item->size);
        }
        #endif

        if (func->body.stack_layout.total_bytes < I8_MAX) {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0x83);
            buf_push(context->bytecode, 0xec);
            str_push_integer(&context->bytecode, sizeof(i8), (u8) func->body.stack_layout.total_bytes);
        } else {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0x81);
            buf_push(context->bytecode, 0xec);
            str_push_integer(&context->bytecode, sizeof(i32), func->body.stack_layout.total_bytes);
        }
        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("sub rsp, %x\n", func->body.stack_layout.total_bytes);
        #endif
        
        // TODO calling convention -- Preserve non-volatile registers! Also, we need to allocate stack space for that!

        // Copy parameters onto stack
        for (u32 p = 0; p < func->signature.param_count; p += 1) {
            u32 var_index = func->signature.params[p].var_index;
            Local local = { local_variable, false, var_index };

            u64 operand_size = type_size_of(context, func->signature.params[p].type_index);
            assert(operand_size <= 8);

            if (p < 4) {
                u8 reg;
                switch (p) {
                    case 0: reg = reg_rcx; break;
                    case 1: reg = reg_rdx; break;
                    case 2: reg = reg_r8; break;
                    case 3: reg = reg_r9; break;
                    default: assert(false);
                }
                instruction_mov_stack(&context->bytecode, func, mov_to, reg, local, (u8) operand_size);
            }
        }

        // Write out operations
        for (u32 i = 0; i < func->body.op_count; i += 1) {
            Op* op = &func->body.ops[i];
            machinecode_for_op(context, func, op);
        }

        // Pass output
        if (func->signature.has_output) {
            u32 var_index = func->body.output_var_index;

            Local output_local = { local_variable, false, var_index };
            Primitive output_primitive = context->type_buf[func->signature.output_type_index];

            if (primitive_is_compound(output_primitive)) {
                if (output_primitive == primitive_array) {
                    unimplemented(); // TODO by-reference semantics
                } else {
                    assert(false);
                }
            } else {
                u8 operand_size = primitive_size_of(output_primitive);
                instruction_mov_stack(&context->bytecode, func, mov_from, reg_rax, output_local, operand_size);
            }
        } else {
            instruction_arithmetic_reg_reg(&context->bytecode, arithmetic_xor, reg_rax, reg_rax, POINTER_SIZE);
        }

        // Reset stack
        if (func->body.stack_layout.total_bytes < I8_MAX) {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0x83);
            buf_push(context->bytecode, 0xc4);
            buf_push(context->bytecode, func->body.stack_layout.total_bytes);
        } else {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0x81);
            buf_push(context->bytecode, 0xc4);
            str_push_integer(&context->bytecode, sizeof(i32), func->body.stack_layout.total_bytes);
        }
        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("add rsp, %x\n", (u64) func->body.stack_layout.total_bytes);
        #endif


        // TODO TODO TODO TODO TODO TODO REMOVE REMOVE REMOVE This will break stuff later on!!!!!!!!
        // TODO TODO TODO TODO TODO TODO REMOVE REMOVE REMOVE This will break stuff later on!!!!!!!!
        // TODO TODO TODO TODO TODO TODO REMOVE REMOVE REMOVE This will break stuff later on!!!!!!!!
        if (func == main_func) continue; // Don't 'ret' after main, so we can inject fake stuff manually after it


        // Return to caller
        buf_push(context->bytecode, 0xc3);
        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("ret\n");
        #endif
    }

    // Call fixups
    buf_foreach (Call_Fixup, fixup, context->call_fixups) {
        i32* target = (i32*) (context->bytecode + fixup->text_location);
        assert(*target == 0xefbeadde);

        Func* callee = &context->funcs[fixup->func_index];
        assert(callee->kind == func_kind_normal);

        u32 jump_to = callee->body.bytecode_start;
        u32 jump_from = fixup->text_location + sizeof(i32);
        i32 jump_by = ((i32) jump_to) - ((i32) jump_from);
        *target = jump_by;
    }

    // Move output into .data+0
    {
        Local output_local = { local_variable, false, 0 };
        u8 output_reg = reg_rax;

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


    u32 library_name_index = string_table_canonicalize(&context->string_table, "kernel32.lib", 12);
    u32 name_1_index = string_table_canonicalize(&context->string_table, "GetStdHandle", 12);
    u32 name_2_index = string_table_canonicalize(&context->string_table, "WriteFile", 9);
    u32 name_3_index = string_table_canonicalize(&context->string_table, "ExitProcess", 11);
    Import_Index index_get_std_handle = add_import(context, library_name_index, name_1_index);
    Import_Index index_write_file     = add_import(context, library_name_index, name_2_index);
    Import_Index index_exit_process   = add_import(context, library_name_index, name_3_index);

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
    fixup.import_index = index_get_std_handle;
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
    fixup.import_index = index_write_file;
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
    fixup.import_index = index_exit_process;
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

const u16 COFF_MACHINE_AMD64  = 0x8664;
const u16 COFF_MACHINE_UNKOWN = 0x0000;

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

typedef struct Archive_Member_Header {
    u8 name[16];
    u8 irrelevant[32];
    u8 size[10]; // Size of member, excluding header, as an ascii string
    u8 end[2];
} Archive_Member_Header;

typedef struct Import_Header {
    u16 s1; // IMAGE_FILE_MACHINE_UNKOWN
    u16 s2; // 0xffff
    u16 version;
    u16 machine;
    u32 time_date_stamp;
    u32 size_of_data;
    u16 ordinal;
    u16 extra;
} Import_Header;

// NB only intended for use within read_archive_member_header
bool parse_ascii_integer(u8* string, u32 length, u64* value) {
    *value = 0;
    for (u32 i = 0; i < length; i += 1) {
        u8 c = string[i];
        if (c >= '0' && c <= '9') {
            *value *= 10;
            *value += c - '0';
        } else if (c == ' ') {
            break;
        } else {
            return false;
        }
    }
    return true;
}

bool read_archive_member_header(
    u8** cursor, u32* cursor_length,
    u8** member, u32* member_length
) {
    if (*cursor_length < sizeof(Archive_Member_Header)) {
        return false;
    }

    Archive_Member_Header* header = (void*) *cursor;

    if (header->end[0] != 0x60 || header->end[1] != 0x0a) {
        return false;
    }

    u64 member_size;
    if (!parse_ascii_integer(header->size, 10, &member_size)) {
        return false;
    }
    if (*cursor_length < sizeof(Archive_Member_Header) + member_size) {
        return false;
    }

    if (member != null) {
        *member = (*cursor + sizeof(Archive_Member_Header));
        *member_length = member_size;
    }

    u32 total_size = sizeof(Archive_Member_Header) + member_size;
    *cursor += total_size;
    *cursor_length -= total_size;
    return true;
}

bool parse_library(Context* context, Library_Import* import) {
    // TODO how do we actually find libraries? Windows has some paths where it stuffs these. Otherwise we should look in
    // the working directory, I guess.
    u8* raw_lib_name = string_table_access(context->string_table, import->lib_name);
    u8* path;
    if (str_cmp(raw_lib_name, "kernel32.lib")) {
        path = "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.16299.0/um/x64/kernel32.lib";
    } else {
        unimplemented();
    }

    u8* file;
    u32 file_length;
    if (!read_entire_file(path, &file, &file_length)) {
        printf("Couldn't open \"%s\"\n", path);
        return false;
    }

    if (file_length < 8 || !mem_cmp(file, "!<arch>\n", 8)) goto invalid;

    u8* cursor = file + 8;
    u32 cursor_length = file_length - 8;

    u8* symbol_data;
    u32 symbol_data_length;

    if (
        !read_archive_member_header(&cursor, &cursor_length, null, null) ||
        !read_archive_member_header(&cursor, &cursor_length, &symbol_data, &symbol_data_length) ||
        !read_archive_member_header(&cursor, &cursor_length, null, null)
    ) goto invalid;

    if (symbol_data_length < 4) goto invalid;
    u32 archive_member_count = *((u32*) symbol_data);
    symbol_data += 4;
    symbol_data_length -= 4;

    if (symbol_data_length < archive_member_count*4) goto invalid;
    u32* archive_member_offsets = (u32*) symbol_data;
    symbol_data += archive_member_count*4;
    symbol_data_length -= archive_member_count*4;

    if (symbol_data_length < 4) goto invalid;
    u32 symbol_count = *((u32*) symbol_data);
    symbol_data += 4;
    symbol_data_length -= 4;

    if (symbol_data_length < 2*symbol_count) goto invalid;
    u16* symbol_indices = (u16*) symbol_data;
    symbol_data += symbol_count*2;
    symbol_data_length -= 2;

    import->function_hints = (u32*) arena_alloc(&context->arena, buf_length(import->function_names) * sizeof(u32));
    u32_fill(import->function_hints, buf_length(import->function_names), U32_MAX);

    u8* other_dll_name = arena_alloc(&context->arena, 17); // NB used somewhere in an inner loop

    u32 s = 0;
    u32 i = 0;
    while (i < symbol_data_length && s < symbol_count) {
        u8* symbol_name_start = &symbol_data[i];
        u32 start_i = i;
        while (i < symbol_data_length && symbol_data[i] != 0) i += 1;
        u32 symbol_name_length = i - start_i;
        i += 1;

        u16 index = symbol_indices[s];
        s += 1;

        if (index > archive_member_count) goto invalid;
        u32 archive_member_offset = archive_member_offsets[index];

        if (file_length - sizeof(Archive_Member_Header) - sizeof(Import_Header) < archive_member_offset) goto invalid;
        Archive_Member_Header* member_header = (void*) (file + archive_member_offset);
        Import_Header* import_header = (void*) (file + archive_member_offset + sizeof(Archive_Member_Header));
        if (import_header->s1 != COFF_MACHINE_UNKOWN || import_header->s2 != 0xffff) continue;

        if (import_header->machine != COFF_MACHINE_AMD64) continue;

        u8 import_type = import_header->extra & 0x03;
        u8 name_type   = (import_header->extra >> 2) & 0x07;

        for (u32 j = 0; j < buf_length(import->function_names); j += 1) {
            u32* hint = &import->function_hints[j];
            if (*hint != U32_MAX) continue;
            u8* specified_name = string_table_access(context->string_table, import->function_names[j]);

            bool match = true;
            for (u32 k = 0; k < symbol_name_length; k += 1) {
                if (symbol_name_start[k] != specified_name[k] || specified_name[k] == 0) {
                    match = false;
                    break;
                }
            }

            if (match) {
                *hint = import_header->ordinal;

                // Figure out the dll name
                if (import->dll_name == null) {
                    u8* dll_name = arena_alloc(&context->arena, 17);
                    mem_clear(dll_name, 17);

                    for (u32 l = 0; l < 16; l += 1) {
                        if (member_header->name[l] == '/' || member_header->name[l] == ' ') break;
                        dll_name[l] = member_header->name[l];
                    }

                    import->dll_name = dll_name;
                } else {
                    mem_clear(other_dll_name, 17);
                    for (u32 l = 0; l < 16; l += 1) {
                        if (member_header->name[l] == '/' || member_header->name[l] == ' ') break;
                        other_dll_name[l] = member_header->name[l];
                    }

                    if (!str_cmp(import->dll_name, other_dll_name)) {
                        printf(
                            "Couldn't load %s: It contains imports from multiple dlls: %s and %s\n",
                            path, import->dll_name, other_dll_name
                        );
                        return false;
                    }
                }

                break;
            }
        }
    }

    for (u32 i = 0; i < buf_length(import->function_names); i += 1) {
        if (import->function_hints[i] == U32_MAX) {
            u8* name = string_table_access(context->string_table, import->function_names[i]);
            printf("Could not find %s in \"%s\"\n", name, path);
            return false;
        }
    }

    free(file);
    return true;

    invalid:
    free(file);
    printf("Couldn't load \"%s\": Invalid archive\n", path);
    return false;
}

bool write_executable(u8* path, Context* context) {
    enum { section_count = 4 }; // So we can use it as an array length
    u64 in_file_alignment = 0x200;
    u64 in_memory_alignment = 0x1000;
    u64 dos_prepend_size = 200;
    u64 total_header_size = dos_prepend_size + sizeof(COFF_Header) + sizeof(Image_Header) + section_count*sizeof(Section_Header);

    u64 text_length = buf_length(context->bytecode);
    u64 data_length = buf_length(context->bytecode_data);

    // TODO pdata is completly messed up. It is supposed to be pointing to some
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
                u32 l = fixup->import_index.library;
                u32 f = fixup->import_index.function;

                assert(l < buf_length(context->imports));
                assert(f < buf_length(context->imports[l].function_names));
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
    str_push_zeroes(&idata, (buf_length(context->imports) + 1) * sizeof(Import_Entry));
    for (u64 i = 0; i < buf_length(context->imports); i += 1) {
        Library_Import* import = &context->imports[i];
        if (!parse_library(context, import)) {
            return false;
        }

        assert(import->dll_name != null);

        u64 table_size = sizeof(u64) * (1 + buf_length(import->function_names));
        u64 address_table_start = buf_length(idata);
        u64 lookup_table_start = address_table_start + table_size;

        str_push_zeroes(&idata, 2*table_size); // Make space for the address & lookup table

        u64 name_table_start = buf_length(idata);
        str_push_cstr(&idata, import->dll_name);
        buf_push(idata, 0);

        for (u64 j = 0; j < buf_length(import->function_names); j += 1) {
            u64 function_name_address = idata_memory_start + buf_length(idata);
            if ((function_name_address & 0x7fffffff) != function_name_address) {
                panic("Import data will be invalid, because it has functions at to high rvas: %x!", function_name_address);
            }

            u8* name = string_table_access(context->string_table, import->function_names[j]);
            u16 hint = import->function_hints[j];

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
            if (fixup->kind != fixup_imported_function || fixup->import_index.library != i) { continue; }

            u32 function = fixup->import_index.function;
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
    u32 main_bytecode_start = context->funcs[main_func_index].body.bytecode_start;
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
    image.data_directories[1].size = (buf_length(context->imports) + 1)*sizeof(Import_Entry);
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

    return true;
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

void print_verbose_info(Context* context) {
    printf("%u functions:\n", (u64) buf_length(context->funcs));
    for (u32 f = 0; f < buf_length(context->funcs); f += 1) {
        Func* func = context->funcs + f;

        u8* name = string_table_access(context->string_table, func->name);
        printf("  fn %s\n", name);

        if (func->kind == func_kind_normal) {
            printf("    %u variables: ", (u64) func->body.var_count);
            for (u32 v = 0; v < func->body.var_count; v += 1) {
                Var* var = &func->body.vars[v];
                u8* name = string_table_access(context->string_table, var->name);

                if (v == 0) {
                    printf("%s", name);
                } else {
                    printf(", %s", name);
                }
            }
            printf("\n");

            printf("    %u statements:\n", (u64) func->body.stmt_count);
            for (u32 s = 0; s < func->body.stmt_count; s += 1) {
                printf("      ");
                print_stmt(context, func, &func->body.stmts[s]);
                printf("\n");
            }
        } else if (func->kind == func_kind_imported) {
            printf("    (Imported)\n");
        } else {
            assert(false);
        }
    }
}


void main() {
    //print_executable_info("build/tiny.exe");

    i64 start_time = perf_time();

    Context context = {0};
    bool success;

    if (!build_ast(&context, "W:/asm2/code.txt")) {
        return; // We print errors inside build_ast
    }
    if (!typecheck(&context)) {
        return;
    }

    print_verbose_info(&context);

    build_intermediate(&context);
    eval_ops(&context);

    build_machinecode(&context);
    if (!write_executable("out.exe", &context)) {
        return;
    }

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

    i64 end_time = perf_time();
    printf("Ran in %i ms\n", (end_time - start_time) * 1000 / perf_frequency);
}
