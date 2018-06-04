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
#define U64_MAX 0xffffffffffffffff

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

#define assert(x)        ((x)? (null) : (printf("(%s:%u) assert(%s)\n", __FILE__, (u64) __LINE__, #x), printf_flush(), trap_or_exit(), null))
#define panic(x, ...)    (printf("(%s:%u) Panic: ", __FILE__, (u64) __LINE__), printf(x, __VA_ARGS__), printf_flush(), trap_or_exit())
#define unimplemented()  (printf("(%s:%u) Reached unimplemented code\n", __FILE__, (u64) __LINE__), printf_flush(), trap_or_exit(), null)

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

u64 str_length(u8* s) {
    u64 length = 0;
    for (u8* t = s; *t != 0; t += 1) {
        length += 1;
    }
    return length;
}

bool str_cmp(u8* a, u8* b) {
    while (true) {
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
    u32 cstr_length = str_length(cstr);
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
#define arena_new(a, T)    (arena_insert_with_size((a), &((T) {0}), sizeof(T)))

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
    return string_table_search_with_length(table, string, str_length(string));
}

u32 string_table_intern(u8** table, u8* string, u32 length) {
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

u32 string_table_intern_cstr(u8** table, u8* string) {
    return string_table_intern(table, string, str_length(string));
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

                // Format numbers as 1st, 2nd, 3rd, 4th, etc...
                case 'n': {
                    u64 value = va_arg(args, u64);
                    printf_integer(value, 10);

                    switch (value) {
                        case 1:  buf_push(printf_buf, 's'); buf_push(printf_buf, 't'); break;
                        case 2:  buf_push(printf_buf, 'n'); buf_push(printf_buf, 'd'); break;
                        case 3:  buf_push(printf_buf, 'r'); buf_push(printf_buf, 'd'); break;
                        default: buf_push(printf_buf, 't'); buf_push(printf_buf, 'h'); break;
                    }
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

typedef enum IO_Result {
    io_ok = 0,

    io_error,
    io_not_found,
    io_already_open,
} IO_Result;

u8* io_result_message(IO_Result result) {
    switch (result) {
        case io_ok:             return "Ok";
        case io_error:          return "IO Error";
        case io_not_found:      return "File not found";
        case io_already_open:   return "File is open in another program";

        default: {
            assert(false);
            return null;
        }
    }
}

IO_Result get_temp_path(u8* path_into, u32* length) {
    *length = GetTempPathA(*length, path_into);
    if (*length == 0) {
        u32 error_code = GetLastError();
        switch (error_code) {
            default: return io_error;
        }
    } else {
        return io_ok;
    }
}

IO_Result read_entire_file(u8* file_name, u8** contents, u32* length) {
    Handle file = CreateFileA(file_name, GENERIC_READ, 0, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
    if (file == INVALID_HANDLE_VALUE) {
        u32 error_code = GetLastError();
        switch (error_code) {
            case 2:  return io_not_found;
            default: return io_error;
        }
    }

    i64 file_size;
    if (!GetFileSizeEx(file, &file_size)) {
        u32 error_code = GetLastError();
        switch (error_code) {
            default: return io_error;
        }
    }

    *contents = alloc(file_size);

    u32 read = 0;
    i32 success = ReadFile(file, *contents, file_size, &read, null);
    if (!success || read != file_size) {
        free(*contents);
        *contents = null;

        u32 error_code = GetLastError();
        switch (error_code) {
            default: return io_error;
        }
    }

    *length = file_size;

    CloseHandle(file);

    return io_ok;
}

IO_Result write_entire_file(u8* file_name, u8* contents, u32 length) {
    Handle file = CreateFileA(file_name, GENERIC_WRITE, 0, null, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, null);
    if (file == INVALID_HANDLE_VALUE) {
        u32 error_code = GetLastError();
        switch (error_code) {
            case 32: return io_already_open;
            default: return io_error;
        }
    }

    u32 written = 0;
    i32 success = WriteFile(file, contents, length, &written, null);
    if (!success || written != length) {
        u32 error_code = GetLastError();
        switch (error_code) {
            default: return io_error;
        }
    }

    CloseHandle(file);

    return io_ok;
}


typedef struct File_Pos {
    u32 line;
} File_Pos;

bool file_pos_is_after(File_Pos a, File_Pos b) {
    return a.line > b.line;
}

typedef struct Token {
    enum {
        token_end_of_stream = 0,

        token_bracket_round_open   = '(',
        token_bracket_round_close  = ')',
        token_bracket_square_open  = '[',
        token_bracket_square_close = ']',
        token_bracket_curly_open   = '{',
        token_bracket_curly_close  = '}',
        token_semicolon = ';',
        token_comma     = ',',
        token_colon     = ':',

        token_add = '+',
        token_sub = '-',
        token_mul = '*', // also used for pointers
        token_div = '/',
        token_mod = '%', // TODO

        token_and = '&',
        token_not = '!', // TODO
        token_or  = '|', // TODO
        token_xor = '^', // TODO

        token_greater = '>',
        token_less = '<',
        token_assign = '=',

        token_SEPARATOR = 128, // Values before this use literal ascii character codes, to simplify some parsing

        token_greater_or_equal, // ">="
        token_less_or_equal, // "<="
        token_equal, // "=="
        token_not_equal, // "!="
        token_arrow, // "->"

        token_shift_left, // "<<", TODO
        token_shift_right, // ">>", TODO

        token_add_assign, // "+="
        token_sub_assign, // "-="

        token_identifier,
        token_literal,
        token_string,

        token_keyword_fn,
        token_keyword_extern,
        token_keyword_let,
        token_keyword_if,
        token_keyword_else,
        token_keyword_for,
        token_keyword_null,
        token_keyword_true,
        token_keyword_false,

        TOKEN_KIND_COUNT,
    } kind;

    union {
        u32 identifier_string_table_index;

        u64 literal_value;

        struct {
            u8* bytes; // null-terminated
            u64 length;
        } string;

        i32 bracket_offset_to_matching;
    };

    File_Pos pos;
} Token;

u8* TOKEN_NAMES[TOKEN_KIND_COUNT] = {
    [token_identifier] = null,
    [token_literal] = null,
    [token_string] = null,

    [token_end_of_stream]        = "end of file",
    [token_add]                  = "+",
    [token_sub]                  = "-",
    [token_mul]                  = "*",
    [token_div]                  = "/",
    [token_mod]                  = "%",
    [token_and]                  = "&",
    [token_or]                   = "|",
    [token_not]                  = "!",
    [token_xor]                  = "^",
    [token_greater]              = ">",
    [token_greater_or_equal]     = ">=",
    [token_less]                 = "<",
    [token_less_or_equal]        = "<=",
    [token_equal]                = "==",
    [token_not_equal]            = "!=",
    [token_assign]               = "=",
    [token_arrow]                = "->",
    [token_shift_left]           = "<<",
    [token_shift_right]          = ">>",
    [token_add_assign]           = "+=",
    [token_sub_assign]           = "-=",

    [token_semicolon]            = "semicolon ';'",
    [token_comma]                = "comma ','",
    [token_colon]                = "colon ':'",

    [token_bracket_round_open]   = "opening parenthesis '('",
    [token_bracket_round_close]  = "closing parenthesis ')'",
    [token_bracket_square_open]  = "opening square bracket '['",
    [token_bracket_square_close] = "closing square bracket ']'",
    [token_bracket_curly_open]   = "opening curly brace '{'",
    [token_bracket_curly_close]  = "closing curly brace '}'",

    [token_keyword_fn]           = "fn",
    [token_keyword_extern]       = "extern",
    [token_keyword_let]          = "let",
    [token_keyword_if]           = "if",
    [token_keyword_else]         = "else",
    [token_keyword_for]          = "for",
    [token_keyword_true]         = "true",
    [token_keyword_false]        = "false",
    [token_keyword_null]         = "null",
};


typedef struct Expr Expr;


// When a var index has this bit set, it refers to a global rather than to a local
// We assume that there will never be more than (2^31 - 1) local variables
#define VAR_INDEX_GLOBAL_FLAG 0x80000000
#define MAX_LOCAL_VARS        0x7fffffff

typedef struct Var {
    u32 name;
    u32 type_index; // We set this to 0 to indicate that we want to infer the type
    File_Pos declaration_pos;
} Var;

typedef struct Global_Var {
    Var var;
    Expr* initial_expr;
    u32 data_offset;

    bool checked, valid;
} Global_Var;


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

    primitive_bool,

    PRIMITIVE_COUNT,
} Primitive;

Primitive DEFAULT_INTEGER_TYPE = primitive_i64;

void init_primitive_names(u32* names, u8** string_table) {
    names[primitive_unsolidified_int] = string_table_intern(string_table, "<int>", 5);

    names[primitive_void] = string_table_intern_cstr(string_table, "void");
    names[primitive_u8]   = string_table_intern_cstr(string_table, "u8");
    names[primitive_u16]  = string_table_intern_cstr(string_table, "u16");
    names[primitive_u32]  = string_table_intern_cstr(string_table, "u32");
    names[primitive_u64]  = string_table_intern_cstr(string_table, "u64");
    names[primitive_i8]   = string_table_intern_cstr(string_table, "i8");
    names[primitive_i16]  = string_table_intern_cstr(string_table, "i16");
    names[primitive_i32]  = string_table_intern_cstr(string_table, "i32");
    names[primitive_i64]  = string_table_intern_cstr(string_table, "i64");
    names[primitive_bool] = string_table_intern_cstr(string_table, "bool");
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

        case primitive_bool: return "bool";

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
        case primitive_bool: return 1;
        case primitive_void: return 0;
        case primitive_pointer: return POINTER_SIZE;
        case primitive_invalid: assert(false);
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
        case primitive_bool: return false;
        case primitive_void: return false;
        case primitive_pointer: return false;
        case primitive_invalid: assert(false);
        case primitive_unsolidified_int: return false;

        default: assert(false); return false;
    }
}

bool primitive_is_integer(Primitive primitive) {
    switch (primitive) {
        case primitive_void:
        case primitive_pointer:
        case primitive_array:
        case primitive_unsolidified_int:
        case primitive_bool:
        {
            return false;
        } break;

        case primitive_u8:
        case primitive_u16:
        case primitive_u32:
        case primitive_u64:
        case primitive_i8:
        case primitive_i16:
        case primitive_i32:
        case primitive_i64:
        {
            return true;
        } break;

        case primitive_invalid:
        default:
        {
            assert(false);
            return false;
        } break;
    }
}

bool primitive_is_signed(Primitive primitive) {
    switch (primitive) {
        case primitive_u8:
        case primitive_u16:
        case primitive_u32:
        case primitive_u64:
        case primitive_void:
        case primitive_pointer:
        case primitive_array:
        case primitive_unsolidified_int:
        case primitive_bool:
        {
            return false;
        } break;

        case primitive_i8:
        case primitive_i16:
        case primitive_i32:
        case primitive_i64:
        {
            return true;
        } break;

        case primitive_invalid:
        default:
        {
            assert(false);
            return false;
        } break;
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



typedef enum Unary_Op {
    unary_op_invalid = 0,

    unary_not,
    unary_neg,
    unary_dereference,
    unary_address_of,

    UNARY_OP_COUNT,
} Unary_Op;

u8* UNARY_OP_SYMBOL[UNARY_OP_COUNT] = {
    [unary_not]         = "!",
    [unary_neg]         = "-",
    [unary_dereference] = "*",
    [unary_address_of]  = "&",
};

typedef enum Binary_Op {
    binary_op_invalid = 0,

    binary_add,
    binary_sub,
    binary_mul,
    binary_div,
    binary_mod,

    binary_eq,
    binary_neq,
    binary_gt,
    binary_gteq,
    binary_lt,
    binary_lteq,

    BINARY_OP_COUNT,
} Binary_Op;

u8 BINARY_OP_PRECEDENCE[BINARY_OP_COUNT] = {
    [binary_mul] = 2,
    [binary_div] = 2,
    [binary_mod] = 2,

    [binary_add] = 1,
    [binary_sub] = 1,

    [binary_neq] = 0,
    [binary_eq] = 0,
    [binary_gt] = 0,
    [binary_gteq] = 0,
    [binary_lt] = 0,
    [binary_lteq] = 0,
};

bool BINARY_OP_STRICTLY_LEFT_ASSOCIATIVE[BINARY_OP_COUNT] = {
    [binary_sub] = true,
    [binary_div] = true,
    [binary_mod] = true,
    [binary_mul] = false,
    [binary_add] = false,
    [binary_neq] = false,
    [binary_eq] = false,
    [binary_gt] = false,
    [binary_gteq] = false,
    [binary_lt] = false,
    [binary_lteq] = false,
};

u8* BINARY_OP_SYMBOL[BINARY_OP_COUNT] = {
    [binary_add] = "+",
    [binary_sub] = "-",
    [binary_mul] = "*",
    [binary_div] = "/",
    [binary_mod] = "%",

    [binary_neq]  = "!=",
    [binary_eq]   = "==",
    [binary_gt]   = ">",
    [binary_gteq] = ">=",
    [binary_lt]   = "<",
    [binary_lteq] = "<=",
};


typedef struct Expr_List Expr_List;
struct Expr_List {
    Expr* expr;
    Expr_List* next;
};


#define EXPR_FLAG_UNRESOLVED 0x01
#define EXPR_FLAG_ASSIGNABLE 0x02

typedef enum Expr_Kind {
    expr_variable,
    expr_literal,
    expr_string_literal,
    expr_compound_literal,
    expr_binary,
    expr_unary,
    expr_call,
    expr_cast,
    expr_subscript,
} Expr_Kind;

struct Expr { // 'typedef'd earlier!
    Expr_Kind kind;
    u8 flags;

    union {
        union { u32 index; u32 unresolved_name; } variable; // discriminated by EXPR_FLAG_UNRESOLVED

        struct {
            u64 value;
            enum {
                expr_literal_integer,
                expr_literal_pointer,
                expr_literal_bool,
            } kind;
        } literal;

        struct {
            u8* bytes; // null-terminated
            u64 length;
        } string;

        struct {
            Expr_List* content; // *[*Expr]
            u32 count;
        } compound_literal;

        struct {
            Binary_Op op;
            Expr* left;
            Expr* right;
        } binary;

        struct {
            Unary_Op op;
            Expr* inner;
        } unary;

        struct {
            union {
                u32 unresolved_name;
                u32 func_index;
            }; // discriminated by EXPR_FLAG_UNRESOLVED

            Expr_List* params;
            u32 param_count;
        } call;

        Expr* cast_from;

        struct {
            Expr* array;
            Expr* index;
        } subscript;
    };

    u32 type_index;
    File_Pos pos;
};

typedef struct Stmt Stmt;
struct Stmt {
    enum {
        stmt_end, // Sentinel, returned to mark that no more statements can be parsed

        stmt_declaration,
        stmt_expr,
        stmt_assignment,

        stmt_block,
        stmt_if,
        stmt_loop,
    } kind;

    union {
        struct {
            u32 var_index;
            Expr* right; // 'right' might be null
        } declaration;

        Expr* expr;

        struct {
            Expr* left;
            Expr* right;
        } assignment;

        struct {
            Stmt* inner;
        } block;

        struct {
            Expr* condition;
            Stmt* then;
            Stmt* else_then;
        } conditional;

        struct {
            Expr* condition;
            Stmt* body;
        } loop;
    };

    File_Pos pos;

    Stmt* next;
};


// NB 'Local' probably is the wrong name now, 'Op_Param' would be more fitting
typedef struct Local {
    enum {
        local_temporary = 0,
        local_variable = 1,
        local_literal = 2,
        local_global = 3,
    } kind;
    bool as_reference;
    u64 value;
} Local;

bool local_cmp(Local* a, Local* b) {
    return a->kind == b->kind && a->as_reference == b->as_reference && a->value == b->value;
}


typedef enum Op_Kind {
    op_end_of_function = 0,

    op_call,
    op_cast,
    op_jump,
    op_load_data,

    // 'unary'
    op_neg,
    op_not,
    
    // 'binary'
    op_set,
    op_add,
    op_sub,
    op_mul,
    op_div,
    op_mod,
    op_address_of,
    op_neq,
    op_eq,
    op_gt,
    op_gteq,
    op_lt,
    op_lteq,

    OP_COUNT,
} Op_Kind;

u8* OP_NAMES[OP_COUNT] = {
    [op_end_of_function] = "end_of_function",
    [op_call] = "call",
    [op_cast] = "cast",
    [op_jump] = "jump",
    [op_load_data] = "load_data",
    [op_neg] = "neg",
    [op_not] = "not",
    [op_set] = "set",
    [op_add] = "add",
    [op_sub] = "sub",
    [op_mul] = "mul",
    [op_div] = "div",
    [op_mod] = "mod",
    [op_address_of] = "address_of",
    [op_neq] = "neq",
    [op_eq] = "eq",
    [op_gt] = "gt",
    [op_gteq] = "gteq",
    [op_lt] = "lt",
    [op_lteq] = "lteq",
};

typedef struct Op_Call_Param {
    Local local;
    u8 size;
} Op_Call_Param;

typedef struct Op {
    u8 kind;

    // We take this kind of primitive in, but might produce another primitive as a result. Also, some 'Op's
    // just ignore this.
    u8 primitive; 

    union {
        u32 temporary;

        Local unary;

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
            bool conditional;
            Local condition;
            u32 to_op;
        } jump;

        struct {
            Local other;
            Local offset;
            u32 var_index;
        } member;

        struct {
            Local local;
            u32 data_offset;
            bool writable; // selects seg_rodata or seg_rwdata
        } load_data;
    };

    u32 text_start;
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
        fixup_rwdata,
        fixup_rodata,
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

typedef struct Jump_Fixup {
    u32 from_op, to_op;
    u64 text_location; // 'i32' at this location
} Jump_Fixup;



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

            Tmp* tmps;
            u32 tmp_count;

            Mem_Layout mem_layout; // used for eval_ops
            Mem_Layout stack_layout; // for machinecode generations

            Stmt* first_stmt;

            Op* ops;
            u32 op_count;

            u32 text_start;
        } body;
    };
} Func;


typedef enum X64_Reg {
    reg_rax, reg_rcx, reg_rdx, reg_rbx,
    reg_rsp, reg_rbp, reg_rsi, reg_rdi,
    reg_r8,  reg_r9,  reg_r10, reg_r11,
    reg_r12, reg_r13, reg_r14, reg_r15,

    REG_COUNT,

    reg_invalid = U8_MAX,
} X64_Reg;

u8* reg_names[REG_COUNT] = {
    "rax", "rcx", "rdx", "rbx",
    "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11",
    "r12", "r13", "r14", "r15"
};

// These match the the 'cc' part in 'jmpcc', 'setcc' and 'movcc'
typedef enum X64_Condition {
    x64_condition_eq,
    x64_condition_neq,
    x64_condition_gt,
    x64_condition_gteq,
    x64_condition_lt,
    x64_condition_lteq,
} X64_Condition;

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
    Global_Var* global_vars;
    Var* tmp_vars; // stretchy-buffer
    Op* tmp_ops; // stretchy-buffer, linearized from of stmts
    Tmp* tmp_tmps; // stretchy-buffer, also built during op generation

    // NB the first 'PRIMITIVE_COUNT' elements are the respective primitives, which
    // simplifies refering directly to primitives: A type index of 'primitive_i64' points
    // to 'primitive_i64'
    u8* type_buf; // stretchy-buffer of chained 'Primitive's
    u32 string_type; // *u8

    // Low level representation
    u8* seg_text; // stretchy-buffer
    u8* seg_rwdata; // stretchy-buffer
    u8* seg_rodata; // stretchy-buffer
    Fixup* fixups; // stretchy-buffer

    Library_Import* imports; // stretchy-buffer
    Call_Fixup* call_fixups; // stretchy-buffer
    Jump_Fixup* jump_fixups; // stretchy-buffer
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

u64 add_exe_data(Context* context, u8* data, u64 length, bool writable) {
    u8** buffer;
    if (writable) {
        buffer = &context->seg_rwdata;
    } else {
        buffer = &context->seg_rodata;
    }

    u64 data_offset = buf_length(*buffer);

    if (data == null) {
        str_push_zeroes(buffer, length);
    } else {
        str_push_str(buffer, data, length);
    }

    return data_offset;
}

bool type_cmp(Context* context, u32 a, u32 b) {
    while (true) {
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
            // NB this is a bit of a hack to make *[N]Foo == *Foo
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

    while (true) {
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
    while (true) {
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
    while (true) {
        Primitive p = context->type_buf[i];
        i += 1;

        bool keep_going = false;

        switch (p) {
            case primitive_invalid:          printf("<invalid>"); break;
            case primitive_void:             printf("void"); break;
            case primitive_unsolidified_int: printf("<int>"); break;

            case primitive_pointer: {
                printf("*");
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
            case primitive_bool: printf("bool"); break;

            default: assert(false);
        }

        if (!keep_going) break;
    }
}

void print_token(u8* string_table, Token* t) {
    u8* s = null;

    switch (t->kind) {
        case token_identifier: {
            u32 index = t->identifier_string_table_index;
            s = string_table_access(string_table, index);
        } break;

        case token_literal: {
            printf("%u", t->literal_value);
        } break;
        case token_string: {
            printf("\"%z\"", t->string.length, t->string.bytes);
        } break;

        default: {
            printf(TOKEN_NAMES[t->kind]);
        } break;
    }
}

void print_expr(Context* context, Func* func, Expr* expr) {
    switch (expr->kind) {
        case expr_variable: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u8* name = string_table_access(context->string_table, expr->variable.unresolved_name);
                printf("<unresolved %s>", name);
            } else {
                Var* var;
                if (expr->variable.index & VAR_INDEX_GLOBAL_FLAG) {
                    u32 global_index = expr->variable.index & (~VAR_INDEX_GLOBAL_FLAG);
                    var = &context->global_vars[global_index].var;
                } else {
                    var = &func->body.vars[expr->variable.index];
                }

                u8* name = string_table_access(context->string_table, var->name);
                printf("%s", name);
            }
        } break;

        case expr_literal: {
            switch (expr->literal.kind) {
                case expr_literal_integer: {
                    printf("%u", expr->literal.value);
                } break;
                case expr_literal_pointer: {
                    if (expr->literal.value == 0) {
                        printf("null");
                    } else {
                        printf("%x", expr->literal.value);
                    }
                } break;
                case expr_literal_bool: {
                    assert(expr->literal.value == true || expr->literal.value == false);
                    printf(expr->literal.value? "true" : "false");
                } break;
                default: assert(false);
            }
        } break;

        case expr_compound_literal: {
            print_type(context, expr->type_index);
            printf(" { ");
            bool first = true;
            for (Expr_List* node = expr->compound_literal.content; node != null; node = node->next) {
                if (!first) printf(", ");
                first = false;
                print_expr(context, func, node->expr);
            }
            printf(" }");
        } break;

        case expr_string_literal: {
            printf("\"%z\"", expr->string.length, expr->string.bytes);
        } break;

        case expr_binary: {
            printf("(");
            print_expr(context, func, expr->binary.left);
            printf(" %s ", BINARY_OP_SYMBOL[expr->binary.op]);
            print_expr(context, func, expr->binary.right);
            printf(")");
        } break;

        case expr_unary: {
            printf(UNARY_OP_SYMBOL[expr->unary.op]);
            print_expr(context, func, expr->unary.inner);
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
            bool first = true;
            for (Expr_List* node = expr->call.params; node != null; node = node->next) {
                if (!first) printf(", ");
                first = false;
                print_expr(context, func, node->expr);
            }
            printf(")");
        } break;

        case expr_cast: {
            print_type(context, expr->type_index);
            printf("(");
            print_expr(context, func, expr->cast_from);
            printf(")");
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

void print_stmts(Context* context, Func* func, Stmt* stmt, u32 indent_level) {
    for (u32 i = 0; i < indent_level; i += 1) printf("    ");

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
            printf("var %s", name);

            if (stmt->declaration.right != null) {
                printf(" = ");
                print_expr(context, func, stmt->declaration.right);
            }

            printf(";");
        } break;

        case stmt_block: {
            printf("{\n");

            print_stmts(context, func, stmt->block.inner, indent_level + 1);

            for (u32 i = 0; i < indent_level; i += 1) printf("    ");
            printf("}");
        } break;

        case stmt_if: {
            printf("if (");
            print_expr(context, func, stmt->conditional.condition);
            printf(") {\n");

            print_stmts(context, func, stmt->conditional.then, indent_level + 1);

            for (u32 i = 0; i < indent_level; i += 1) printf("    ");
            printf("}");

            if (stmt->conditional.else_then != null) {
                printf(" else {\n");

                print_stmts(context, func, stmt->conditional.else_then, indent_level + 1);

                for (u32 i = 0; i < indent_level; i += 1) printf("    ");
                printf("}");
            }
        } break;

        case stmt_loop: {
            if (stmt->loop.condition != null) {
                printf("for (");
                print_expr(context, func, stmt->loop.condition);
                printf(") {\n");
            } else {
                printf("for {\n");
            }

            print_stmts(context, func, stmt->loop.body, indent_level + 1);

            for (u32 i = 0; i < indent_level; i += 1) printf("    ");
            printf("}");
        } break;

        case stmt_end: printf("<end>"); break;

        default: assert(false);
    }

    printf("\n");

    if (stmt->next != null && stmt->next->kind != stmt_end) {
        print_stmts(context, func, stmt->next, indent_level);
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

        case local_global: {
            Var* var = &context->global_vars[local.value].var;
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
        case op_neg: case op_not:
        {
            printf("(%s) %s ", primitive_name(op->primitive), OP_NAMES[op->kind]);
            print_local(context, func, op->unary);
        } break;

        case op_set: case op_add: case op_sub: case op_mul: case op_div: case op_mod:
        case op_neq: case op_eq: case op_gt: case op_gteq: case op_lt: case op_lteq:
        {
            printf("(%s) %s ", primitive_name(op->primitive), OP_NAMES[op->kind]);
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

        case op_jump: {
            printf("jump");
            if (op->jump.conditional) {
                printf("if ");
                print_local(context, func, op->jump.condition);
            }
            printf(" to %u", (u64) op->jump.to_op);
        } break;

        case op_load_data: {
            printf("address of ");
            print_local(context, func, op->load_data.local);
            printf(", %s + %u into ", op->load_data.writable? ".data" : ".rdata", (u64) op->load_data.data_offset);
        } break;

        default: assert(false);
    }
}


u32 find_var(Context* context, Func* func, u32 name) {
    if (func != null) {
        for (u32 i = 0; i < func->body.var_count; i += 1) {
            if (func->body.vars[i].name == name) {
                return i;
            }
        }
    }

    for (u32 i = 0; i < buf_length(context->global_vars); i += 1) {
        if (context->global_vars[i].var.name == name) {
            return i | VAR_INDEX_GLOBAL_FLAG;
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

Primitive parse_primitive_name(Context* context, u32 name_index) {
    for (u32 p = 0; p < PRIMITIVE_COUNT; p += 1) {
        if (context->primitive_names[p] == name_index) {
            return p;
        }
    }

    return primitive_invalid;
}

bool expect_single_token(Context* context, Token* t, int kind, u8* location) {
    if (t->kind != kind) {
        printf("Expected %s %s, but got ", TOKEN_NAMES[kind], location);
        print_token(context->string_table, t);
        printf(" (Line %u)\n", (u64) t->pos.line);
        return false;
    } else {
        return true;
    }
}

u32 parse_type(Context* context, Token* t, u32* length) {
    Token* t_start = t;

    u32 index = buf_length(context->type_buf);

    while (true) {
        if (t->kind == token_bracket_square_open) {
            t += 1;

            if (t->kind != token_literal) {
                printf("Expected array size, but got ");
                print_token(context->string_table, t);
                printf(" (Line %u)\n", t->pos.line);

                *length = t - t_start + 2;
                return U32_MAX;
            }
            u64 array_size = t->literal_value;
            t += 1;

            if (!expect_single_token(context, t, token_bracket_square_close, "after array size")) {
                *length = t - t_start + 1;
                return U32_MAX;
            }
            t += 1;

            buf_push(context->type_buf, primitive_array);
            for (u32 i = 0; i < sizeof(u64); i += 1) {
                buf_push(context->type_buf, (u8) (array_size & 0xff));
                array_size = array_size >> 8;
            }

        } else if (t->kind == token_mul) {
            buf_push(context->type_buf, primitive_pointer);
            t += 1;

        } else if (t->kind == token_identifier) {
            Primitive p = parse_primitive_name(context, t->identifier_string_table_index);

            if (p == primitive_invalid) {
                u8* name = string_table_access(context->string_table, t->identifier_string_table_index);
                printf("Not a valid type: %s (Line %u)\n", name, (u64) t->pos.line);

                *length = t - t_start + 1;
                return U32_MAX;
            }

            if (t == t_start) {
                *length = 1;
                return p;
            } else {
                buf_push(context->type_buf, p);
                *length = t - t_start + 1;
                return index;
            }

            t += 1;

        } else {
            printf("Unexpected token in type: ");
            print_token(context->string_table, t);
            printf(" (Line %u)\n", (u64) t->pos.line);

            t += 1;
            *length = t - t_start;
            return U32_MAX;
        }
    }
}

typedef struct Shunting_Yard {
    Expr** expr_queue;
    u32 expr_queue_index, expr_queue_size;

    Binary_Op* op_queue;
    u32 op_queue_index, op_queue_size;

    Expr* unary_prefix;
} Shunting_Yard;

Shunting_Yard* shunting_yard_setup(Context* context) {
    Shunting_Yard* yard = arena_new(&context->stack, Shunting_Yard);

    yard->op_queue_size = 25;
    yard->expr_queue_size = 25;

    yard->op_queue = (void*) arena_alloc(&context->stack, yard->op_queue_size * sizeof(*yard->op_queue));
    yard->expr_queue = (void*) arena_alloc(&context->stack, yard->expr_queue_size * sizeof(*yard->expr_queue));

    return yard;
}

void shunting_yard_push_unary_prefix(Shunting_Yard* yard, Expr* expr) {
    assert(expr->kind == expr_unary);

    if (yard->unary_prefix == null) {
        yard->unary_prefix = expr;
    } else {
        assert(yard->unary_prefix->kind == expr_unary);

        Expr* inner = yard->unary_prefix;
        while (inner->unary.inner != null) {
            inner = inner->unary.inner;
        }
        inner->unary.inner = expr;
    }
}

void shunting_yard_push_subscript(Context* context, Shunting_Yard* yard, Expr* index) {
    assert(yard->unary_prefix == null);
    assert(yard->expr_queue_index > 0);

    Expr** array = &yard->expr_queue[yard->expr_queue_index - 1];

    while (true) {
        bool done = false;
        if ((*array)->kind == expr_unary) {
            array = &((*array)->unary.inner);
        } else {
            done = true;
        }
        if (done) break;
    }

    Expr* expr = arena_new(&context->arena, Expr);
    expr->kind = expr_subscript;
    expr->subscript.array = *array;
    expr->subscript.index = index;
    expr->pos = expr->subscript.array->pos;

    *array = expr;
}

void shunting_yard_push_expr(Context* context, Shunting_Yard* yard, Expr* new_expr) {
    if (yard->unary_prefix != null) {
        Expr* inner = yard->unary_prefix;
        while (inner->unary.inner != null) {
            inner = inner->unary.inner;
        }
        inner->unary.inner = new_expr;

        new_expr = yard->unary_prefix;
        yard->unary_prefix = null;
    }

    assert(yard->expr_queue_index < yard->expr_queue_size);
    yard->expr_queue[yard->expr_queue_index] = new_expr;
    yard->expr_queue_index += 1;
}

void shunting_yard_collapse(Context* context, Shunting_Yard* yard) {
    assert(yard->op_queue_index >= 1);
    assert(yard->expr_queue_index >= 2);

    Expr* expr = arena_new(&context->arena, Expr);
    expr->kind = expr_binary;

    expr->binary.op = yard->op_queue[yard->op_queue_index - 1];
    expr->binary.right = yard->expr_queue[yard->expr_queue_index - 1];
    expr->binary.left = yard->expr_queue[yard->expr_queue_index - 2];
    yard->op_queue_index -= 1;
    yard->expr_queue_index -= 2;

    expr->pos = expr->binary.left->pos;

    shunting_yard_push_expr(context, yard, expr);
}

void shunting_yard_push_op(Context* context, Shunting_Yard* yard, Binary_Op new_op) {
    u8 new_precedence = BINARY_OP_PRECEDENCE[new_op];

    while (yard->op_queue_index > 0) {
        Binary_Op head_op = yard->op_queue[yard->op_queue_index - 1];
        bool force_left = BINARY_OP_STRICTLY_LEFT_ASSOCIATIVE[head_op];
        u8 old_precedence = BINARY_OP_PRECEDENCE[head_op];

        if (old_precedence > new_precedence || (force_left && old_precedence == new_precedence)) {
            shunting_yard_collapse(context, yard);
        } else {
            break;
        }
    }

    assert(yard->op_queue_index < yard->op_queue_size);
    yard->op_queue[yard->op_queue_index] = new_op;
    yard->op_queue_index += 1;
}

Expr* parse_compound_literal(Context* context, Token* t, u32* length);

Expr* parse_expr(Context* context, Token* t, u32* length) {
    Token* t_start = t;

    // NB: We only pop the stack if we succesfully parse. That is, for eroneous code we leak memory.
    // As we should terminate at some point in that case though, it doesn't really matter.
    arena_stack_push(&context->stack);

    bool expect_value = true;

    Shunting_Yard* yard = shunting_yard_setup(context);
    
    while (true) {
        bool could_parse = false;
        bool reached_end = false;

        if (expect_value) {
            switch (t->kind) {
                // Variable, function call, structure literal
                case token_identifier: {
                    u32 name_index = t->identifier_string_table_index;
                    expect_value = false;
                    t += 1;

                    // Function call or cast
                    if (t->kind == token_bracket_round_open) {
                        File_Pos start_pos = t->pos;
                        t += 1;

                        Expr_List* param_list = null;
                        Expr_List* param_list_head = null;
                        u32 param_count = 0;

                        while (t->kind != token_bracket_round_close) {
                            u32 param_length = 0;
                            Expr* param = parse_expr(context, t, &param_length);
                            t += param_length;

                            if (param == null) {
                                *length = t - t_start;
                                return null;
                            }

                            if (t->kind != token_bracket_round_close) {
                                if (t->kind != token_comma) {
                                    printf("Expected comma ',' or closing parenthesis ')' after parameter in call, but got ");
                                    print_token(context->string_table, t);
                                    printf(" (Line %u)\n", (u64) t->pos.line);
                                    *length = t - t_start;
                                    return null;
                                }
                                t += 1;
                            }

                            Expr_List* list_item = arena_new(&context->arena, Expr_List);
                            list_item->expr = param;

                            if (param_list_head == null) {
                                param_list_head = list_item;
                            } else {
                                param_list->next = list_item;
                            }
                            param_list = list_item;

                            param_count += 1;
                        }

                        if (!expect_single_token(context, t, token_bracket_round_close, "after function call")) {
                            *length = t - t_start;
                            return null;
                        }
                        t += 1;


                        Primitive cast_to_primitive = primitive_invalid;
                        for (u32 i = 0; i < PRIMITIVE_COUNT; i += 1) {
                            if (name_index == context->primitive_names[i]) {
                                cast_to_primitive = i;
                                break;
                            }
                        }

                        if (cast_to_primitive != primitive_invalid) {
                            if (param_count != 1) {
                                printf(
                                    "Expected 1 parameter for cast to %s, but got %u (Line %u)\n",
                                    primitive_name(cast_to_primitive), (u64) param_count, (u64) start_pos.line
                                );
                                *length = t - t_start;
                                return null;
                            }

                            if (!(cast_to_primitive >= primitive_u8 && cast_to_primitive <= primitive_i64)) {
                                printf("Can't cast to %s (Line %u)\n", primitive_name(cast_to_primitive), (u64) start_pos.line);
                                *length = t - t_start;
                                return null;
                            }

                            Expr* expr = arena_new(&context->arena, Expr);
                            expr->pos = start_pos;
                            expr->kind = expr_cast;
                            expr->cast_from = param_list_head->expr;
                            expr->type_index = cast_to_primitive;

                            shunting_yard_push_expr(context, yard, expr);
                            could_parse = true;
                        } else {
                            Expr* expr = arena_new(&context->arena, Expr);
                            expr->pos = start_pos;
                            expr->kind = expr_call;
                            expr->call.unresolved_name = name_index;
                            expr->flags |= EXPR_FLAG_UNRESOLVED;
                            expr->call.params = param_list_head;
                            expr->call.param_count = param_count;

                            shunting_yard_push_expr(context, yard, expr);
                            could_parse = true;
                        }
                    
                    // Structure literal
                    } else if (t->kind == token_bracket_curly_open) {
                        unimplemented(); // TODO

                    // Variable
                    } else {
                        Expr* expr = arena_new(&context->arena, Expr);
                        expr->kind = expr_variable;
                        expr->variable.unresolved_name = name_index;
                        expr->flags |= EXPR_FLAG_UNRESOLVED;
                        expr->pos = t->pos;

                        shunting_yard_push_expr(context, yard, expr);
                        could_parse = true;
                    }
                } break;

                case token_literal:
                case token_keyword_null:
                case token_keyword_true:
                case token_keyword_false:
                {
                    Expr* expr = arena_new(&context->arena, Expr);
                    expr->kind = expr_literal;
                    expr->literal.value = 0;
                    expr->literal.kind = expr_literal_pointer;
                    expr->pos = t->pos;

                    switch (t->kind) {
                        case token_literal: {
                            expr->literal.value = t->literal_value;
                            expr->literal.kind = expr_literal_integer;
                        } break;
                        case token_keyword_null: {
                            expr->literal.value = 0;
                            expr->literal.kind = expr_literal_pointer;
                        } break;
                        case token_keyword_false: {
                            expr->literal.value = 0;
                            expr->literal.kind = expr_literal_bool;
                        } break;
                        case token_keyword_true: {
                            expr->literal.value = 1;
                            expr->literal.kind = expr_literal_bool;
                        } break;
                        default: assert(false);
                    }

                    shunting_yard_push_expr(context, yard, expr);

                    t += 1;
                    could_parse = true;
                    expect_value = false;
                } break;

                case token_string: {
                    Expr* expr = arena_new(&context->arena, Expr);
                    expr->type_index = context->string_type;
                    expr->kind = expr_string_literal;
                    expr->string.bytes = t->string.bytes;
                    expr->string.length = t->string.length;
                    expr->pos = t->pos;

                    shunting_yard_push_expr(context, yard, expr);

                    t += 1;
                    could_parse = true;
                    expect_value = false;
                } break;

                // Parenthesized expression
                case token_bracket_round_open: {
                    t += 1;
                    u32 inner_length = 0;
                    Expr* inner = parse_expr(context, t, &inner_length);
                    t += inner_length;

                    if (inner == null) {
                        *length = t - t_start;
                        return null;
                    }

                    if (!expect_single_token(context, t, token_bracket_round_close, "after parenthesized subexpression")) {
                        *length = t - t_start;
                        return null;
                    }
                    t += 1;

                    shunting_yard_push_expr(context, yard, inner);

                    expect_value = false;
                    could_parse = true;
                } break;

                // Array compound literal, or untyped compound literals
                case token_bracket_curly_open:
                case token_bracket_square_open:
                {
                    u32 type_index = 0;
                    if (t->kind == token_bracket_square_open) {
                        u32 type_length = 0;
                        type_index = parse_type(context, t, &type_length);
                        t += type_length;

                        if (type_index == U32_MAX) {
                            *length = t - t_start;
                            return null;
                        }
                    }

                    u32 compound_literal_length = 0;
                    Expr* expr = parse_compound_literal(context, t, &compound_literal_length);
                    t += compound_literal_length;

                    if (expr == null) {
                        *length = t - t_start;
                        return null;
                    }

                    expr->type_index = type_index;

                    shunting_yard_push_expr(context, yard, expr);

                    could_parse = true;
                    expect_value = false;
                } break;

                default: {
                    Unary_Op op = unary_op_invalid;
                    switch (t->kind) {
                        case token_and: op = unary_address_of; break;
                        case token_mul: op = unary_dereference; break;
                        case token_not: op = unary_not; break;
                        case token_sub: op = unary_neg; break;
                    }

                    if (op != unary_op_invalid) {
                        Expr* expr = arena_new(&context->arena, Expr);
                        expr->kind = expr_unary;
                        expr->unary.op = op;
                        expr->pos = t->pos;

                        shunting_yard_push_unary_prefix(yard, expr);

                        could_parse = true;
                        expect_value = true;
                    }

                    t += 1;
                } break;
            }
        } else {
            switch (t->kind) {
                case token_bracket_square_open: {
                    t += 1;

                    u32 index_length = 0;
                    Expr* index = parse_expr(context, t, &index_length);
                    t += index_length;

                    if (index == null) {
                        *length = t - t_start;
                        return null;
                    }

                    if (!expect_single_token(context, t, token_bracket_square_close, "after subscript index")) {
                        *length = t - t_start;
                        return null;
                    }
                    t += 1;

                    shunting_yard_push_subscript(context, yard, index);

                    expect_value = false;
                    could_parse = true;
                } break;

                // End of expression
                case token_semicolon:
                case token_comma:
                case ')': case ']': case '}':
                case token_assign:
                case token_keyword_let:
                case token_keyword_fn:
                case token_add_assign:
                case token_sub_assign:
                {
                    reached_end = true;
                } break;

                default: {
                    Binary_Op op = binary_op_invalid;
                    switch (t->kind) {
                        case token_add:                op = binary_add; break;
                        case token_sub:                op = binary_sub; break;
                        case token_mul:                op = binary_mul; break;
                        case token_div:                op = binary_div; break;
                        case token_mod:                op = binary_mod; break;
                        case token_greater:            op = binary_gt; break;
                        case token_greater_or_equal:   op = binary_gteq; break;
                        case token_less:               op = binary_lt; break;
                        case token_less_or_equal:      op = binary_lteq; break;
                        case token_equal:              op = binary_eq; break;
                        case token_not_equal:          op = binary_neq; break;

                        case token_and:
                        case token_or:
                        case token_xor:
                        case token_shift_left:
                        case token_shift_right:
                        {
                            unimplemented(); // TODO bitwise operators
                        } break;
                    }

                    if (op != binary_op_invalid) {
                        shunting_yard_push_op(context, yard, op);
                        could_parse = true;
                        expect_value = true;
                    }

                    t += 1;
                } break;
            }
        }

        if (reached_end) break;

        if (!could_parse) {
            printf("Expected ");
            if (expect_value) {
                printf("a value or a unary operator");
            } else {
                printf("a binary operator or a postfix operator (array subscript or member access)");
            }
            printf(" but got ");
            print_token(context->string_table, t);
            printf(" (Line %u)\n", (u64) t->pos.line);
            *length = t - t_start;
            return null;
        }
    }

    while (yard->op_queue_index > 0) {
        shunting_yard_collapse(context, yard);
    }
    assert(yard->expr_queue_index == 1);
    Expr* expr = yard->expr_queue[0];

    arena_stack_pop(&context->stack);

    *length = t - t_start;
    return expr;
}

Expr* parse_compound_literal(Context* context, Token* t, u32* length) {
    Token* t_start = t;

    if (!expect_single_token(context, t, token_bracket_curly_open, "after type of compound literal")) {
        *length = t - t_start;
        return null;
    }
    t += 1;

    Expr_List* expr_list = null;
    Expr_List* expr_list_head = null;
    u32 expr_count = 0;

    while (t->kind != token_bracket_curly_close) {
        u32 sub_expr_length = 0;
        Expr* sub_expr = parse_expr(context, t, &sub_expr_length);
        t += sub_expr_length;

        if (sub_expr == null) {
            *length = t - t_start;
            return null;
        }

        if (t->kind != token_bracket_curly_close) {
            if (t->kind != token_comma) {
                printf("Expected comma ',' or closing curly brace '}' after value in compound literal, but got ");
                print_token(context->string_table, t);
                printf(" (Line %u)\n", (u64) t->pos.line);
                *length = t - t_start;
                return null;
            }
            t += 1;
        }

        Expr_List* list_item = arena_new(&context->arena, Expr_List);
        list_item->expr = sub_expr;

        if (expr_list_head == null) {
            expr_list_head = list_item;
        } else {
            expr_list->next = list_item;
        }
        expr_list = list_item;

        expr_count += 1;
    }
    
    if (!expect_single_token(context, t, token_bracket_curly_close, "to close compound literal")) {
        *length = t - t_start;
        return null;
    }
    t += 1;

    Expr* expr = arena_new(&context->arena, Expr);
    expr->kind = expr_compound_literal;
    expr->compound_literal.content = expr_list_head;
    expr->compound_literal.count = expr_count;
    expr->pos = t_start->pos;

    *length = t - t_start;
    return expr;
}

Stmt* parse_stmts(Context* context, Token* t, u32* length);

Stmt* parse_basic_block(Context* context, Token* t, u32* length) {
    if (!expect_single_token(context, t, '{', "before block")) return null;
    t += 1;

    u32 inner_length = 0;
    Stmt* stmts = parse_stmts(context, t, &inner_length);
    t += inner_length;
    *length = inner_length + 1;

    if (stmts == null) return null;

    if (!expect_single_token(context, t, '}', "after block")) return null;
    t += 1;

    *length = inner_length + 2;
    return stmts;
}

Stmt* parse_stmts(Context* context, Token* t, u32* length) {
    Token* t_start = t;
    
    // Semicolons are just empty statements, skip them
    while (t->kind == token_semicolon) t += 1;

    Stmt* stmt = arena_new(&context->arena, Stmt);
    stmt->pos = t->pos;

    // End of a block
    if (t->kind == token_bracket_curly_close) {
        stmt->kind = stmt_end;

    // Basic blocks
    } else if (t->kind == token_bracket_curly_open) {
        u32 block_length = 0;
        Stmt* inner = parse_basic_block(context, t, &block_length);
        t += block_length;
        if (inner == null) return null;

        stmt->kind = stmt_block;
        stmt->block.inner = inner;

    // Control flow - if
    } else if (t->kind == token_keyword_if) {
        Stmt* if_stmt = stmt;

        while (true) {
            if_stmt->kind = stmt_if;

            t += 1;

            if (!expect_single_token(context, t, '(', "before condition")) return null;
            t += 1;

            u32 condition_length = 0;
            if_stmt->conditional.condition = parse_expr(context, t, &condition_length);
            t += condition_length;
            if (if_stmt->conditional.condition == null) return null;

            if (!expect_single_token(context, t, ')', "after condition")) return null;
            t += 1;

            u32 block_length = 0;
            if_stmt->conditional.then = parse_basic_block(context, t, &block_length);
            t += block_length;
            if (if_stmt->conditional.then == null) return null;

            bool parse_another_if = false;
            if (t->kind == token_keyword_else) {
                t += 1;

                switch (t->kind) {
                    case token_bracket_curly_open: {
                        u32 block_length = 0;
                        if_stmt->conditional.else_then = parse_basic_block(context, t, &block_length);
                        t += block_length;
                        if (if_stmt->conditional.else_then == null) return null;
                    } break;

                    case token_keyword_if: {
                        parse_another_if = true;

                        Stmt* next_if_stmt = arena_new(&context->arena, Stmt);
                        next_if_stmt->next = arena_new(&context->arena, Stmt); // Sentinel

                        if_stmt->conditional.else_then = next_if_stmt;
                        if_stmt = next_if_stmt;
                    } break;

                    default: {
                        printf("Expected another if-statmenet or a basic block after else, but got ");
                        print_token(context->string_table, t);
                        printf(" (Line %u)\n", t->pos.line);
                        return null;
                    } break;
                }
            }

            if(!parse_another_if) break;
        }

    // Control flow - for
    } else if (t->kind == token_keyword_for) {
        t += 1;

        switch (t->kind) {
            // Infinite loop
            case '{': {
                u32 body_length = 0;
                Stmt* body = parse_basic_block(context, t, &body_length);
                t += body_length;
                if (body == null) return null;

                stmt->kind = stmt_loop;
                stmt->loop.condition = null;
                stmt->loop.body = body;
            } break;

            case '(': {
                t += 1;

                u32 first_length = 0;
                Expr* first = parse_expr(context, t, &first_length);
                t += first_length;
                if (first == null) return null;
                
                // TODO for-each and c-style loops

                if (!expect_single_token(context, t, ')', "after loop condition")) return null;
                t += 1;

                u32 body_length = 0;
                Stmt* body = parse_basic_block(context, t, &body_length);
                t += body_length;
                if (body == null) return null;

                stmt->kind = stmt_loop;
                stmt->loop.condition = first;
                stmt->loop.body = body;
            } break;

            default: {
                printf("Expected opening parenthesis '(' or curly brace '{' after for, but got ");
                print_token(context->string_table, t);
                printf(" (Line %u)\n", t->pos.line);
                return null;
            } break;
        }

    // Variable declaration
    } else if (t->kind == token_keyword_let) {
        t += 1;

        if (t->kind != token_identifier) {
            printf("Expected variable name, but found ");
            print_token(context->string_table, t);
            printf(" (Line %u)\n", t->pos.line);
            return null;
        }
        u32 name_index = t->identifier_string_table_index;
        t += 1;

        u32 type_index = 0;
        if (t->kind == token_colon) {
            t += 1;

            u32 type_length = 0;
            type_index = parse_type(context, t, &type_length);
            if (type_index == U32_MAX) return null;
            t += type_length;
        }

        Expr* expr = null;
        if (t->kind == token_assign) {
            t += 1;

            u32 right_length = 0;
            expr = parse_expr(context, t, &right_length); 
            if (expr == null) return null;
            t += right_length;
        }

        if (expr == null && type_index == null) {
            u8* name = string_table_access(context->string_table, name_index);
            printf("Declared variable '%s' without specifying type or initial value. Hence can't infer type (Line %u)\n", name, t->pos.line);
            return null;
        }

        u32 var_index = buf_length(context->tmp_vars);
        buf_push(context->tmp_vars, ((Var) {
            .name = name_index,
            .declaration_pos = stmt->pos,
            .type_index = type_index,
        }));

        assert(buf_length(context->tmp_vars) < MAX_LOCAL_VARS);

        stmt->kind = stmt_declaration;
        stmt->declaration.var_index = var_index;
        stmt->declaration.right = expr;

        if (!expect_single_token(context, t, token_semicolon, "after variable declaration")) return null;
        t += 1;

    // Assignment or free standing expression
    } else {
        u32 left_length = 0;
        Expr* left = parse_expr(context, t, &left_length);
        t += left_length;

        if (left == null) return null;

        switch (t->kind) {
            case token_assign: {
                t += 1;

                u32 right_length = 0;
                Expr* right = parse_expr(context, t, &right_length);
                t += right_length;

                if (right == null) return null;

                stmt->kind = stmt_assignment;
                stmt->assignment.left = left;
                stmt->assignment.right = right;
            } break;

            case token_add_assign:
            case token_sub_assign:
            {
                Binary_Op op;
                switch (t->kind) {
                    case token_add_assign: op = binary_add; break;
                    case token_sub_assign: op = binary_sub; break;
                    default: assert(false);
                }

                t += 1;

                u32 right_length = 0;
                Expr* right = parse_expr(context, t, &right_length);
                t += right_length;

                if (right == null) return null;

                Expr* binary = arena_new(&context->arena, Expr);
                binary->kind = expr_binary;
                binary->pos = left->pos;
                binary->binary.left = left;
                binary->binary.right = right;
                binary->binary.op = op;

                stmt->kind = stmt_assignment;
                stmt->assignment.left = left;
                stmt->assignment.right = binary;
            } break;

            default: {
                stmt->kind = stmt_expr;
                stmt->expr = left;
            } break;
        }

        if (!expect_single_token(context, t, token_semicolon, "after statement")) return null;
        t += 1;
    }

    // Try parsing more statements after this one
    if (stmt->kind != stmt_end) {
        u32 next_length = 0;
        Stmt* next_stmt = parse_stmts(context, t, &next_length);
        t += next_length;

        if (next_stmt == null) {
            return null; // Propagate errors
        } else {
            stmt->next = next_stmt;
        }
    }

    *length = t - t_start;
    return stmt;
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
        if (t[i].kind == token_bracket_round_open || t[i].kind == token_bracket_square_open || t[i].kind == token_bracket_curly_open) {
            i += t[i].bracket_offset_to_matching;
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

        u32 type_length = 0;
        u32 type_index = parse_type(context, &t[start + 2], &type_length);
        if (type_index == U32_MAX) {
            return false;
        }

        if (type_length != length - 2) {
            printf("Invalid token after type in parameter delcaration list: ");
            print_token(context->string_table, &t[start + 2 + type_length]);
            printf(" (Line %u)\n", (u64) t[start + 2 + type_length].pos.line);
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

    buf_push(context->funcs, ((Func) {0}));
    Func* func = buf_end(context->funcs) - 1;
    func->name = name_index;

    // Parameter list
    t += 1;
    if (t->kind != token_bracket_round_open) {
        u8* name = string_table_access(context->string_table, name_index);
        printf("Expected a open parenthesis '(' to after 'fn %s', but got ", name);
        print_token(context->string_table, t);
        printf(" (Line %u)\n", (u64) t->pos.line);
        return null;
    }

    u32 parameter_length = t->bracket_offset_to_matching - 1;
    if (!parse_parameter_declaration_list(context, func, t + 1, parameter_length)) return null;
    t += parameter_length + 2;

    // Return type
    if (t->kind == token_arrow) {
        t += 1;

        u32 output_type_length = 0;
        u32 output_type_index = parse_type(context, t, &output_type_length);
        t += output_type_length;

        if (output_type_index == U32_MAX) {
            return null;
        } else {
            func->signature.has_output = true;
            func->signature.output_type_index = output_type_index;
            func->body.output_var_index = buf_length(context->tmp_vars);

            Var output_var = {0};
            output_var.name = string_table_intern(&context->string_table, "output", 6);
            output_var.type_index = output_type_index;
            buf_push(context->tmp_vars, output_var);
        }
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

        if (t->kind != token_bracket_curly_open) {
            u8* name = string_table_access(context->string_table, name_index);
            printf("Expected an open curly brace { after 'fn %s ...', but found ", name);
            print_token(context->string_table, t);
            printf(" (Line %u)\n", (u64) t->pos.line);
            return null;
        }

        Token* body = t + 1;
        u32 body_length = t->bracket_offset_to_matching - 1;
        t = t + t->bracket_offset_to_matching;

        *length = (u32) (t - start) + 1;


        u32 stmts_length = 0;
        Stmt* first_stmt = parse_stmts(context, body, &stmts_length);

        if (first_stmt == null || stmts_length != body_length) {
            valid = false;
        }

        func->body.first_stmt = first_stmt;
    }

    // Copy data out of temporary buffers into permanent arena storage
    func->body.var_count = buf_length(context->tmp_vars);
    func->body.vars = (Var*) arena_alloc(&context->arena, buf_bytes(context->tmp_vars));
    mem_copy((u8*) context->tmp_vars, (u8*) func->body.vars, buf_bytes(context->tmp_vars));

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
    u32 library_name_index = string_table_intern(&context->string_table, t->string.bytes, t->string.length);

    // Body
    t += 1;
    if (t->kind != token_bracket_curly_open) {
        printf("Expected an open curly brace { after 'extern \"%s\" ...', but found ", library_name);
        print_token(context->string_table, t);
        printf(" (Line %u)\n", (u64) t->pos.line);
        return false;
    }

    Token* body = t + 1;
    u32 body_length = t->bracket_offset_to_matching - 1;
    t = t + t->bracket_offset_to_matching;

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

    IO_Result read_result = read_entire_file(path, &file, &file_length);
    if (read_result != io_ok) {
        printf("Couldn't load \"%s\": %s\n", path, io_result_message(read_result));
        return false;
    }

    bool valid = true;

    enum { KEYWORD_COUNT = 9 };
    u32 keyword_token_table[KEYWORD_COUNT][2] = {
        { token_keyword_fn,     string_table_intern_cstr(&context->string_table, "fn") },
        { token_keyword_extern, string_table_intern_cstr(&context->string_table, "extern") },
        { token_keyword_let,    string_table_intern_cstr(&context->string_table, "let") },
        { token_keyword_if,     string_table_intern_cstr(&context->string_table, "if") },
        { token_keyword_else,   string_table_intern_cstr(&context->string_table, "else") },
        { token_keyword_for,    string_table_intern_cstr(&context->string_table, "for") },
        { token_keyword_null,   string_table_intern_cstr(&context->string_table, "null") },
        { token_keyword_true,   string_table_intern_cstr(&context->string_table, "true") },
        { token_keyword_false,  string_table_intern_cstr(&context->string_table, "false") },
    };

    init_primitive_names(context->primitive_names, &context->string_table);

    for (u32 t = 0; t < PRIMITIVE_COUNT; t += 1) {
        // Now we can use primitive_* as a type index directly
        buf_push(context->type_buf, t);
    }

    context->string_type = buf_length(context->type_buf);
    buf_push(context->type_buf, primitive_pointer);
    buf_push(context->type_buf, primitive_u8);

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

            u32 string_table_index = string_table_intern(&context->string_table, identifier, length);


            bool is_keyword = false;
            for (u32 k = 0; k < KEYWORD_COUNT; k += 1) {
                if (string_table_index == keyword_token_table[k][1]) {
                    buf_push(tokens, ((Token) { keyword_token_table[k][0], .pos = file_pos }));
                    is_keyword = true;
                    break;
                }
            }

            if (!is_keyword) {
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

        case '+': case '-': case '*': case '/': case '%':
        case '=': case '<': case '>':
        case '&': case '!': case '|': case '^':
        {
            u8 a = file[i];
            u8 b = i + 1 < file_length? file[i + 1] : 0;

            int kind = -1;
            switch (a) {
                case '+': {
                    if (b == '=') {
                        kind = token_add_assign;
                        i += 2;
                    } else {
                        kind = token_add;
                        i += 1;
                    }
                } break;

                case '-': {
                    if (b == '>') {
                        kind = token_arrow;
                        i += 2;
                    } else if (b == '=') {
                        kind = token_sub_assign;
                        i += 2;
                    } else {
                        kind = token_sub;
                        i += 1;
                    }
                } break;

                case '*': {
                    kind = token_mul;
                    i += 1;
                } break;

                case '/': {
                    // Comments!
                    if (b == '/') {
                        for (; i < file_length; i += 1) if (file[i] == '\n' || file[i] == '\r') break;
                    } else if (b == '*') {
                        i += 2;
                        u32 comment_level = 1;

                        while (i < file_length) {
                            switch (file[i]) {
                                case '\n': case '\r': {
                                    i += 1;
                                    if (i < file_length && file[i] + file[i - 1] == '\n' + '\r') {
                                        i += 1;
                                    }

                                    file_pos.line += 1;
                                } break;

                                case '/': {
                                    i += 1;
                                    if (file[i] == '*') {
                                        comment_level += 1;
                                    }
                                    i += 1;
                                } break;

                                case '*': {
                                    i += 1;
                                    if (file[i] == '/') {
                                        comment_level -= 1;
                                    }
                                    i += 1;
                                } break;

                                default: {
                                    i += 1;
                                } break;
                            }

                            if (comment_level == 0) {
                                break;
                            }
                        }

                    } else {
                        kind = token_div;
                        i += 1;
                    }
                } break;

                case '%': {
                    kind = token_mod;
                    i += 1;
                } break;

                case '&': {
                    kind = token_and;
                    i += 1;
                } break;

                case '>': {
                    switch (b) {
                        case '=': {
                            kind = token_greater_or_equal;
                            i += 2;
                        } break;
                        case '>': {
                            kind = token_shift_right;
                            i += 2;
                        } break;
                        default: {
                            kind = token_greater;
                            i += 1;
                        } break;
                    }
                } break;

                case '<': {
                    switch (b) {
                        case '=': {
                            kind = token_less_or_equal;
                            i += 2;
                        } break;
                        case '<': {
                            kind = token_shift_left;
                            i += 2;
                        } break;
                        default: {
                            kind = token_less;
                            i += 1;
                        } break;
                    }
                } break;

                case '=': {
                    if (b == '=') {
                        kind = token_equal;
                        i += 2;
                    } else {
                        kind = token_assign;
                        i += 1;
                    }
                } break;

                case '!': {
                    if (b == '=') {
                        kind = token_not_equal;
                        i += 2;
                    } else {
                        kind = token_not;
                        i += 1;
                    }
                } break;

                case '|': {
                    kind = token_or;
                } break;

                case '^': {
                    kind = token_xor;
                } break;
            }

            if (kind != -1) {
                buf_push(tokens, ((Token) { kind, .pos = file_pos }));
            }
        } break;

        case '{': case '}':
        case '(': case ')':
        case '[': case ']':
        {
            u8 our_char = file[i];

            u8 kind = our_char;

            u8 matching_kind;
            bool open;
            switch (kind) {
                case '{': matching_kind = '}'; open = true;  break;
                case '}': matching_kind = '{'; open = false; break;
                case '(': matching_kind = ')'; open = true;  break;
                case ')': matching_kind = '('; open = false; break;
                case '[': matching_kind = ']'; open = true;  break;
                case ']': matching_kind = '['; open = false; break;
            }
            i += 1;

            i32 offset;

            if (all_brackets_matched) {
                if (open) {
                    Bracket_Info* info = arena_insert(&context->stack, ((Bracket_Info) {0}));
                    info->our_char = our_char;
                    info->our_line = file_pos.line;
                    info->needed_match = matching_kind;
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
                        offset = -((i32) unsigned_offset);
                        tokens[open_position].bracket_offset_to_matching = -offset;
                        bracket_match = bracket_match->previous;
                    }
                }
            }

            buf_push(tokens, ((Token) {
                kind,
                .bracket_offset_to_matching = offset,
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
                    printf("Strings can't span multiple lines (Line %u)\n", (u64) file_pos.line);
                    break;
                }

                if (file[i] == '"') {
                    break;
                }
            }

            u32 length = i - start_index;
            i += 1;

            u8* arena_pointer = null;
            arena_pointer = arena_alloc(&context->arena, length + 1);
            
            u32 collapsed_length = length;
            u32 j = 0, i = 0;
            while (i < length) {
                if (start[i] == '\\') {
                    collapsed_length -= 1;

                    u8 c = U8_MAX;
                    switch (start[i + 1]) {
                        case 'n': c = 0x0a; break;
                        case 'r': c = 0x0d; break;
                        case 't': c = 0x09; break;
                        case '0': c = 0x00; break;
                    }

                    if (c == U8_MAX) {
                        printf("Invalid escape sequence: '\\%c' (Line %u)\n", start[i + 1], (u64) file_pos.line);
                        valid = false;
                        break;
                    }

                    arena_pointer[j] = c;
                    j += 1;
                    i += 2;
                } else {
                    arena_pointer[j] = start[i];
                    i += 1;
                    j += 1;
                }
            }

            if (valid) {
                arena_pointer[collapsed_length] = 0;

                buf_push(tokens, ((Token) {
                    token_string,
                    .string.bytes = arena_pointer,
                    .string.length = collapsed_length,
                }));
            }
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
                    "Function %s doesn't have a body. Functions without bodies can only be inside 'extern' blocks (Line %u)\n",
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

        case token_keyword_let: {
            File_Pos start_pos = t->pos;
            t += 1;

            if (t->kind != token_identifier) {
                printf("Expected global variable name, but found ");
                print_token(context->string_table, t);
                printf(" (Line %u)\n", t->pos.line);
                return null;
            }
            u32 name_index = t->identifier_string_table_index;
            t += 1;

            u32 type_index = 0;
            if (t->kind == token_colon) {
                t += 1;

                u32 type_length = 0;
                type_index = parse_type(context, t, &type_length);
                if (type_index == U32_MAX) return null;
                t += type_length;
            }

            Expr* expr = null;
            if (t->kind == token_assign) {
                t += 1;

                u32 right_length = 0;
                expr = parse_expr(context, t, &right_length); 
                if (expr == null) return null;
                t += right_length;
            }

            if (expr == null && type_index == null) {
                u8* name = string_table_access(context->string_table, name_index);
                printf("Declared global variable '%s' without specifying type or initial value. Hence can't infer type (Line %u)\n", name, t->pos.line);
                return null;
            }

            if (!expect_single_token(context, t, token_semicolon, "after global variable declaration")) return null;
            t += 1;


            Global_Var global = {0};
            global.var.name = name_index;
            global.var.declaration_pos = start_pos;
            global.var.type_index = type_index;
            global.initial_expr = expr;
            buf_push(context->global_vars, global);

            assert(buf_length(context->global_vars) < MAX_LOCAL_VARS);
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


typedef struct Scope Scope;
struct Scope {
    u32 var_count;
    u8* map; // list of booleans, for marking which variables currently are in scope

    Scope *child, *parent;
};

typedef struct Typecheck_Info {
    Context* context;
    Func* func;
    Scope* scope;
} Typecheck_Info;

Scope* scope_new(Context* context, u32 var_count) {
    Scope* scope = arena_new(&context->stack, Scope);
    scope->var_count = var_count;
    scope->map = arena_alloc(&context->stack, var_count);
    mem_clear(scope->map, var_count);
    return scope;
}

void typecheck_scope_push(Typecheck_Info* info) {
    if (info->scope->child == null) {
        info->scope->child = scope_new(info->context, info->scope->var_count);
        info->scope->child->parent = info->scope;
    }

    mem_copy(info->scope->map, info->scope->child->map, info->scope->var_count);

    info->scope = info->scope->child;
}

void typecheck_scope_pop(Typecheck_Info* info) {
    assert(info->scope->parent != null);
    info->scope = info->scope->parent;
}

bool typecheck_expr(Typecheck_Info* info, Expr* expr, u32 solidify_to) {
    switch (expr->kind) {
        case expr_literal: {
            Primitive solidify_to_primitive = info->context->type_buf[solidify_to];

            switch (expr->literal.kind) {
                case expr_literal_integer: {
                    if (solidify_to_primitive == primitive_pointer) {
                        solidify_to_primitive = primitive_u64;
                    }
                    bool can_solidify = solidify_to_primitive >= primitive_u8 && solidify_to_primitive <= primitive_i64;

                    if (can_solidify) {
                        expr->type_index = solidify_to_primitive;

                        u64 mask = size_mask(primitive_size_of(solidify_to_primitive));
                        u64 value = expr->literal.value;

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

                case expr_literal_pointer: {
                    if (solidify_to_primitive == primitive_pointer) {
                        expr->type_index = solidify_to;
                    } else {
                        expr->type_index = primitive_invalid;
                    }
                } break;

                case expr_literal_bool: {
                    assert(expr->literal.value == true || expr->literal.value == false);
                    expr->type_index = primitive_bool;
                } break;

                default: assert(false);
            }

        } break;

        case expr_string_literal: {
            assert(expr->type_index == info->context->string_type);
        } break;

        case expr_compound_literal: {
            if (expr->type_index == 0) {
                expr->type_index = solidify_to;
            }

            Primitive primitive = info->context->type_buf[expr->type_index];
            if (primitive == primitive_array) {
                u64 expected_child_count = *((u64*) &info->context->type_buf[expr->type_index + 1]);
                u32 expected_child_type_index = expr->type_index + 1 + sizeof(u64);

                if (expr->compound_literal.count != expected_child_count) {
                    printf(
                        "Too %s values in compound literal: expected %u, got %u (Line %u)\n",
                        (expr->compound_literal.count > expected_child_count)? "many" : "few",
                        (u64) expected_child_count,
                        (u64) expr->compound_literal.count,
                        (u64) expr->pos.line
                    );
                    return false;
                }

                for (Expr_List* node = expr->compound_literal.content; node != null; node = node->next) {
                    Expr* child = node->expr;
                    if (!typecheck_expr(info, child, expected_child_type_index)) {
                        return false;
                    }

                    if (!type_cmp(info->context, expected_child_type_index, child->type_index)) {
                        printf("Invalid type inside compound literal: Expected ");
                        print_type(info->context, expected_child_type_index);
                        printf(" but got ");
                        print_type(info->context, child->type_index);
                        printf(" (Line %u)\n", (u64) expr->pos.line);

                        return false;
                    }
                }
            } else {
                printf("Invalid type for compound literal: ");
                print_type(info->context, expr->type_index);
                printf(" (Line %u)\n", expr->pos.line);
                return false;
            }
        } break;

        case expr_variable: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u32 var_index = find_var(info->context, info->func, expr->variable.unresolved_name);

                if (var_index == U32_MAX) {
                    u8* var_name = string_table_access(info->context->string_table, expr->variable.unresolved_name);
                    printf("Can't find variable '%s' ", var_name);
                    if (info->func != null) {
                        u8* func_name = string_table_access(info->context->string_table, info->func->name);
                        printf("in function '%s' or ", func_name);
                    }
                    printf("in global scope (Line %u)\n", (u64) expr->pos.line);
                    return false;
                }

                if (var_index & VAR_INDEX_GLOBAL_FLAG) {
                    u32 global_index = var_index & (~VAR_INDEX_GLOBAL_FLAG);
                    Global_Var* global = &info->context->global_vars[global_index];

                    if (!global->valid) {
                        if (!global->checked) {
                            u8* name = string_table_access(info->context->string_table, global->var.name);
                            printf(
                                "Can't use global variable %s before its declaration on line %u (Line %u)\n",
                                name, (u64) global->var.declaration_pos.line, (u64) expr->pos.line
                            );
                        }

                        return false;
                    }
                } else if (info->scope->map[var_index] == false) {
                    Var* var = &info->func->body.vars[var_index];
                    u8* var_name = string_table_access(info->context->string_table, expr->variable.unresolved_name);

                    u64 use_line = expr->pos.line;
                    u64 decl_line = var->declaration_pos.line;

                    if (use_line <= decl_line) {
                        printf(
                            "Can't use variable %s on line %u before its declaration on line %u\n",
                            var_name, use_line, decl_line
                        );
                    } else {
                        printf(
                            "Can't use variable %s on line %u, as it isn't in scope\n",
                            var_name, use_line
                        );
                    }

                    return false;
                }

                expr->variable.index = var_index;
                expr->flags &= ~EXPR_FLAG_UNRESOLVED;
            }

            if (expr->variable.index & VAR_INDEX_GLOBAL_FLAG) {
                u32 global_index = expr->variable.index & (~VAR_INDEX_GLOBAL_FLAG);
                expr->type_index = info->context->global_vars[global_index].var.type_index;
            } else {
                expr->type_index = info->func->body.vars[expr->variable.index].type_index;
            }

            expr->flags |= EXPR_FLAG_ASSIGNABLE;
        } break;

        case expr_binary: {
            bool is_comparasion = false;
            switch (expr->binary.op) {
                case binary_eq:
                case binary_neq:
                case binary_gt:
                case binary_gteq:
                case binary_lt:
                case binary_lteq:
                {
                    is_comparasion = true;
                    solidify_to = primitive_u64;
                } break;
            }

            if (!typecheck_expr(info, expr->binary.left, solidify_to))  return false;
            if (!typecheck_expr(info, expr->binary.right, solidify_to)) return false;

            assert(info->context->type_buf[expr->binary.left->type_index] != primitive_unsolidified_int);
            assert(info->context->type_buf[expr->binary.left->type_index] != primitive_unsolidified_int);

            // We take one shot at matching the types to each other by changing what we try solidifying to
            if (!type_cmp(info->context, expr->binary.left->type_index, expr->binary.right->type_index)) {
                bool left_strong = info->context->type_buf[expr->binary.left->type_index] != solidify_to;
                bool right_strong = info->context->type_buf[expr->binary.right->type_index] != solidify_to;

                if (left_strong) {
                    assert(typecheck_expr(info, expr->binary.right, expr->binary.left->type_index));
                } else if (right_strong) {
                    assert(typecheck_expr(info, expr->binary.left, expr->binary.right->type_index));
                }
            }

            expr->type_index = primitive_invalid;

            Primitive left_primitive = info->context->type_buf[expr->binary.left->type_index];
            Primitive right_primitive = info->context->type_buf[expr->binary.right->type_index];

            if (is_comparasion) {
                expr->type_index = primitive_bool;

                bool valid;
                if (expr->binary.op == binary_eq) {
                    valid = left_primitive == right_primitive && !primitive_is_compound(left_primitive);
                } else {
                    valid = left_primitive == right_primitive && primitive_is_integer(left_primitive);
                }

                if (!valid) {
                    printf("Can't compare ");
                    print_type(info->context, expr->binary.left->type_index);
                    printf(" with ");
                    print_type(info->context, expr->binary.right->type_index);
                    printf(" using operator %s (Line %u)\n", BINARY_OP_SYMBOL[expr->binary.op], (u64) expr->pos.line);
                    return false;
                }
            } else {
                if (left_primitive == right_primitive && primitive_is_integer(left_primitive)) {
                    expr->type_index = expr->binary.left->type_index;

                // Handle special cases for pointer arithmetic
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
                    case binary_mod: {} break;

                    default: assert(false);
                }
            }

            if (expr->type_index == primitive_invalid) {
                printf("Types for operator %s don't match: ", BINARY_OP_SYMBOL[expr->binary.op]);
                print_type(info->context, expr->binary.left->type_index);
                printf(" vs ");
                print_type(info->context, expr->binary.right->type_index);
                printf(" (Line %u)\n", (u64) expr->pos.line);
                return false;
            }
        } break;

        case expr_call: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u32 func_index = find_func(info->context, expr->call.unresolved_name);
                if (func_index == U32_MAX) {
                    u8* name = string_table_access(info->context->string_table, expr->call.unresolved_name);
                    printf("Can't find function '%s' (Line %u)\n", name, (u64) expr->pos.line);
                    return false;
                }

                expr->call.func_index = func_index;
                expr->flags &= ~EXPR_FLAG_UNRESOLVED;
            }

            Func* callee = &info->context->funcs[expr->call.func_index];
            expr->type_index = callee->signature.output_type_index;

            if (expr->call.param_count != callee->signature.param_count) {
                u8* name = string_table_access(info->context->string_table, callee->name);
                printf(
                    "Function '%s' takes %u parameters, but %u were given (Line %u)\n",
                    name, (u64) callee->signature.param_count, (u64) expr->call.param_count, (u64) expr->pos.line
                );
                return false;
            }

            Expr_List* param_expr = expr->call.params;
            for (u32 p = 0; p < expr->call.param_count; p += 1, param_expr = param_expr->next) {
                u32 var_index = callee->signature.params[p].var_index;
                u32 expected_type_index = callee->signature.params[p].type_index;

                if (!typecheck_expr(info, param_expr->expr, expected_type_index)) {
                    return false;
                }

                u32 actual_type_index = param_expr->expr->type_index;
                if (!type_cmp(info->context, expected_type_index, actual_type_index)) {
                    u8* func_name = string_table_access(info->context->string_table, callee->name);
                    printf("Invalid type for %n parameter to %s: Expected ", (u64) (p + 1), func_name);
                    print_type(info->context, expected_type_index);
                    printf(" but got ");
                    print_type(info->context, actual_type_index);
                    printf(" (Line %u)\n", (u64) expr->pos.line);

                    return false;
                }
            }
        } break;

        case expr_cast: {
            Primitive primitive = info->context->type_buf[expr->type_index];
            assert(primitive >= primitive_u8 && primitive <= primitive_i64);
            typecheck_expr(info, expr->cast_from, expr->type_index);
        } break;

        case expr_unary: {
            u32 inner_solidify_to;
            switch (expr->unary.op) {
                case unary_not:         inner_solidify_to = solidify_to; break;
                case unary_neg:         inner_solidify_to = solidify_to; break;
                case unary_dereference: inner_solidify_to = primitive_invalid; break;
                case unary_address_of:  inner_solidify_to = primitive_invalid; break;
                default: assert(false);
            }

            if (!typecheck_expr(info, expr->unary.inner, inner_solidify_to)) {
                return false;
            }

            switch (expr->unary.op) {
                case unary_not: {
                    // TODO allow using unary_not to do a bitwise not on integers
                    Primitive child_primitive = info->context->type_buf[expr->unary.inner->type_index];
                    if (child_primitive != primitive_bool) {
                        printf("Can only 'not' a 'bool', not a ");
                        print_type(info->context, expr->unary.inner->type_index);
                        printf(" (Line %u)\n", expr->unary.inner->pos.line);
                        return false;
                    }

                    expr->type_index = expr->unary.inner->type_index;
                } break;

                case unary_neg: {
                    Primitive child_primitive = info->context->type_buf[expr->unary.inner->type_index];
                    if (!primitive_is_integer(child_primitive)) {
                        printf("Can only negatve integers, not a ");
                        print_type(info->context, expr->unary.inner->type_index);
                        printf(" (Line %u)\n", expr->unary.inner->pos.line);
                        return false;
                    }

                    expr->type_index = expr->unary.inner->type_index;
                } break;

                case unary_dereference: {
                    Primitive child_primitive = info->context->type_buf[expr->unary.inner->type_index];
                    if (child_primitive != primitive_pointer) {
                        printf("Can't dereference non-pointer ");
                        print_expr(info->context, info->func, expr->unary.inner);
                        printf(" (Line %u)\n", expr->pos.line);
                        return false;
                    }

                    expr->type_index = expr->unary.inner->type_index + 1;
                    expr->flags |= EXPR_FLAG_ASSIGNABLE;
                } break;

                case unary_address_of: {
                    if (!(expr->unary.inner->flags & EXPR_FLAG_ASSIGNABLE)) {
                        printf("Can't take address of ");
                        print_expr(info->context, info->func, expr->unary.inner);
                        printf(" (Line %u)\n", expr->pos.line);
                        return false;
                    }

                    expr->type_index = buf_length(info->context->type_buf);
                    buf_push(info->context->type_buf, primitive_pointer);
                    u32 duped = type_duplicate(info->context, expr->unary.inner->type_index);
                    assert(duped == expr->type_index + 1);
                } break;

                default: assert(false);
            }
        } break;

        case expr_subscript: {
            if (!typecheck_expr(info, expr->subscript.array, primitive_invalid)) {
                return false;
            }

            if (!typecheck_expr(info, expr->subscript.index, primitive_u64)) {
                return false;
            }

            bool bad = false;

            u32 array_type_index = expr->subscript.array->type_index;
            if (info->context->type_buf[array_type_index] == primitive_array) {
                expr->type_index = array_type_index + sizeof(u64) + 1;
                expr->flags |= EXPR_FLAG_ASSIGNABLE;
            } else if (info->context->type_buf[array_type_index] == primitive_pointer && info->context->type_buf[array_type_index + 1] == primitive_array) {
                expr->type_index = array_type_index + sizeof(u64) + 2;
                expr->flags |= EXPR_FLAG_ASSIGNABLE;
            } else {
                printf("Can't index a ");
                print_type(info->context, array_type_index);
                printf(" (Line %u)\n", (u64) expr->pos.line);
                bad = true;
            }

            u32 index_type_index = expr->subscript.index->type_index;
            if (info->context->type_buf[index_type_index] != primitive_u64) {
                // TODO should we allow other integer types and insert automatic promotions as neccesary here??
                printf("Can only use u64 as an array index, not ");
                print_type(info->context, index_type_index);
                printf(" (Line %u)\n", (u64) expr->subscript.index->pos.line);
                bad = true;
            }

            if (bad) return false;
        } break;

        default: assert(false);
    }

    return true;
}

bool typecheck_stmt(Typecheck_Info* info, Stmt* stmt) {
    switch (stmt->kind) {
        case stmt_assignment: {
            if (!typecheck_expr(info, stmt->assignment.left, primitive_invalid)) {
                return false;
            }
            u32 left_type_index = stmt->assignment.left->type_index;

            if (!typecheck_expr(info, stmt->assignment.right, left_type_index)) {
                return false;
            }
            u32 right_type_index = stmt->assignment.right->type_index;

            if (!type_cmp(info->context, left_type_index, right_type_index)) {
                printf("Types on left and right side of assignment don't match: ");
                print_type(info->context, left_type_index);
                printf(" vs ");
                print_type(info->context, right_type_index);
                printf(" (Line %u)\n", (u64) stmt->pos.line);
                return false;
            }

            if (!(stmt->assignment.left->flags & EXPR_FLAG_ASSIGNABLE)) {
                printf("Can't assign to left hand side: ");
                print_expr(info->context, info->func, stmt->assignment.left);
                printf(" (Line %u)\n", (u64) stmt->pos.line);
                return false;
            }
        } break;

        case stmt_expr: {
            if (!typecheck_expr(info, stmt->expr, primitive_invalid)) {
                return false;
            }
        } break;

        case stmt_declaration: {
            u32 var_index = stmt->declaration.var_index;
            Var* var = &info->func->body.vars[var_index];
            Expr* right = stmt->declaration.right;

            assert(var->type_index != 0 || stmt->declaration.right != null);

            bool bad_types = false;

            if (right != null) {
                u32 solidify_to;
                if (var->type_index == 0) {
                    solidify_to = DEFAULT_INTEGER_TYPE;
                } else {
                    solidify_to = var->type_index;
                }

                if (!typecheck_expr(info, right, solidify_to)) {
                    bad_types = true;
                } else if (var->type_index == 0) {
                    var->type_index = right->type_index;
                } else if (!type_cmp(info->context, var->type_index, right->type_index)) {
                    printf("Right hand side of variable declaration doesn't have correct type. Expected ");
                    print_type(info->context, var->type_index);
                    printf(" but got ");
                    print_type(info->context, right->type_index);
                    printf(" (Line %u)\n", stmt->pos.line);
                    bad_types = true;
                }
            }

            assert(!info->scope->map[stmt->declaration.var_index]);
            info->scope->map[stmt->declaration.var_index] = true;

            if (bad_types) return false;
        } break;

        case stmt_block: {
            typecheck_scope_push(info);
            for (Stmt* inner = stmt->block.inner; inner->kind != stmt_end; inner = inner->next) {
                if (!typecheck_stmt(info, inner)) return false;
            }
            typecheck_scope_pop(info);
        } break;

        case stmt_if: {
            if (!typecheck_expr(info, stmt->conditional.condition, primitive_bool)) return false;

            Primitive condition_primitive = info->context->type_buf[stmt->conditional.condition->type_index];
            if (condition_primitive != primitive_bool) {
                printf("Expected bool but got ");
                print_type(info->context, stmt->conditional.condition->type_index);
                printf(" in 'if'-statement (Line %u)\n", stmt->conditional.condition->pos.line);
                return false;
            }

            typecheck_scope_push(info);
            for (Stmt* inner = stmt->conditional.then; inner->kind != stmt_end; inner = inner->next) {
                if (!typecheck_stmt(info, inner)) return false;
            }
            typecheck_scope_pop(info);

            if (stmt->conditional.else_then != null) {
                typecheck_scope_push(info);
                for (Stmt* inner = stmt->conditional.else_then; inner->kind != stmt_end; inner = inner->next) {
                    if (!typecheck_stmt(info, inner)) return false;
                }
                typecheck_scope_pop(info);
            }
        } break;

        case stmt_loop: {
            if (stmt->loop.condition != null) {
                if (!typecheck_expr(info, stmt->loop.condition, primitive_bool)) return false;

                Primitive condition_primitive = info->context->type_buf[stmt->loop.condition->type_index];
                if (condition_primitive != primitive_bool) {
                    printf("Expected bool but got ");
                    print_type(info->context, stmt->loop.condition->type_index);
                    printf(" in 'for'-loop (Line %u)\n", stmt->loop.condition->pos.line);
                    return false;
                }
            }

            typecheck_scope_push(info);
            for (Stmt* inner = stmt->loop.body; inner->kind != stmt_end; inner = inner->next) {
                if (!typecheck_stmt(info, inner)) return false;
            }
            typecheck_scope_pop(info);
        } break;

        default: assert(false);
    }

    return true;
}

// NB This will allocate on context->stack, push/pop before/after
bool eval_compile_time_expr(Typecheck_Info* info, Expr* expr, u8* result_into) {
    u64 type_size = type_size_of(info->context, expr->type_index);
    assert(type_size > 0);

    switch (expr->kind) {
        case expr_literal: {
            assert(type_size <= 8);
            mem_copy((u8*) &expr->literal.value, result_into, type_size);
            return true;
        } break;

        case expr_variable: {
            if (expr->variable.index & VAR_INDEX_GLOBAL_FLAG) {
                u32 global_index = expr->variable.index & (~VAR_INDEX_GLOBAL_FLAG);
                Global_Var* global = &info->context->global_vars[global_index];

                if (!global->valid) {
                    if (!global->checked) {
                        u8* name = string_table_access(info->context->string_table, global->var.name);
                        printf(
                            "Can't use global variable %s in a compile time expression before its declaration on line %u (Line %u)\n",
                            name, (u64) global->var.declaration_pos.line, (u64) expr->pos.line
                        );
                    }
                    return false;
                } else {
                    u64 other_size = type_size_of(info->context, global->var.type_index);
                    assert(other_size == type_size);

                    u8* other_value = &info->context->seg_rwdata[global->data_offset];
                    mem_copy(other_value, result_into, type_size);
                    return true;
                }
            } else {
                printf("Can't use local variables in constant expressions (Line %u)\n", expr->pos.line);
                return false;
            }
        } break;

        case expr_binary: {
            assert(expr->binary.left->type_index == expr->binary.right->type_index);
            u64 child_size = type_size_of(info->context, expr->binary.left->type_index);

            assert(type_size <= 8 && child_size <= 8);
            u64 left_result, right_result;

            if (!eval_compile_time_expr(info, expr->binary.left, (u8*) &left_result)) return false;
            if (!eval_compile_time_expr(info, expr->binary.right, (u8*) &right_result)) return false;

            bool is_signed = primitive_is_signed(info->context->type_buf[expr->binary.left->type_index]);

            u64 result = 0;

            if (is_signed) {
                i64 left  = *((i64*) &left_result);
                i64 right = *((i64*) &right_result);
                switch (child_size) {
                    case 1: left = (i64) ((i8)  left_result); right = (i64) ((i8)  right); break;
                    case 2: left = (i64) ((i16) left_result); right = (i64) ((i16) right); break;
                    case 4: left = (i64) ((i32) left_result); right = (i64) ((i32) right); break;
                    case 8: break;
                    default: assert(false);
                }

                switch (expr->binary.op) {
                    case binary_add:  result = left +  right; break;
                    case binary_sub:  result = left -  right; break;
                    case binary_mul:  result = left *  right; break;
                    case binary_div:  result = left /  right; break;
                    case binary_mod:  result = left %  right; break;
                    case binary_eq:   result = left == right; break;
                    case binary_neq:  result = left != right; break;
                    case binary_gt:   result = left >  right; break;
                    case binary_gteq: result = left >= right; break;
                    case binary_lt:   result = left <  right; break;
                    case binary_lteq: result = left <= right; break;
                }
            } else {
                u64 left = left_result;
                u64 right = right_result;
                switch (child_size) {
                    case 1: left = (u64) ((u8)  left_result); right = (u64) ((u8)  right); break;
                    case 2: left = (u64) ((u16) left_result); right = (u64) ((u16) right); break;
                    case 4: left = (u64) ((u32) left_result); right = (u64) ((u32) right); break;
                    case 8: break;
                    default: assert(false);
                }

                switch (expr->binary.op) {
                    case binary_add:  result = left +  right; break;
                    case binary_sub:  result = left -  right; break;
                    case binary_mul:  result = left *  right; break;
                    case binary_div:  result = left /  right; break;
                    case binary_mod:  result = left %  right; break;
                    case binary_eq:   result = left == right; break;
                    case binary_neq:  result = left != right; break;
                    case binary_gt:   result = left >  right; break;
                    case binary_gteq: result = left >= right; break;
                    case binary_lt:   result = left <  right; break;
                    case binary_lteq: result = left <= right; break;
                }
            }

            mem_copy((u8*) &result, result_into, type_size);
            return true;
        } break;
    }

    printf("Can't evaluate this expression at compile time yet (Line %u)\n", expr->pos.line);
    return false;
}

bool typecheck(Context* context) {
    bool valid = true;

    Typecheck_Info info = {0};
    info.context = context;

    // Global variables
    for (u32 g = 0; g < buf_length(context->global_vars); g += 1) {
        Global_Var* global = &context->global_vars[g];
        global->checked = true;

        bool resolved_type = global->var.type_index != 0;

        if (global->initial_expr != null) {
            u32 solidify_to;
            if (global->var.type_index == 0) {
                solidify_to = DEFAULT_INTEGER_TYPE;
            } else {
                solidify_to = global->var.type_index;
            }

            if (typecheck_expr(&info, global->initial_expr, solidify_to)) {
                if (global->var.type_index == 0) {
                    global->var.type_index = global->initial_expr->type_index;
                    resolved_type = true;
                } else if (!type_cmp(context, global->var.type_index, global->initial_expr->type_index)) {
                    printf("Right hand side of variable declaration doesn't have correct type. Expected ");
                    print_type(context, global->var.type_index);
                    printf(" but got ");
                    print_type(context, global->initial_expr->type_index);
                    printf(" (Line %u)\n", global->var.declaration_pos.line);
                } else {
                    resolved_type = true;
                }
            } else {
                resolved_type = false;
            }
        }

        if (!resolved_type) {
            valid = false;
            continue;
        }

        u64 type_size = type_size_of(context, global->var.type_index);
        assert(type_size > 0);

        global->data_offset = add_exe_data(context, null, type_size, true);
        u8* result_into = &context->seg_rwdata[global->data_offset];

        bool computed_value = true;

        if (global->initial_expr != null) {
            arena_stack_push(&context->stack);
            bool could_init = eval_compile_time_expr(&info, global->initial_expr, result_into);
            arena_stack_pop(&context->stack);

            if (!could_init) computed_value = false;
        }

        if (resolved_type && computed_value) {
            global->valid = true;
        }
    }

    if (!valid) return false;

    // Functions
    for (u32 f = 0; f < buf_length(context->funcs); f += 1) {
        arena_stack_push(&context->stack);

        info.func = context->funcs + f;
        if (info.func->kind != func_kind_normal) continue;

        info.scope = scope_new(context, info.func->body.var_count);

        // output and parameters are allways in scope
        if (info.func->signature.has_output) {
            info.scope->map[info.func->body.output_var_index] = true;
        }
        for (u32 i = 0; i < info.func->signature.param_count; i += 1) {
            u32 var_index = info.func->signature.params[i].var_index;
            info.scope->map[var_index] = true;
        }

        for (Stmt* stmt = info.func->body.first_stmt; stmt->kind != stmt_end; stmt = stmt->next) {
            if (!typecheck_stmt(&info, stmt)) {
                valid = false;
            }
        }

        arena_stack_pop(&context->stack);
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
    Primitive target_primitive = context->type_buf[expr->type_index];
    assert(assign_to.kind != local_literal);

    switch (expr->kind) {
        case expr_literal:
        case expr_variable:
        {
            Local source;
            switch (expr->kind) {
                case expr_literal: {
                    source = (Local) { local_literal, false, expr->literal.value };
                } break;

                case expr_variable: {
                    u32 var_index = expr->variable.index;

                    if (var_index & VAR_INDEX_GLOBAL_FLAG) {
                        u32 global_index = var_index & (~VAR_INDEX_GLOBAL_FLAG);
                        source = (Local) { local_global, false, global_index };
                    } else {
                        source = (Local) { local_variable, false, var_index };
                    }
                } break;
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
                assert(!primitive_is_compound(target_primitive));

                Op op = {0};
                op.kind = op_set;
                op.primitive = target_primitive;
                op.binary.source = source;
                op.binary.target = assign_to;
                buf_push(context->tmp_ops, op);
            }
        } break;

        case expr_string_literal: {
            assert(!get_address);

            bool writable = false; // Decides whether strings should be writable by user code

            u64 data_offset = add_exe_data(context, expr->string.bytes, expr->string.length + 1, writable);
            assert(data_offset <= U32_MAX);

            Op op = {0};
            op.kind = op_load_data;
            op.load_data.local = assign_to;
            op.load_data.data_offset = (u32) data_offset;
            op.load_data.writable = writable;
            buf_push(context->tmp_ops, op);
        } break;

        case expr_compound_literal: {
            assert(!get_address);
            assert(assign_to.as_reference);
            assert(primitive_is_compound(target_primitive));

            if (target_primitive == primitive_array) {
                u64 array_length = *((u64*) &context->type_buf[expr->type_index + 1]);
                assert(array_length == expr->compound_literal.count);

                u32 child_type_index = expr->type_index + 1 + sizeof(u64);
                u64 stride = type_size_of(context, child_type_index);

                Local element_pointer = assign_to;

                bool first = true;
                for (Expr_List* node = expr->compound_literal.content; node != null; node = node->next) {
                    element_pointer.as_reference = false;

                    if (!first) {
                        buf_push(context->tmp_ops, ((Op) {
                            .kind = op_add,
                            .primitive = primitive_pointer,
                            .binary = { (Local) { local_literal, false, stride }, element_pointer }
                        }));
                    }
                    first = false;

                    element_pointer.as_reference = true;

                    linearize_expr(context, node->expr, element_pointer, false);
                }

                u64 negative_offset = stride * (expr->compound_literal.count - 1);

                element_pointer.as_reference = false;
                buf_push(context->tmp_ops, ((Op) {
                    .kind = op_sub,
                    .primitive = primitive_pointer,
                    .binary = { (Local) { local_literal, false, negative_offset }, element_pointer },
                }));
            } else {
                assert(false);
            }

        } break;

        case expr_binary: {
            assert(!get_address);

            if (assign_to.kind == local_temporary) {
                u64 left_size = type_size_of(context, expr->binary.left->type_index);
                Tmp* tmp = &context->tmp_tmps[assign_to.value];
                tmp->size = max(left_size, tmp->size);
            }

            linearize_expr(context, expr->binary.left, assign_to, false);

            Local right_local = {0};
            if (!linearize_expr_to_local(expr->binary.right, &right_local)) {
                u64 right_size = type_size_of(context, expr->binary.right->type_index);
                right_local = intermediate_allocate_temporary(context, right_size);
                linearize_expr(context, expr->binary.right, right_local, false);
            }


            Op op = {0};

            switch (expr->binary.op) {
                case binary_add:  op.kind = op_add;  break;
                case binary_sub:  op.kind = op_sub;  break;
                case binary_mul:  op.kind = op_mul;  break;
                case binary_div:  op.kind = op_div;  break;
                case binary_mod:  op.kind = op_mod;  break;
                case binary_neq:  op.kind = op_neq;  break;
                case binary_eq:   op.kind = op_eq;   break;
                case binary_gt:   op.kind = op_gt;   break;
                case binary_gteq: op.kind = op_gteq; break;
                case binary_lt:   op.kind = op_lt;   break;
                case binary_lteq: op.kind = op_lteq; break;
                default: assert(false);
            }

            op.binary.target = assign_to;
            op.binary.source = right_local;

            switch (expr->binary.op) {
                case binary_add:
                case binary_sub:
                case binary_mul:
                case binary_div:
                case binary_mod:
                {
                    op.primitive = target_primitive;
                } break;

                case binary_eq:
                case binary_neq:
                case binary_gt:
                case binary_gteq:
                case binary_lt:
                case binary_lteq:
                {
                    // NB for comparative operations, 'op.primitive' should be the type we are comparing, not the
                    // type we are producing (which always is bool)
                    Primitive left_primitive  = context->type_buf[expr->binary.left->type_index];
                    Primitive right_primitive = context->type_buf[expr->binary.right->type_index];
                    assert(left_primitive == right_primitive);
                    op.primitive = left_primitive;
                } break;

                default: assert(false);
            }

            buf_push(context->tmp_ops, op);

            if (right_local.kind == local_temporary) {
                intermediate_deallocate_temporary(context, right_local);
            }
        } break;

        case expr_call: {
            assert(!get_address);

            Op_Call_Param* call_params = (Op_Call_Param*) arena_alloc(&context->arena, sizeof(Op_Call_Param) * expr->call.param_count);

            u32 p = 0;
            for (Expr_List* node = expr->call.params; node != null; node = node->next) {
                Expr* expr = node->expr;

                u64 param_size = type_size_of(context, expr->type_index);
                if (param_size > 8) unimplemented(); // TODO by-reference semantics

                Local local = {0};
                if (!linearize_expr_to_local(expr, &local)) {
                    local = intermediate_allocate_temporary(context, param_size);
                    linearize_expr(context, expr, local, false);
                }

                call_params[p].size = param_size;
                call_params[p].local = local;
                p += 1;
            }

            Op op = {0};
            op.kind = op_call;
            op.primitive = context->type_buf[expr->type_index];
            op.call.func_index = expr->call.func_index;
            op.call.target = assign_to;
            op.call.params = call_params;
            buf_push(context->tmp_ops, op);

            for (u32 i = 0; i < expr->call.param_count; i += 1) {
                if (call_params[i].local.kind == local_temporary) {
                    intermediate_deallocate_temporary(context, call_params[i].local);
                }
            }
        } break;

        case expr_cast: {
            assert(!get_address);

            if (assign_to.kind == local_temporary) {
                u64 left_size = type_size_of(context, expr->cast_from->type_index);
                Tmp* tmp = &context->tmp_tmps[assign_to.value];
                tmp->size = max(left_size, tmp->size);
            }

            linearize_expr(context, expr->cast_from, assign_to, false);

            if (!type_cmp(context, expr->type_index, expr->cast_from->type_index)) {
                Op op = {0};
                op.kind = op_cast;
                op.primitive = target_primitive;
                op.cast.local = assign_to;
                op.cast.old_primitive = context->type_buf[expr->cast_from->type_index];
                buf_push(context->tmp_ops, op);
            }
        } break;

        case expr_unary: {
            switch (expr->unary.op) {
                case unary_not: {
                    assert(!get_address);
                    
                    linearize_expr(context, expr->unary.inner, assign_to, false);

                    Op op = {0};
                    op.kind = op_not;
                    op.unary = assign_to;
                    op.primitive = context->type_buf[expr->type_index];
                    buf_push(context->tmp_ops, op);
                } break;

                case unary_neg: {
                    assert(!get_address);
                    
                    linearize_expr(context, expr->unary.inner, assign_to, false);

                    Op op = {0};
                    op.kind = op_neg;
                    op.unary = assign_to;
                    op.primitive = context->type_buf[expr->type_index];
                    buf_push(context->tmp_ops, op);
                } break;

                case unary_dereference: {
                    if (get_address) {
                        // Used for lvalues
                        linearize_expr(context, expr->unary.inner, assign_to, false);
                    } else {
                        Local right_local = intermediate_allocate_temporary(context, POINTER_SIZE);
                        right_local.as_reference = false;
                        linearize_expr(context, expr->unary.inner, right_local, false);
                        right_local.as_reference = true;

                        if (primitive_is_compound(context->type_buf[expr->type_index])) {
                            assert(assign_to.as_reference);
                        }

                        intermediate_write_compound_set(context, right_local, assign_to, expr->type_index);

                        intermediate_deallocate_temporary(context, right_local);
                    }
                } break;

                case unary_address_of: {
                    assert(!get_address);
                    linearize_expr(context, expr->unary.inner, assign_to, true);
                } break;

                default: assert(false);
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

            if (stride > 1) {
                Op op = {0};
                op.kind = op_mul;
                op.primitive = primitive_pointer;
                op.binary.source = (Local) { local_literal, false, stride };
                op.binary.target = offset;
                buf_push(context->tmp_ops, op);
            }

            Op op = {0};
            op.kind = op_add;
            op.primitive = primitive_pointer;
            op.binary.source = offset;
            op.binary.target = base_pointer;
            buf_push(context->tmp_ops, op);

            if (!get_address) {
                if (primitive_is_compound(target_primitive)) {
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

bool linearize_expr_to_local(Expr* expr, Local* local) {
    switch (expr->kind) {
        case expr_literal: {
            local->kind = local_literal;
            local->as_reference = false;
            local->value = expr->literal.value;
            return true;
        } break;

        case expr_variable: {
            u32 var_index = expr->variable.index;

            if (var_index & VAR_INDEX_GLOBAL_FLAG) {
                u32 global_index = var_index & (~VAR_INDEX_GLOBAL_FLAG);
                local->kind = local_global;
                local->as_reference = false;
                local->value = global_index;
            } else {
                local->kind = local_variable;
                local->as_reference = false;
                local->value = var_index;
            }

            return true;
        } break;

        default: {
            return false;
        } break;
    }
}

bool linearize_assignment_needs_temporary(Expr* expr, u32 var_index) {
    switch (expr->kind) {
        case expr_variable: {
            return !(expr->flags & EXPR_FLAG_UNRESOLVED) && expr->variable.index == var_index;
        } break;

        case expr_compound_literal: {
            for (Expr_List* node = expr->compound_literal.content; node != null; node = node->next) {
                if (linearize_assignment_needs_temporary(node->expr, var_index)) return true;
            }
        } break;

        case expr_binary: {
            return linearize_assignment_needs_temporary(expr->binary.left, var_index) ||
                   linearize_assignment_needs_temporary(expr->binary.right, var_index);
        } break;

        case expr_call: {
            for (Expr_List* node = expr->call.params; node != null; node = node->next) {
                if (linearize_assignment_needs_temporary(node->expr, var_index)) return true;
            }
        } break;

        case expr_cast: {
            return linearize_assignment_needs_temporary(expr->cast_from, var_index);
        } break;

        case expr_unary: {
            return linearize_assignment_needs_temporary(expr->unary.inner, var_index);
        } break;

        case expr_subscript: {
            return linearize_assignment_needs_temporary(expr->subscript.array, var_index) ||
                   linearize_assignment_needs_temporary(expr->subscript.index, var_index);
        } break;
    }

    return false;
}

void linearize_assignment(Context* context, Expr* left, Expr* right) {
    assert(left->flags & EXPR_FLAG_ASSIGNABLE);

    switch (left->kind) {
        case expr_subscript:
        case expr_unary:
        {
            if (left->kind == expr_unary && left->unary.op != unary_dereference) {
                break;
            }

            bool use_pointer_to_right = primitive_is_compound(context->type_buf[left->type_index]);

            Local right_data_local = intermediate_allocate_temporary(context, type_size_of(context, right->type_index));
            Local pointer_to_right_data_local, right_local;
            if (use_pointer_to_right) {
                pointer_to_right_data_local = intermediate_allocate_temporary(context, POINTER_SIZE);

                buf_push(context->tmp_ops, ((Op) {
                    .kind = op_address_of,
                    .binary = { right_data_local, pointer_to_right_data_local }
                }));

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
            assert(!(left->flags & EXPR_FLAG_UNRESOLVED));

            Primitive left_primitive = context->type_buf[left->type_index];
            u64 operand_size = type_size_of(context, left->type_index);

            bool needs_temporary = linearize_assignment_needs_temporary(right, left->variable.index);

            Local variable_local;
            if (left->variable.index & VAR_INDEX_GLOBAL_FLAG) {
                variable_local.kind = local_global;
                variable_local.as_reference = false;
                variable_local.value = left->variable.index & (~VAR_INDEX_GLOBAL_FLAG);
            } else {
                variable_local.kind = local_variable;
                variable_local.as_reference = false;
                variable_local.value = left->variable.index;
            }

            if (primitive_is_compound(left_primitive)) {
                if (left_primitive == primitive_array) {
                    if (needs_temporary) {
                        Local tmp_local = intermediate_allocate_temporary(context, operand_size);
                        Local pointer_to_tmp_local  = intermediate_allocate_temporary(context, POINTER_SIZE);

                        buf_push(context->tmp_ops, ((Op) {
                            .kind = op_address_of,
                            .binary = { tmp_local, pointer_to_tmp_local },
                        }));

                        {
                            Local tmp_pointer  = intermediate_allocate_temporary(context, POINTER_SIZE);
                            buf_push(context->tmp_ops, ((Op) {
                                .kind = op_set,
                                .primitive = primitive_pointer,
                                .binary = { pointer_to_tmp_local, tmp_pointer },
                            }));
                            tmp_pointer.as_reference = true;
                            linearize_expr(context, right, tmp_pointer, false);
                            intermediate_deallocate_temporary(context, tmp_pointer);
                        }

                        Local pointer_to_variable_local  = intermediate_allocate_temporary(context, POINTER_SIZE);

                        buf_push(context->tmp_ops, ((Op) {
                            .kind = op_address_of,
                            .binary = {
                                .source = variable_local,
                                .target = pointer_to_variable_local,
                            },
                        }));

                        pointer_to_tmp_local.as_reference = true;
                        pointer_to_variable_local.as_reference = true;
                        intermediate_write_compound_set(context, pointer_to_tmp_local, pointer_to_variable_local, left->type_index);

                        intermediate_deallocate_temporary(context, tmp_local);
                        intermediate_deallocate_temporary(context, pointer_to_tmp_local);
                        intermediate_deallocate_temporary(context, pointer_to_variable_local);
                    } else {
                        Local pointer_to_variable_local  = intermediate_allocate_temporary(context, POINTER_SIZE);

                        buf_push(context->tmp_ops, ((Op) {
                            .kind = op_address_of,
                            .binary = { variable_local, pointer_to_variable_local },
                        }));
                        pointer_to_variable_local.as_reference = true;

                        linearize_expr(context, right, pointer_to_variable_local, false);

                        intermediate_deallocate_temporary(context, pointer_to_variable_local);
                    }
                } else {
                    assert(false);
                }

            } else {
                assert(operand_size <= POINTER_SIZE);

                if (needs_temporary) {
                    Local tmp_local = intermediate_allocate_temporary(context, operand_size);
                    linearize_expr(context, right, tmp_local, false);
                    intermediate_write_compound_set(context, tmp_local, variable_local, left->type_index);
                    intermediate_deallocate_temporary(context, tmp_local);
                } else {
                    linearize_expr(context, right, variable_local, false);
                }
            }
        } break;

        default: panic("Invalid lexpr\n");
    }
}

void linearize_stmt(Context* context, Func* func, Stmt* stmt) {
    switch (stmt->kind) {
        case stmt_assignment: {
            linearize_assignment(context, stmt->assignment.left, stmt->assignment.right);
        } break;

        case stmt_expr: {
            linearize_expr(context, stmt->expr, (Local) {0}, false);
        } break;

        case stmt_declaration: {
            if (stmt->declaration.right != null) {
                Expr left = {0};
                left.kind = expr_variable;
                left.variable.index = stmt->declaration.var_index;
                left.flags |= EXPR_FLAG_ASSIGNABLE;
                left.type_index = func->body.vars[left.variable.index].type_index;
                left.pos = stmt->pos;

                linearize_assignment(context, &left, stmt->declaration.right);
            }
        } break;

        case stmt_block: {
            for (Stmt* inner = stmt->block.inner; inner->kind != stmt_end; inner = inner->next) {
                linearize_stmt(context, func, inner);
            }
        } break;

        case stmt_if: {
            Local bool_local = intermediate_allocate_temporary(context, 1);
            linearize_expr(context, stmt->conditional.condition, bool_local, false);

            Op if_jump_op = {0};
            if_jump_op.kind = op_jump;
            if_jump_op.jump.conditional = true;
            if_jump_op.jump.condition = bool_local;
            u64 if_jump_op_index = buf_length(context->tmp_ops);
            buf_push(context->tmp_ops, if_jump_op);

            intermediate_deallocate_temporary(context, bool_local);

            for (Stmt* inner = stmt->conditional.then; inner->kind != stmt_end; inner = inner->next) {
                linearize_stmt(context, func, inner);
            } 

            Op* if_jump_op_pointer = &context->tmp_ops[if_jump_op_index];
            if_jump_op_pointer->jump.to_op = buf_length(context->tmp_ops);

            if (stmt->conditional.else_then != null) {
                if_jump_op_pointer->jump.to_op += 1; // Also jump past else_jump_op

                Op else_jump_op = {0};
                else_jump_op.kind = op_jump;
                else_jump_op.jump.conditional = false;
                u64 else_jump_op_index = buf_length(context->tmp_ops);
                buf_push(context->tmp_ops, else_jump_op);

                for (Stmt* inner = stmt->conditional.else_then; inner->kind != stmt_end; inner = inner->next) {
                    linearize_stmt(context, func, inner);
                }

                Op* else_jump_op_pointer = &context->tmp_ops[else_jump_op_index];
                else_jump_op_pointer->jump.to_op = buf_length(context->tmp_ops);
            }
        } break;

        case stmt_loop: {
            u64 initial_jump = U64_MAX;
            u64 loop_start = buf_length(context->tmp_ops);

            if (stmt->loop.condition != null) {
                Local bool_local = intermediate_allocate_temporary(context, 1);
                linearize_expr(context, stmt->conditional.condition, bool_local, false);

                initial_jump = buf_length(context->tmp_ops);
                buf_push(context->tmp_ops, ((Op) {
                    op_jump,
                    .jump = { .conditional = true, .condition = bool_local },
                }));

                intermediate_deallocate_temporary(context, bool_local);
            }

            for (Stmt* inner = stmt->loop.body; inner->kind != stmt_end; inner = inner->next) {
                linearize_stmt(context, func, inner);
            }

            buf_push(context->tmp_ops, ((Op) {
                op_jump,
                .jump = {
                    .conditional = false,
                    .to_op = loop_start,
                },
            }));

            if (stmt->loop.condition != null) {
                Op* initial_jump_pointer = &context->tmp_ops[initial_jump];
                assert(initial_jump_pointer->kind == op_jump);
                initial_jump_pointer->jump.to_op = buf_length(context->tmp_ops);
            }
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

        for (Stmt* stmt = func->body.first_stmt; stmt->kind != stmt_end; stmt = stmt->next) {
            linearize_stmt(context, func, stmt);
        }

        buf_foreach (Tmp, tmp, context->tmp_tmps) assert(!tmp->currently_allocated);

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
            printf(" (%u) ", (u64) i);
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


void instruction_int3(u8** b) {
    buf_push(*b, 0xcc);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("int 3\n");
    #endif
}

void instruction_nop(u8** b) {
    buf_push(*b, 0x90);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("nop\n");
    #endif
}

typedef enum X64_Instruction_Binary {
    instruction_xor,
    instruction_add,
    instruction_sub,
    instruction_cmp,
    BINARY_INSTRUCTION_COUNT,
} X64_Instruction_Binary;

u8 BINARY_INSTRUCTION_OPCODES_BYTE[BINARY_INSTRUCTION_COUNT] = {
    [instruction_xor] = 0x32,
    [instruction_add] = 0x02,
    [instruction_sub] = 0x2a,
    [instruction_cmp] = 0x3a,
};
u8 BINARY_INSTRUCTION_OPCODES_INT[BINARY_INSTRUCTION_COUNT] = {
    [instruction_xor] = 0x33,
    [instruction_add] = 0x03,
    [instruction_sub] = 0x2b,
    [instruction_cmp] = 0x3b,
};
u8* BINARY_INSTRUCTION_OP_NAMES[BINARY_INSTRUCTION_COUNT] = {
    [instruction_xor] = "xor",
    [instruction_add] = "add",
    [instruction_sub] = "sub",
    [instruction_cmp] = "cmp",
};

typedef enum X64_Instruction_Unary {
    instruction_mul,
    instruction_div,
    instruction_not, // ones-complement negation
    instruction_neg, // twos-complement negation
    UNARY_INSTRUCTION_COUNT,
} X64_Instruction_Unary;

u8 UNARY_INSTRUCTION_REG[UNARY_INSTRUCTION_COUNT] = {
    [instruction_mul] = 4,
    [instruction_div] = 6,
    [instruction_not] = 2,
    [instruction_neg] = 3,
};
u8* UNARY_INSTRUCTION_OP_NAMES[UNARY_INSTRUCTION_COUNT] = {
    [instruction_mul] = "mul",
    [instruction_div] = "div",
    [instruction_not] = "not",
    [instruction_neg] = "neg",
};

void instruction_general_reg_reg(u8** b, X64_Instruction_Binary instruction, X64_Reg a_reg, X64_Reg b_reg, u8 bytes) {
    bool use_small_op = false;
    u8 rex = REX_BASE;
    u8 modrm = 0xc0;

    modrm |= (a_reg << MODRM_REG_OFFSET) & MODRM_REG_MASK;
    if (a_reg >= reg_r8) rex |= REX_R;
    assert(a_reg < 16);

    modrm |= (b_reg << MODRM_RM_OFFSET) & MODRM_RM_MASK;
    if (b_reg >= reg_r8) rex |= REX_B;
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
        buf_push(*b, BINARY_INSTRUCTION_OPCODES_BYTE[instruction]);
    } else {
        buf_push(*b, BINARY_INSTRUCTION_OPCODES_INT[instruction]);
    }

    buf_push(*b, modrm);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("%s%u %s %s\n", BINARY_INSTRUCTION_OP_NAMES[instruction], (u64) bytes*8, reg_names[a_reg], reg_names[b_reg]);
    #endif
}

void instruction_general_reg(u8** b, X64_Instruction_Unary instruction, X64_Reg reg, u8 bytes) {
    u8 rex = REX_BASE;
    u8 modrm = 0xc0;

    modrm |= ((UNARY_INSTRUCTION_REG[instruction] << MODRM_REG_OFFSET) & MODRM_REG_MASK);

    modrm |= ((reg << MODRM_RM_OFFSET) & MODRM_RM_MASK);
    if (reg >= reg_r8) rex |= REX_B;
    assert(reg < 16);

    u8 opcode = 0xf7;
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
    printf("%s%u rax, %s\n", UNARY_INSTRUCTION_OP_NAMES[instruction], (u64) bytes*8, reg_names[reg]);
    #endif
}

void instruction_xor_reg_imm(u8** b, X64_Reg reg, u32 immediate, u8 bytes) {
    immediate = immediate & size_mask(bytes);

    u8 rex = REX_BASE;
    u8 modrm = 0xf0;

    modrm |= ((reg << MODRM_RM_OFFSET) & MODRM_RM_MASK);
    if (reg >= reg_r8) rex |= REX_B;
    assert(reg < 16);

    u8 opcode = 0x81;
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
    str_push_integer(b, min(bytes, sizeof(u32)), immediate);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("xor%u %s, %x\n", (u64) bytes*8, reg_names[reg], immediate);
    #endif

}

void instruction_zero_extend_byte(u8** b, X64_Reg reg, u8 target_bytes) {
    u8 modrm =
        0xc0 |
        ((reg << MODRM_REG_OFFSET) & MODRM_REG_MASK) |
        ((reg << MODRM_RM_OFFSET) & MODRM_RM_MASK);
    u8 rex = REX_BASE;

    if (reg > reg_r8) {
        rex |= REX_R | REX_B;
    }

    switch (target_bytes) {
        case 1: assert(false); // Can't zero-extend from 1 byte to 1 byte
        case 2: buf_push(*b, 0x66); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    if (rex != REX_BASE) {
        buf_push(*b, rex);
    }
    buf_push(*b, 0x0f);
    buf_push(*b, 0xb6);
    buf_push(*b, modrm);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    u8* reg_name = reg_names[reg];
    printf("movzx %s %s (8 -> %u)\n", reg_name, reg_name, target_bytes*8);
    #endif
}

void instruction_setcc(u8** b, X64_Condition condition, bool sign, X64_Reg reg) {
    u8 opcode;
    if (sign) {
        switch (condition) {
            case x64_condition_eq:   opcode = 0x94; break;
            case x64_condition_neq:  opcode = 0x95; break;
            case x64_condition_gt:   opcode = 0x9f; break;
            case x64_condition_gteq: opcode = 0x9d; break;
            case x64_condition_lt:   opcode = 0x9c; break;
            case x64_condition_lteq: opcode = 0x9e; break;
            default: assert(false);
        }
    } else {
        switch (condition) {
            case x64_condition_eq:   opcode = 0x94; break;
            case x64_condition_neq:  opcode = 0x95; break;
            case x64_condition_gt:   opcode = 0x97; break;
            case x64_condition_gteq: opcode = 0x93; break;
            case x64_condition_lt:   opcode = 0x92; break;
            case x64_condition_lteq: opcode = 0x96; break;
            default: assert(false);
        }
    }

    u8 rex = REX_BASE;
    u8 modrm = 0xc0;

    modrm |= ((reg << MODRM_RM_OFFSET) & MODRM_RM_MASK);
    if (reg >= reg_r8) rex |= REX_B;
    assert(reg < 16);

    if (rex != REX_BASE) {
        buf_push(*b, rex);
    }
    buf_push(*b, 0x0f);
    buf_push(*b, opcode);
    buf_push(*b, modrm);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    u8* condition_name;
    if (sign) {
        switch (condition) {
            case x64_condition_eq:   condition_name = "e";  break;
            case x64_condition_neq:  condition_name = "ne"; break;
            case x64_condition_gt:   condition_name = "g";  break;
            case x64_condition_gteq: condition_name = "ge"; break;
            case x64_condition_lt:   condition_name = "l";  break;
            case x64_condition_lteq: condition_name = "le"; break;
            default: assert(false);
        }
    } else {
        switch (condition) {
            case x64_condition_eq:   condition_name = "e"; break;
            case x64_condition_neq:  condition_name = "ne"; break;
            case x64_condition_gt:   condition_name = "a"; break;
            case x64_condition_gteq: condition_name = "ae"; break;
            case x64_condition_lt:   condition_name = "b"; break;
            case x64_condition_lteq: condition_name = "be"; break;
            default: assert(false);
        }
    }
    printf("set%s %s\n", condition_name, reg_names[reg]);
    #endif
}

// Returns offset into *b where an i8 should be written
u64 instruction_jmp_rcx_zero(u8** b) {
    buf_push(*b, 0xe3);
    buf_push(*b, 0x00);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("jrcxz ??\n");
    #endif

    return buf_length(*b) - sizeof(i8);
}

// Returns offset into *b where an i32 should be written
u64 instruction_jmp_i32(u8** b) {
    buf_push(*b, 0xe9);
    buf_push(*b, 0xef);
    buf_push(*b, 0xbe);
    buf_push(*b, 0xad);
    buf_push(*b, 0xde);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("jmp ??\n");
    #endif

    return buf_length(*b) - sizeof(i32);
}

Mem_Item* get_stack_item(Func* func, Local local) {
    Mem_Item* item;
    switch (local.kind) {
        case local_variable:  item = &func->body.stack_layout.vars[local.value]; break;
        case local_temporary: item = &func->body.stack_layout.tmps[local.value]; break;
        case local_global:  assert(false);
        case local_literal: assert(false);
        default: assert(false);
    }
    return item;
}

void instruction_lea_stack(u8** b, u32 offset, X64_Reg reg) {
    u8 rex = REX_BASE | REX_W;
    u8 modrm = 0;

    modrm |= (reg << MODRM_REG_OFFSET) & MODRM_REG_MASK;
    if (reg >= reg_r8) rex |= REX_R;
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

void instruction_lea_data(Context* context, u32 data_offset, bool writable, X64_Reg reg) {
    buf_push(context->seg_text, 0x48);
    buf_push(context->seg_text, 0x8d);
    buf_push(context->seg_text, 0x05);
    buf_push(context->seg_text, 0xde);
    buf_push(context->seg_text, 0xad);
    buf_push(context->seg_text, 0xbe);
    buf_push(context->seg_text, 0xef);

    Fixup fixup = {0};
    fixup.kind = writable? fixup_rwdata : fixup_rodata;
    fixup.text_location = buf_length(context->seg_text) - sizeof(u32);
    fixup.data_offset = data_offset;
    buf_push(context->fixups, fixup);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("lea %s, [.data + %u]\n", reg_names[reg], (u64) data_offset);
    #endif
}

void instruction_lea_mem(Context* context, Func* func, Local local, X64_Reg reg) {
    switch (local.kind) {
        case local_global: {
            Global_Var* global = &context->global_vars[local.value];
            instruction_lea_data(context, global->data_offset, true, reg);
        } break;

        case local_variable:
        case local_temporary:
        {
            Mem_Item* item = get_stack_item(func, local);
            u32 offset = item->offset;
            instruction_lea_stack(&context->seg_text, offset, reg);
        } break;

        case local_literal: assert(false);
        default: assert(false);
    }
}

typedef enum Mov_Mode {
    mov_to,
    mov_from,
} Mov_Mode;

void instruction_mov_pointer(u8** b, Mov_Mode mode, X64_Reg pointer_reg, X64_Reg value_reg, u8 bytes) {
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
    if (value_reg >= reg_r8) rex |= REX_R;
    assert(value_reg < 16);

    modrm |= (pointer_reg << MODRM_RM_OFFSET) & MODRM_RM_MASK;
    if (pointer_reg >= reg_r8) rex |= REX_B;
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

// Moves to/from '[rsp + offset]'
void instruction_mov_stack(u8** b, Mov_Mode mode, X64_Reg reg, u32 offset, u8 bytes) {
    u8 rex = REX_BASE;
    u8 modrm = 0;
    u8 opcode;

    if (mode == mov_to) {
        opcode = 0x89;
    } else {
        opcode = 0x8b;
    }

    switch (bytes) {
        case 1: opcode -= 1; break;
        case 2: buf_push(*b, 0x66); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    modrm |= (reg << MODRM_REG_OFFSET) & MODRM_REG_MASK;
    if (reg >= reg_r8) rex |= REX_R;
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

void instruction_mov_data(Context* context, Mov_Mode mode, u32 data_offset, bool writable, X64_Reg reg, u8 bytes) {
    u8 rex = REX_BASE;
    u8 opcode = 0x8d;
    u8 modrm = 0x05;

    if (mode == mov_to) {
        opcode = 0x89;
    } else {
        opcode = 0x8b;
    }

    switch (bytes) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, 0x66); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    modrm |= (reg << MODRM_REG_OFFSET) & MODRM_REG_MASK;
    if (reg >= reg_r8) rex |= REX_R;
    assert(reg < 16);

    if (rex != REX_BASE) {
        buf_push(context->seg_text, rex);
    }
    buf_push(context->seg_text, opcode);
    buf_push(context->seg_text, modrm);

    buf_push(context->seg_text, 0xde);
    buf_push(context->seg_text, 0xad);
    buf_push(context->seg_text, 0xbe);
    buf_push(context->seg_text, 0xef);

    Fixup fixup = {0};
    fixup.kind = writable? fixup_rwdata : fixup_rodata;
    fixup.text_location = buf_length(context->seg_text) - sizeof(u32);
    fixup.data_offset = data_offset;
    buf_push(context->fixups, fixup);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    if (mode == mov_to) {
        printf("mov%u [.data + %u], %s\n", (u64) (bytes*8), (u64) data_offset, reg_names[reg]);
    } else {
        printf("mov%u %s, [.data + %u]\n", (u64) (bytes*8), reg_names[reg], (u64) data_offset);
    }
    #endif
}

void instruction_mov_mem(Context* context, Func* func, Mov_Mode mode, Local local, X64_Reg reg, u8 bytes) {
    switch (local.kind) {
        case local_global: {
            Global_Var* global = &context->global_vars[local.value];
            instruction_mov_data(context, mode, global->data_offset, true, reg, bytes);
        } break;

        case local_variable:
        case local_temporary:
        {
            Mem_Item* item = get_stack_item(func, local);
            u32 offset = item->offset;
            instruction_mov_stack(&context->seg_text, mode, reg, offset, bytes);
        } break;

        case local_literal: assert(false);
        default: assert(false);
    }
}

void instruction_mov_imm_to_reg(u8** b, u64 value, X64_Reg reg, u8 bytes) {
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
    if (reg >= reg_r8) rex |= REX_B;
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

void instruction_load_local(Context* context, Func* func, Local local, X64_Reg reg, u8 bytes) {
    if (local.kind == local_literal) {
        assert(!local.as_reference);
        instruction_mov_imm_to_reg(&context->seg_text, local.value, reg, bytes);
    } else if (local.as_reference) {
        instruction_mov_mem(context, func, mov_from, local, reg, POINTER_SIZE);
        instruction_mov_pointer(&context->seg_text, mov_from, reg, reg, bytes);
    } else {
        instruction_mov_mem(context, func, mov_from, local, reg, bytes);
    }
}

void instruction_mov_ah_to_al(u8** b) {
    buf_push(*b, 0x88);
    buf_push(*b, 0xe0);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov8 al, ah");
    #endif
}


void machinecode_for_op(Context* context, Func* func, u32 op_index) {
    Op* op = &func->body.ops[op_index];
    op->text_start = buf_length(context->seg_text);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("; ");
    print_op(context, func, op);
    printf("\n");
    #endif

    switch (op->kind) {
        case op_neg:
        case op_not:
        {
            u8 primitive_size = primitive_size_of(op->primitive);

            instruction_load_local(context, func, op->unary, reg_rax, primitive_size);

            switch (op->kind) {
                case op_neg: {
                    // NB we use the same logic for signed and usigned integers!
                    assert(primitive_is_integer(op->primitive));
                    instruction_general_reg(&context->seg_text, instruction_neg, reg_rax, primitive_size);
                } break;

                case op_not: {
                    // NB this only works if we assume the bools value was either 1 or 0
                    assert(op->primitive == primitive_bool);
                    instruction_xor_reg_imm(&context->seg_text, reg_rax, 1, primitive_size);
                } break;

                default: assert(false);
            }

            if (op->unary.as_reference) {
                instruction_mov_mem(context, func, mov_from, op->unary, reg_rcx, POINTER_SIZE);
                instruction_mov_pointer(&context->seg_text, mov_to, reg_rcx, reg_rax, primitive_size);
            } else {
                instruction_mov_mem(context, func, mov_to, op->unary, reg_rax, primitive_size);
            }
        } break;

        case op_set: {
            u8 primitive_size = primitive_size_of(op->primitive);

            instruction_load_local(context, func, op->binary.source, reg_rax, primitive_size);

            if (op->binary.target.as_reference) {
                instruction_mov_mem(context, func, mov_from, op->binary.target, reg_rcx, POINTER_SIZE);
                instruction_mov_pointer(&context->seg_text, mov_to, reg_rcx, reg_rax, primitive_size);
            } else {
                instruction_mov_mem(context, func, mov_to, op->binary.target, reg_rax, primitive_size);
            }
        } break;

        case op_address_of: {
            // TODO neither of these cases currently ever happens, due to how we generate the intermediate bytecode. Once we start
            // optimizing, this might change though...
            if (op->binary.source.as_reference) unimplemented(); // TODO
            if (op->binary.target.as_reference) unimplemented(); // TODO

            instruction_lea_mem(context, func, op->binary.source, reg_rax);
            instruction_mov_mem(context, func, mov_to, op->binary.target, reg_rax, POINTER_SIZE);
        } break;

        case op_add:
        case op_sub:
        {
            u8 primitive_size = primitive_size_of(op->primitive);

            if (op->binary.target.as_reference) {
                instruction_mov_mem(context, func, mov_from, op->binary.target, reg_rcx, POINTER_SIZE);
                instruction_mov_pointer(&context->seg_text, mov_from, reg_rcx, reg_rax, primitive_size);
            } else {
                instruction_mov_mem(context, func, mov_from, op->binary.target, reg_rax, primitive_size);
            }

            instruction_load_local(context, func, op->binary.source, reg_rdx, primitive_size);

            int kind;
            switch (op->kind) {
                case op_add: kind = instruction_add; break;
                case op_sub: kind = instruction_sub; break;
                default: assert(false);
            }
            instruction_general_reg_reg(&context->seg_text, kind, reg_rax, reg_rdx, primitive_size);

            if (op->binary.target.as_reference) {
                instruction_mov_pointer(&context->seg_text, mov_to, reg_rcx, reg_rax, primitive_size);
            } else {
                instruction_mov_mem(context, func, mov_to, op->binary.target, reg_rax, primitive_size);
            }
        } break;

        case op_mul:
        case op_div:
        case op_mod:
        {
            u8 primitive_size = primitive_size_of(op->primitive);

            if (op->binary.target.as_reference) unimplemented(); // TODO

            instruction_mov_mem(context, func, mov_from, op->binary.target, reg_rax, primitive_size);
            instruction_load_local(context, func, op->binary.source, reg_rcx, primitive_size);

            if (op->kind == op_div || op->kind == op_mod) {
                // NB We need to clear rdx when executing 'div', as x64 divides rdx:rax (128 bits), or in
                // 8 bit mode, we need to clear ah because 'div' uses ah:al

                if (primitive_size == 1) {
                    instruction_zero_extend_byte(&context->seg_text, reg_rax, 2);
                } else {
                    instruction_general_reg_reg(&context->seg_text, instruction_xor, reg_rdx, reg_rdx, POINTER_SIZE);
                }
            }

            X64_Reg result_reg;
            X64_Instruction_Unary kind;
            switch (op->kind) {
                case op_mul: kind = instruction_mul; result_reg = reg_rax; break;
                case op_div: kind = instruction_div; result_reg = reg_rax; break;
                case op_mod: kind = instruction_div; result_reg = reg_rdx; break;
                default: assert(false);
            }
            instruction_general_reg(&context->seg_text, kind, reg_rcx, primitive_size);

            if (primitive_size == 1 && op->kind == op_mod) {
                instruction_mov_ah_to_al(&context->seg_text);
                result_reg = reg_rax;
            }

            instruction_mov_mem(context, func, mov_to, op->binary.target, result_reg, primitive_size);
        } break;

        case op_neq:
        case op_eq:
        case op_gt:
        case op_gteq:
        case op_lt:
        case op_lteq:
        {
            u8 primitive_size = primitive_size_of(op->primitive);

            if (op->binary.target.as_reference) {
                instruction_mov_mem(context, func, mov_from, op->binary.target, reg_rcx, POINTER_SIZE);
                instruction_mov_pointer(&context->seg_text, mov_from, reg_rcx, reg_rax, primitive_size);
            } else {
                instruction_mov_mem(context, func, mov_from, op->binary.target, reg_rax, primitive_size);
            }

            instruction_load_local(context, func, op->binary.source, reg_rdx, primitive_size);

            bool sign = primitive_is_signed(op->primitive); 
            X64_Condition condition;
            switch (op->kind) {
                case op_eq:   condition = x64_condition_eq;     break;
                case op_neq:  condition = x64_condition_neq;    break;
                case op_gt:   condition = x64_condition_gt;     break;
                case op_gteq: condition = x64_condition_gteq;   break;
                case op_lt:   condition = x64_condition_lt;     break;
                case op_lteq: condition = x64_condition_lteq;   break;
                default: assert(false);
            }

            instruction_general_reg_reg(&context->seg_text, instruction_cmp, reg_rax, reg_rdx, primitive_size);
            instruction_setcc(&context->seg_text, condition, sign, reg_rax);

            if (op->binary.target.as_reference) {
                instruction_mov_pointer(&context->seg_text, mov_to, reg_rcx, reg_rax, primitive_size);
            } else {
                instruction_mov_mem(context, func, mov_to, op->binary.target, reg_rax, primitive_size);
            }

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
                    default: reg = reg_rax; break;
                }

                instruction_load_local(context, func, local, reg, size);

                if (p >= 4) {
                    u32 offset = POINTER_SIZE * p;
                    instruction_mov_stack(&context->seg_text, mov_to, reg, offset, size);
                }
            }

            // Actually call the function
            switch (callee->kind) {
                case func_kind_normal: {
                    buf_push(context->seg_text, 0xe8);
                    buf_push(context->seg_text, 0xde);
                    buf_push(context->seg_text, 0xad);
                    buf_push(context->seg_text, 0xbe);
                    buf_push(context->seg_text, 0xef);

                    Call_Fixup fixup = {0};
                    fixup.text_location = buf_length(context->seg_text) - sizeof(i32);
                    fixup.func_index = op->call.func_index;
                    buf_push(context->call_fixups, fixup);
                } break;

                case func_kind_imported: {
                    buf_push(context->seg_text, 0xff);
                    buf_push(context->seg_text, 0x15);
                    buf_push(context->seg_text, 0xde);
                    buf_push(context->seg_text, 0xad);
                    buf_push(context->seg_text, 0xbe);
                    buf_push(context->seg_text, 0xef);

                    Fixup fixup = {0};
                    fixup.text_location = buf_length(context->seg_text) - sizeof(i32);
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
                if (op->call.target.as_reference) {
                    instruction_mov_mem(context, func, mov_from, op->call.target, reg_rcx, POINTER_SIZE);
                    instruction_mov_pointer(&context->seg_text, mov_to, reg_rcx, reg_rax, primitive_size_of(op->primitive));
                } else {
                    instruction_mov_mem(context, func, mov_to, op->call.target, reg_rax, primitive_size_of(op->primitive));
                }
            }
        } break;

        case op_cast: {
            if (primitive_is_signed(op->primitive) || primitive_is_signed(op->cast.old_primitive)) {
                // TODO zero-extend for signed types!
                unimplemented();
            }

            u8 new_size = primitive_size_of(op->primitive);
            u8 old_size = primitive_size_of(op->cast.old_primitive);

            if (new_size > old_size) {
                if (op->cast.local.as_reference) unimplemented(); // TODO
                instruction_mov_mem(context, func, mov_from, op->cast.local, reg_rax, old_size);
                instruction_mov_mem(context, func, mov_to, op->cast.local, reg_rax, new_size);
            }
        } break;

        case op_jump: {
            u64 big_jump_text_location;

            if (op->jump.conditional) {
                instruction_load_local(context, func, op->jump.condition, reg_rcx, 1);
                instruction_xor_reg_imm(&context->seg_text, reg_rcx, 1, 1);
                instruction_zero_extend_byte(&context->seg_text, reg_rcx, 8);
                u64 small_jump_text_location = instruction_jmp_rcx_zero(&context->seg_text);
                u64 small_jump_from = buf_length(context->seg_text);
                big_jump_text_location = instruction_jmp_i32(&context->seg_text);
                u64 small_jump_to = buf_length(context->seg_text);

                u8 small_jump_size = small_jump_to - small_jump_from;
                assert(small_jump_size < I8_MAX);
                context->seg_text[small_jump_text_location] = small_jump_size;
            } else {
                big_jump_text_location = instruction_jmp_i32(&context->seg_text);
            }

            // NB The way we currently do 'Jump_Fixup's depends on the jmp being the last instruction
            // generated for the given op (so rip is at the start of the next op afterwards). This could
            // be changed trivially though.

            Jump_Fixup fixup = {0};
            fixup.from_op = op_index;
            fixup.to_op = op->jump.to_op;
            fixup.text_location = big_jump_text_location;
            buf_push(context->jump_fixups, fixup);
        } break;

        case op_load_data: {
            instruction_lea_data(context, op->load_data.data_offset, op->load_data.writable, reg_rax);

            Local local = op->load_data.local;
            if (local.as_reference) {
                instruction_mov_mem(context, func, mov_from, local, reg_rcx, POINTER_SIZE);
                instruction_mov_pointer(&context->seg_text, mov_to, reg_rcx, reg_rax, POINTER_SIZE);
            } else {
                instruction_mov_mem(context, func, mov_to, local, reg_rax, POINTER_SIZE);
            }
        } break;

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

        func->body.text_start = buf_length(context->seg_text);

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
        u32 max_params = 4;
        bool any_params = false;
        for (u32 i = 0; i < func->body.op_count; i += 1) {
            Op* op = &func->body.ops[i];
            if (op->kind == op_call) {
                Func* callee = &context->funcs[op->call.func_index];

                any_params = true;
                max_params = max(max_params, callee->signature.param_count);
            }
        }
        if (any_params) {
            offset += max_params * POINTER_SIZE;
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
            buf_push(context->seg_text, 0x48);
            buf_push(context->seg_text, 0x83);
            buf_push(context->seg_text, 0xec);
            str_push_integer(&context->seg_text, sizeof(i8), (u8) func->body.stack_layout.total_bytes);
        } else {
            buf_push(context->seg_text, 0x48);
            buf_push(context->seg_text, 0x81);
            buf_push(context->seg_text, 0xec);
            str_push_integer(&context->seg_text, sizeof(i32), func->body.stack_layout.total_bytes);
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
                instruction_mov_mem(context, func, mov_to, local, reg, (u8) operand_size);
            }
        }

        // Write out operations
        for (u32 i = 0; i < func->body.op_count; i += 1) {
            machinecode_for_op(context, func, i);
        }
        assert(func->body.ops[func->body.op_count].kind == op_end_of_function);
        func->body.ops[func->body.op_count].text_start = buf_length(context->seg_text);

        buf_foreach (Jump_Fixup, fixup, context->jump_fixups) {
            u64 from_instruction = func->body.ops[fixup->from_op + 1].text_start;
            u64 to_instruction   = func->body.ops[fixup->to_op].text_start;

            i32* jump = (i32*) (context->seg_text + fixup->text_location);
            assert(*jump == 0xdeadbeef);

            if (from_instruction > to_instruction) {
                u64 diff = from_instruction - to_instruction;
                assert(diff <= I32_MAX);
                *jump = -((i32) diff);
            } else {
                u64 diff = to_instruction - from_instruction;
                assert(diff < I32_MAX);
                *jump = (i32) diff;
            }
        }
        buf_clear(context->jump_fixups);

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
                instruction_mov_mem(context, func, mov_from, output_local, reg_rax, operand_size);
            }
        } else {
            instruction_general_reg_reg(&context->seg_text, instruction_xor, reg_rax, reg_rax, POINTER_SIZE);
        }

        // Reset stack
        if (func->body.stack_layout.total_bytes < I8_MAX) {
            buf_push(context->seg_text, 0x48);
            buf_push(context->seg_text, 0x83);
            buf_push(context->seg_text, 0xc4);
            buf_push(context->seg_text, func->body.stack_layout.total_bytes);
        } else {
            buf_push(context->seg_text, 0x48);
            buf_push(context->seg_text, 0x81);
            buf_push(context->seg_text, 0xc4);
            str_push_integer(&context->seg_text, sizeof(i32), func->body.stack_layout.total_bytes);
        }
        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("add rsp, %x\n", (u64) func->body.stack_layout.total_bytes);
        #endif

        // Return to caller
        buf_push(context->seg_text, 0xc3);
        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("ret\n");
        #endif
    }

    // Call fixups
    buf_foreach (Call_Fixup, fixup, context->call_fixups) {
        i32* target = (i32*) (context->seg_text + fixup->text_location);
        assert(*target == 0xefbeadde);

        Func* callee = &context->funcs[fixup->func_index];
        assert(callee->kind == func_kind_normal);

        u32 jump_to = callee->body.text_start;
        u32 jump_from = fixup->text_location + sizeof(i32);
        i32 jump_by = ((i32) jump_to) - ((i32) jump_from);
        *target = jump_by;
    }

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

    IO_Result read_result = read_entire_file(path, &file, &file_length);
    if (read_result != io_ok) {
        printf("Couldn't open \"%s\": %s\n", path, io_result_message(read_result));
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
            printf("Couldn't find %s in \"%s\"\n", name, path);
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
    enum { MAX_SECTION_COUNT = 5 }; // So we can use it as an array length

    u64 text_length = buf_length(context->seg_text);
    u64 rodata_length = buf_length(context->seg_rodata);
    u64 rwdata_length = buf_length(context->seg_rwdata);

    u32 section_count = 3;
    if (rwdata_length > 0) section_count += 1;
    if (rodata_length > 0) section_count += 1;

    u64 in_file_alignment = 0x200;
    u64 in_memory_alignment = 0x1000;
    u64 dos_prepend_size = 200;
    u64 total_header_size = dos_prepend_size + sizeof(COFF_Header) + sizeof(Image_Header) + section_count*sizeof(Section_Header);

    // TODO pdata is completly messed up. It is supposed to be pointing to some
    // unwind info, which we deleted by accident. We have to figure out how to
    // generate that info. We can't test that without first having some codegen
    // though...
    typedef struct Pdata_Entry { u32 begin_address, end_address, unwind_address; } Pdata_Entry; // Proper format for x64!!
    u8 pdata[12]  = { 0x0, 0x10, 0x0, 0x0, 0xa5, 0x10, 0x0, 0x0, 0x10, 0x21, 0x0, 0x0 };
    u64 pdata_length = 12;

    // Figure out placement and final size
    // NB sections data needs to be in the same order as section headers!
    u64 header_space = round_to_next(total_header_size, in_file_alignment);

    u64 text_file_start   = header_space;
    u64 rwdata_file_start = text_file_start   + round_to_next(text_length,   in_file_alignment);
    u64 rodata_file_start = rwdata_file_start + round_to_next(rwdata_length, in_file_alignment);
    u64 pdata_file_start  = rodata_file_start + round_to_next(rodata_length, in_file_alignment);
    u64 idata_file_start  = pdata_file_start  + round_to_next(pdata_length,  in_file_alignment);

    u64 text_memory_start   = round_to_next(total_header_size, in_memory_alignment);
    u64 rwdata_memory_start = text_memory_start   + round_to_next(text_length,   in_memory_alignment);
    u64 rodata_memory_start = rwdata_memory_start + round_to_next(rwdata_length, in_memory_alignment);
    u64 pdata_memory_start  = rodata_memory_start + round_to_next(rodata_length, in_memory_alignment);
    u64 idata_memory_start  = pdata_memory_start  + round_to_next(pdata_length,  in_memory_alignment);

    // Verify that fixups are not bogus data, so we don't have to do that later...
    for (u64 i = 0; i < buf_length(context->fixups); i += 1) {
        Fixup* fixup = &context->fixups[i];

        if (fixup->text_location >= text_length) {
            panic("Can't apply fixup at %x which is beyond end of text section at %x\n", fixup->text_location, text_length);
        }

        i32 text_value = *((u32*) (context->seg_text + fixup->text_location));
        if (text_value != 0xefbeadde /* 0xdeadbeef, but in big endian */) {
            panic("All fixup override locations should be set to { 0xde, 0xad, 0xbe, 0xef } as a sentinel. Found %x instead\n", text_value);
        }

        switch (fixup->kind) {
            case fixup_imported_function: {
                u32 l = fixup->import_index.library;
                u32 f = fixup->import_index.function;

                assert(l < buf_length(context->imports));
                assert(f < buf_length(context->imports[l].function_names));
            } break;

            case fixup_rwdata: assert(fixup->data_offset < rwdata_length); break;
            case fixup_rodata: assert(fixup->data_offset < rodata_length); break;

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

            i32* text_value = (i32*) (context->seg_text + fixup->text_location);
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
        i32* text_value = (u32*) (context->seg_text + fixup->text_location);

        switch (fixup->kind) {
            case fixup_imported_function: break;

            case fixup_rodata: {
                *text_value = rodata_memory_start + fixup->data_offset;
                *text_value -= (text_memory_start + fixup->text_location + sizeof(i32)); // make relative
            } break;

            case fixup_rwdata: {
                *text_value = rwdata_memory_start + fixup->data_offset;
                *text_value -= (text_memory_start + fixup->text_location + sizeof(i32)); // make relative
            } break;

            default: assert(false);
        }
    }

    // Set up section headers
    Section_Header section_headers[MAX_SECTION_COUNT] = {0};
    u32 section_index = 0;

    Section_Header* text_header = &section_headers[section_index];
    section_index += 1;
    mem_copy(".text", text_header->name, 5);
    text_header->flags = SECTION_FLAGS_EXECUTE | SECTION_FLAGS_READ | SECTION_FLAGS_CODE;
    text_header->virtual_size = text_length;
    text_header->virtual_address = text_memory_start;
    text_header->size_of_raw_data = round_to_next(text_length, in_file_alignment);
    text_header->pointer_to_raw_data = text_file_start;

    if (rwdata_length > 0) {
        Section_Header* rwdata_header = &section_headers[section_index];
        section_index += 1;
        mem_copy(".data", rwdata_header->name, 5);
        rwdata_header->flags = SECTION_FLAGS_READ | SECTION_FLAGS_WRITE | SECTION_FLAGS_INITIALIZED_DATA;
        rwdata_header->virtual_size = rwdata_length;
        rwdata_header->virtual_address = rwdata_memory_start;
        rwdata_header->size_of_raw_data = round_to_next(rwdata_length, in_file_alignment);
        rwdata_header->pointer_to_raw_data = rwdata_file_start;
    }

    if (rodata_length > 0) {
        Section_Header* rodata_header = &section_headers[section_index];
        section_index += 1;
        mem_copy(".rdata", rodata_header->name, 6);
        rodata_header->flags = SECTION_FLAGS_READ | SECTION_FLAGS_INITIALIZED_DATA;
        rodata_header->virtual_size = rodata_length;
        rodata_header->virtual_address = rodata_memory_start;
        rodata_header->size_of_raw_data = round_to_next(rodata_length, in_file_alignment);
        rodata_header->pointer_to_raw_data = rodata_file_start;
    }

    Section_Header* pdata_header = &section_headers[section_index];
    section_index += 1;
    mem_copy(".pdata", pdata_header->name, 6);
    pdata_header->flags = SECTION_FLAGS_READ | SECTION_FLAGS_INITIALIZED_DATA;
    pdata_header->virtual_size = pdata_length;
    pdata_header->virtual_address = pdata_memory_start;
    pdata_header->size_of_raw_data = round_to_next(pdata_length, in_file_alignment);
    pdata_header->pointer_to_raw_data = pdata_file_start;

    Section_Header* idata_header = &section_headers[section_index];
    section_index += 1;
    mem_copy(".idata", idata_header->name, 6);
    idata_header->flags = SECTION_FLAGS_READ | SECTION_FLAGS_WRITE | SECTION_FLAGS_INITIALIZED_DATA;
    idata_header->virtual_size = idata_length;
    idata_header->virtual_address = idata_memory_start;
    idata_header->size_of_raw_data = round_to_next(idata_length, in_file_alignment);
    idata_header->pointer_to_raw_data = idata_file_start;

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

    // TODO switching this disables address-space randomization, which might be nice for debugging
    #if 1
    image.dll_flags =
        IMAGE_DLL_FLAGS_TERMINAL_SERVER_AWARE |
        IMAGE_DLL_FLAGS_NX_COMPAT |
        IMAGE_DLL_FLAGS_DYNAMIC_BASE |
        //IMAGE_DLL_FLAGS_NO_SEH |
        IMAGE_DLL_FLAGS_64_BIT_VA;
    #else
    image.dll_flags = 0;
    #endif

    image.file_alignment = in_file_alignment;
    image.section_alignment = in_memory_alignment;
    image.size_of_headers = header_space;
    coff.section_count = section_count;

    image.size_of_code = text_length;
    image.size_of_initialized_data = rodata_length + rwdata_length + idata_length + pdata_length;
    image.size_of_uninitialized_data = 0;

    u32 main_func_index = find_func(context, string_table_search(context->string_table, "main")); 
    if (main_func_index == STRING_TABLE_NO_MATCH) {
        panic("No main function");
    }
    u32 main_text_start = context->funcs[main_func_index].body.text_start;
    image.entry_point = text_memory_start + main_text_start;

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

    // Write headers
    u64 header_offset = dos_prepend_size;

    mem_copy((u8*) &coff, output_file + header_offset, sizeof(COFF_Header));
    header_offset += sizeof(COFF_Header);

    mem_copy((u8*) &image, output_file + header_offset, sizeof(Image_Header));
    header_offset += sizeof(Image_Header);

    mem_copy((u8*) section_headers, output_file + header_offset, section_count * sizeof(Section_Header));

    // Write data
    mem_copy(context->seg_text, output_file + text_file_start, text_length);
    mem_copy(context->seg_rwdata, output_file + rwdata_file_start, rwdata_length);
    mem_copy(context->seg_rodata, output_file + rodata_file_start, rodata_length);
    mem_copy(pdata, output_file + pdata_file_start, pdata_length);
    mem_copy(idata, output_file + idata_file_start, idata_length);

    IO_Result result = write_entire_file(path, output_file, file_image_size);
    if (result != io_ok) {
        printf("Couldn't write \"%s\": %s\n", path, io_result_message(result));
        return false;
    }

    buf_free(idata);

    return true;
}


void print_verbose_info(Context* context) {
    printf("\n%u functions:\n", (u64) buf_length(context->funcs));
    buf_foreach (Func, func, context->funcs) {
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

            printf("    Statements:\n");
            print_stmts(context, func, func->body.first_stmt, 2);
        } else if (func->kind == func_kind_imported) {
            printf("    (Imported)\n");
        } else {
            assert(false);
        }
    }
}

bool build_file_to_executable(u8* source_path, u8* exe_path) {
    Context context = {0};
    if (!build_ast(&context, source_path)) return false;
    if (!typecheck(&context)) return false;
    //print_verbose_info(&context);
    build_intermediate(&context);
    build_machinecode(&context);
    if (!write_executable(exe_path, &context)) return false;

    {
        u64 total_ops = 0;
        buf_foreach (Func, func, context.funcs) {
            if (func->kind == func_kind_normal) {
                total_ops += func->body.op_count;
            }
        }

        printf("%u intermediate ops, %u bytes of machine code\n", total_ops, buf_length(context.seg_text));
    }

    return true;
}

bool run_executable(u8* exe_path) {
    STARTUPINFO startup_info = {0};
    startup_info.size = sizeof(STARTUPINFO);
    PROCESSINFO process_info = {0};
    bool result = CreateProcessA(exe_path, "", null, null, false, 0, null, null, &startup_info, &process_info);
    if (!result) {
        printf("Failed to start generated executable\n");
        return false;
    }

    WaitForSingleObject(process_info.process, 0xffffffff);

    return true;
}

void compile_and_run(u8* source_path, u8* exe_path) {
    printf("    Compiling %s to %s\n", source_path, exe_path);
    if (build_file_to_executable(source_path, exe_path)) {
        printf("    Running %s:\n", exe_path);
        run_executable(exe_path);
    }
}

void main() {
    i64 start_time = perf_time();

    compile_and_run("W:/asm2/code.foo", "out.exe");

    i64 end_time = perf_time();
    printf("Compile + run in %i ms\n", (end_time - start_time) * 1000 / perf_frequency);
}
