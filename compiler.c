
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
#define f32 float
#define f64 double

#define U8_MAX 0xff
#define U16_MAX 0xffff
#define U32_MAX 0xffffffff
#define U64_MAX 0xffffffffffffffff

#define I8_MAX 127
#define I8_MIN -128
#define I16_MAX 32767
#define I16_MIN -32768
#define I32_MAX 2147483647ull
#define I32_MIN -2147483648ll

#define max(a, b)  ((a) > (b)? (a) : (b))
#define min(a, b)  ((a) > (b)? (b) : (a))

int _fltused; // To make floating point work without the c runtime

#include <stdarg.h>

// Our substitute for windows.h
#if WINDOWS
    // NB Im not sure if we need these, stuff works just fine without them it seems...
    #define WINAPI_PRE  __declspec(dllimport)
    #define WINAPI_POST //__stdcall // Is ignored on x64, but needed on x86

    typedef void* Handle;

    WINAPI_PRE void WINAPI_POST ExitProcess(u32 exit_code);
    WINAPI_PRE u32 WINAPI_POST GetLastError();

    // NB bytes must be u32 on win32
    WINAPI_PRE void* WINAPI_POST HeapAlloc(Handle heap, u32 flags, u64 bytes);
    WINAPI_PRE void* WINAPI_POST HeapReAlloc(Handle heap, u32 flags, void* memory, u64 bytes);
    WINAPI_PRE bool  WINAPI_POST HeapFree(Handle heap, u32 flags, void* memory);
    WINAPI_PRE Handle WINAPI_POST GetProcessHeap();


    WINAPI_PRE Handle WINAPI_POST GetStdHandle(u32 key);
    #define STD_INPUT_HANDLE  ((u32)-10)
    #define STD_OUTPUT_HANDLE ((u32)-11)
    #define STD_ERROR_HANDLE  ((u32)-12)

    WINAPI_PRE u32 WINAPI_POST GetTempPathA(u32 buffer_length, u8* buffer);

    WINAPI_PRE Handle WINAPI_POST CreateFileA(
        u8* file_name,              // Zero-terminated string
        u32 access,                 // GENERIC_READ/WRITE/EXECUTE
        u32 share_mode,             // 0
        void* security_attributes,  // We don't use this, so it can be null
        u32 creation_disposition,   // OPEN_EXISTING, etc
        u32 flags_and_attributes,   // FILE_ATTRIBUTE_NORMAL
        Handle template_file        // null
    );

    WINAPI_PRE bool WINAPI_POST GetFileSizeEx(
        Handle file,
        i64* file_size // Unix timestamp
    );

    WINAPI_PRE bool WINAPI_POST ReadFile(
        Handle file,
        void* buffer,
        u32 bytes_to_read,
        u32* bytes_read,
        void* overlapped // We don't use this, let it be null
    );

    WINAPI_PRE bool WINAPI_POST WriteFile(
        Handle file,
        void* buffer,
        u32 bytes_to_write,
        u32* bytes_written,
        void* overlapped // We don't use this, let it be null
    );

    #define GENERIC_READ    0x80000000
    #define GENERIC_WRITE   0x40000000
    #define GENERIC_EXECUTE 0x20000000
    #define GENERIC_ALL     0x10000000

    #define FILE_SHARE_READ   0x1
    #define FILE_SHARE_WRITE  0x2
    #define FILE_SHARE_DELETE 0x4

    #define CREATE_NEW 1
    #define CREATE_ALWAYS 2
    #define OPEN_EXISTING 3
    #define OPEN_ALWAYS 4
    #define TRUNCATE_EXISTING 5

    #define INVALID_HANDLE_VALUE  ((Handle)-1)
    #define FILE_ATTRIBUTE_NORMAL 0x80

    typedef struct Startup_Info Startup_Info;
    typedef struct Process_Info Process_Info;

    WINAPI_PRE bool WINAPI_POST CreateProcessA(
      u8* application_name,
      u8* arguments,
      void* process_attributes,
      void* thread_attributes,
      bool inherit_handles,
      u32 creation_flags,
      void* environment,
      u8* current_directory,
      Startup_Info* startup_info,
      Process_Info* process_info
    );

    struct Startup_Info {
        u32 size;
        void* reserved_1;
        u8* desktop;
        u8* title;
        u32 x, y;
        u32 width, height;
        u32 console_width, console_height;
        u32 fill_attribute;
        u32 flags;
        u16 show_window;
        u16 reserved_2;
        void* reserved_3;
        Handle stdin;
        Handle stdout;
        Handle stderr;
    };

    struct Process_Info {
        Handle process;
        Handle thread;
        u32 process_id;
        u32 thread_id;
    };

    WINAPI_PRE u32 WINAPI_POST WaitForSingleObject(Handle handle, u32 milliseconds);

    // NB these functions in reality take a LARGE_INTEGER*, but LARGE_INTEGER is a union of a single
    // 64 bit int and two 32 bit ints, to make the function work on windows. That means we can just use
    // a single 64 bit int.
    WINAPI_PRE bool WINAPI_POST QueryPerformanceCounter(i64* counter);
    WINAPI_PRE bool WINAPI_POST QueryPerformanceFrequency(i64* frequency);

    WINAPI_PRE void WINAPI_POST DebugBreak();
    WINAPI_PRE void WINAPI_POST OutputDebugStringA(u8* string);


    typedef struct System_Info {
        union {
            u32  oem_id;
            struct {
                u16 processor_architecture;
                u16 reserved;
            };
        };
        u32 page_size;
        void* min_app_address;
        void* max_app_address;
        u32* active_processor_mask;
        u32 processor_count;
        u32 processor_type;
        u32 alloc_granularity;
        u16 processor_level;
        u16 processor_revision;
    } System_Info;

    WINAPI_PRE void WINAPI_POST GetSystemInfo(System_Info* info);
#endif

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

#define assert(x)        ((x)? (null) : (printf("%s(%u): assert(%s)\n", __FILE__, (u64) __LINE__, #x), printf_flush(), trap_or_exit(), null))
#define panic(x, ...)    (printf("%s(%u): Panic: ", __FILE__, (u64) __LINE__), printf(x, __VA_ARGS__), printf_flush(), trap_or_exit())
#define unimplemented()  (printf("%s(%u): Reached unimplemented code\n", __FILE__, (u64) __LINE__), printf_flush(), trap_or_exit(), null)

// Code that is inserted at the start of every user program
#define PRELOAD_QUOTE(...) #__VA_ARGS__
u8 *preload_code_text = PRELOAD_QUOTE(

enum Type_Kind (u8) { // We rely on this enum being one byte large!
    VOID    = 1,
    BOOL    = 2,
    U8      = 4,
    U16     = 5,
    U32     = 6,
    U64     = 7,
    I8      = 8,
    I16     = 9,
    I32     = 10,
    I64     = 11,
    F32     = 13,
    F64     = 14,
    POINTER = 15,
    ARRAY   = 16,
    STRUCT  = 18,
    ENUM    = 19,
}

);
#undef PRELOAD_QUOTE

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

void mem_fill(u8* ptr, u8 value, u64 count) {
    u64 big_value = ((u64) value) | (((u64) value) << 8);
    big_value = big_value | (big_value << 16);
    big_value = big_value | (big_value << 32);

    while (count >= 8) {
        *((u64*) ptr) = big_value;
        ptr += 8;
        count -= 8;
    }

    while (count >= 1) {
        *ptr = value;
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

#define buf_foreach(t, x, b)     for (t* x = (b); x != buf_end(b); x += 1)
#define buf_foreach_remove(b, x) (_buf_remove((b), (x), sizeof(*(b))), (x) -= 1)

void *_buf_grow(void *buf, u64 new_len, u64 element_size) {
    Buf_Header *new_header;

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

        Buf_Header *old_header = _buf_header(buf);
        new_header = (Buf_Header*) realloc(old_header, new_bytes);
        new_header->capacity = new_capacity;
    }

    return new_header->buffer;
}

void _buf_remove(void *buf, void *element, u64 element_size) {
    u64 length = _buf_header(buf)->length;
    _buf_header(buf)->length = length - 1;

    u64 index = ((u8*) element - (u8*) buf) / element_size;
    assert((((u8*) element - (u8*) buf) % element_size) == 0);

    mem_copy(((u8*) element) + element_size, (u8*) element, (length - index) * element_size);
}

// Appends a c-string onto a stretchy buffer. Does not push the null terminator!
void str_push_cstr(u8 **buf, u8 *cstr) {
    u64 cstr_length = str_length(cstr);
    if (cstr_length == 0) return;

    _buf_fit(*buf, cstr_length);
    u64* buf_length = &_buf_header(*buf)->length;
    mem_copy(cstr, *buf + *buf_length, cstr_length);
    *buf_length += cstr_length;
}

void str_push_str(u8 **buf, u8 *str, u64 length) {
    _buf_fit(*buf, length);
    u64* buf_length = &_buf_header(*buf)->length;
    mem_copy(str, *buf + *buf_length, length);
    *buf_length += length;
}

void str_push_zeroes(u8 **buf, u64 length) {
    _buf_fit(*buf, length);
    u64* buf_length = &_buf_header(*buf)->length;
    mem_clear(*buf + *buf_length, length);
    *buf_length += length;
}

void str_push_integer(u8 **buf, u8 bytes, u64 value) {
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

u8* string_table_access_and_get_length(u8* table, u32 index, u32* length) {
    u64 table_length = buf_length(table);
    assert(index < table_length);

    *length = table[index];
    assert(table[index + *length + 1] == 0); // Invalid string index

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
u8 char_for_digit(u8 c);

void printf_flush() {
    #ifdef DEBUG
    buf_push(printf_buf, '\0');
    OutputDebugStringA(printf_buf);
    buf_pop(printf_buf);
    #endif

    print(printf_buf, buf_length(printf_buf));

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

                case 'f': {
                    f64 value = va_arg(args, f64);
                    u64 bits = *((u64*) &value);

                    buf_push(printf_buf, '0');
                    buf_push(printf_buf, 'x');
                    printf_integer(bits, 16);
                } break;

                case 'x': {
                    buf_push(printf_buf, '0');
                    buf_push(printf_buf, 'x');
                    u64 value = va_arg(args, u64);
                    printf_integer(value, 16);
                } break;

                case 'b': {
                    u8 byte = va_arg(args, u8);

                    u8 hi = byte >> 4;
                    u8 lo = byte & 0x0f;

                    buf_push(printf_buf, char_for_digit(hi));
                    buf_push(printf_buf, char_for_digit(lo));
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

        buf_push(printf_buf, char_for_digit(digit));

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

u8 char_for_digit(u8 c) {
    if (c <= 9) {
        return '0' + c;
    } else {
        return 'a' + (c - 10);
    }
}

// IO stuff

u8 *path_get_folder(Arena *arena, u8 *path) {
    u32 last_separator = 0;

    u8 *p = path;
    while (*p != 0) {
        if (*p == '/' || *p == '\\') {
            last_separator = p - path;
        }
        p += 1;
    }

    u8* new_path = arena_alloc(arena, last_separator + 2);
    mem_copy(path, new_path, last_separator + 1);
    new_path[last_separator + 1] = '\0';

    return new_path;
}

u8 *path_join(Arena *arena, u8 *a, u8 *b) {
    u64 a_length = str_length(a);
    u64 b_length = str_length(b);
    u8 *new_path = arena_alloc(arena, a_length + b_length + 1);

    u64 b_start = a_length;
    if (a[a_length - 1] != '/' && a[a_length - 1] != '\\') {
        new_path[b_start] = '/';
        b_start += 1;
    }

    mem_copy(a, new_path, a_length);
    mem_copy(b, new_path + b_start, b_length + 1);

    return new_path;
}

typedef enum IO_Result {
    IO_OK = 0,

    IO_ERROR,
    IO_NOT_FOUND,
    IO_ALREADY_OPEN,
} IO_Result;

u8* io_result_message(IO_Result result) {
    switch (result) {
        case IO_OK:             return "Ok";
        case IO_ERROR:          return "IO Error";
        case IO_NOT_FOUND:      return "File not found";
        case IO_ALREADY_OPEN:   return "File is open in another program";

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
            default: return IO_ERROR;
        }
    } else {
        return IO_OK;
    }
}

IO_Result read_entire_file(u8* file_name, u8** contents, u32* length) {
    Handle file = CreateFileA(file_name, GENERIC_READ, 0, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
    if (file == INVALID_HANDLE_VALUE) {
        u32 error_code = GetLastError();
        switch (error_code) {
            case 2:  return IO_NOT_FOUND; // File not found
            case 3:  return IO_NOT_FOUND; // Path not found
            default: return IO_ERROR;
        }
    }

    i64 file_size;
    if (!GetFileSizeEx(file, &file_size)) {
        u32 error_code = GetLastError();
        switch (error_code) {
            default: return IO_ERROR;
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
            default: return IO_ERROR;
        }
    }

    *length = file_size;

    CloseHandle(file);

    return IO_OK;
}

IO_Result write_entire_file(u8* file_name, u8* contents, u32 length) {
    Handle file = CreateFileA(file_name, GENERIC_WRITE, 0, null, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, null);
    if (file == INVALID_HANDLE_VALUE) {
        u32 error_code = GetLastError();
        switch (error_code) {
            case 32: return IO_ALREADY_OPEN;
            default: return IO_ERROR;
        }
    }

    u32 written = 0;
    i32 success = WriteFile(file, contents, length, &written, null);
    if (!success || written != length) {
        u32 error_code = GetLastError();
        switch (error_code) {
            default: return IO_ERROR;
        }
    }

    CloseHandle(file);

    return IO_OK;
}


typedef struct File_Pos {
    u8* file_name;
    u32 line;
} File_Pos;

enum { KEYWORD_COUNT = 15 };

typedef struct Token {
    enum {
        TOKEN_END_OF_STREAM = 0,

        TOKEN_BRACKET_ROUND_OPEN   = '(',
        TOKEN_BRACKET_ROUND_CLOSE  = ')',
        TOKEN_BRACKET_SQUARE_OPEN  = '[',
        TOKEN_BRACKET_SQUARE_CLOSE = ']',
        TOKEN_BRACKET_CURLY_OPEN   = '{',
        TOKEN_BRACKET_CURLY_CLOSE  = '}',
        TOKEN_SEMICOLON = ';',
        TOKEN_COMMA     = ',',
        TOKEN_DOT       = '.',
        TOKEN_COLON     = ':',

        TOKEN_ADD = '+',
        TOKEN_SUB = '-',
        TOKEN_MUL = '*', // also used for pointers
        TOKEN_DIV = '/',
        TOKEN_MOD = '%', // TODO

        TOKEN_AND = '&',
        TOKEN_NOT = '!', // TODO
        TOKEN_OR  = '|', // TODO
        TOKEN_XOR = '^', // TODO

        TOKEN_GREATER = '>',
        TOKEN_LESS = '<',
        TOKEN_ASSIGN = '=',

        __TOKEN_SEPARATOR = 128, // Values before this use literal ascii character codes, to simplify some parsing

        TOKEN_STATIC_ACCESS, // "::"

        TOKEN_GREATER_OR_EQUAL, // ">="
        TOKEN_LESS_OR_EQUAL, // "<="
        TOKEN_EQUAL, // "=="
        TOKEN_NOT_EQUAL, // "!="
        TOKEN_ARROW, // "->"

        TOKEN_SHIFT_LEFT, // "<<", TODO
        TOKEN_SHIFT_RIGHT, // ">>", TODO

        TOKEN_ADD_ASSIGN, // "+="
        TOKEN_SUB_ASSIGN, // "-="

        TOKEN_IDENTIFIER,
        TOKEN_LITERAL_INT,
        TOKEN_LITERAL_FLOAT,
        TOKEN_STRING,

        TOKEN_KEYWORD_FN,
        TOKEN_KEYWORD_EXTERN,
        TOKEN_KEYWORD_LET,
        TOKEN_KEYWORD_IF,
        TOKEN_KEYWORD_ELSE,
        TOKEN_KEYWORD_FOR,
        TOKEN_KEYWORD_RETURN,
        TOKEN_KEYWORD_CONTINUE,
        TOKEN_KEYWORD_BREAK,
        TOKEN_KEYWORD_STRUCT,
        TOKEN_KEYWORD_ENUM,
        TOKEN_KEYWORD_UNION,
        TOKEN_KEYWORD_NULL,
        TOKEN_KEYWORD_TRUE,
        TOKEN_KEYWORD_FALSE,

        TOKEN_KIND_COUNT,
    } kind;

    union {
        u32 identifier_string_table_index;

        u64 literal_int;
        f64 literal_float;

        struct {
            u8* bytes; // null-terminated
            u64 length;
        } string;

        i32 bracket_offset_to_matching;
    };

    File_Pos pos;
} Token;

u8* TOKEN_NAMES[TOKEN_KIND_COUNT] = {
    [TOKEN_IDENTIFIER] = null,
    [TOKEN_LITERAL_INT] = null,
    [TOKEN_LITERAL_FLOAT] = null,
    [TOKEN_STRING] = null,

    [TOKEN_END_OF_STREAM]        = "end of file",
    [TOKEN_ADD]                  = "+",
    [TOKEN_SUB]                  = "-",
    [TOKEN_MUL]                  = "*",
    [TOKEN_DIV]                  = "/",
    [TOKEN_MOD]                  = "%",
    [TOKEN_AND]                  = "&",
    [TOKEN_OR]                   = "|",
    [TOKEN_NOT]                  = "!",
    [TOKEN_XOR]                  = "^",
    [TOKEN_GREATER]              = ">",
    [TOKEN_GREATER_OR_EQUAL]     = ">=",
    [TOKEN_LESS]                 = "<",
    [TOKEN_LESS_OR_EQUAL]        = "<=",
    [TOKEN_EQUAL]                = "==",
    [TOKEN_NOT_EQUAL]            = "!=",
    [TOKEN_ASSIGN]               = "=",
    [TOKEN_ARROW]                = "->",
    [TOKEN_SHIFT_LEFT]           = "<<",
    [TOKEN_SHIFT_RIGHT]          = ">>",
    [TOKEN_ADD_ASSIGN]           = "+=",
    [TOKEN_SUB_ASSIGN]           = "-=",

    [TOKEN_DOT]                  = "a dot '.'",
    [TOKEN_SEMICOLON]            = "a semicolon ';'",
    [TOKEN_COMMA]                = "a comma ','",
    [TOKEN_COLON]                = "a colon ':'",
    [TOKEN_STATIC_ACCESS]        = "::",

    [TOKEN_BRACKET_ROUND_OPEN]   = "an opening parenthesis '('",
    [TOKEN_BRACKET_ROUND_CLOSE]  = "a closing parenthesis ')'",
    [TOKEN_BRACKET_SQUARE_OPEN]  = "an opening square bracket '['",
    [TOKEN_BRACKET_SQUARE_CLOSE] = "a closing square bracket ']'",
    [TOKEN_BRACKET_CURLY_OPEN]   = "an opening curly brace '{'",
    [TOKEN_BRACKET_CURLY_CLOSE]  = "a closing curly brace '}'",

    [TOKEN_KEYWORD_FN]           = "fn",
    [TOKEN_KEYWORD_EXTERN]       = "extern",
    [TOKEN_KEYWORD_LET]          = "let",
    [TOKEN_KEYWORD_IF]           = "if",
    [TOKEN_KEYWORD_ELSE]         = "else",
    [TOKEN_KEYWORD_FOR]          = "for",
    [TOKEN_KEYWORD_RETURN]       = "return",
    [TOKEN_KEYWORD_CONTINUE]     = "continue",
    [TOKEN_KEYWORD_BREAK]        = "break",
    [TOKEN_KEYWORD_STRUCT]       = "struct",
    [TOKEN_KEYWORD_ENUM]         = "enum",
    [TOKEN_KEYWORD_UNION]        = "union",
    [TOKEN_KEYWORD_TRUE]         = "true",
    [TOKEN_KEYWORD_FALSE]        = "false",
    [TOKEN_KEYWORD_NULL]         = "null",
};


typedef enum Builtin_Func {
    BUILTIN_INVALID = 0,

    BUILTIN_TYPE_INFO_OF_TYPE,
    BUILTIN_TYPE_INFO_OF_VALUE,
    BUILTIN_ENUM_MEMBER_NAME,
    BUILTIN_ENUM_LENGTH,
    BUILTIN_CAST,

    BUILTIN_COUNT,
} Builtin_Func;


// NB NB NB This MUST always be synchronized with the values in preload.foo
typedef enum Type_Kind {
    TYPE_INVALID = 0,
    TYPE_VOID = 1,
    TYPE_BOOL = 2,

    TYPE_U8  = 4,
    TYPE_U16 = 5,
    TYPE_U32 = 6,
    TYPE_U64 = 7,
    TYPE_I8  = 8,
    TYPE_I16 = 9,
    TYPE_I32 = 10,
    TYPE_I64 = 11,

    TYPE_F32 = 13,
    TYPE_F64 = 14,

    TYPE_POINTER = 15,
    TYPE_ARRAY = 16,
    TYPE_UNRESOLVED_NAME = 17,
    TYPE_STRUCT = 18,
    TYPE_ENUM = 19,

    TYPE_KIND_COUNT = 20,
} Type_Kind;

enum { POINTER_SIZE = 8 };
Type_Kind DEFAULT_INT_TYPE   = TYPE_I64;
Type_Kind DEFAULT_FLOAT_TYPE = TYPE_F32;

u8* PRIMITIVE_NAMES[TYPE_KIND_COUNT] = {
    [TYPE_VOID] = "void",
    [TYPE_BOOL] = "bool",

    [TYPE_U8]  = "u8",
    [TYPE_U16] = "u16",
    [TYPE_U32] = "u32",
    [TYPE_U64] = "u64",
    [TYPE_I8]  = "i8",
    [TYPE_I16] = "i16",
    [TYPE_I32] = "i32",
    [TYPE_I64] = "i64",

    [TYPE_F32] = "f32",
    [TYPE_F64] = "f64",

    [TYPE_INVALID]          = "<invalid>",
    [TYPE_POINTER]          = "<pointer>",
    [TYPE_ARRAY]            = "<array>",

    [TYPE_UNRESOLVED_NAME]  = "<unresolved>",
    [TYPE_STRUCT]           = "<struct>",
    [TYPE_ENUM]             = "<enum>",
};


#define TYPE_FLAG_SIZE_NOT_COMPUTED 0x01
#define TYPE_FLAG_UNRESOLVED        0x02

typedef struct Type Type;
typedef struct Type_List Type_List;

struct Type {
    Type_Kind kind;
    u32 flags;

    union {
        u32 primitive_name;
        u32 unresolved_name;

        struct {
            u32 name;

            u32 member_count;
            struct {
                u32 name;
                Type* type;
                i32 offset;
                File_Pos declaration_pos;
            } *members;

            u32 size, align;
        } structure;

        struct {
            u32 name;

            u32 member_count;
            struct {
                u32 name;
                u64 value;
                File_Pos declaration_pos;
            } *members;

            Type_Kind value_primitive;

            u64 name_table_data_offset; // U64_MAX if we haven't generated the table!
            u64 name_table_invalid_offset;
            u64 name_table_entries;
        } enumeration;
        
        struct {
            u64 length;
            Type* of;
        } array;

        Type* pointer_to;
    };

    Type* pointer_type;
    Type_List* array_types;
};

struct Type_List {
    Type type;
    Type_List* next;
};



typedef struct Expr Expr;


// When a var index has this bit set, it refers to a global rather than to a local
// We assume that there will never be more than (2^31 - 1) local variables
#define VAR_INDEX_GLOBAL_FLAG 0x80000000
#define MAX_LOCAL_VARS        0x7fffffff

typedef struct Var {
    u32 name;
    Type* type; // We set this to 'null' to indicate that we want to infer the type
    File_Pos declaration_pos;
} Var;

typedef struct Global_Var {
    Var var;
    Expr* initial_expr;

    u32 data_offset;

    bool checked;
    bool valid;
    bool compute_at_runtime;
} Global_Var;

typedef enum Unary_Op {
    UNARY_OP_INVALID = 0,

    UNARY_NOT,
    UNARY_NEG,
    UNARY_DEREFERENCE,
    UNARY_ADDRESS_OF,

    UNARY_OP_COUNT,
} Unary_Op;

u8* UNARY_OP_SYMBOL[UNARY_OP_COUNT] = {
    [UNARY_NOT]         = "!",
    [UNARY_NEG]         = "-",
    [UNARY_DEREFERENCE] = "*",
    [UNARY_ADDRESS_OF]  = "&",
};

typedef enum Binary_Op {
    BINARY_OP_INVALID = 0,

    BINARY_ADD,
    BINARY_SUB,
    BINARY_MUL,
    BINARY_DIV,
    BINARY_MOD,

    BINARY_EQ,
    BINARY_NEQ,
    BINARY_GT,
    BINARY_GTEQ,
    BINARY_LT,
    BINARY_LTEQ,

    BINARY_OP_COUNT,
} Binary_Op;

u8 BINARY_OP_PRECEDENCE[BINARY_OP_COUNT] = {
    [BINARY_MUL] = 2,
    [BINARY_DIV] = 2,
    [BINARY_MOD] = 2,

    [BINARY_ADD] = 1,
    [BINARY_SUB] = 1,

    [BINARY_NEQ] = 0,
    [BINARY_EQ] = 0,
    [BINARY_GT] = 0,
    [BINARY_GTEQ] = 0,
    [BINARY_LT] = 0,
    [BINARY_LTEQ] = 0,
};

bool BINARY_OP_STRICTLY_LEFT_ASSOCIATIVE[BINARY_OP_COUNT] = {
    [BINARY_SUB] = true, [BINARY_DIV] = true, [BINARY_MOD] = true,
    [BINARY_MUL] = false, [BINARY_ADD] = false,
    [BINARY_NEQ] = false, [BINARY_EQ] = false, [BINARY_GT] = false, [BINARY_GTEQ] = false, [BINARY_LT] = false, [BINARY_LTEQ] = false,
};

bool BINARY_OP_COMPARATIVE[BINARY_OP_COUNT] = {
    [BINARY_SUB] = false, [BINARY_DIV] = false, [BINARY_MOD] = false, [BINARY_MUL] = false, [BINARY_ADD] = false,
    [BINARY_NEQ] = true, [BINARY_EQ] = true, [BINARY_GT] = true, [BINARY_GTEQ] = true, [BINARY_LT] = true, [BINARY_LTEQ] = true,
};

u8* BINARY_OP_SYMBOL[BINARY_OP_COUNT] = {
    [BINARY_ADD] = "+",
    [BINARY_SUB] = "-",
    [BINARY_MUL] = "*",
    [BINARY_DIV] = "/",
    [BINARY_MOD] = "%",
    [BINARY_NEQ]  = "!=",
    [BINARY_EQ]   = "==",
    [BINARY_GT]   = ">",
    [BINARY_GTEQ] = ">=",
    [BINARY_LT]   = "<",
    [BINARY_LTEQ] = "<=",
};


typedef struct Compound_Member {
    Expr* expr;

    enum {
        EXPR_COMPOUND_NO_NAME,
        EXPR_COMPOUND_UNRESOLVED_NAME,
        EXPR_COMPOUND_NAME
    } name_mode;

    union {
        u32 unresolved_name;
        u32 member_index;
    };
} Compound_Member;

#define EXPR_FLAG_UNRESOLVED 0x01
#define EXPR_FLAG_ASSIGNABLE 0x02

typedef enum Expr_Kind {
    EXPR_VARIABLE,
    EXPR_LITERAL,
    EXPR_STRING_LITERAL,
    EXPR_COMPOUND,
    EXPR_BINARY,
    EXPR_UNARY,
    EXPR_CALL,
    EXPR_CAST,
    EXPR_SUBSCRIPT,
    EXPR_MEMBER_ACCESS, // a.b
    EXPR_STATIC_MEMBER_ACCESS, // a::b

    EXPR_TYPE_INFO_OF_TYPE,
    EXPR_TYPE_INFO_OF_VALUE,
    EXPR_ENUM_LENGTH,
    EXPR_ENUM_MEMBER_NAME,
} Expr_Kind;

struct Expr { // 'typedef'd earlier!
    Expr_Kind kind;
    u8 flags;
    Type* type;
    File_Pos pos;

    union {
        union { u32 unresolved_name; u32 index; } variable; // discriminated by EXPR_FLAG_UNRESOLVED

        struct {
            u64 raw_value;
            u64 masked_value;

            enum {
                EXPR_LITERAL_INTEGER,
                EXPR_LITERAL_POINTER,
                EXPR_LITERAL_BOOL,
                EXPR_LITERAL_FLOAT, // 'value' is the bitpattern of a 'f64'
            } kind;
        } literal;

        struct {
            u8* bytes; // null-terminated
            u64 length; // not including trailing \0
        } string;

        struct {
            Compound_Member *content;
            u32 count;
        } compound;

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
            union { u32 unresolved_name; u32 func_index; }; // discriminated by EXPR_FLAG_UNRESOLVED

            Expr** params; // []*Expr
            u32 param_count;
        } call;

        Type* type_info_of_type;
        Expr* type_info_of_value;
        Expr* cast_from;
        Type* enum_length_of;
        Expr* enum_member;

        struct {
            Expr* array;
            Expr* index;
        } subscript;

        struct {
            Expr* parent;
            union { u32 member_name; u32 member_index; }; // discriminated by EXPR_FLAG_UNRESOLVED
        } member_access;

        struct {
            // Both unions discriminated by EXPR_FLAG_UNRESOLVED
            union { u32 parent_name; Type* parent_type; };
            union { u32 member_name; u32 member_index; };
        } static_member_access;
    };
};

typedef struct Stmt Stmt;
struct Stmt {
    enum {
        STMT_END = 0, // Sentinel, returned to mark that no more statements can be parsed

        STMT_DECLARATION,
        STMT_EXPR,
        STMT_ASSIGNMENT,

        STMT_BLOCK,
        STMT_IF,
        STMT_LOOP,

        STMT_RETURN,
        STMT_BREAK,
        STMT_CONTINUE,
    } kind;

    union {
        struct {
            u32 var_index;
            Expr *right; // 'right' might be null
        } declaration;

        Expr *expr;

        struct {
            Expr *left;
            Expr *right;
        } assignment;

        Stmt* block;

        struct {
            Expr *condition;
            Stmt *then;
            Stmt *else_then;
        } conditional;

        struct {
            Expr *condition;
            Stmt *body;
        } loop;

        struct {
            Expr *value;
            bool trailing;
        } return_stmt;
    };

    File_Pos pos;

    Stmt* next;
};


typedef enum Condition {
    COND_E, COND_NE,

    // Signed
    COND_G, COND_GE,
    COND_L, COND_LE,

    // Unsigned
    COND_A, COND_AE,
    COND_B, COND_BE,

    COND_COUNT,
} Condition;

u8* CONDITION_NAMES[COND_COUNT] = {
    [COND_E]   = "==",
    [COND_NE]  = "!=",
    [COND_G]   = "> (signed)",
    [COND_GE]  = ">= (signed)",
    [COND_L]   = "< (signed)",
    [COND_LE]  = "<= (signed)",
    [COND_A]   = "> (unsigned)",
    [COND_AE]  = ">= (unsigned)",
    [COND_B]   = "< (unsigned)",
    [COND_BE]  = "<= (unsigned)",
};

u8* CONDITION_POSTFIXES[COND_COUNT] = {
    [COND_E]   = "e",
    [COND_NE]  = "ne",
    [COND_G]   = "g",
    [COND_GE]  = "ge",
    [COND_L]   = "l",
    [COND_LE]  = "le",
    [COND_A]   = "a",
    [COND_AE]  = "ae",
    [COND_B]   = "b",
    [COND_LE]  = "be",
};

Condition condition_not(Condition c) {
    switch (c) {
        case COND_E:  return COND_NE;
        case COND_NE: return COND_E;
        case COND_G:  return COND_LE;
        case COND_GE: return COND_L;
        case COND_L:  return COND_GE;
        case COND_LE: return COND_G;
        case COND_A:  return COND_BE;
        case COND_AE: return COND_B;
        case COND_B:  return COND_AE;
        case COND_BE: return COND_A;
        default: assert(false); return 0;
    }
}


typedef struct Import_Index {
    // names are string table indices
    u32 library;
    u32 function;
} Import_Index;

typedef struct Library_Import {
    // most names are string table indices

    u8* importing_source_file;
    u32 lib_name;
    u32* function_names; // stretchy-buffer TODO make this a hashtable (?)

    // Set in  'parse_library'
    u8* dll_name;
    u32* function_hints;
} Library_Import;

typedef struct Fixup {
    // Fixups which rely on information about adresses in the final executable go here,
    // other kinds of fixups can have their own struct

    u64 text_location;

    enum {
        FIXUP_IMPORTED_FUNCTION,
        FIXUP_DATA,
    } kind;

    union {
        Import_Index import_index;
        u32 data_offset;
    };
} Fixup;

typedef struct Call_Fixup {
    u64 text_location;
    bool builtin;
    u32 func_index;
} Call_Fixup;

typedef struct Stack_Access_Fixup {
    enum {
        STACK_ACCESS_FIXUP_INPUT_SECTION,
        STACK_ACCESS_FIXUP_LOCAL_SECTION,
    } kind;
    u64 text_location;
} Stack_Access_Fixup;

typedef struct Jump_Fixup {
    u64 text_location;
    u64 jump_from;

    enum {
        JUMP_TO_END_OF_LOOP,
        JUMP_TO_START_OF_LOOP,
        JUMP_TO_END_OF_FUNCTION,
    } jump_to;
} Jump_Fixup;


typedef struct Func {
    u32 name;
    File_Pos declaration_pos;

    enum {
        FUNC_KIND_NORMAL, // use '.body'
        FUNC_KIND_IMPORTED, // use '.import_info'
    } kind;

    struct {
        bool has_return;
        Type* return_type;
        bool return_by_reference;
        // ... otherwise return in RAX, which we can even do for structs. See reference/notes.md

        struct {
            Type* type;
            u32 var_index;
            bool reference_semantics;
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

            Stmt* first_stmt;

            u32 text_start;
        } body;
    };
} Func;


typedef struct Context {
    Arena arena, stack; // arena is for permanent storage, stack for temporary

    u8* string_table;
    u32 keyword_token_table[KEYWORD_COUNT][2];
    u32 builtin_names[BUILTIN_COUNT];

    // AST & intermediate representation
    Func* funcs;
    Type primitive_types[TYPE_KIND_COUNT];
    Type *void_pointer_type, *string_type, *type_info_type;
    Type **user_types;

    // These are only for temporary use, we copy to arena buffers & clear
    Global_Var *global_vars;
    Var *tmp_vars;

    // Low level representation
    u8* seg_text;
    u8* seg_data;
    Fixup* fixups;

    Library_Import *imports;
    Call_Fixup *call_fixups;
    Stack_Access_Fixup *stack_access_fixups;
    Jump_Fixup *jump_fixups;
} Context;



Type* get_pointer_type(Context* context, Type* type) {
    if (type->pointer_type == null) {
        type->pointer_type = arena_new(&context->arena, Type);
        type->pointer_type->kind = TYPE_POINTER;
        type->pointer_type->pointer_to = type;

        if (type->flags & TYPE_FLAG_UNRESOLVED) {
            type->pointer_type->flags = TYPE_FLAG_UNRESOLVED;
        }
    }

    return type->pointer_type;
}

Type* get_array_type(Context* context, Type* type, u64 length) {
    for (Type_List* node = type->array_types; node != null; node = node->next) {
        if (node->type.array.length == length) {
            return &node->type;
        }
    }

    Type_List* new = arena_new(&context->arena, Type_List);
    new->next = type->array_types;
    type->array_types = new;

    new->type.kind = TYPE_ARRAY;
    new->type.array.length = length;
    new->type.array.of = type;

    if (type->flags & TYPE_FLAG_UNRESOLVED) {
        new->type.flags = TYPE_FLAG_UNRESOLVED;
    }

    return &new->type;
}

void init_primitive_types(Context* context) {
    #define init_primitive(kind) context->primitive_types[kind] = (Type) { kind, .primitive_name = string_table_intern_cstr(&context->string_table, PRIMITIVE_NAMES[kind]) };

    init_primitive(TYPE_INVALID);
    init_primitive(TYPE_VOID);
    init_primitive(TYPE_BOOL);
    init_primitive(TYPE_U8);
    init_primitive(TYPE_U16);
    init_primitive(TYPE_U32);
    init_primitive(TYPE_U64);
    init_primitive(TYPE_I8);
    init_primitive(TYPE_I16);
    init_primitive(TYPE_I32);
    init_primitive(TYPE_I64);
    init_primitive(TYPE_F32);
    init_primitive(TYPE_F64);

    #undef init_primitives

    context->void_pointer_type = get_pointer_type(context, &context->primitive_types[TYPE_VOID]);
    context->string_type = get_pointer_type(context, &context->primitive_types[TYPE_U8]);
}

void init_builtin_func_names(Context* context) {
    context->builtin_names[BUILTIN_TYPE_INFO_OF_TYPE]  = string_table_intern_cstr(&context->string_table, "type_info_of_type");
    context->builtin_names[BUILTIN_TYPE_INFO_OF_VALUE] = string_table_intern_cstr(&context->string_table, "type_info_of_value");
    context->builtin_names[BUILTIN_ENUM_MEMBER_NAME]   = string_table_intern_cstr(&context->string_table, "enum_member_name");
    context->builtin_names[BUILTIN_ENUM_LENGTH]        = string_table_intern_cstr(&context->string_table, "enum_length");
    context->builtin_names[BUILTIN_CAST]               = string_table_intern_cstr(&context->string_table, "cast");
}

void init_keyword_names(Context* context) {
    u32 i = 0;

    #define add_keyword(token, name) \
    context->keyword_token_table[i][0] = token; \
    context->keyword_token_table[i][1] = string_table_intern_cstr(&context->string_table, name); \
    i += 1;

    add_keyword(TOKEN_KEYWORD_FN,       "fn");
    add_keyword(TOKEN_KEYWORD_EXTERN,   "extern");
    add_keyword(TOKEN_KEYWORD_LET,      "let");
    add_keyword(TOKEN_KEYWORD_IF,       "if");
    add_keyword(TOKEN_KEYWORD_ELSE,     "else");
    add_keyword(TOKEN_KEYWORD_FOR,      "for");
    add_keyword(TOKEN_KEYWORD_RETURN,   "return");
    add_keyword(TOKEN_KEYWORD_CONTINUE, "continue");
    add_keyword(TOKEN_KEYWORD_BREAK,    "break");
    add_keyword(TOKEN_KEYWORD_STRUCT,   "struct");
    add_keyword(TOKEN_KEYWORD_ENUM,     "enum");
    add_keyword(TOKEN_KEYWORD_UNION,    "union");
    add_keyword(TOKEN_KEYWORD_NULL,     "null");
    add_keyword(TOKEN_KEYWORD_TRUE,     "true");
    add_keyword(TOKEN_KEYWORD_FALSE,    "false");

    #undef add_keyword
}

Condition find_condition_for_op_and_type(Binary_Op op, Type_Kind type) {
    if (primitive_is_signed(type)) {
        switch (op) {
            case BINARY_EQ:   return COND_E;
            case BINARY_NEQ:  return COND_NE;
            case BINARY_GT:   return COND_G;
            case BINARY_GTEQ: return COND_GE;
            case BINARY_LT:   return COND_L;
            case BINARY_LTEQ: return COND_LE;
            default: assert(false);
        }
    } else {
        switch (op) {
            case BINARY_EQ:   return COND_E;
            case BINARY_NEQ:  return COND_NE;
            case BINARY_GT:   return COND_A;
            case BINARY_GTEQ: return COND_AE;
            case BINARY_LT:   return COND_L;
            case BINARY_LTEQ: return COND_LE;
            default: assert(false);
        }
    }
    return 0;
}

// Says '*[3]Foo' is equal to '*Foo'
bool type_can_assign(Type* a, Type* b) {
    if (a == b) return true;

    while (true) {
        Type_Kind a_primitive = a->kind;
        Type_Kind b_primitive = b->kind;

        if (a_primitive != b_primitive) {
            return false;
        }

        switch (a_primitive) {
            case TYPE_POINTER: {
                a = a->pointer_to;
                b = b->pointer_to;
                if (a->kind == TYPE_ARRAY) a = a->array.of;
                if (b->kind == TYPE_ARRAY) b = b->array.of;
            } break;

            case TYPE_ARRAY: {
                if (a->array.length != b->array.length) return false;
                a = a->array.of;
                b = b->array.of;
            } break;

            default: return true;
        }
    }

    assert(false);
    return false;
}

u8 primitive_size_of(Type_Kind primitive) {
    switch (primitive) {
        case TYPE_BOOL: return 1;
        case TYPE_VOID: return 0;
        case TYPE_U8:  return 1;
        case TYPE_U16: return 2;
        case TYPE_U32: return 4;
        case TYPE_U64: return 8;
        case TYPE_I8:  return 1;
        case TYPE_I16: return 2;
        case TYPE_I32: return 4;
        case TYPE_I64: return 8;
        case TYPE_F32: return 4;
        case TYPE_F64: return 8;
        case TYPE_POINTER: return POINTER_SIZE;
        case TYPE_INVALID: assert(false); return 0;
        case TYPE_ARRAY: assert(false); return 0;
        case TYPE_STRUCT: assert(false); return 0;
        case TYPE_ENUM: assert(false); return 0;
        default: assert(false); return 0;
    }
}

u8* compound_member_name(Context* context, Expr* expr, Compound_Member* member) {
    u32 name_index;
    switch (member->name_mode) {
        case EXPR_COMPOUND_NAME: {
            assert(expr->type->kind == TYPE_STRUCT);
            u32 member_index = member->member_index;
            name_index = expr->type->structure.members[member_index].name;
        } break;

        case EXPR_COMPOUND_UNRESOLVED_NAME: {
            name_index = member->unresolved_name;
        } break;

        case EXPR_COMPOUND_NO_NAME: {
            return null;
        } break;

        default: assert(false);
    }
    return string_table_access(context->string_table, name_index);
}

u64 type_size_of(Type* type) {
    u64 array_multiplier = 1;

    while (true) {
        if (type->kind == TYPE_ARRAY) {
            array_multiplier *= type->array.length;
            type = type->array.of;

        } else {
            assert(!(type->flags & TYPE_FLAG_SIZE_NOT_COMPUTED));

            u64 base_size;
            switch (type->kind) {
                case TYPE_STRUCT: base_size = type->structure.size; break;
                case TYPE_ENUM:   base_size = primitive_size_of(type->enumeration.value_primitive); break;
                default:          base_size = primitive_size_of(type->kind); break;
            }

            return base_size * array_multiplier;
        }
    }

    assert(false);
    return 0;
}

u64 type_align_of(Type* type) {
    while (true) {
        if (type->kind == TYPE_ARRAY) {
            type = type->array.of;
        } else {
            assert(!(type->flags & TYPE_FLAG_SIZE_NOT_COMPUTED));

            if (type->kind == TYPE_STRUCT) {
                return type->structure.align;
            } else {
                return primitive_size_of(primitive_of(type));
            }
        }
    }

    assert(false);
    return 0;
}

u32 user_type_name(Type* type) {
    u32 name;
    switch (type->kind) {
        case TYPE_STRUCT: name = type->structure.name; break;
        case TYPE_ENUM:   name = type->enumeration.name; break;
        default: assert(false);
    }
    return name;
}
 
Type_Kind primitive_of(Type* type) {
    if (type->kind == TYPE_ENUM) {
        return type->enumeration.value_primitive;
    } else {
        return type->kind;
    }
}

bool primitive_is_compound(Type_Kind primitive) {
    switch (primitive) {
        case TYPE_ARRAY: return true;
        case TYPE_STRUCT: return true;

        case TYPE_U8:  return false;
        case TYPE_U16: return false;
        case TYPE_U32: return false;
        case TYPE_U64: return false;
        case TYPE_I8:  return false;
        case TYPE_I16: return false;
        case TYPE_I32: return false;
        case TYPE_I64: return false;
        case TYPE_F32: return false;
        case TYPE_F64: return false;
        case TYPE_BOOL: return false;
        case TYPE_VOID: return false;
        case TYPE_ENUM: return false;
        case TYPE_POINTER: return false;
        case TYPE_INVALID: assert(false); return false;
        case TYPE_UNRESOLVED_NAME: assert(false); return false;

        default: assert(false); return false;
    }
}

bool primitive_is_integer(Type_Kind primitive) {
    switch (primitive) {
        case TYPE_U8: case TYPE_U16: case TYPE_U32: case TYPE_U64:
        case TYPE_I8: case TYPE_I16: case TYPE_I32: case TYPE_I64:
            return true;
        default: return false;
    }
}

bool primitive_is_float(Type_Kind primitive) {
    switch (primitive) {
        case TYPE_F32: case TYPE_F64: return true;
        default: return false;
    }
}

bool primitive_is_signed(Type_Kind primitive) {
    switch (primitive) {
        case TYPE_I8: case TYPE_I16: case TYPE_I32: case TYPE_I64: return true;
        default: return false;
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

// NB This currently just assumes we are trying to import a function. In the future we might want to support importing
// other items, though we probably want to find an example of that first, so we know what we are doing!
Import_Index add_import(Context* context, u8* source_path, u32 library_name, u32 function_name) {
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
        new.importing_source_file = source_path;
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

u64 add_exe_data(Context* context, u8* data, u64 length, u64 alignment) {
    u64 data_offset = buf_length(context->seg_data);

    u64 aligned_data_offset = round_to_next(data_offset, alignment);
    if (aligned_data_offset > data_offset) {
        str_push_zeroes(&context->seg_data, aligned_data_offset - data_offset);
    }

    if (data == null) {
        str_push_zeroes(&context->seg_data, length);
    } else {
        str_push_str(&context->seg_data, data, length);
    }

    return aligned_data_offset;
}

void print_file_pos(File_Pos* pos) {
    u8* name = pos->file_name;
    if (name == null) name = "<unkown file>";
    printf("%s(%u): ", name, (u64) pos->line);
}

void print_type(Context* context, Type* type) {
    while (type != null) {
        switch (type->kind) {
            case TYPE_POINTER: {
                printf("*");
                type = type->pointer_to;
            } break;

            case TYPE_ARRAY: {
                printf("[%u]", type->array.length);
                type = type->array.of;
            } break;

            case TYPE_STRUCT: {
                u8* name = string_table_access(context->string_table, type->structure.name);
                printf(name);
                type = null;
            } break;

            case TYPE_ENUM: {
                u8* name = string_table_access(context->string_table, type->enumeration.name);
                printf(name);
                type = null;
            } break;

            case TYPE_UNRESOLVED_NAME: {
                u8* name = string_table_access(context->string_table, type->unresolved_name);
                printf("<unresolved %s>", name);
                type = null;
            } break;

            default: {
                printf(PRIMITIVE_NAMES[type->kind]);
                type = null;
            } break;
        }
    }
}

void print_token(u8* string_table, Token* t) {
    u8* s = null;

    switch (t->kind) {
        case TOKEN_IDENTIFIER: {
            u32 index = t->identifier_string_table_index;
            printf("'%s'", string_table_access(string_table, index));
        } break;
        case TOKEN_STRING: {
            printf("\"%z\"", t->string.length, t->string.bytes);
        } break;

        case TOKEN_LITERAL_INT:   printf("%u", t->literal_int); break;
        case TOKEN_LITERAL_FLOAT: printf("%f", t->literal_float); break;

        default: {
            printf(TOKEN_NAMES[t->kind]);
        } break;
    }
}

void print_expr(Context* context, Func* func, Expr* expr) {
    switch (expr->kind) {
        case EXPR_VARIABLE: {
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

                if (var != null) {
                    u8* name = string_table_access(context->string_table, var->name);
                    printf("%s", name);
                }
            }
        } break;

        case EXPR_LITERAL: {
            switch (expr->literal.kind) {
                case EXPR_LITERAL_INTEGER: {
                    printf("%u", expr->literal.masked_value);
                } break;
                case EXPR_LITERAL_POINTER: {
                    if (expr->literal.masked_value == 0) {
                        printf("null");
                    } else {
                        printf("%x", expr->literal.masked_value);
                    }
                } break;
                case EXPR_LITERAL_BOOL: {
                    assert(expr->literal.masked_value == true || expr->literal.masked_value == false);
                    printf(expr->literal.masked_value? "true" : "false");
                } break;
                default: assert(false);
            }
        } break;

        case EXPR_COMPOUND: {
            print_type(context, expr->type);

            printf(" { ");
            for (u32 i = 0; i < expr->compound.count; i += 1) {
                if (i > 0) printf(", ");

                u8* member_name = compound_member_name(context, expr, &expr->compound.content[i]);
                if (member_name != null) printf("%s: ", member_name);

                Expr* child = expr->compound.content[i].expr;
                print_expr(context, func, child);
            }
            printf(" }");
        } break;

        case EXPR_STRING_LITERAL: {
            printf("\"%z\"", expr->string.length, expr->string.bytes);
        } break;

        case EXPR_BINARY: {
            printf("(");
            print_expr(context, func, expr->binary.left);
            printf(" %s ", BINARY_OP_SYMBOL[expr->binary.op]);
            print_expr(context, func, expr->binary.right);
            printf(")");
        } break;

        case EXPR_UNARY: {
            printf(UNARY_OP_SYMBOL[expr->unary.op]);
            print_expr(context, func, expr->unary.inner);
        } break;

        case EXPR_CALL: {
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
                if (i > 0) printf(", ");
                Expr* child = expr->call.params[i];
                print_expr(context, func, child);
            }
            printf(")");
        } break;

        case EXPR_CAST: {
            print_type(context, expr->type);
            printf("(");
            print_expr(context, func, expr->cast_from);
            printf(")");
        } break;

        case EXPR_SUBSCRIPT: {
            print_expr(context, func, expr->subscript.array);
            printf("[");
            print_expr(context, func, expr->subscript.index);
            printf("]");
        } break;

        case EXPR_MEMBER_ACCESS: {
            print_expr(context, func, expr->member_access.parent);
            printf(".");
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u8* name = string_table_access(context->string_table, expr->member_access.member_name);
                printf("<unresolved %s>", name);
            } else {
                Type* s = expr->member_access.parent->type;
                if (s->kind == TYPE_POINTER) {
                    s = s->pointer_to;
                }
                assert(s->kind == TYPE_STRUCT);

                u32 name_index = s->structure.members[expr->member_access.member_index].name;
                u8* name = string_table_access(context->string_table, name_index);
                printf(name);
            }
        } break;

        case EXPR_STATIC_MEMBER_ACCESS: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u8* parent_name = string_table_access(context->string_table, expr->static_member_access.parent_name);
                u8* member_name = string_table_access(context->string_table, expr->static_member_access.member_name);
                printf("<unresolved %s::%s>", parent_name, member_name);
            } else {
                Type* parent = expr->static_member_access.parent_type;
                assert(parent->kind == TYPE_ENUM);

                u8* parent_name = string_table_access(context->string_table, parent->enumeration.name);

                u32 m = expr->static_member_access.member_index;
                u32 member_name_index = parent->enumeration.members[m].name;
                u8* member_name = string_table_access(context->string_table, member_name_index);
                printf("%s::%s", parent_name, member_name);
            }

        } break;

        case EXPR_TYPE_INFO_OF_TYPE: {
            printf("type_info_of_type(");
            print_type(context, expr->type_info_of_type);
            printf(")");
        } break;

        case EXPR_TYPE_INFO_OF_VALUE: {
            printf("type_info_of_value(");
            print_expr(context, func, expr->type_info_of_value);
            printf(")");
        } break;

        case EXPR_ENUM_LENGTH: {
            printf("enum_length(");
            print_type(context, expr->enum_length_of);
            printf(")");
        } break;

        case EXPR_ENUM_MEMBER_NAME: {
            printf("enum_member_name(");
            print_expr(context, func, expr->enum_member);
            printf(")");
        } break;

        default: assert(false);
    }
}

void print_stmt(Context* context, Func* func, Stmt* stmt, u32 indent_level) {
    for (u32 i = 0; i < indent_level; i += 1) printf("    ");

    switch (stmt->kind) {
        case STMT_ASSIGNMENT: {
            print_expr(context, func, stmt->assignment.left);
            printf(" = ");
            print_expr(context, func, stmt->assignment.right);
            printf(";");
        } break;

        case STMT_EXPR: {
            print_expr(context, func, stmt->expr);
            printf(";");
        } break;

        case STMT_DECLARATION: {
            Var* var = &func->body.vars[stmt->declaration.var_index];
            u8* name = string_table_access(context->string_table, var->name);
            printf("let %s: ", name);

            print_type(context, var->type);

            if (stmt->declaration.right != null) {
                printf(" = ");
                print_expr(context, func, stmt->declaration.right);
            }

            printf(";");
        } break;

        case STMT_BLOCK: {
            printf("{\n");

            for (Stmt *inner = stmt->block; inner->kind != STMT_END; inner = inner->next) {
                print_stmt(context, func, inner, indent_level + 1);
            }

            for (u32 i = 0; i < indent_level; i += 1) printf("    ");
            printf("}");
        } break;

        case STMT_IF: {
            printf("if (");
            print_expr(context, func, stmt->conditional.condition);
            printf(") {\n");

            for (Stmt *inner = stmt->conditional.then; inner->kind != STMT_END; inner = inner->next) {
                print_stmt(context, func, inner, indent_level + 1);
            }

            for (u32 i = 0; i < indent_level; i += 1) printf("    ");
            printf("}");

            if (stmt->conditional.else_then != null) {
                printf(" else {\n");

                for (Stmt *inner = stmt->conditional.else_then; inner->kind != STMT_END; inner = inner->next) {
                    print_stmt(context, func, inner, indent_level + 1);
                }

                for (u32 i = 0; i < indent_level; i += 1) printf("    ");
                printf("}");
            }
        } break;

        case STMT_LOOP: {
            if (stmt->loop.condition != null) {
                printf("for (");
                print_expr(context, func, stmt->loop.condition);
                printf(") {\n");
            } else {
                printf("for {\n");
            }

            for (Stmt *inner = stmt->loop.body; inner->kind != STMT_END; inner = inner->next) {
                print_stmt(context, func, inner, indent_level + 1);
            }

            for (u32 i = 0; i < indent_level; i += 1) printf("    ");
            printf("}");
        } break;

        case STMT_RETURN: {
            if (stmt->return_stmt.value != null) {
                printf("return ");
                print_expr(context, func, stmt->return_stmt.value);
                printf(";");
            } else {
                printf("return;");
            }
        } break;

        case STMT_CONTINUE: printf("continue;"); break;
        case STMT_BREAK:    printf("break;"); break;

        case STMT_END: printf("<end>"); break;

        default: assert(false);
    }

    printf("\n");
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

bool expect_single_token(Context* context, Token* t, int kind, u8* location) {
    if (t->kind != kind) {
        print_file_pos(&t->pos);
        printf("Expected %s %s, but got ", TOKEN_NAMES[kind], location);
        print_token(context->string_table, t);
        printf("\n");
        return false;
    } else {
        return true;
    }
}

f64 parse_f64(u8* string, u64 length) {
    if (length == 0) return 0.0;

    f64 value = 0.0;
    u64 i = 0;

    for (; i < length; i += 1) {
        u8 digit = string[i] - '0';
        if (!(digit >= 0 && digit <= 9)) break;

        value *= 10.0;
        value += (f64) digit;
    }

    if (i < length && string[i] == '.') {
        i += 1;

        f64 power = 10.0;
        for (; i < length; i += 1) {
            u8 digit = string[i] - '0';
            if (!(digit >= 0 && digit <= 9)) break;
            value += ((f64) digit) / power;
            power *= 10.0;
        }
    }

    assert(i == length);

    return value;
}

Type* parse_primitive_name(Context* context, u32 name_index) {
    for (u32 i = 0; i < TYPE_KIND_COUNT; i += 1) {
        Type* type = &context->primitive_types[i];
        if (type->primitive_name == name_index) {
            return type;
        }
    }

    return null;
}

Builtin_Func parse_builtin_func_name(Context* context, u32 name_index) {
    for (u32 i = 0; i < BUILTIN_COUNT; i += 1) {
        if (context->builtin_names[i] == name_index) {
            return i;
        }
    }

    return BUILTIN_INVALID;
}

Type* parse_user_type_name(Context* context, u32 name_index) {
    buf_foreach (Type*, user_type, context->user_types) {
        u32 user_type_name = 0;
        switch ((*user_type)->kind) {
            case TYPE_STRUCT: {
                user_type_name = (*user_type)->structure.name;
            } break;
            case TYPE_ENUM: {
                user_type_name = (*user_type)->enumeration.name;
            } break;
            default: assert(false);
        }

        if (name_index == user_type_name) {
            return *user_type;
        }
    }

    return null;
}

Type* parse_type(Context* context, Token* t, u32* length) {
    Token* t_start = t;

    typedef struct Prefix Prefix;
    struct Prefix {
        enum { PREFIX_POINTER, PREFIX_ARRAY } kind;
        u64 array_length;
        Prefix* link;
    };
    Prefix* prefix = null;

    arena_stack_push(&context->stack);

    Type* base_type = null;
    while (base_type == null) {
        switch (t->kind) {
            case TOKEN_IDENTIFIER: {
                base_type = parse_primitive_name(context, t->identifier_string_table_index);

                if (base_type == null) {
                    base_type = parse_user_type_name(context, t->identifier_string_table_index);
                }

                if (base_type == null) {
                    base_type = arena_new(&context->arena, Type);
                    base_type->kind = TYPE_UNRESOLVED_NAME;
                    base_type->unresolved_name = t->identifier_string_table_index;
                    base_type->flags |= TYPE_FLAG_UNRESOLVED;
                }

                t += 1;
            } break;

            case TOKEN_BRACKET_SQUARE_OPEN: {
                t += 1;

                if (t->kind != TOKEN_LITERAL_INT) {
                    print_file_pos(&t->pos);
                    printf("Expected array size, but got ");
                    print_token(context->string_table, t);
                    printf("\n");
                    *length = t - t_start;
                    return null;
                }
                u64 array_length = t->literal_int;
                t += 1;

                if (!expect_single_token(context, t, TOKEN_BRACKET_SQUARE_CLOSE, "after array size")) {
                    *length = t - t_start;
                    return null;
                }
                t += 1;

                Prefix* new = arena_new(&context->stack, Prefix);
                new->kind = PREFIX_ARRAY;
                new->array_length = array_length;
                new->link = prefix;
                prefix = new;
            }  break;

            case TOKEN_MUL: {
                t += 1;

                Prefix* new = arena_new(&context->stack, Prefix);
                new->kind = PREFIX_POINTER;
                new->link = prefix;
                prefix = new;
            } break;

            default: {
                print_file_pos(&t->pos);
                printf("Unexpected token in type: ");
                print_token(context->string_table, t);
                printf("\n");

                t += 1;
                *length = t - t_start;
                return null;
            } break;
        }
    }

    Type* type = base_type;
    while (prefix != null) {
        switch (prefix->kind) {
            case PREFIX_POINTER: type = get_pointer_type(context, type); break;
            case PREFIX_ARRAY:   type = get_array_type(context, type, prefix->array_length); break;
        }
        prefix = prefix->link;
    }

    arena_stack_pop(&context->stack);

    *length = t - t_start;
    return type;
}

Type* parse_struct_declaration(Context* context, Token* t, u32* length) {
    Token* t_start = t;

    assert(t->kind == TOKEN_KEYWORD_STRUCT);
    t += 1;

    Type* type = arena_new(&context->arena, Type);
    type->kind = TYPE_STRUCT;

    if (t->kind != TOKEN_IDENTIFIER) {
        print_file_pos(&t->pos);
        printf("Expected struct name, but got ");
        print_token(context->string_table, t);
        printf("\n");
        return null;
    }
    type->structure.name = t->identifier_string_table_index;
    t += 1;

    if (!expect_single_token(context, t, TOKEN_BRACKET_CURLY_OPEN, "after struct name")) return null;
    t += 1;


    typedef struct Member Member;
    struct Member {
        u32 name;
        Type* type;
        File_Pos pos;
        Member *next, *previous;
    };

    Member* first = null;
    Member* last = null;

    arena_stack_push(&context->stack);

    while (t->kind != TOKEN_BRACKET_CURLY_CLOSE) {
        u32 names_given = 0;
        while (true) {
            if (t->kind != TOKEN_IDENTIFIER) {
                print_file_pos(&t->pos);
                printf("Expected a member name, but got ");
                print_token(context->string_table, t);
                printf("\n");
                return null;
            }

            Member* next = arena_new(&context->stack, Member);
            next->name = t->identifier_string_table_index;
            next->pos = t->pos;

            t += 1;

            if (first == null) {
                first = next;
            } else {
                next->previous = last;
                last->next = next;
            }
            last = next;

            names_given += 1;
            type->structure.member_count += 1;

            if (t->kind == TOKEN_COMMA) {
                t += 1;
                continue;
            } else {
                break;
            }
        }

        if (!expect_single_token(context, t, TOKEN_COLON, names_given > 1? "after member names" : "after member name")) return null;
        t += 1;

        u32 type_length = 0;
        Type* member_type = parse_type(context, t, &type_length);
        t += type_length;
        if (member_type == null) return null;

        if (!expect_single_token(context, t, TOKEN_SEMICOLON, "after member declaration")) return null;

        Member* m = last;
        for (u32 i = 0; i < names_given; i += 1) {
            m->type = member_type;
            m = m->previous;
        }

        t += 1;
    }
    t += 1;

    type->structure.members = (void*) arena_alloc(&context->arena, type->structure.member_count * sizeof(*type->structure.members));

    Member* m = first;
    for (u32 i = 0; i < type->structure.member_count; i += 1, m = m->next) {
        type->structure.members[i].name = m->name;
        type->structure.members[i].type = m->type;
        type->structure.members[i].declaration_pos = m->pos;
    }

    arena_stack_pop(&context->stack);

    type->flags |= TYPE_FLAG_SIZE_NOT_COMPUTED;

    *length = t - t_start;
    return type;
}

Type* parse_enum_declaration(Context* context, Token* t, u32* length) {
    Token* t_start = t;

    assert(t->kind == TOKEN_KEYWORD_ENUM);
    t += 1;

    Type* type = arena_new(&context->arena, Type);
    type->kind = TYPE_ENUM;
    type->enumeration.name_table_data_offset = U64_MAX;

    if (t->kind != TOKEN_IDENTIFIER) {
        print_file_pos(&t->pos);
        printf("Expected enum name, but got ");
        print_token(context->string_table, t);
        printf("\n");
        *length = t - t_start;
        return null;
    }
    type->enumeration.name = t->identifier_string_table_index;
    t += 1;

    if (t->kind == TOKEN_BRACKET_ROUND_OPEN) {
        t += 1;
        File_Pos type_start_pos = t->pos;

        if (t->kind != TOKEN_IDENTIFIER) {
            print_file_pos(&type_start_pos);
            printf("Expected primitive name, but got ");
            print_token(context->string_table, t);
            printf("\n");
            *length = t - t_start;
            return null;
        }
        u32 type_name_index = t->identifier_string_table_index;
        t += 1;

        if (!expect_single_token(context, t, TOKEN_BRACKET_ROUND_CLOSE, "after enum primitive")) {
            *length = t - t_start;
            return null;
        }
        t += 1;

        Type* primitive = parse_primitive_name(context, type_name_index);
        if (primitive == null || !(primitive_is_integer(primitive->kind) && !primitive_is_signed(primitive->kind))) {
            print_file_pos(&type_start_pos);
            printf("Expected unsigned integer type, but got %s\n", string_table_access(context->string_table, type_name_index));
            *length = t - t_start;
            return null;
        }

        type->enumeration.value_primitive = primitive->kind;
    } else {
        type->enumeration.value_primitive = TYPE_U32;
    }

    if (!expect_single_token(context, t, TOKEN_BRACKET_CURLY_OPEN, "after enum name/type")) {
        *length = t - t_start;
        return null;
    }
    t += 1;


    typedef struct Member Member;
    struct Member {
        u32 name;
        u64 value;
        File_Pos pos;
        Member *next, *previous;
    };

    Member* first = null;
    Member* last = null;

    arena_stack_push(&context->stack);

    u64 next_value = 0;

    while (t->kind != TOKEN_BRACKET_CURLY_CLOSE) {
        if (t->kind != TOKEN_IDENTIFIER) {
            print_file_pos(&t->pos);
            printf("Expected a member name, but got ");
            print_token(context->string_table, t);
            printf("\n");
            *length = t - t_start;
            return null;
        }

        Member* next = arena_new(&context->stack, Member);
        next->name = t->identifier_string_table_index;
        next->pos = t->pos;

        t += 1;

        if (t->kind == TOKEN_ASSIGN) {
            t += 1;

            if (t->kind != TOKEN_LITERAL_INT) {
                print_file_pos(&t->pos);
                printf("Expected literal value, but got ");
                print_token(context->string_table, t);
                printf("\n");
                *length = t - t_start;
                return null;
            }

            next->value = t->literal_int;
            t += 1;
        } else {
            next->value = next_value;
        }

        next_value = next->value + 1;

        if (first == null) {
            first = next;
        } else {
            next->previous = last;
            last->next = next;
        }
        last = next;

        type->enumeration.member_count += 1;

        if (t->kind != TOKEN_BRACKET_CURLY_CLOSE) {
            if (t->kind == TOKEN_COMMA) {
                t += 1;
            } else {
                print_file_pos(&t->pos);
                printf("Expected comma ',' or closing curly brace '}' after value in enum, but got ");
                print_token(context->string_table, t);
                printf("\n");
                *length = t - t_start;
                return null;
            }
        }
    }
    t += 1;

    type->enumeration.members = (void*) arena_alloc(&context->arena, type->enumeration.member_count * sizeof(*type->enumeration.members));

    Member* m = first;
    for (u32 i = 0; i < type->structure.member_count; i += 1, m = m->next) {
        type->enumeration.members[i].name = m->name;
        type->enumeration.members[i].value = m->value;
        type->enumeration.members[i].declaration_pos = m->pos;
    }

    arena_stack_pop(&context->stack);

    *length = t - t_start;
    return type;
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
    assert(expr->kind == EXPR_UNARY);

    if (yard->unary_prefix == null) {
        yard->unary_prefix = expr;
    } else {
        assert(yard->unary_prefix->kind == EXPR_UNARY);

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
        if ((*array)->kind == EXPR_UNARY) {
            array = &((*array)->unary.inner);
        } else {
            break;
        }
    }

    Expr* expr = arena_new(&context->arena, Expr);
    expr->kind = EXPR_SUBSCRIPT;
    expr->subscript.array = *array;
    expr->subscript.index = index;
    expr->pos = expr->subscript.array->pos;

    *array = expr;
}

void shunting_yard_push_member_access(Context* context, Shunting_Yard* yard, u32 member_name) {
    assert(yard->unary_prefix == null);
    assert(yard->expr_queue_index > 0);

    Expr** structure = &yard->expr_queue[yard->expr_queue_index - 1];

    while (true) {
        if ((*structure)->kind == EXPR_UNARY) {
            structure = &((*structure)->unary.inner);
        } else {
            break;
        }
    }

    Expr* expr = arena_new(&context->arena, Expr);
    expr->kind = EXPR_MEMBER_ACCESS;
    expr->member_access.parent = *structure;
    expr->member_access.member_name = member_name;
    expr->flags = EXPR_FLAG_UNRESOLVED;
    expr->pos = expr->subscript.array->pos;

    *structure = expr;
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
    expr->kind = EXPR_BINARY;

    expr->binary.op = yard->op_queue[yard->op_queue_index - 1];
    expr->binary.right = yard->expr_queue[yard->expr_queue_index - 1];
    expr->binary.left = yard->expr_queue[yard->expr_queue_index - 2];
    expr->pos = expr->binary.left->pos;
    yard->op_queue_index -= 1;
    yard->expr_queue_index -= 2;

    expr->pos = expr->binary.left->pos;

    shunting_yard_push_expr(context, yard, expr);
}

void shunting_yard_push_op(Context* context, Shunting_Yard* yard, Binary_Op new_op) {
    u8 new_precedence = BINARY_OP_PRECEDENCE[new_op];

    while (yard->op_queue_index > 0) {
        Binary_Op head_op = yard->op_queue[yard->op_queue_index - 1];
        u8 old_precedence = BINARY_OP_PRECEDENCE[head_op];

        if (old_precedence >= new_precedence) {
            shunting_yard_collapse(context, yard);
        } else {
            break;
        }
    }

    assert(yard->op_queue_index < yard->op_queue_size);
    yard->op_queue[yard->op_queue_index] = new_op;
    yard->op_queue_index += 1;
}

Expr* parse_compound(Context* context, Token* t, u32* length);
Expr** parse_parameter_list(Context* context, Token* t, u32* length, u32* count);
Expr* parse_call(Context* context, Token* t, u32* length);

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
                case TOKEN_IDENTIFIER: {
                    File_Pos start_pos = t->pos;

                    u32 name_index = t->identifier_string_table_index;

                    switch ((t + 1)->kind) {
                        // Some call (either a function or a builtin)
                        case TOKEN_BRACKET_ROUND_OPEN: {
                            u32 call_length = 0;
                            Expr* expr = parse_call(context, t, &call_length);
                            t += call_length;

                            if (expr == null) {
                                *length = t - t_start;
                                return null;
                            }

                            shunting_yard_push_expr(context, yard, expr);
                        } break;

                        // Structure literal
                        case TOKEN_BRACKET_CURLY_OPEN: {
                            File_Pos start_pos = t->pos;

                            Type* type = parse_user_type_name(context, t->identifier_string_table_index);
                            if (type == null) {
                                type = arena_new(&context->arena, Type);
                                type->kind = TYPE_UNRESOLVED_NAME;
                                type->unresolved_name = t->identifier_string_table_index;
                                type->flags |= TYPE_FLAG_UNRESOLVED;
                            }
                            t += 1;

                            u32 struct_length = 0;
                            Expr* expr = parse_compound(context, t, &struct_length);
                            t += struct_length;

                            if (expr == null) {
                                *length = t - t_start;
                                return null;
                            }

                            expr->type = type;
                            shunting_yard_push_expr(context, yard, expr);
                        } break;

                        case TOKEN_STATIC_ACCESS: {
                            File_Pos start_pos = t->pos;
                            t += 2;

                            if (t->kind != TOKEN_IDENTIFIER) {
                                print_file_pos(&t->pos);
                                printf("Expected struct name, but got ");
                                print_token(context->string_table, t);
                                printf("\n");
                                *length = t - t_start;
                                return null;
                            }

                            u32 member_name_index = t->identifier_string_table_index;
                            t += 1;

                            Expr* expr = arena_new(&context->arena, Expr);
                            expr->kind = EXPR_STATIC_MEMBER_ACCESS;
                            expr->static_member_access.parent_name = name_index;;
                            expr->static_member_access.member_name = member_name_index;;
                            expr->flags |= EXPR_FLAG_UNRESOLVED;
                            expr->pos = start_pos;

                            shunting_yard_push_expr(context, yard, expr);
                        } break;

                        default: {
                            Expr* expr = arena_new(&context->arena, Expr);
                            expr->kind = EXPR_VARIABLE;
                            expr->variable.unresolved_name = name_index;
                            expr->flags |= EXPR_FLAG_UNRESOLVED;
                            expr->pos = t->pos;

                            shunting_yard_push_expr(context, yard, expr);

                            t += 1;
                        } break;
                    }

                    could_parse = true;
                    expect_value = false;
                } break;

                case TOKEN_LITERAL_INT:
                case TOKEN_LITERAL_FLOAT:
                case TOKEN_KEYWORD_NULL:
                case TOKEN_KEYWORD_TRUE:
                case TOKEN_KEYWORD_FALSE:
                {
                    Expr* expr = arena_new(&context->arena, Expr);
                    expr->kind = EXPR_LITERAL;
                    expr->literal.kind = EXPR_LITERAL_POINTER;
                    expr->pos = t->pos;

                    switch (t->kind) {
                        case TOKEN_LITERAL_INT: {
                            expr->literal.raw_value = t->literal_int;
                            expr->literal.kind = EXPR_LITERAL_INTEGER;
                        } break;

                        case TOKEN_LITERAL_FLOAT: {
                            expr->literal.raw_value = *((u64*) &t->literal_float);
                            expr->literal.kind = EXPR_LITERAL_FLOAT;
                        } break;

                        case TOKEN_KEYWORD_NULL: {
                            expr->literal.raw_value = 0;
                            expr->literal.kind = EXPR_LITERAL_POINTER;
                        } break;

                        case TOKEN_KEYWORD_FALSE: {
                            expr->literal.raw_value = 0;
                            expr->literal.kind = EXPR_LITERAL_BOOL;
                        } break;

                        case TOKEN_KEYWORD_TRUE: {
                            expr->literal.raw_value = 1;
                            expr->literal.kind = EXPR_LITERAL_BOOL;
                        } break;

                        default: assert(false);
                    }

                    expr->literal.masked_value = expr->literal.raw_value;

                    shunting_yard_push_expr(context, yard, expr);

                    t += 1;
                    could_parse = true;
                    expect_value = false;
                } break;

                case TOKEN_STRING: {
                    Expr* expr = arena_new(&context->arena, Expr);
                    expr->type = context->string_type;
                    expr->kind = EXPR_STRING_LITERAL;
                    expr->string.bytes = t->string.bytes;
                    expr->string.length = t->string.length;
                    expr->pos = t->pos;

                    shunting_yard_push_expr(context, yard, expr);

                    t += 1;
                    could_parse = true;
                    expect_value = false;
                } break;

                // Parenthesized expression
                case TOKEN_BRACKET_ROUND_OPEN: {
                    t += 1;
                    u32 inner_length = 0;
                    Expr* inner = parse_expr(context, t, &inner_length);
                    t += inner_length;

                    if (inner == null) {
                        *length = t - t_start;
                        return null;
                    }

                    if (!expect_single_token(context, t, TOKEN_BRACKET_ROUND_CLOSE, "after parenthesized subexpression")) {
                        *length = t - t_start;
                        return null;
                    }
                    t += 1;

                    shunting_yard_push_expr(context, yard, inner);

                    expect_value = false;
                    could_parse = true;
                } break;

                // Array literal, or untyped compound literals
                case TOKEN_BRACKET_CURLY_OPEN:
                case TOKEN_BRACKET_SQUARE_OPEN:
                {
                    Type* type = null;
                    if (t->kind == TOKEN_BRACKET_SQUARE_OPEN) {
                        u32 type_length = 0;
                        type = parse_type(context, t, &type_length);
                        t += type_length;

                        if (type == null) {
                            *length = t - t_start;
                            return null;
                        }
                    }

                    u32 array_literal_length = 0;
                    Expr* expr = parse_compound(context, t, &array_literal_length);
                    t += array_literal_length;

                    if (expr == null) {
                        *length = t - t_start;
                        return null;
                    }

                    expr->type = type;

                    shunting_yard_push_expr(context, yard, expr);

                    could_parse = true;
                    expect_value = false;
                } break;

                default: {
                    Unary_Op op = UNARY_OP_INVALID;
                    switch (t->kind) {
                        case TOKEN_AND: op = UNARY_ADDRESS_OF; break;
                        case TOKEN_MUL: op = UNARY_DEREFERENCE; break;
                        case TOKEN_NOT: op = UNARY_NOT; break;
                        case TOKEN_SUB: op = UNARY_NEG; break;
                    }

                    if (op != UNARY_OP_INVALID) {
                        Expr* expr = arena_new(&context->arena, Expr);
                        expr->kind = EXPR_UNARY;
                        expr->unary.op = op;
                        expr->pos = t->pos;

                        shunting_yard_push_unary_prefix(yard, expr);

                        could_parse = true;
                        expect_value = true;
                        t += 1;
                    }
                } break;
            }
        } else {
            switch (t->kind) {
                case TOKEN_BRACKET_SQUARE_OPEN: {
                    t += 1;

                    u32 index_length = 0;
                    Expr* index = parse_expr(context, t, &index_length);
                    t += index_length;

                    if (index == null) {
                        *length = t - t_start;
                        return null;
                    }

                    if (!expect_single_token(context, t, TOKEN_BRACKET_SQUARE_CLOSE, "after subscript index")) {
                        *length = t - t_start;
                        return null;
                    }
                    t += 1;

                    shunting_yard_push_subscript(context, yard, index);

                    expect_value = false;
                    could_parse = true;
                } break;

                case TOKEN_DOT: {
                    t += 1;

                    if (t->kind != TOKEN_IDENTIFIER) {
                        print_file_pos(&t->pos);
                        printf("Expected member name, but got ");
                        print_token(context->string_table, t);
                        printf("\n");
                        *length = t - t_start;
                        return null;
                    }
                    u32 member_name = t->identifier_string_table_index;
                    t += 1;

                    shunting_yard_push_member_access(context, yard, member_name);

                    expect_value = false;
                    could_parse = true;
                } break;

                // End of expression
                case TOKEN_SEMICOLON:
                case TOKEN_COMMA:
                case ')': case ']': case '}':
                case TOKEN_ASSIGN:
                case TOKEN_KEYWORD_LET:
                case TOKEN_KEYWORD_FN:
                case TOKEN_ADD_ASSIGN:
                case TOKEN_SUB_ASSIGN:
                {
                    reached_end = true;
                } break;

                default: {
                    Binary_Op op = BINARY_OP_INVALID;
                    switch (t->kind) {
                        case TOKEN_ADD:                op = BINARY_ADD; break;
                        case TOKEN_SUB:                op = BINARY_SUB; break;
                        case TOKEN_MUL:                op = BINARY_MUL; break;
                        case TOKEN_DIV:                op = BINARY_DIV; break;
                        case TOKEN_MOD:                op = BINARY_MOD; break;
                        case TOKEN_GREATER:            op = BINARY_GT; break;
                        case TOKEN_GREATER_OR_EQUAL:   op = BINARY_GTEQ; break;
                        case TOKEN_LESS:               op = BINARY_LT; break;
                        case TOKEN_LESS_OR_EQUAL:      op = BINARY_LTEQ; break;
                        case TOKEN_EQUAL:              op = BINARY_EQ; break;
                        case TOKEN_NOT_EQUAL:          op = BINARY_NEQ; break;

                        case TOKEN_AND:
                        case TOKEN_OR:
                        case TOKEN_XOR:
                        case TOKEN_SHIFT_LEFT:
                        case TOKEN_SHIFT_RIGHT:
                        {
                            unimplemented(); // TODO bitwise operators
                        } break;
                    }

                    if (op != BINARY_OP_INVALID) {
                        shunting_yard_push_op(context, yard, op);
                        could_parse = true;
                        expect_value = true;
                        t += 1;
                    }
                } break;
            }
        }

        if (reached_end) break;

        if (!could_parse) {
            print_file_pos(&t->pos);
            printf("Expected ");
            if (expect_value) {
                printf("a value or a unary operator");
            } else {
                printf("a binary operator or a postfix operator");
            }
            printf(", but got ");
            print_token(context->string_table, t);
            printf("\n");

            t += 1;
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

Expr* parse_compound(Context* context, Token* t, u32* length) {
    Token* t_start = t;

    if (!expect_single_token(context, t, TOKEN_BRACKET_CURLY_OPEN, "after type of array literal")) {
        *length = t - t_start;
        return null;
    }
    t += 1;

    typedef struct Member_Expr Member_Expr;
    struct Member_Expr {
        Expr* expr;
        u32 name_index;
        Member_Expr *next, *previous;
    };

    u32 member_count = 0;
    Member_Expr* first_member = null;
    Member_Expr* last_member = null;

    arena_stack_push(&context->stack);

    while (t->kind != TOKEN_BRACKET_CURLY_CLOSE) {
        u32 name_index = U32_MAX;
        if (t->kind == TOKEN_IDENTIFIER && (t + 1)->kind == TOKEN_COLON) {
            name_index = t->identifier_string_table_index;
            t += 2;
        }

        u32 member_length = 0;
        Expr* member = parse_expr(context, t, &member_length);
        t += member_length;

        if (member == null) {
            *length = t - t_start;
            return null;
        }

        Member_Expr* next = arena_new(&context->stack, Member_Expr);
        next->name_index = name_index;
        next->expr = member;

        if (first_member == null) {
            first_member = next;
        } else {
            next->previous = last_member;
            last_member->next = next;
        }
        last_member = next;

        member_count += 1;

        if (t->kind != TOKEN_BRACKET_CURLY_CLOSE) {
            if (t->kind != TOKEN_COMMA) {
                print_file_pos(&t->pos);
                printf("Expected comma ',' or closing parenthesis '}' after value in array litereral, but got ");
                print_token(context->string_table, t);
                printf("\n");
                *length = t - t_start;
                return null;
            }
            t += 1;
        }
    }

    if (!expect_single_token(context, t, TOKEN_BRACKET_CURLY_CLOSE, "to close array literal")) {
        *length = t - t_start;
        return null;
    }
    t += 1;

    Expr* expr = arena_new(&context->arena, Expr);
    expr->kind = EXPR_COMPOUND;
    expr->pos = t_start->pos;

    expr->compound.count = member_count;
    expr->compound.content = (void*) arena_alloc(&context->arena, member_count * sizeof(Compound_Member));

    Member_Expr* p = first_member;
    for (u32 i = 0; i < member_count; i += 1, p = p->next) {
        Compound_Member* member = &expr->compound.content[i];
        member->expr = p->expr;

        if (p->name_index == U32_MAX) {
            member->name_mode = EXPR_COMPOUND_NO_NAME;
        } else {
            member->unresolved_name = p->name_index;
            member->name_mode = EXPR_COMPOUND_UNRESOLVED_NAME;
        }
    }

    arena_stack_pop(&context->stack);

    *length = t - t_start;
    return expr;
}

Expr** parse_parameter_list(Context* context, Token* t, u32* length, u32* count) {
    Token* t_start = t;

    typedef struct Param_Expr Param_Expr;
    struct Param_Expr {
        Expr* expr;
        Param_Expr *next, *previous;
    };

    u32 param_count = 0;
    Param_Expr* first_param = null;
    Param_Expr* last_param = null;

    arena_stack_push(&context->stack);

    while (t->kind != TOKEN_BRACKET_ROUND_CLOSE) {
        u32 param_length = 0;
        Expr* param = parse_expr(context, t, &param_length);
        t += param_length;

        if (param == null) {
            *length = t - t_start;
            return null;
        }

        if (t->kind != TOKEN_BRACKET_ROUND_CLOSE) {
            if (t->kind != TOKEN_COMMA) {
                print_file_pos(&t->pos);
                printf("Expected comma ',' or closing parenthesis ')' after parameter in call, but got ");
                print_token(context->string_table, t);
                printf("\n");
                *length = t - t_start;
                return null;
            }
            t += 1;
        }

        Param_Expr* next = arena_new(&context->stack, Param_Expr);
        next->expr = param;

        if (first_param == null) {
            first_param = next;
        } else {
            next->previous = last_param;
            last_param->next = next;
        }
        last_param = next;

        param_count += 1;
    }
    t += 1;

    *count = param_count;
    Expr** exprs = (void*) arena_alloc(&context->arena, param_count * sizeof(Expr*));

    Param_Expr* p = first_param;
    for (u32 i = 0; i < param_count; i += 1, p = p->next) {
        exprs[i] = p->expr;
    }

    arena_stack_pop(&context->stack);

    *length = t - t_start;
    return exprs;
}

Expr* parse_call(Context* context, Token* t, u32* length) {
    assert(t->kind == TOKEN_IDENTIFIER);
    u32 name_index = t->identifier_string_table_index;

    Token* t_start = t;
    File_Pos start_pos = t->pos;

    t += 1;
    assert(t->kind == TOKEN_BRACKET_ROUND_OPEN);
    t += 1;

    switch (parse_builtin_func_name(context, name_index)) {
        case BUILTIN_TYPE_INFO_OF_TYPE: {
            u32 type_length = 0;
            Type* type = parse_type(context, t, &type_length);
            t += type_length;

            if (type == null) {
                *length = t - t_start;
                return null;
            }

            if (!expect_single_token(context, t, TOKEN_BRACKET_ROUND_CLOSE, "after type in 'type_info_of_type'")) {
                *length = t - t_start;
                return null;
            }
            t += 1;

            Expr* expr = arena_new(&context->arena, Expr);
            expr->pos = start_pos;
            expr->kind = EXPR_TYPE_INFO_OF_TYPE;
            expr->type_info_of_type = type;
            expr->type = context->type_info_type;

            *length = t - t_start;
            return expr;
        } break;

        case BUILTIN_TYPE_INFO_OF_VALUE: {
            u32 inner_length = 0;
            Expr* inner = parse_expr(context, t, &inner_length);
            t += inner_length;

            if (inner == null) {
                *length = t - t_start;
                return null;
            }

            if (!expect_single_token(context, t, TOKEN_BRACKET_ROUND_CLOSE, "after type in 'type_info_of_value'")) {
                *length = t - t_start;
                return null;
            }
            t += 1;

            Expr* expr = arena_new(&context->arena, Expr);
            expr->pos = start_pos;
            expr->kind = EXPR_TYPE_INFO_OF_VALUE;
            expr->type_info_of_value = inner;
            expr->type = context->type_info_type;

            *length = t - t_start;
            return expr;
        } break;

        case BUILTIN_ENUM_LENGTH: {
            u32 type_length = 0;
            Type* type = parse_type(context, t, &type_length);
            t += type_length;

            if (type == null) {
                *length = t - t_start;
                return null;
            }

            if (!expect_single_token(context, t, TOKEN_BRACKET_ROUND_CLOSE, "after type in 'enum_length'")) {
                *length = t - t_start;
                return null;
            }
            t += 1;

            Expr* expr = arena_new(&context->arena, Expr);
            expr->pos = start_pos;
            expr->kind = EXPR_ENUM_LENGTH;
            expr->enum_length_of = type;
            expr->type = &context->primitive_types[TYPE_U64];

            *length = t - t_start;
            return expr;
        } break;

        case BUILTIN_ENUM_MEMBER_NAME: {
            u32 inner_expr_length = 0;
            Expr* inner = parse_expr(context, t, &inner_expr_length);
            t += inner_expr_length;

            if (inner == null) {
                *length = t - t_start;
                return null;
            }

            if (!expect_single_token(context, t, TOKEN_BRACKET_ROUND_CLOSE, "after type in 'enum_member_name'")) {
                *length = t - t_start;
                return null;
            }
            t += 1;

            Expr* expr = arena_new(&context->arena, Expr);
            expr->pos = start_pos;
            expr->kind = EXPR_ENUM_MEMBER_NAME;
            expr->enum_member = inner;
            expr->type = context->string_type;

            *length = t - t_start;
            return expr;
        } break;

        case BUILTIN_CAST: {
            u32 type_length = 0;
            Type* cast_to = parse_type(context, t, &type_length);
            t += type_length;

            if (cast_to == null) {
                *length = t - t_start;
                return null;
            }

            if (!expect_single_token(context, t, TOKEN_COMMA, "after type in cast")) {
                *length = t - t_start;
                return null;
            }
            t += 1;

            u32 inner_length = 0;
            Expr* cast_from = parse_expr(context, t, &inner_length);
            t += inner_length;

            if (cast_from == null) {
                *length = t - t_start;
                return null;
            }

            if (!expect_single_token(context, t, TOKEN_BRACKET_ROUND_CLOSE, "after cast")) {
                *length = t - t_start;
                return null;
            }
            t += 1;

            Expr* expr = arena_new(&context->arena, Expr);
            expr->pos = start_pos;
            expr->kind = EXPR_CAST;
            expr->cast_from = cast_from;
            expr->type = cast_to;

            *length = t - t_start;
            return expr;
        } break;

        // A normal function call or a simple cast
        case BUILTIN_INVALID: {
            u32 param_list_length = 0;
            u32 param_count = 0;
            Expr** params = parse_parameter_list(context, t, &param_list_length, &param_count);
            t += param_list_length;
            if (params == null) {
                *length = t - t_start;
                return null;
            }

            Type* cast_to_primitive = parse_primitive_name(context, name_index);
            if (cast_to_primitive != null) {
                if (!primitive_is_integer(cast_to_primitive->kind)) {
                    print_file_pos(&start_pos);
                    printf("Can't cast to %s\n", PRIMITIVE_NAMES[cast_to_primitive->kind]);
                    *length = t - t_start;
                    return null;
                }

                if (param_count != 1) {
                    print_file_pos(&start_pos);
                    printf(
                        "Expected 1 parameter for cast to %s, but got %u\n",
                        PRIMITIVE_NAMES[cast_to_primitive->kind], (u64) param_count
                    );
                    *length = t - t_start;
                    return null;
                }

                Expr* expr = arena_new(&context->arena, Expr);
                expr->pos = start_pos;
                expr->kind = EXPR_CAST;
                expr->cast_from = params[0];
                expr->type = cast_to_primitive;

                *length = t - t_start;
                return expr;
            } else {
                Expr* expr = arena_new(&context->arena, Expr);
                expr->pos = start_pos;
                expr->kind = EXPR_CALL;
                expr->call.unresolved_name = name_index;
                expr->flags |= EXPR_FLAG_UNRESOLVED;
                expr->call.params = params;
                expr->call.param_count = param_count;

                *length = t - t_start;
                return expr;
            }
        } break;

        default: assert(false);
    }

    assert(false);
    return null;
}

Stmt* parse_stmts(Context* context, Token* t, u32* length);

Stmt* parse_basic_block(Context* context, Token* t, u32* length) {
    Token* t_start = t;

    if (!expect_single_token(context, t, '{', "before block")) {
        *length = t - t_start;
        return null;
    }
    t += 1;

    u32 inner_length = 0;
    Stmt* stmts = parse_stmts(context, t, &inner_length);
    t += inner_length;
    *length = inner_length + 1;

    if (stmts == null) {
        *length = t - t_start;
        return null;
    }

    if (!expect_single_token(context, t, '}', "after block")) {
        *length = t - t_start;
        return null;
    }
    t += 1;

    *length = inner_length + 2;
    return stmts;
}

Stmt* parse_stmts(Context* context, Token* t, u32* length) {
    Token* t_first_stmt_start = t;

    Stmt* first_stmt = arena_new(&context->arena, Stmt);
    first_stmt->pos = t->pos;

    Stmt* stmt = first_stmt;

    while (true) {
        // Semicolons are just empty statements, skip them
        while (t->kind == TOKEN_SEMICOLON) {
            t += 1;
            continue;
        }

        Token* t_start = t;
        stmt->pos = t->pos;

        switch (t->kind) {
            case TOKEN_BRACKET_CURLY_CLOSE: {
                stmt->kind = STMT_END;
            } break;

            case TOKEN_BRACKET_CURLY_OPEN: {
                u32 block_length = 0;
                Stmt* inner = parse_basic_block(context, t, &block_length);
                t += block_length;
                if (inner == null) {
                    *length = t - t_first_stmt_start;
                    return null;
                }

                stmt->kind = STMT_BLOCK;
                stmt->block = inner;
            } break;

            case TOKEN_KEYWORD_IF: {
                Stmt* if_stmt = stmt;

                while (true) {
                    if_stmt->kind = STMT_IF;

                    t += 1;

                    if (!expect_single_token(context, t, '(', "before condition")) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }

                    t += 1;

                    u32 condition_length = 0;
                    if_stmt->conditional.condition = parse_expr(context, t, &condition_length);
                    t += condition_length;
                    if (if_stmt->conditional.condition == null) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }

                    if (!expect_single_token(context, t, ')', "after condition")) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }

                    t += 1;

                    u32 block_length = 0;
                    if_stmt->conditional.then = parse_basic_block(context, t, &block_length);
                    t += block_length;
                    if (if_stmt->conditional.then == null) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }

                    bool parse_another_if = false;
                    if (t->kind == TOKEN_KEYWORD_ELSE) {
                        t += 1;

                        switch (t->kind) {
                            case TOKEN_BRACKET_CURLY_OPEN: {
                                u32 block_length = 0;
                                if_stmt->conditional.else_then = parse_basic_block(context, t, &block_length);
                                t += block_length;
                                if (if_stmt->conditional.else_then == null) {
                                    *length = t - t_first_stmt_start;
                                    return null;
                                }
                            } break;

                            case TOKEN_KEYWORD_IF: {
                                parse_another_if = true;

                                Stmt* next_if_stmt = arena_new(&context->arena, Stmt);
                                next_if_stmt->next = arena_new(&context->arena, Stmt); // Sentinel

                                if_stmt->conditional.else_then = next_if_stmt;
                                if_stmt = next_if_stmt;
                            } break;

                            default: {
                                print_file_pos(&t->pos);
                                printf("Expected another if-statmenet or a basic block after else, but got ");
                                print_token(context->string_table, t);
                                printf("\n");
                                *length = t - t_first_stmt_start;
                                return null;
                            } break;
                        }
                    }

                    if(!parse_another_if) break;
                }
            } break;

            case TOKEN_KEYWORD_FOR: {
                t += 1;

                switch (t->kind) {
                    // Infinite loop
                    case '{': {
                        u32 body_length = 0;
                        Stmt* body = parse_basic_block(context, t, &body_length);
                        t += body_length;
                        if (body == null) {
                            *length = t - t_first_stmt_start;
                            return null;
                        }

                        stmt->kind = STMT_LOOP;
                        stmt->loop.condition = null;
                        stmt->loop.body = body;
                    } break;

                    case '(': {
                        t += 1;

                        u32 first_length = 0;
                        Expr* first = parse_expr(context, t, &first_length);
                        t += first_length;
                        if (first == null) {
                            *length = t - t_first_stmt_start;
                            return null;
                        }
                        
                        // TODO for-each and c-style loops

                        if (!expect_single_token(context, t, ')', "after loop condition")) {
                            *length = t - t_first_stmt_start;
                            return null;
                        }
                        t += 1;

                        u32 body_length = 0;
                        Stmt* body = parse_basic_block(context, t, &body_length);
                        t += body_length;
                        if (body == null) {
                            *length = t - t_first_stmt_start;
                            return null;
                        }

                        stmt->kind = STMT_LOOP;
                        stmt->loop.condition = first;
                        stmt->loop.body = body;
                    } break;

                    default: {
                        print_file_pos(&t->pos);
                        printf("Expected opening parenthesis '(' or curly brace '{' after for, but got ");
                        print_token(context->string_table, t);
                        printf("\n");
                        *length = t - t_first_stmt_start;
                        return null;
                    } break;
                }
            } break;

            case TOKEN_KEYWORD_RETURN: {
                stmt->kind = STMT_RETURN;
                t += 1;

                if (t->kind != TOKEN_SEMICOLON) {
                    u32 expr_length = 0;
                    stmt->return_stmt.value = parse_expr(context, t, &expr_length);
                    t += expr_length;
                    if (stmt->return_stmt.value == null) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }
                }

                if (!expect_single_token(context, t, TOKEN_SEMICOLON, "after variable declaration")) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
                t += 1;
            } break;

            case TOKEN_KEYWORD_BREAK: {
                stmt->kind = STMT_BREAK;
                t += 1;

                if (!expect_single_token(context, t, TOKEN_SEMICOLON, "after variable declaration")) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
                t += 1;
            } break;

            case TOKEN_KEYWORD_CONTINUE: {
                stmt->kind = STMT_CONTINUE;
                t += 1;

                if (!expect_single_token(context, t, TOKEN_SEMICOLON, "after variable declaration")) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
                t += 1;
            } break;

            case TOKEN_KEYWORD_LET: {
                t += 1;

                if (t->kind != TOKEN_IDENTIFIER) {
                    print_file_pos(&t->pos);
                    printf("Expected variable name, but found ");
                    print_token(context->string_table, t);
                    printf("\n");
                    *length = t - t_first_stmt_start;
                    return null;
                }
                u32 name_index = t->identifier_string_table_index;
                t += 1;

                Type* type = null;
                if (t->kind == TOKEN_COLON) {
                    t += 1;

                    u32 type_length = 0;
                    type = parse_type(context, t, &type_length);
                    if (type == null) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }
                    t += type_length;
                }

                Expr* expr = null;
                if (t->kind == TOKEN_ASSIGN) {
                    t += 1;

                    u32 right_length = 0;
                    expr = parse_expr(context, t, &right_length); 
                    if (expr == null) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }
                    t += right_length;
                }

                if (expr == null && type == null) {
                    u8* name = string_table_access(context->string_table, name_index);
                    print_file_pos(&t->pos);
                    printf("Declared variable '%s' without specifying type or initial value. Hence can't infer type\n", name);
                    *length = t - t_first_stmt_start;
                    return null;
                }

                buf_foreach (Var, old_var, context->tmp_vars) {
                    if (old_var->name == name_index) {
                        u8* name_string = string_table_access(context->string_table, name_index);
                        u32 initial_decl_line = old_var->declaration_pos.line;
                        print_file_pos(&stmt->pos);
                        printf("Redeclaration of variable '%s'. Initial declaration on line %u\n", name_string, (u64) initial_decl_line);
                        *length = t - t_first_stmt_start;
                        return null;
                    }
                }

                u32 var_index = buf_length(context->tmp_vars);
                buf_push(context->tmp_vars, ((Var) {
                    .name = name_index,
                    .declaration_pos = stmt->pos,
                    .type = type,
                }));

                assert(buf_length(context->tmp_vars) < MAX_LOCAL_VARS);

                stmt->kind = STMT_DECLARATION;
                stmt->declaration.var_index = var_index;
                stmt->declaration.right = expr;

                if (!expect_single_token(context, t, TOKEN_SEMICOLON, "after variable declaration")) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
                t += 1;
            } break;

            default: {
                u32 left_length = 0;
                Expr* left = parse_expr(context, t, &left_length);
                t += left_length;

                if (left == null) {
                    *length = t - t_first_stmt_start;
                    return null;
                }

                switch (t->kind) {
                    case TOKEN_ASSIGN: {
                        t += 1;

                        u32 right_length = 0;
                        Expr* right = parse_expr(context, t, &right_length);
                        t += right_length;

                        if (right == null) {
                            *length = t - t_first_stmt_start;
                            return null;
                        }

                        stmt->kind = STMT_ASSIGNMENT;
                        stmt->assignment.left = left;
                        stmt->assignment.right = right;
                    } break;

                    case TOKEN_ADD_ASSIGN:
                    case TOKEN_SUB_ASSIGN:
                    {
                        Binary_Op op;
                        switch (t->kind) {
                            case TOKEN_ADD_ASSIGN: op = BINARY_ADD; break;
                            case TOKEN_SUB_ASSIGN: op = BINARY_SUB; break;
                            default: assert(false);
                        }

                        t += 1;

                        u32 right_length = 0;
                        Expr* right = parse_expr(context, t, &right_length);
                        t += right_length;

                        if (right == null) {
                            *length = t - t_first_stmt_start;
                            return null;
                        }

                        Expr* binary = arena_new(&context->arena, Expr);
                        binary->kind = EXPR_BINARY;
                        binary->pos = left->pos;
                        binary->binary.left = left;
                        binary->binary.right = right;
                        binary->binary.op = op;

                        stmt->kind = STMT_ASSIGNMENT;
                        stmt->assignment.left = left;
                        stmt->assignment.right = binary;
                    } break;

                    default: {
                        stmt->kind = STMT_EXPR;
                        stmt->expr = left;
                    } break;
                }

                if (!expect_single_token(context, t, TOKEN_SEMICOLON, "after statement")) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
                t += 1;
            } break;
        }

        // Try parsing more statements after this one
        if (stmt->kind != STMT_END) {
            stmt->next = arena_new(&context->arena, Stmt);
            stmt = stmt->next;
        } else {
            break;
        }
    }

    *length = t - t_first_stmt_start;
    return first_stmt;
}

bool parse_parameter_declaration_list(Context* context, Func* func, Token* t, u32* length) {
    Token* t_start = t;

    if (!expect_single_token(context, t, TOKEN_BRACKET_ROUND_OPEN, "after function name")) {
        return null;
    }
    t += 1;

    assert(func->signature.param_count == 0);
    assert(func->signature.params == null);

    typedef struct Param Param;
    struct Param {
        u32 name;
        Type* type;
        File_Pos pos;
        Param *next, *previous;
    };

    Param* first = null;
    Param* last = null;

    arena_stack_push(&context->stack);

    if (t->kind == TOKEN_BRACKET_ROUND_CLOSE) {
        t += 1;
    } else while (true) {
        u32 names_given = 0;
        while (true) {
            if (t->kind != TOKEN_IDENTIFIER) {
                print_file_pos(&t->pos);
                printf("Expected a parameter name, but got ");
                print_token(context->string_table, t);
                printf("\n");
                *length = t - t_start;
                return false;
            }

            Param* next = arena_new(&context->stack, Param);
            next->name = t->identifier_string_table_index;
            next->pos = t->pos;

            t += 1;

            if (first == null) {
                first = next;
            } else {
                next->previous = last;
                last->next = next;
            }
            last = next;

            names_given += 1;
            func->signature.param_count += 1;

            if (t->kind == TOKEN_COMMA) {
                t += 1;
                continue;
            } else {
                break;
            }
        }

        if (!expect_single_token(context, t, TOKEN_COLON, names_given > 1? "after parameter names" : "after parameter name")) {
            *length = t - t_start;
            return false;
        }
        t += 1;

        u32 type_length = 0;
        Type* param_type = parse_type(context, t, &type_length);
        t += type_length;
        if (param_type == null) {
            *length = t - t_start;
            return false;
        }

        Param* p = last;
        for (u32 i = 0; i < names_given; i += 1) {
            p->type = param_type;
            p = p->previous;
        }

        if (t->kind == TOKEN_BRACKET_ROUND_CLOSE) {
            t += 1;
            break;
        } else {
            if (!expect_single_token(context, t, TOKEN_COMMA, "after member declaration")) return false;
            t += 1;
        }
    }

    func->signature.params = (void*) arena_alloc(&context->arena, func->signature.param_count * sizeof(*func->signature.params));

    u32 i = 0;
    for (Param* p = first; p != null; p = p->next, i += 1) {
        Var var = {0};
        var.name = p->name;
        var.type = p->type;
        var.declaration_pos = p->pos;

        u32 var_index = buf_length(context->tmp_vars);
        buf_push(context->tmp_vars, var);

        func->signature.params[i].var_index = var_index;
        func->signature.params[i].type = p->type;
    }

    arena_stack_pop(&context->stack);

    *length = t - t_start;
    return true;
}

// This parsing function returns length via a pointer, rather than taking it as a parameter
Func* parse_function(Context* context, Token* t, u32* length) {
    assert(t->kind == TOKEN_KEYWORD_FN);
    bool valid = true;

    Token* start = t;
    File_Pos declaration_pos = t->pos;

    // Estimate size of function, so we still print reasonable errors on bad function declarations
    // NB This assumes functions with bodies at the moment, maybe that is bad?
    *length = 1;
    for (Token* u = t + 1; !(u->kind == TOKEN_END_OF_STREAM || u->kind == TOKEN_KEYWORD_FN); u += 1) {
        *length += 1;
    }

    // Name
    t += 1;
    if (t->kind != TOKEN_IDENTIFIER) {
        print_file_pos(&t->pos);
        printf("Expected function name, but found ");
        print_token(context->string_table, t);
        printf("\n");

        return null;
    }
    u32 name_index = t->identifier_string_table_index;
    t += 1;

    u32 other_func_index = find_func(context, name_index);
    if (other_func_index != U32_MAX) {
        Func* other_func = &context->funcs[other_func_index];
        u8* name = string_table_access(context->string_table, name_index);
        print_file_pos(&start->pos);
        printf("A function called '%s' is defined both on line %u and line %u\n", name, (u64) declaration_pos.line, (u64) other_func->declaration_pos.line);
        valid = false;
    }

    if (parse_primitive_name(context, name_index) != null || context->builtin_names[BUILTIN_CAST] == name_index) {
        u8* name = string_table_access(context->string_table, name_index);
        print_file_pos(&start->pos);
        printf("Can't use '%s' as a function name, as it is reserved for casts\n", name);
        valid = false;
    } else if (parse_builtin_func_name(context, name_index) != BUILTIN_INVALID) {
        u8* name = string_table_access(context->string_table, name_index);
        print_file_pos(&start->pos);
        printf("Can't use '%s' as a function name, as it would shadow a builtin function\n", name);
        valid = false;
    }

    // NB we use these while parsing, and then copy them into the memory arena
    buf_clear(context->tmp_vars); 

    buf_push(context->funcs, ((Func) {0}));
    Func* func = buf_end(context->funcs) - 1;
    func->name = name_index;
    func->declaration_pos = start->pos;

    // Parameter list
    u32 parameter_length = 0;
    if (!parse_parameter_declaration_list(context, func, t, &parameter_length)) return null;
    t += parameter_length;

    // Return type
    func->signature.has_return = false;
    func->signature.return_type = &context->primitive_types[TYPE_VOID];

    if (t->kind == TOKEN_ARROW) {
        t += 1;

        u32 return_type_length = 0;
        Type* return_type = parse_type(context, t, &return_type_length);
        t += return_type_length;

        if (return_type == null) {
            return null;
        } else if (return_type->kind != TYPE_VOID) {
            func->signature.has_return = true;
            func->signature.return_type = return_type;
        }
    }

    // Functions without a body
    if (t->kind == TOKEN_SEMICOLON) {
        func->kind = FUNC_KIND_IMPORTED;

    // Body
    } else {
        func->kind = FUNC_KIND_NORMAL;

        if (t->kind != TOKEN_BRACKET_CURLY_OPEN) {
            u8* name = string_table_access(context->string_table, name_index);
            print_file_pos(&t->pos);
            printf("Expected an open curly brace { after 'fn %s ...', but found ", name);
            print_token(context->string_table, t);
            printf("\n");
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

bool parse_extern(Context* context, u8* source_path, Token* t, u32* length) {
    assert(t->kind == TOKEN_KEYWORD_EXTERN);

    Token* start = t;
    File_Pos declaration_pos = t->pos;

    // Estimate size of block, so we still print reasonable errors on bad function declarations
    *length = 1;
    for (Token* u = t + 1; !(u->kind == TOKEN_END_OF_STREAM || u->kind == TOKEN_KEYWORD_FN); u += 1) {
        *length += 1;
    }

    // Library name
    t += 1;
    if (t->kind != TOKEN_STRING) {
        print_file_pos(&t->pos);
        printf("Expected library name, but got ");
        print_token(context->string_table, t);
        printf("\n");
        return false;
    }
    u8* library_name = t->string.bytes;
    u32 library_name_index = string_table_intern(&context->string_table, t->string.bytes, t->string.length);

    // Body
    t += 1;
    if (t->kind != TOKEN_BRACKET_CURLY_OPEN) {
        print_file_pos(&t->pos);
        printf("Expected an open curly brace { after 'extern \"%s\" ...', but found ", library_name);
        print_token(context->string_table, t);
        printf("\n");
        return false;
    }

    Token* body = t + 1;
    u32 body_length = t->bracket_offset_to_matching - 1;
    t = t + t->bracket_offset_to_matching;

    *length = (u32) (t - start) + 1;

    bool valid = true;

    for (u32 i = 0; i < body_length; i += 1) {
        switch (body[i].kind) {
            case TOKEN_KEYWORD_FN: {
                u32 length;
                Func* func = parse_function(context, &body[i], &length);

                if (func == null) {
                    valid = false;
                } else if (func->kind != FUNC_KIND_IMPORTED) {
                    u8* name = string_table_access(context->string_table, func->name);
                    print_file_pos(&body[i].pos);
                    printf("Function '%s' has a body, but functions inside 'extern' blocks can't have bodies\n", name);
                    valid = false;
                } else {
                    Import_Index import_index = add_import(context, source_path, library_name_index, func->name);
                    func->import_info.index = import_index;
                }

                i += length - 1;
            } break;

            default: {
                print_file_pos(&body[i].pos);
                printf("Found invalid token at top level inside 'extern' block: ");
                print_token(context->string_table, &body[i]);
                printf("\n");

                i += 1;
                while (i < body_length && body[i].kind != TOKEN_SEMICOLON) { i += 1; }
            } break;
        }
        // TODO parse function templates
    }

    return valid;
}


bool lex_and_parse_text(Context* context, u8* file_name, u8* file, u32 file_length);

bool build_ast(Context* context, u8* file_name) {
    init_keyword_names(context);
    init_builtin_func_names(context);
    init_primitive_types(context);

    u8* file;
    u32 file_length;

    IO_Result read_result = read_entire_file(file_name, &file, &file_length);
    if (read_result != IO_OK) {
        printf("Couldn't load \"%s\": %s\n", file_name, io_result_message(read_result));
        return false;
    }

    bool valid = true;

    valid &= lex_and_parse_text(context, "<preload>", preload_code_text, str_length(preload_code_text));

    u32 type_kind_name_index = string_table_intern_cstr(&context->string_table, "Type_Kind");
    context->type_info_type = parse_user_type_name(context, type_kind_name_index);
    assert(context->type_info_type != null);
    assert(context->type_info_type->kind == TYPE_ENUM);
    assert(context->type_info_type->enumeration.name == type_kind_name_index);

    valid &= lex_and_parse_text(context, file_name, file, file_length);

    free(file);

    if (valid) {
        return true;
    } else {
        printf("Encountered errors while lexing / parsing, exiting compiler!\n");
        return false;
    }
}

bool lex_and_parse_text(Context* context, u8* file_name, u8* file, u32 file_length) {
    bool valid = true;

    // Lex
    arena_stack_push(&context->stack); // pop at end of lexing

    typedef struct Bracket_Info Bracket_Info;
    struct Bracket_Info {
        u8 our_char;
        u8 needed_match;
        File_Pos our_pos;
        u32 token_position;
        Bracket_Info* previous;
    };

    Bracket_Info* bracket_match = null;
    bool all_brackets_matched = true;


    Token* tokens = null;
    File_Pos file_pos = {0};
    file_pos.file_name = file_name;
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
                if (string_table_index == context->keyword_token_table[k][1]) {
                    buf_push(tokens, ((Token) { context->keyword_token_table[k][0], .pos = file_pos }));
                    is_keyword = true;
                    break;
                }
            }

            if (!is_keyword) {
                buf_push(tokens, ((Token) { TOKEN_IDENTIFIER, .identifier_string_table_index = string_table_index, .pos = file_pos }));
            }
        } break;

        DIGIT {
            u32 first = i;
            u32 last = i;
            bool overflow = false;
            bool floating_point = false;
            
            u64 value = 0;

            if (i + 2 < file_length && file[i] == '0' && file[i + 1] == 'x') {
                i += 2;

                for (; i < file_length; i += 1) {
                    u64 previous_value = value;
                    u64 digit;

                    switch (file[i]) {
                        case '0': digit = 0x0; break; case '1': digit = 0x1; break;
                        case '2': digit = 0x2; break; case '3': digit = 0x3; break;
                        case '4': digit = 0x4; break; case '5': digit = 0x5; break;
                        case '6': digit = 0x6; break; case '7': digit = 0x7; break;
                        case '8': digit = 0x8; break; case '9': digit = 0x9; break;
                        case 'a': digit = 0xa; break; case 'b': digit = 0xb; break;
                        case 'c': digit = 0xc; break; case 'd': digit = 0xd; break;
                        case 'e': digit = 0xe; break; case 'f': digit = 0xf; break;
                        case 'A': digit = 0xA; break; case 'B': digit = 0xB; break;
                        case 'C': digit = 0xC; break; case 'D': digit = 0xD; break;
                        case 'E': digit = 0xE; break; case 'F': digit = 0xF; break;
                        default: goto done_with_literal;
                    }

                    last = i;

                    value <<= 4;
                    value += digit;

                    if (value < previous_value) {
                        overflow = true;
                    }
                }
            } else {
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

                        case '.': {
                            floating_point = true;
                        } break;

                        default: goto done_with_literal;
                    }
                }
            }

            done_with_literal:

            if (overflow) {
                print_file_pos(&file_pos);
                printf(
                    "Literal %z is to large. Wrapped around to %u\n",
                    (u64) (last - first + 1), &file[first], value
                );
            }

            if (floating_point) {
                f64 float_value = parse_f64(&file[first], last - first + 1);

                buf_push(tokens, ((Token) {
                    .kind = TOKEN_LITERAL_FLOAT,
                    .literal_float = float_value,
                    .pos = file_pos
                }));
            } else {
                buf_push(tokens, ((Token) {
                    .kind = TOKEN_LITERAL_INT,
                    .literal_int = value,
                    .pos = file_pos
                }));
            }
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
                        kind = TOKEN_ADD_ASSIGN;
                        i += 2;
                    } else {
                        kind = TOKEN_ADD;
                        i += 1;
                    }
                } break;

                case '-': {
                    if (b == '>') {
                        kind = TOKEN_ARROW;
                        i += 2;
                    } else if (b == '=') {
                        kind = TOKEN_SUB_ASSIGN;
                        i += 2;
                    } else {
                        kind = TOKEN_SUB;
                        i += 1;
                    }
                } break;

                case '*': {
                    kind = TOKEN_MUL;
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
                        kind = TOKEN_DIV;
                        i += 1;
                    }
                } break;

                case '%': {
                    kind = TOKEN_MOD;
                    i += 1;
                } break;

                case '&': {
                    kind = TOKEN_AND;
                    i += 1;
                } break;

                case '>': {
                    switch (b) {
                        case '=': {
                            kind = TOKEN_GREATER_OR_EQUAL;
                            i += 2;
                        } break;
                        case '>': {
                            kind = TOKEN_SHIFT_RIGHT;
                            i += 2;
                        } break;
                        default: {
                            kind = TOKEN_GREATER;
                            i += 1;
                        } break;
                    }
                } break;

                case '<': {
                    switch (b) {
                        case '=': {
                            kind = TOKEN_LESS_OR_EQUAL;
                            i += 2;
                        } break;
                        case '<': {
                            kind = TOKEN_SHIFT_LEFT;
                            i += 2;
                        } break;
                        default: {
                            kind = TOKEN_LESS;
                            i += 1;
                        } break;
                    }
                } break;

                case '=': {
                    if (b == '=') {
                        kind = TOKEN_EQUAL;
                        i += 2;
                    } else {
                        kind = TOKEN_ASSIGN;
                        i += 1;
                    }
                } break;

                case '!': {
                    if (b == '=') {
                        kind = TOKEN_NOT_EQUAL;
                        i += 2;
                    } else {
                        kind = TOKEN_NOT;
                        i += 1;
                    }
                } break;

                case '|': {
                    kind = TOKEN_OR;
                } break;

                case '^': {
                    kind = TOKEN_XOR;
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
                    Bracket_Info* info = arena_new(&context->stack, Bracket_Info);
                    info->our_char = our_char;
                    info->our_pos = file_pos;
                    info->needed_match = matching_kind;
                    info->token_position = buf_length(tokens);
                    info->previous = bracket_match;
                    bracket_match = info;
                    offset = 0;
                } else {
                    if (bracket_match == null) {
                        print_file_pos(&file_pos);
                        printf("Found a closing bracket '%c' before any opening brackets were found\n", our_char);
                        all_brackets_matched = false;
                    } else if (bracket_match->needed_match != kind) {
                        print_file_pos(&file_pos);
                        printf(
                            "Found a closing bracket '%c', which doesn't match the previous '%c' (Line %u and %u)\n",
                            our_char, bracket_match->our_char, (u64) bracket_match->our_pos.line, (u64) file_pos.line
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
                    print_file_pos(&file_pos);
                    printf("Strings can't span multiple lines\n");
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
                    i += 1;
                    collapsed_length -= 1;

                    u8 escaped = start[i];
                    u8 resolved = U8_MAX;
                    switch (escaped) {
                        case 'n': resolved = 0x0a; i += 1; break;
                        case 'r': resolved = 0x0d; i += 1; break;
                        case 't': resolved = 0x09; i += 1; break;
                        case '0': resolved = 0x00; i += 1; break;
                    }

                    if (resolved == U8_MAX) {
                        print_file_pos(&file_pos);
                        printf("Invalid escape sequence: '\\%c'\n", escaped);
                        valid = false;
                        break;
                    }

                    arena_pointer[j] = resolved;
                    j += 1;
                } else {
                    arena_pointer[j] = start[i];
                    i += 1;
                    j += 1;
                }
            }

            if (valid) {
                arena_pointer[collapsed_length] = 0;

                buf_push(tokens, ((Token) {
                    TOKEN_STRING,
                    .string.bytes = arena_pointer,
                    .string.length = collapsed_length,
                    .pos = file_pos,
                }));
            }
        } break;

        case ',': {
            i += 1;
            buf_push(tokens, ((Token) { TOKEN_COMMA, .pos = file_pos }));
        } break;

        case '.': {
            i += 1;
            buf_push(tokens, ((Token) { TOKEN_DOT, .pos = file_pos }));
        } break;

        case ':': {
            if (i + 1 < file_length && file[i + 1] == ':') {
                i += 2;
                buf_push(tokens, ((Token) { TOKEN_STATIC_ACCESS, .pos = file_pos }));
            } else {
                i += 1;
                buf_push(tokens, ((Token) { TOKEN_COLON, .pos = file_pos }));
            }
        } break;

        case ';': {
            i += 1;
            buf_push(tokens, ((Token) { TOKEN_SEMICOLON, .pos = file_pos }));
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
            print_file_pos(&file_pos);
            printf("Unexpected character: %c\n", file[i]);
            valid = false;
            i += 1;
        } break;
    }
    buf_push(tokens, ((Token) { TOKEN_END_OF_STREAM, .pos = file_pos }));


    if (all_brackets_matched && bracket_match != null) {
        all_brackets_matched = false;
        print_file_pos(&bracket_match->our_pos);
        printf("Unclosed bracket '%c'\n", bracket_match->our_char);
    }

    arena_stack_pop(&context->stack);

    if (!all_brackets_matched) {
        return false;
    }

    #if 0
    printf("%u tokens:\n", (u64) buf_length(tokens));
    for (Token* t = tokens; t->kind != TOKEN_END_OF_STREAM; t += 1) {
        print_token_pos(&t->pos);
        printf("  ");
        print_token(string_table, t);
        printf("\n");
    }
    #endif

    // Parse
    Token* t = tokens;
    while (t->kind != TOKEN_END_OF_STREAM && valid) switch (t->kind) {
        case TOKEN_KEYWORD_FN: {
            u32 length = 0;
            Func* func = parse_function(context, t, &length);

            if (func == null) {
                valid = false;
            } else if (func->kind != FUNC_KIND_NORMAL) {
                u8* name = string_table_access(context->string_table, func->name);
                print_file_pos(&t->pos);
                printf("Function '%s' doesn't have a body. Functions without bodies can only be inside 'extern' blocks\n", name);
                valid = false;
            }

            t += length;
        } break;

        case TOKEN_KEYWORD_EXTERN: {
            u32 length = 0;
            valid &= parse_extern(context, file_name, t, &length);
            t += length;
        } break;

        case TOKEN_KEYWORD_LET: {
            File_Pos start_pos = t->pos;
            t += 1;

            if (t->kind != TOKEN_IDENTIFIER) {
                print_file_pos(&t->pos);
                printf("Expected global variable name, but found ");
                print_token(context->string_table, t);
                printf("\n");
                valid = false;
                break;
            }
            u32 name_index = t->identifier_string_table_index;
            t += 1;

            Type* type = null;
            if (t->kind == TOKEN_COLON) {
                t += 1;

                u32 type_length = 0;
                type = parse_type(context, t, &type_length);
                t += type_length;
                if (type == null) {
                    valid = false;
                    break;
                }
            }

            Expr* expr = null;
            if (t->kind == TOKEN_ASSIGN) {
                t += 1;

                u32 right_length = 0;
                expr = parse_expr(context, t, &right_length); 
                if (expr == null) {
                    valid = false;
                    break;
                }
                t += right_length;
            }

            if (expr == null && type == null) {
                u8* name = string_table_access(context->string_table, name_index);
                print_file_pos(&t->pos);
                printf("Declared global variable '%s' without specifying type or initial value. Hence can't infer type\n", name);
                valid = false;
                break;
            }

            if (!expect_single_token(context, t, TOKEN_SEMICOLON, "after global variable declaration")) {
                valid = false;
                break;
            }
            t += 1;

            bool redeclaration = false;
            buf_foreach (Global_Var, old_global, context->global_vars) {
                if (old_global->var.name == name_index) {
                    u8* name_string = string_table_access(context->string_table, name_index);
                    u32 initial_decl_line = old_global->var.declaration_pos.line;
                    print_file_pos(&start_pos);
                    printf("Redeclaration of global '%s'. Initial declaration on line %u\n", name_string, (u64) initial_decl_line);
                    redeclaration = true;
                    break;
                }
            }

            if (redeclaration) {
                valid = false;
                break;
            } else {
                Global_Var global = {0};
                global.var.name = name_index;
                global.var.declaration_pos = start_pos;
                global.var.type = type;
                global.initial_expr = expr;
                buf_push(context->global_vars, global);

                assert(buf_length(context->global_vars) < MAX_LOCAL_VARS);
            }
        } break;

        case TOKEN_KEYWORD_ENUM:
        case TOKEN_KEYWORD_STRUCT:
        {
            File_Pos start_pos = t->pos;

            u32 length = 0;
            Type* type;
            switch (t->kind) {
                case TOKEN_KEYWORD_ENUM:   type = parse_enum_declaration(context, t, &length); break;
                case TOKEN_KEYWORD_STRUCT: type = parse_struct_declaration(context, t, &length); break;
                default: assert(false);
            }
            t += length;

            if (type == null) {
                valid = false;
                break;
            }

            u32 our_name = user_type_name(type);

            bool redeclaration = false;
            buf_foreach(Type*, old_type_pointer, context->user_types) {
                u32 old_name = user_type_name(*old_type_pointer);
                if (old_name == our_name) {
                    redeclaration = true;
                    break;
                }
            }

            if (redeclaration) {
                u8* our_name_string = string_table_access(context->string_table, our_name);
                print_file_pos(&start_pos);
                printf("Duplicate definition of type '%s'\n", our_name_string);
                valid = false;
            } else {
                buf_push(context->user_types, type);
            }
        } break;

        case TOKEN_KEYWORD_UNION: {
            unimplemented(); // TODO
        } break;

        default: {
            valid = false;

            print_file_pos(&t->pos);
            printf("Found invalid token at global scope: ");
            print_token(context->string_table, t);
            printf("\n");
        } break;
    }

    return valid;
}


typedef struct Scope Scope;
struct Scope {
    u32 var_count;
    u8 *map; // list of booleans, for marking which variables currently are in scope

    Scope *child, *parent;
};

typedef struct Typecheck_Info {
    Context *context;
    Func *func;
    Scope *scope;
} Typecheck_Info;

Scope* scope_new(Context *context, u32 var_count) {
    Scope* scope = arena_new(&context->stack, Scope);
    scope->var_count = var_count;
    scope->map = arena_alloc(&context->stack, var_count);
    mem_clear(scope->map, var_count);
    return scope;
}

void typecheck_scope_push(Typecheck_Info *info) {
    if (info->scope->child == null) {
        info->scope->child = scope_new(info->context, info->scope->var_count);
        info->scope->child->parent = info->scope;
    }

    mem_copy(info->scope->map, info->scope->child->map, info->scope->var_count);

    info->scope = info->scope->child;
}

void typecheck_scope_pop(Typecheck_Info *info) {
    assert(info->scope->parent != null);
    info->scope = info->scope->parent;
}

bool resolve_type(Context *context, Type **type_slot, File_Pos *pos) {
    // The reason we have a pretty complex system here is because we want types to be pointer-equal

    Type* type = *type_slot;

    if (!(type->flags & TYPE_FLAG_UNRESOLVED)) {
        return true;
    }

    typedef struct Prefix Prefix;
    struct Prefix {
        enum { PREFIX_POINTER, PREFIX_ARRAY } kind;
        u64 array_length;
        Prefix* link;
    };
    Prefix* prefix = null;

    arena_stack_push(&context->stack); // We allocate prefixes, if any, on the stack

    while (true) {
        bool done = false;

        switch (type->kind) {
            case TYPE_POINTER: {
                Prefix* new = arena_new(&context->stack, Prefix);
                new->kind = PREFIX_POINTER;
                new->link = prefix;
                prefix = new;

                type = type->pointer_to;
            } break;

            case TYPE_ARRAY: {
                Prefix* new = arena_new(&context->stack, Prefix);
                new->kind = PREFIX_ARRAY;
                new->array_length = type->array.length;
                new->link = prefix;
                prefix = new;

                type = type->array.of;
            } break;

            case TYPE_UNRESOLVED_NAME: {
                Type* new = parse_user_type_name(context, type->unresolved_name);

                if (new == null) {
                    u8* name_string = string_table_access(context->string_table, type->unresolved_name);
                    print_file_pos(pos);
                    printf("No such type: '%s'\n", name_string);
                    return false;
                }

                type = new;

                done = true;
            } break;

            default: assert(false);
        }

        if (done) break;
    }

    while (prefix != null) {
        switch (prefix->kind) {
            case PREFIX_POINTER: type = get_pointer_type(context, type); break;
            case PREFIX_ARRAY:   type = get_array_type(context, type, prefix->array_length); break;
        }
        prefix = prefix->link;
    }

    arena_stack_pop(&context->stack);

    *type_slot = type;
    return true;
}

typedef enum Typecheck_Expr_Result {
    TYPECHECK_EXPR_STRONG,
    TYPECHECK_EXPR_WEAK , // Used for e.g. integer literals, which can solidify to any integer type
    TYPECHECK_EXPR_BAD,
} Typecheck_Expr_Result;

Typecheck_Expr_Result typecheck_expr(Typecheck_Info* info, Expr* expr, Type* solidify_to) {
    bool strong = true;

    switch (expr->kind) {
        case EXPR_VARIABLE: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u32 var_index = find_var(info->context, info->func, expr->variable.unresolved_name);

                if (var_index == U32_MAX) {
                    u8* var_name = string_table_access(info->context->string_table, expr->variable.unresolved_name);
                    print_file_pos(&expr->pos);
                    printf("Can't find variable '%s' ", var_name);
                    if (info->func != null) {
                        u8* func_name = string_table_access(info->context->string_table, info->func->name);
                        printf("in function '%s' or ", func_name);
                    }
                    printf("in global scope\n");
                    return TYPECHECK_EXPR_BAD;
                }

                if (var_index & VAR_INDEX_GLOBAL_FLAG) {
                    u32 global_index = var_index & (~VAR_INDEX_GLOBAL_FLAG);
                    Global_Var* global = &info->context->global_vars[global_index];

                    if (!global->valid) {
                        if (!global->checked) {
                            u8* name = string_table_access(info->context->string_table, global->var.name);
                            print_file_pos(&expr->pos);
                            printf(
                                "Can't use global variable '%s' before its declaration on line %u\n",
                                name, (u64) global->var.declaration_pos.line
                            );
                        }

                        return TYPECHECK_EXPR_BAD;
                    }
                } else if (info->scope->map[var_index] == false) {
                    Var* var = &info->func->body.vars[var_index];
                    u8* var_name = string_table_access(info->context->string_table, expr->variable.unresolved_name);

                    u64 use_line = expr->pos.line;
                    u64 decl_line = var->declaration_pos.line;

                    if (use_line <= decl_line) {
                        printf(
                            "Can't use variable '%s' on line %u before its declaration on line %u\n",
                            var_name, use_line, decl_line
                        );
                    } else {
                        printf(
                            "Can't use variable '%s' on line %u, as it isn't in scope\n",
                            var_name, use_line
                        );
                    }

                    return TYPECHECK_EXPR_BAD;
                }

                expr->variable.index = var_index;
                expr->flags &= ~EXPR_FLAG_UNRESOLVED;
                expr->flags |= EXPR_FLAG_ASSIGNABLE;
            }

            if (expr->variable.index & VAR_INDEX_GLOBAL_FLAG) {
                u32 global_index = expr->variable.index & (~VAR_INDEX_GLOBAL_FLAG);
                expr->type = info->context->global_vars[global_index].var.type;
            } else {
                expr->type = info->func->body.vars[expr->variable.index].type;
            }
        } break;

        case EXPR_LITERAL: {
            Type_Kind to_primitive = solidify_to->kind;

            expr->literal.masked_value = expr->literal.raw_value;

            switch (expr->literal.kind) {
                case EXPR_LITERAL_POINTER: {
                    if (to_primitive == TYPE_POINTER) {
                        expr->type = solidify_to;
                    } else {
                        expr->type = info->context->void_pointer_type;
                    }
                } break;

                case EXPR_LITERAL_BOOL: {
                    assert(expr->literal.raw_value == true || expr->literal.raw_value == false);
                    expr->type = &info->context->primitive_types[TYPE_BOOL];
                } break;

                case EXPR_LITERAL_INTEGER: {
                    strong = false;

                    if (primitive_is_integer(to_primitive)) {
                        expr->type = solidify_to;
                    } else if (to_primitive == TYPE_POINTER) {
                        // Handles 'pointer + integer' and similar cases
                        expr->type = &info->context->primitive_types[TYPE_U64];
                    } else {
                        expr->type = &info->context->primitive_types[DEFAULT_INT_TYPE];
                    }

                    u64 mask = size_mask(primitive_size_of(expr->type->kind));
                    expr->literal.masked_value = expr->literal.raw_value & mask;
                    if (expr->literal.masked_value != expr->literal.raw_value) {
                        print_file_pos(&expr->pos);
                        printf(
                            "Warning: Literal %u won't fit fully into a %s and will be masked!\n",
                            (u64) expr->literal.raw_value, PRIMITIVE_NAMES[solidify_to->kind]
                        );
                    }
                } break;

                case EXPR_LITERAL_FLOAT: {
                    strong = false;

                    if (primitive_is_float(to_primitive)) {
                        expr->type = solidify_to;
                    } else {
                        expr->type = &info->context->primitive_types[DEFAULT_FLOAT_TYPE];
                    }

                    switch (expr->type->kind) {
                        case TYPE_F64: expr->literal.masked_value = expr->literal.raw_value; break;
                        case TYPE_F32: {
                            f64 big = *((f64*) &expr->literal.raw_value);
                            f32 small = (f32) big;
                            expr->literal.masked_value = (u64) *((u32*) &small);
                        } break;
                    }
                } break;

                default: assert(false);
            }
        } break;

        case EXPR_STRING_LITERAL: {
            assert(expr->type == info->context->string_type);
        } break;

        case EXPR_COMPOUND: {
            if (expr->type == null) {
                if (solidify_to->kind == TYPE_VOID) {
                    print_file_pos(&expr->pos);
                    printf("No type given for compound literal\n");
                    return TYPECHECK_EXPR_BAD;
                }
                expr->type = solidify_to;
            }

            if (!resolve_type(info->context, &expr->type, &expr->pos)) return TYPECHECK_EXPR_BAD;

            switch (expr->type->kind) {
                case TYPE_ARRAY: {
                    u64 expected_child_count = expr->type->array.length;
                    Type* expected_child_type = expr->type->array.of;

                    if (expr->compound.count != expected_child_count) {
                        print_file_pos(&expr->pos);
                        printf(
                            "Too %s values in compound literal: expected %u, got %u\n",
                            (expr->compound.count > expected_child_count)? "many" : "few",
                            (u64) expected_child_count,
                            (u64) expr->compound.count
                        );
                        return TYPECHECK_EXPR_BAD;
                    }

                    for (u32 m = 0; m < expr->compound.count; m += 1) {
                        Compound_Member* member = &expr->compound.content[m];

                        if (member->name_mode != EXPR_COMPOUND_NO_NAME) {
                            print_file_pos(&expr->pos);
                            printf("Unexpected member name '%s' given inside array literal\n", compound_member_name(info->context, expr, member));
                            return TYPECHECK_EXPR_BAD;
                        }

                        if (typecheck_expr(info, member->expr, expected_child_type) == TYPECHECK_EXPR_BAD) return TYPECHECK_EXPR_BAD;

                        if (expected_child_type != member->expr->type) {
                            print_file_pos(&expr->pos);
                            printf("Invalid type inside compound literal: Expected ");
                            print_type(info->context, expected_child_type);
                            printf(" but got ");
                            print_type(info->context, member->expr->type);
                            printf("\n");
                            return TYPECHECK_EXPR_BAD;
                        }
                    }
                } break;

                case TYPE_STRUCT: {
                    if (expr->compound.count > expr->type->structure.member_count) {
                        u64 expected = expr->type->structure.member_count;
                        u64 given = expr->compound.count;
                        print_file_pos(&expr->pos);
                        printf("Expected at most %u %s, but got %u for struct literal\n", expected, expected == 1? "member" : "members", given);
                        return TYPECHECK_EXPR_BAD;
                    }

                    bool any_named = false;
                    bool any_unnamed = false;

                    u8* set_map = arena_alloc(&info->context->stack, expr->type->structure.member_count);
                    mem_clear(set_map, expr->type->structure.member_count);

                    for (u32 i = 0; i < expr->compound.count; i += 1) {
                        Expr* child = expr->compound.content[i].expr;

                        if (expr->compound.content[i].name_mode == EXPR_COMPOUND_UNRESOLVED_NAME) {
                            u32 unresolved_name = expr->compound.content[i].unresolved_name;
                            u32 member_index = U32_MAX;

                            for (u32 m = 0; m < expr->type->structure.member_count; m += 1) {
                                if (expr->type->structure.members[m].name == unresolved_name) {
                                    member_index = m;
                                    break;
                                }
                            }

                            if (member_index == U32_MAX) {
                                u8* member_name = string_table_access(info->context->string_table, unresolved_name);
                                u8* struct_name = string_table_access(info->context->string_table, expr->type->structure.name);
                                print_file_pos(&expr->pos);
                                printf("Struct '%s' has no member '%s'\n", struct_name, member_name);
                                return TYPECHECK_EXPR_BAD;
                            } else {
                                expr->compound.content[i].name_mode = EXPR_COMPOUND_NAME;
                                expr->compound.content[i].member_index = member_index;
                            }
                        }

                        if (expr->compound.content[i].name_mode == EXPR_COMPOUND_NO_NAME) {
                            assert(expr->compound.content[i].member_index == 0);
                            expr->compound.content[i].member_index = i;
                            any_unnamed = true;
                        } else {
                            any_named = true;
                        }

                        u32 m = expr->compound.content[i].member_index;
                        Type* member_type = expr->type->structure.members[m].type;
                        
                        if (typecheck_expr(info, child, member_type) == TYPECHECK_EXPR_BAD) {
                            return TYPECHECK_EXPR_BAD;
                        }

                        if (member_type != child->type) {
                            u8* member_name = string_table_access(info->context->string_table, expr->type->structure.members[m].name);
                            u8* struct_name = string_table_access(info->context->string_table, expr->type->structure.name);

                            print_file_pos(&child->pos);
                            printf("Expected ");
                            print_type(info->context, member_type);
                            printf(" but got ");
                            print_type(info->context, child->type);
                            printf(" for member '%s' of struct '%s'\n", member_name, struct_name);
                            return TYPECHECK_EXPR_BAD;
                        }

                        if (set_map[i]) {
                            u32 name_index = expr->type->structure.members[m].name;
                            u8* member_name = string_table_access(info->context->string_table, name_index);

                            print_file_pos(&child->pos);
                            printf("'%s' is set more than once in struct literal\n", member_name);
                            return TYPECHECK_EXPR_BAD;
                        }
                        set_map[i] = true;
                    }

                    if (any_named && any_unnamed) {
                        print_file_pos(&expr->pos);
                        printf("Struct literal can't have both named and unnamed members\n");
                        return TYPECHECK_EXPR_BAD;
                    }

                    if (any_unnamed && expr->compound.count != expr->type->structure.member_count) {
                        print_file_pos(&expr->pos);
                        printf("Expected %u members, but got %u for struct literal\n", expr->type->structure.member_count, expr->compound.count);
                        return TYPECHECK_EXPR_BAD;
                    }
                } break;

                default: {
                    print_file_pos(&expr->pos);
                    printf("Invalid type for compound literal: ");
                    print_type(info->context, expr->type);
                    printf("\n");
                    return TYPECHECK_EXPR_BAD;
                } break;
            }
        } break;

        case EXPR_BINARY: {
            if (BINARY_OP_COMPARATIVE[expr->binary.op]) {
                solidify_to = &info->context->primitive_types[TYPE_VOID];
            }

            Typecheck_Expr_Result left_result, right_result;

            left_result = typecheck_expr(info, expr->binary.left, solidify_to);
            right_result = typecheck_expr(info, expr->binary.right, solidify_to);

            if (left_result == TYPECHECK_EXPR_BAD || right_result == TYPECHECK_EXPR_BAD) {
                return TYPECHECK_EXPR_BAD;
            }

            if (left_result == TYPECHECK_EXPR_WEAK && right_result == TYPECHECK_EXPR_WEAK ) {
                right_result = typecheck_expr(info, expr->binary.right, expr->binary.left->type);
            } else if (left_result == TYPECHECK_EXPR_WEAK  && right_result == TYPECHECK_EXPR_STRONG) {
                left_result = typecheck_expr(info, expr->binary.left, expr->binary.right->type);
            } else if (left_result == TYPECHECK_EXPR_STRONG && right_result == TYPECHECK_EXPR_WEAK ) {
                right_result = typecheck_expr(info, expr->binary.right, expr->binary.left->type);
            }

            assert(left_result != TYPECHECK_EXPR_BAD && right_result != TYPECHECK_EXPR_BAD);
            if (left_result == TYPECHECK_EXPR_WEAK  && right_result == TYPECHECK_EXPR_WEAK ) {
                strong = false;
            }

            bool valid_types = false;

            if (BINARY_OP_COMPARATIVE[expr->binary.op]) {
                expr->type = &info->context->primitive_types[TYPE_BOOL];

                if (expr->binary.left->type == expr->binary.right->type && !primitive_is_compound(expr->binary.left->type->kind)) {
                    valid_types = true;
                }
                if (expr->binary.left->type->kind == TYPE_POINTER && expr->binary.left->type->kind == TYPE_POINTER) {
                    valid_types = true;
                }
                if (!(expr->binary.op == BINARY_EQ || expr->binary.op == BINARY_NEQ) && !primitive_is_integer(expr->binary.left->type->kind)) {
                    valid_types = false;
                }
            } else {
                if (expr->binary.left->type == expr->binary.right->type && (primitive_is_integer(expr->binary.left->type->kind) || primitive_is_float(expr->binary.left->type->kind))) {
                    expr->type = expr->binary.left->type;
                    valid_types = true;

                // Special-case pointer-pointer arithmetic
                } else switch (expr->binary.op) {
                    case BINARY_ADD: {
                        if (expr->binary.left->type->kind == TYPE_POINTER && expr->binary.right->type->kind == TYPE_U64) {
                            expr->type = expr->binary.left->type;
                            valid_types = true;
                        }
                        if (expr->binary.left->type->kind == TYPE_U64 && expr->binary.right->type->kind == TYPE_POINTER) {
                            expr->type = expr->binary.right->type;
                            valid_types = true;
                        }
                    } break;

                    case BINARY_SUB: {
                        if (expr->binary.left->type->kind == TYPE_POINTER && expr->binary.right->type->kind == TYPE_U64) {
                            expr->type = expr->binary.left->type;
                            valid_types = true;
                        }
                    } break;

                    case BINARY_MUL: {} break;
                    case BINARY_DIV: {} break;
                    case BINARY_MOD: {} break;

                    default: assert(false);
                }
            }

            if (!valid_types) {
                if (expr->binary.left->type != expr->binary.right->type) {
                    print_file_pos(&expr->pos);
                    printf("Types for operator %s don't match: ", BINARY_OP_SYMBOL[expr->binary.op]);
                    print_type(info->context, expr->binary.left->type);
                    printf(" vs ");
                    print_type(info->context, expr->binary.right->type);
                    printf("\n");
                    return TYPECHECK_EXPR_BAD;
                } else {
                    print_file_pos(&expr->pos);
                    printf("Can't use operator %s on ", BINARY_OP_SYMBOL[expr->binary.op]);
                    print_type(info->context, expr->binary.left->type);
                    printf("\n");
                    return TYPECHECK_EXPR_BAD;
                }
            }
        } break;

        case EXPR_UNARY: {
            switch (expr->unary.op) {
                case UNARY_DEREFERENCE: {
                    solidify_to = get_pointer_type(info->context, solidify_to);
                } break;

                case UNARY_ADDRESS_OF: {
                    if (solidify_to->kind == TYPE_POINTER) {
                        solidify_to = solidify_to->pointer_to;
                    }
                } break;
            }

            if (typecheck_expr(info, expr->unary.inner, solidify_to) == TYPECHECK_EXPR_BAD) return TYPECHECK_EXPR_BAD;

            switch (expr->unary.op) {
                case UNARY_NOT: {
                    // TODO allow using UNARY_NOT to do a bitwise not on integers
                    expr->type = expr->unary.inner->type;
                    if (expr->type->kind != TYPE_BOOL) {
                        print_file_pos(&expr->unary.inner->pos);
                        printf("Can only apply unary not (!) to ");
                        print_type(info->context, expr->type);
                        printf(", its not a bool\n");
                        return TYPECHECK_EXPR_BAD;
                    }
                } break;

                case UNARY_NEG: {
                    expr->type = expr->unary.inner->type;
                    if (!primitive_is_integer(expr->type->kind)) {
                        print_file_pos(&expr->unary.inner->pos);
                        printf("Can only apply unary negative (-) to ");
                        print_type(info->context, expr->type);
                        printf(", its not a bool\n");
                        return TYPECHECK_EXPR_BAD;
                    }
                } break;

                case UNARY_DEREFERENCE: {
                    expr->type = expr->unary.inner->type->pointer_to;
                    expr->flags |= EXPR_FLAG_ASSIGNABLE;

                    Type_Kind child_primitive = expr->unary.inner->type->kind;
                    if (child_primitive != TYPE_POINTER) {
                        print_file_pos(&expr->pos);
                        printf("Can't dereference non-pointer ");
                        print_expr(info->context, info->func, expr->unary.inner);
                        printf("\n");
                        return TYPECHECK_EXPR_BAD;
                    }

                    Type_Kind pointer_to = expr->unary.inner->type->pointer_to->kind;
                    if (pointer_to == TYPE_VOID) {
                        print_file_pos(&expr->pos);
                        printf("Can't dereference a void pointer ");
                        print_expr(info->context, info->func, expr->unary.inner);
                        printf("\n");
                        return TYPECHECK_EXPR_BAD;
                    }
                } break;

                case UNARY_ADDRESS_OF: {
                    expr->type = get_pointer_type(info->context, expr->unary.inner->type);
                    if (!(expr->unary.inner->flags & EXPR_FLAG_ASSIGNABLE)) {
                        print_file_pos(&expr->pos);
                        printf("Can't take address of ");
                        print_expr(info->context, info->func, expr->unary.inner);
                        printf("\n");
                        return TYPECHECK_EXPR_BAD;
                    }
                } break;

                default: assert(false);
            }
        } break;

        case EXPR_CALL: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u32 func_index = find_func(info->context, expr->call.unresolved_name);
                if (func_index == U32_MAX) {
                    u8* name = string_table_access(info->context->string_table, expr->call.unresolved_name);
                    print_file_pos(&expr->pos);
                    printf("Can't find function '%s'\n", name);
                    return TYPECHECK_EXPR_BAD;
                }

                expr->call.func_index = func_index;
                expr->flags &= ~EXPR_FLAG_UNRESOLVED;
            }

            Func* callee = &info->context->funcs[expr->call.func_index];
            expr->type = callee->signature.return_type;

            if (expr->call.param_count != callee->signature.param_count) {
                u8* name = string_table_access(info->context->string_table, callee->name);
                print_file_pos(&expr->pos);
                printf(
                    "Function '%s' takes %u parameters, but %u were given\n",
                    name, (u64) callee->signature.param_count, (u64) expr->call.param_count
                );
                return TYPECHECK_EXPR_BAD;
            }

            for (u32 p = 0; p < expr->call.param_count; p += 1) {
                Expr* param_expr = expr->call.params[p];

                u32 var_index = callee->signature.params[p].var_index;

                Type* expected_type = callee->signature.params[p].type;
                if (callee->signature.params[p].reference_semantics) {
                    assert(expected_type->kind == TYPE_POINTER);
                    expected_type = expected_type->pointer_to;
                }

                if (typecheck_expr(info, param_expr, expected_type) == TYPECHECK_EXPR_BAD) return TYPECHECK_EXPR_BAD;

                Type* actual_type = param_expr->type;
                if (!type_can_assign(expected_type, actual_type)) {
                    u8* func_name = string_table_access(info->context->string_table, callee->name);
                    print_file_pos(&expr->pos);
                    printf("Invalid type for %n parameter to '%s' Expected ", (u64) (p + 1), func_name);
                    print_type(info->context, expected_type);
                    printf(" but got ");
                    print_type(info->context, actual_type);
                    printf("\n");

                    return TYPECHECK_EXPR_BAD;
                }
            }
        } break;

        case EXPR_CAST: {
            if (!resolve_type(info->context, &expr->type, &expr->pos)) return TYPECHECK_EXPR_BAD;
            if (typecheck_expr(info, expr->cast_from, expr->type) == TYPECHECK_EXPR_BAD) return TYPECHECK_EXPR_BAD;

            Type_Kind from = expr->cast_from->type->kind;
            Type_Kind to   = expr->type->kind;

            bool valid =
                (from == TYPE_POINTER && to == TYPE_POINTER) ||
                (from == TYPE_POINTER && to == TYPE_U64) ||
                (from == TYPE_U64 && to == TYPE_POINTER) ||
                (primitive_is_integer(from) && primitive_is_integer(to)) ||
                (primitive_is_integer(from) && to == TYPE_ENUM) ||
                (primitive_is_integer(to) && from == TYPE_ENUM);

            u32 result = -1;
            if (valid) {
                result = 0;
            } else if (to == TYPE_POINTER || to == TYPE_ENUM || primitive_is_integer(to) || primitive_is_float(to)) {
                result = 2;
            } else {
                result = 1;
            }

            switch (result) {
                case 0: {} break;
                case 1: {
                    print_file_pos(&expr->pos);
                    printf("Invalid cast. Can't cast to ");
                    print_type(info->context, expr->type);
                    printf("\n");
                    return TYPECHECK_EXPR_BAD;
                } break;
                case 2: {
                    print_file_pos(&expr->pos);
                    printf("Invalid cast. Can't cast from ");
                    print_type(info->context, expr->cast_from->type);
                    printf(" to ");
                    print_type(info->context, expr->type);
                    printf("\n");
                    return TYPECHECK_EXPR_BAD;
                } break;
                default: assert(false);
            }
        } break;

        case EXPR_SUBSCRIPT: {
            if (typecheck_expr(info, expr->subscript.array, &info->context->primitive_types[TYPE_VOID]) == TYPECHECK_EXPR_BAD) return TYPECHECK_EXPR_BAD;
            if (typecheck_expr(info, expr->subscript.index, &info->context->primitive_types[DEFAULT_INT_TYPE]) == TYPECHECK_EXPR_BAD) return TYPECHECK_EXPR_BAD;

            if (expr->subscript.array->flags & EXPR_FLAG_ASSIGNABLE) {
                expr->flags |= EXPR_FLAG_ASSIGNABLE;
            }

            Type* array_type = expr->subscript.array->type;
            if (array_type->kind == TYPE_ARRAY) {
                expr->type = array_type->array.of;
            } else if (array_type->kind == TYPE_POINTER && array_type->pointer_to->kind == TYPE_ARRAY) {
                expr->type = array_type->pointer_to->array.of;
            } else {
                print_file_pos(&expr->pos);
                printf("Can't index a ");
                print_type(info->context, array_type);
                printf("\n");
                return TYPECHECK_EXPR_BAD;
            }

            Type_Kind index_type = expr->subscript.index->type->kind;
            if (index_type != TYPE_U64 && index_type != TYPE_I64) {
                // TODO should we allow other integer types and insert automatic promotions as neccesary here??
                print_file_pos(&expr->subscript.index->pos);
                printf("Can only use %s and %s as an array index, not ", PRIMITIVE_NAMES[TYPE_U64], PRIMITIVE_NAMES[TYPE_I64]);
                print_type(info->context, expr->subscript.index->type);
                printf("\n");
                return TYPECHECK_EXPR_BAD;
            }
        } break;

        case EXPR_MEMBER_ACCESS: {
            Expr* parent = expr->member_access.parent;

            bool bad_but_keep_on_going = false;
            if (typecheck_expr(info, parent, &info->context->primitive_types[TYPE_VOID]) == TYPECHECK_EXPR_BAD) {
                if (parent->type == null) {
                    return TYPECHECK_EXPR_BAD;
                } else {
                    bad_but_keep_on_going = true;
                }
            }

            if (parent->flags & EXPR_FLAG_ASSIGNABLE) {
                expr->flags |= EXPR_FLAG_ASSIGNABLE;
            }

            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u32 access_name = expr->member_access.member_name;

                Type* s = parent->type;
                if (s->kind == TYPE_POINTER && s->pointer_to->kind == TYPE_STRUCT) {
                    s = s->pointer_to;
                }

                bool has_member = false;
                if (s->kind == TYPE_STRUCT) {
                    for (u32 m = 0; m < s->structure.member_count; m += 1) {
                        u32 member_name = s->structure.members[m].name;
                        if (member_name == access_name) {
                            expr->member_access.member_index = m;
                            expr->type = s->structure.members[m].type;
                            expr->flags &= ~EXPR_FLAG_UNRESOLVED;
                            has_member = true;
                            break;
                        }
                    }
                }

                if (!has_member) {
                    u8* name_string = string_table_access(info->context->string_table, access_name);
                    print_file_pos(&expr->pos);
                    print_type(info->context, parent->type);
                    printf(" has no member '%s'\n", name_string);
                    return TYPECHECK_EXPR_BAD;
                }
            }

            if (bad_but_keep_on_going) return TYPECHECK_EXPR_BAD;
        } break;

        case EXPR_STATIC_MEMBER_ACCESS: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                Type* parent = parse_user_type_name(info->context, expr->static_member_access.parent_name);

                if (parent == null) {
                    u8* name_string = string_table_access(info->context->string_table, expr->static_member_access.parent_name);
                    print_file_pos(&expr->pos);
                    printf("No such type: '%s'\n", name_string);
                    return TYPECHECK_EXPR_BAD;
                }

                if (parent->kind != TYPE_ENUM) {
                    print_file_pos(&expr->pos);
                    printf("Can't use operator :: on non-enum type ");
                    print_type(info->context, parent);
                    printf("\n");
                    return TYPECHECK_EXPR_BAD;
                }

                u32 member_index = U32_MAX;
                for (u32 i = 0; i < parent->enumeration.member_count; i += 1) {
                    if (parent->enumeration.members[i].name == expr->static_member_access.member_name) {
                        member_index = i;
                        break;
                    }
                }

                if (member_index == U32_MAX) {
                    u8* member_name = string_table_access(info->context->string_table, expr->static_member_access.member_name);
                    print_file_pos(&expr->pos);
                    print_type(info->context, parent);
                    printf(" has no member '%s'\n", member_name);
                    return TYPECHECK_EXPR_BAD;
                }

                expr->static_member_access.parent_type = parent;
                expr->static_member_access.member_index = member_index;

                expr->flags &= ~EXPR_FLAG_UNRESOLVED;
            }

            expr->type = expr->static_member_access.parent_type;
        } break;


        case EXPR_TYPE_INFO_OF_TYPE: {
            if (!resolve_type(info->context, &expr->type_info_of_type, &expr->pos)) return TYPECHECK_EXPR_BAD;
        } break;

        case EXPR_TYPE_INFO_OF_VALUE: {
            Type *void_type = &info->context->primitive_types[TYPE_VOID];
            if (typecheck_expr(info, expr->type_info_of_value, void_type) == TYPECHECK_EXPR_BAD) return TYPECHECK_EXPR_BAD;
        } break;

        case EXPR_ENUM_LENGTH: {
            if (!resolve_type(info->context, &expr->enum_length_of, &expr->pos)) return TYPECHECK_EXPR_BAD;

            if (expr->enum_length_of->kind != TYPE_ENUM) {
                print_file_pos(&expr->pos);
                printf("Can't call 'enum_length' on ");
                print_type(info->context, expr->enum_length_of);
                printf(", it's not an enum");
                return TYPECHECK_EXPR_BAD;
            }
        } break;

        case EXPR_ENUM_MEMBER_NAME: {
            if (typecheck_expr(info, expr->enum_member, &info->context->primitive_types[TYPE_INVALID]) == TYPECHECK_EXPR_BAD) return TYPECHECK_EXPR_BAD;

            if (expr->enum_member->type->kind != TYPE_ENUM) {
                print_file_pos(&expr->enum_member->pos);
                printf("Can't call 'enum_member_name' on a ");
                print_type(info->context, expr->enum_member->type);
                printf("\n");
                return TYPECHECK_EXPR_BAD;
            }
        } break;

        default: assert(false);
    }

    if (!resolve_type(info->context, &expr->type, &expr->pos)) return TYPECHECK_EXPR_BAD;

    // Autocast from '*void' to any other pointer kind
    if (expr->type == info->context->void_pointer_type && expr->type != solidify_to && solidify_to->kind == TYPE_POINTER) {
        expr->type = solidify_to;
    }

    if (strong) {
        return TYPECHECK_EXPR_STRONG;
    } else {
        return TYPECHECK_EXPR_WEAK ;
    }
}

bool typecheck_stmt(Typecheck_Info* info, Stmt* stmt) {
    Type *void_type = &info->context->primitive_types[TYPE_VOID];

    switch (stmt->kind) {
        case STMT_ASSIGNMENT: {
            if (typecheck_expr(info, stmt->assignment.left, void_type) == TYPECHECK_EXPR_BAD) return false;
            Type* left_type = stmt->assignment.left->type;
            if (typecheck_expr(info, stmt->assignment.right, left_type) == TYPECHECK_EXPR_BAD) return false;
            Type* right_type = stmt->assignment.right->type;

            if (!type_can_assign(right_type, left_type)) {
                print_file_pos(&stmt->pos);
                printf("Types on left and right side of assignment don't match: ");
                print_type(info->context, left_type);
                printf(" vs ");
                print_type(info->context, right_type);
                printf("\n");
                return false;
            }

            if (!(stmt->assignment.left->flags & EXPR_FLAG_ASSIGNABLE)) {
                print_file_pos(&stmt->pos);
                printf("Can't assign to left hand side: ");
                print_expr(info->context, info->func, stmt->assignment.left);
                printf("\n");
                return false;
            }
        } break;

        case STMT_EXPR: {
            if (typecheck_expr(info, stmt->expr, void_type) == TYPECHECK_EXPR_BAD) return false;
        } break;

        case STMT_DECLARATION: {
            u32 var_index = stmt->declaration.var_index;
            Var* var = &info->func->body.vars[var_index];
            Expr* right = stmt->declaration.right;

            bool good_types = true;

            if (right != null) {
                Type* resolve_to = var->type;
                if (resolve_to == null) resolve_to = &info->context->primitive_types[TYPE_VOID];

                if (typecheck_expr(info, right, resolve_to) != TYPECHECK_EXPR_BAD) {
                    if (var->type == null) {
                        var->type = right->type;
                    } else {
                        if (!type_can_assign(var->type, right->type)) {
                            print_file_pos(&stmt->pos);
                            printf("Right hand side of variable declaration doesn't have correct type. Expected ");
                            print_type(info->context, var->type);
                            printf(" but got ");
                            print_type(info->context, right->type);
                            printf("\n");
                            good_types = false;
                        }
                    }
                } else {
                    if (var->type == null) {
                        var->type = right->type;
                    }
                    good_types = false;
                }
            } else {
                assert(var->type != null);
                if (!resolve_type(info->context, &var->type, &var->declaration_pos)) {
                    good_types = false;
                }
            }

            assert(!info->scope->map[stmt->declaration.var_index]);
            info->scope->map[stmt->declaration.var_index] = true;

            if (!good_types) {
                if (var->type == null) {
                    // This only is here to prevent the compiler from crashing when typechecking further statements
                    var->type = &info->context->primitive_types[TYPE_INVALID];
                }
                return false;
            }
        } break;

        case STMT_BLOCK: {
            typecheck_scope_push(info);
            for (Stmt* inner = stmt->block; inner->kind != STMT_END; inner = inner->next) {
                if (!typecheck_stmt(info, inner)) return false;
            }
            typecheck_scope_pop(info);
        } break;

        case STMT_IF: {
            Type* bool_type = &info->context->primitive_types[TYPE_BOOL];
            if (typecheck_expr(info, stmt->conditional.condition, bool_type) == TYPECHECK_EXPR_BAD) return false;

            Type_Kind condition_primitive = stmt->conditional.condition->type->kind;
            if (condition_primitive != TYPE_BOOL) {
                print_file_pos(&stmt->conditional.condition->pos);
                printf("Expected bool but got ");
                print_type(info->context, stmt->conditional.condition->type);
                printf(" in 'if'-statement\n");
                return false;
            }

            typecheck_scope_push(info);
            for (Stmt* inner = stmt->conditional.then; inner->kind != STMT_END; inner = inner->next) {
                if (!typecheck_stmt(info, inner)) return false;
            }
            typecheck_scope_pop(info);

            if (stmt->conditional.else_then != null) {
                typecheck_scope_push(info);
                for (Stmt* inner = stmt->conditional.else_then; inner->kind != STMT_END; inner = inner->next) {
                    if (!typecheck_stmt(info, inner)) return false;
                }
                typecheck_scope_pop(info);
            }
        } break;

        case STMT_LOOP: {
            if (stmt->loop.condition != null) {
                Type* bool_type = &info->context->primitive_types[TYPE_BOOL];
                if (typecheck_expr(info, stmt->loop.condition, bool_type) == TYPECHECK_EXPR_BAD) return false;

                Type_Kind condition_primitive = stmt->loop.condition->type->kind;
                if (condition_primitive != TYPE_BOOL) {
                    print_file_pos(&stmt->loop.condition->pos);
                    printf("Expected bool but got ");
                    print_type(info->context, stmt->loop.condition->type);
                    printf(" in 'for'-loop\n");
                    return false;
                }
            }

            typecheck_scope_push(info);
            for (Stmt* inner = stmt->loop.body; inner->kind != STMT_END; inner = inner->next) {
                if (!typecheck_stmt(info, inner)) return false;
            }
            typecheck_scope_pop(info);
        } break;

        case STMT_RETURN: {
            if (!info->func->signature.has_return) {
                if (stmt->return_stmt.value != null) {
                    u8* name = string_table_access(info->context->string_table, info->func->name);
                    print_file_pos(&stmt->pos);
                    printf("Function '%s' is not declared to return anything, but tried to return a value\n", name);
                    return false;
                }

            } else {
                Type* expected_type = info->func->signature.return_type;

                if (stmt->return_stmt.value == null) {
                    u8* name = string_table_access(info->context->string_table, info->func->name);
                    print_file_pos(&stmt->pos);
                    printf("Function '%s' is declared to return a ", name);
                    print_type(info->context, expected_type);
                    printf(", but tried to return a value. value\n");
                    return false;
                }

                if (typecheck_expr(info, stmt->return_stmt.value, expected_type) == TYPECHECK_EXPR_BAD) return false;

                if (!type_can_assign(expected_type, stmt->return_stmt.value->type)) {
                    u8* name = string_table_access(info->context->string_table, info->func->name);
                    print_file_pos(&stmt->pos);
                    printf("Expected ");
                    print_type(info->context, expected_type);
                    printf(" but got ");
                    print_type(info->context, stmt->return_stmt.value->type);
                    printf(" for return value in function '%s'\n", name);
                    return false;
                }
            }
        } break;

        case STMT_CONTINUE:
        case STMT_BREAK:
        {} break; // Any fancy logic goes in 'check_control_flow'

        default: assert(false);
    }

    return true;
}

typedef enum Eval_Result {
    EVAL_OK,
    EVAL_BAD,
    EVAL_DO_AT_RUNTIME,
} Eval_Result;

// NB This will allocate on context->stack, push/pop before/after
Eval_Result eval_compile_time_expr(Typecheck_Info* info, Expr* expr, u8* result_into) {
    u64 type_size = type_size_of(expr->type);
    assert(type_size > 0);

    switch (expr->kind) {
        case EXPR_LITERAL: {
            assert(type_size <= 8);
            mem_copy((u8*) &expr->literal.masked_value, result_into, type_size);
            return EVAL_OK;
        } break;

        case EXPR_VARIABLE: {
            if (expr->variable.index & VAR_INDEX_GLOBAL_FLAG) {
                u32 global_index = expr->variable.index & (~VAR_INDEX_GLOBAL_FLAG);
                Global_Var* global = &info->context->global_vars[global_index];

                if (global->compute_at_runtime) {
                    return EVAL_DO_AT_RUNTIME;
                } else if (global->valid) {
                    u64 other_size = type_size_of(global->var.type);
                    assert(other_size == type_size);
                    u8* other_value = &info->context->seg_data[global->data_offset];
                    mem_copy(other_value, result_into, type_size);
                    return EVAL_OK;
                } else {
                    if (!global->checked) {
                        u8* name = string_table_access(info->context->string_table, global->var.name);
                        print_file_pos(&expr->pos);
                        printf(
                            "Can't use global variable '%s' in a compile time expression before its declaration on line %u\n",
                            name, (u64) global->var.declaration_pos.line
                        );
                    }
                    return EVAL_BAD;
                }
            } else {
                print_file_pos(&expr->pos);
                printf("Can't use local variables in constant expressions\n");
                return EVAL_BAD;
            }
        } break;

        case EXPR_CAST: {
            Type_Kind primitive = primitive_of(expr->type);
            Type_Kind inner_primitive = primitive_of(expr->cast_from->type);

            u64 inner_type_size = type_size_of(expr->cast_from->type);
            assert(type_size <= 8 && inner_type_size <= 8);
            assert(primitive_is_integer(primitive) && primitive_is_integer(inner_primitive));

            u64 inner = 0;
            Eval_Result result = eval_compile_time_expr(info, expr->cast_from, (u8*) &inner);
            if (result != EVAL_OK) return result;

            u64 after_cast;
            if (primitive_is_signed(primitive) && primitive_is_signed(inner_primitive)) {
                i64 inner_signed;
                // Sign-extend
                switch (inner_type_size) {
                    case 1: inner_signed = (i64) *((i8*)  &inner); break;
                    case 2: inner_signed = (i64) *((i16*) &inner); break;
                    case 4: inner_signed = (i64) *((i32*) &inner); break;
                    case 8: inner_signed = (i64) *((i64*) &inner); break;
                    default: assert(false);
                }
                after_cast = *((u64*) &inner_signed);
            } else {
                switch (inner_type_size) {
                    case 1: after_cast = (u64) *((u8*)  &inner); break;
                    case 2: after_cast = (u64) *((u16*) &inner); break;
                    case 4: after_cast = (u64) *((u32*) &inner); break;
                    case 8: after_cast = (u64) *((u64*) &inner); break;
                    default: assert(false);
                }
            }

            switch (type_size) {
                case 1: *((u8*)  result_into) = (u8)  after_cast; break;
                case 2: *((u16*) result_into) = (u16) after_cast; break;
                case 4: *((u32*) result_into) = (u32) after_cast; break;
                case 8: *((u64*) result_into) = (u64) after_cast; break;
                default: assert(false);
            }

            return EVAL_OK;
        } break;

        case EXPR_SUBSCRIPT: {
            Eval_Result result;

            u64 array_size = type_size_of(expr->subscript.array->type);
            u64 index_size = type_size_of(expr->subscript.index->type);

            assert(index_size <= 8);

            u8* inner_data = arena_alloc(&info->context->stack, array_size);
            mem_clear(inner_data, array_size);
            result = eval_compile_time_expr(info, expr->subscript.array, inner_data);
            if (result != EVAL_OK) return result;

            u64 index = 0;
            result = eval_compile_time_expr(info, expr->subscript.index, (u8*) &index);
            if (result != EVAL_OK) return result;

            Type* array_type = expr->subscript.array->type;
            Type_Kind array_literal_primitive = array_type->kind;
            assert(array_literal_primitive == TYPE_ARRAY);

            Type* child_type = array_type->array.of;
            u64 child_size = type_size_of(child_type);
            assert(child_size == type_size);

            mem_copy(inner_data + index*child_size, result_into, type_size);

            return EVAL_OK;
        } break;

        case EXPR_UNARY: {
            Type_Kind primitive = expr->type->kind;
            Type_Kind inner_primitive = expr->unary.inner->type->kind;

            u64 inner_type_size = type_size_of(expr->unary.inner->type);

            if (expr->unary.op == UNARY_DEREFERENCE) {
                return EVAL_DO_AT_RUNTIME;
            } else if (expr->unary.op == UNARY_ADDRESS_OF) {
                return EVAL_DO_AT_RUNTIME;
            } else {
                assert(inner_type_size <= 8);
                assert(inner_type_size == type_size);

                Eval_Result result = eval_compile_time_expr(info, expr->unary.inner, result_into);
                if (result != EVAL_OK) return result;

                switch (expr->unary.op) {
                    case UNARY_NEG: {
                        switch (type_size) {
                            case 1: *((i8*)  result_into) = -(*((i8*)  result_into)); break;
                            case 2: *((i16*) result_into) = -(*((i16*) result_into)); break;
                            case 4: *((i32*) result_into) = -(*((i32*) result_into)); break;
                            case 8: *((i64*) result_into) = -(*((i64*) result_into)); break;
                            default: assert(false);
                        }
                    } break;

                    case UNARY_NOT: {
                        assert(inner_type_size == 1);
                        *result_into = (*result_into == 0)? 1 : 0;
                    } break;

                    default: assert(false);
                }
            }

            return EVAL_OK;
        } break;

        case EXPR_BINARY: {
            u64 child_size = type_size_of(expr->binary.left->type);

            assert(type_size <= 8 && child_size <= 8);

            u64 left_result, right_result;

            Eval_Result eval_result;
            eval_result = eval_compile_time_expr(info, expr->binary.left, (u8*) &left_result);
            if (eval_result != EVAL_OK) return eval_result;
            eval_result = eval_compile_time_expr(info, expr->binary.right, (u8*) &right_result);
            if (eval_result != EVAL_OK) return eval_result;

            bool is_signed = primitive_is_signed(expr->binary.left->type->kind);

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
                    case BINARY_ADD:  result = left +  right; break;
                    case BINARY_SUB:  result = left -  right; break;
                    case BINARY_MUL:  result = left *  right; break;
                    case BINARY_DIV:  result = left /  right; break;
                    case BINARY_MOD:  result = left %  right; break;
                    case BINARY_EQ:   result = left == right; break;
                    case BINARY_NEQ:  result = left != right; break;
                    case BINARY_GT:   result = left >  right; break;
                    case BINARY_GTEQ: result = left >= right; break;
                    case BINARY_LT:   result = left <  right; break;
                    case BINARY_LTEQ: result = left <= right; break;
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
                    case BINARY_ADD:  result = left +  right; break;
                    case BINARY_SUB:  result = left -  right; break;
                    case BINARY_MUL:  result = left *  right; break;
                    case BINARY_DIV:  result = left /  right; break;
                    case BINARY_MOD:  result = left %  right; break;
                    case BINARY_EQ:   result = left == right; break;
                    case BINARY_NEQ:  result = left != right; break;
                    case BINARY_GT:   result = left >  right; break;
                    case BINARY_GTEQ: result = left >= right; break;
                    case BINARY_LT:   result = left <  right; break;
                    case BINARY_LTEQ: result = left <= right; break;
                }
            }

            mem_copy((u8*) &result, result_into, type_size);
            return EVAL_OK;
        } break;

        case EXPR_COMPOUND: {
            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));

            switch (expr->type->kind) {
                case TYPE_ARRAY: {
                    Type* child_type = expr->type->array.of;
                    u64 child_size = type_size_of(child_type);

                    u8* mem = result_into;
                    for (u32 i = 0; i < expr->compound.count; i += 1) {
                        assert(expr->compound.content[i].name_mode == EXPR_COMPOUND_NO_NAME);
                        Expr* child = expr->compound.content[i].expr;
                        Eval_Result result = eval_compile_time_expr(info, child, mem);
                        if (result != EVAL_OK) return result;
                        mem += child_size;
                    }
                } break;

                case TYPE_STRUCT: {
                    u8* mem = result_into;

                    for (u32 i = 0; i < expr->compound.count; i += 1) {
                        assert(expr->compound.content[i].name_mode != EXPR_COMPOUND_UNRESOLVED_NAME);
                        u32 m = expr->compound.content[i].member_index;
                        u64 offset = expr->type->structure.members[m].offset;

                        Expr* child = expr->compound.content[i].expr;
                        Eval_Result result = eval_compile_time_expr(info, child, mem + offset);
                        if (result != EVAL_OK) return result;
                    }
                } break;

                default: assert(false);
            }

            return EVAL_OK;
        } break;

        case EXPR_STRING_LITERAL: {
            return EVAL_DO_AT_RUNTIME;
        } break;

        case EXPR_CALL: {
            return EVAL_DO_AT_RUNTIME;
        } break;

        case EXPR_MEMBER_ACCESS: {
            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));
            assert(expr->member_access.parent->type->kind == TYPE_STRUCT);

            u64 parent_size = type_size_of(expr->member_access.parent->type);
            u8* inner_data = arena_alloc(&info->context->stack, parent_size);
            mem_clear(inner_data, parent_size);
            Eval_Result result = eval_compile_time_expr(info, expr->member_access.parent, inner_data);
            if (result != EVAL_OK) return result;

            u32 m = expr->member_access.member_index;
            u64 offset = expr->member_access.parent->type->structure.members[m].offset;

            mem_copy(inner_data + offset, result_into, type_size);

            return EVAL_OK;
        } break;

        case EXPR_STATIC_MEMBER_ACCESS: {
            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));

            Type* type = expr->static_member_access.parent_type;
            u32 member_index = expr->static_member_access.member_index;
            assert(type->kind == TYPE_ENUM);

            u64 member_value = type->enumeration.members[member_index].value;
            mem_copy((u8*) &member_value, result_into, type_size);

            return EVAL_OK;
        } break;

        case EXPR_TYPE_INFO_OF_TYPE:
        case EXPR_TYPE_INFO_OF_VALUE:
        {
            return EVAL_DO_AT_RUNTIME;
        } break;

        case EXPR_ENUM_LENGTH: {
            if (expr->enum_length_of->kind == TYPE_UNRESOLVED_NAME) {
                return EVAL_DO_AT_RUNTIME;
            } else {
                assert(expr->enum_length_of->kind == TYPE_ENUM);

                u64 length = 0;
                for (u32 m = 0; m < expr->enum_length_of->enumeration.member_count; m += 1) {
                    u64 value = expr->enum_length_of->enumeration.members[m].value;
                    length = max(value + 1, length);
                }

                assert(expr->type->kind == TYPE_U64);
                mem_copy((u8*) &length, result_into, type_size);

                return EVAL_OK;
            }
        } break;

        case EXPR_ENUM_MEMBER_NAME: {
            return EVAL_DO_AT_RUNTIME;
        } break;

        default: assert(false); return EVAL_BAD;
    }
}

typedef enum Control_Flow_Result {
    CONTROL_FLOW_WILL_RETURN,
    CONTROL_FLOW_MIGHT_RETURN,
    CONTROL_FLOW_INVALID,
} Control_Flow_Result;

Control_Flow_Result check_control_flow(Stmt* stmt, Stmt* parent_loop, bool return_would_be_trailing) {
    bool has_returned = false;
    bool has_skipped_out = false; // continue or break

    for (; stmt->kind != STMT_END; stmt = stmt->next) {
        if (has_returned || has_skipped_out) {
            print_file_pos(&stmt->pos);
            printf("Unreachable code\n");
            return CONTROL_FLOW_INVALID;
        }

        bool is_last_stmt = stmt->next->kind == STMT_END;

        switch (stmt->kind) {
            case STMT_DECLARATION:
            case STMT_EXPR:
            case STMT_ASSIGNMENT:
            {} break;

            case STMT_BLOCK: {
                Control_Flow_Result result = check_control_flow(stmt->block, parent_loop, return_would_be_trailing && is_last_stmt);
                switch (result) {
                    case CONTROL_FLOW_WILL_RETURN: has_returned = true; break;
                    case CONTROL_FLOW_MIGHT_RETURN: break;
                    case CONTROL_FLOW_INVALID: return CONTROL_FLOW_INVALID; break;
                    default: assert(false);
                }
            } break;

            case STMT_IF: {
                bool else_return_would_be_trailing = return_would_be_trailing && is_last_stmt;
                bool then_return_would_be_trailing = else_return_would_be_trailing && (stmt->conditional.else_then == null);

                Control_Flow_Result then_result = check_control_flow(stmt->conditional.then, parent_loop, then_return_would_be_trailing);
                if (then_result == CONTROL_FLOW_INVALID) return then_result;

                Control_Flow_Result else_result = CONTROL_FLOW_MIGHT_RETURN;
                if (stmt->conditional.else_then != null) {
                    else_result = check_control_flow(stmt->conditional.else_then, parent_loop, else_return_would_be_trailing);
                    if (else_result == CONTROL_FLOW_INVALID) return else_result;
                }

                if (then_result == CONTROL_FLOW_WILL_RETURN && else_result == CONTROL_FLOW_WILL_RETURN) {
                    has_returned = true;
                }
            } break;

            case STMT_LOOP: {
                Control_Flow_Result result = check_control_flow(stmt->loop.body, stmt, false);
                if (result == CONTROL_FLOW_INVALID) return CONTROL_FLOW_INVALID;
            } break;

            case STMT_RETURN: {
                has_returned = true;
                stmt->return_stmt.trailing = return_would_be_trailing && is_last_stmt;
            } break;

            case STMT_BREAK:
            case STMT_CONTINUE:
            {
                if (parent_loop == null) {
                    print_file_pos(&stmt->pos);
                    printf("%s outside of loop\n", stmt->kind == STMT_BREAK? "break" : "continue");
                    return CONTROL_FLOW_INVALID;
                } else {
                    has_skipped_out = true;
                }
            } break;
        }
    }

    if (has_returned) {
        return CONTROL_FLOW_WILL_RETURN;
    } else {
        return CONTROL_FLOW_MIGHT_RETURN;
    }
}

bool typecheck(Context* context) {
    bool valid = true;

    Typecheck_Info info = {0};
    info.context = context;

    // User types (structs, enums, unions)
    buf_foreach (Type*, type_ptr, context->user_types) {
        Type* type = *type_ptr;

        switch (type->kind) {
            case TYPE_STRUCT: {
                if (type->flags & TYPE_FLAG_SIZE_NOT_COMPUTED) {
                    u32 max_align = 0;
                    u32 size = 0;

                    for (u32 m = 0; m < type->structure.member_count; m += 1) {
                        File_Pos* member_pos = &type->structure.members[m].declaration_pos;
                        Type* member_type = type->structure.members[m].type;

                        if (!resolve_type(context, &member_type, member_pos)) {
                            valid = false;
                            break;
                        }

                        type->structure.members[m].offset = (i32) size;

                        u32 member_size = 0;
                        u32 member_align = 0;

                        u32 array_multiplier = 1;
                        while (true) {
                            if (member_type->kind == TYPE_ARRAY) {
                                array_multiplier *= member_type->array.length;
                                member_type = member_type->array.of;

                            } else {
                                if (member_type->flags & TYPE_FLAG_SIZE_NOT_COMPUTED) {
                                    print_file_pos(member_pos);
                                    printf("We don't support fully out-of-order declarations. Can't use type ");
                                    print_type(context, member_type);
                                    printf(" directly here\n");
                                    valid = false;
                                    break;
                                }

                                u64 base_size;
                                if (member_type->kind == TYPE_STRUCT) {
                                    member_size = member_type->structure.size;
                                    member_align = member_type->structure.align;
                                } else {
                                    member_size = primitive_size_of(primitive_of(member_type));
                                    member_align = member_size;
                                }

                                member_size *= array_multiplier;
                                break;
                            }
                        }

                        if (member_size == 0) continue;

                        size = round_to_next(size, member_align);
                        size += member_size;

                        max_align = max(max_align, member_align);
                    }

                    if (max_align > 0) {
                        size = round_to_next(size, max_align);
                    }

                    type->structure.size = size;
                    type->structure.align = max_align;

                    type->flags &= ~TYPE_FLAG_SIZE_NOT_COMPUTED;
                }

                #if 0
                u8* name = string_table_access(context->string_table, type->structure.name);
                printf("struct %s\n", name);
                printf("size = %u, align = %u\n", type->structure.size, type->structure.align);
                for (u32 m = 0; m < type->structure.member_count; m += 1) {
                    u8* member_name = string_table_access(context->string_table, type->structure.members[m].name);
                    u64 offset = type->structure.members[m].offset;
                    printf("    %s: offset = %u\n", member_name, offset);
                }
                #endif
            } break;

            case TYPE_ENUM: {
                u64 mask = size_mask(primitive_size_of(type->enumeration.value_primitive));
                u32 count = type->enumeration.member_count;
                for (u32 i = 0; i < count; i += 1) {
                    u64 value_i = type->enumeration.members[i].value;
                    u32 name_index_i = type->enumeration.members[i].name;

                    if ((value_i & mask) != value_i) {
                        u8* member_name = string_table_access(context->string_table, name_index_i);
                        u64 max_value = mask;

                        print_file_pos(&type->enumeration.members[i].declaration_pos);
                        printf(
                            "Member '%s' has the value %u, which is larger than the max value for the enum, %u\n",
                            member_name, value_i, max_value
                        );
                        valid = false;
                        break;
                    }

                    bool done = false;

                    for (u32 j = i + 1; j < count; j += 1) {
                        u64 value_j = type->enumeration.members[j].value;
                        u32 name_index_j = type->enumeration.members[j].name;

                        if (value_i == value_j) {
                            u8* name_i = string_table_access(context->string_table, name_index_i);
                            u8* name_j = string_table_access(context->string_table, name_index_j);

                            print_file_pos(&type->enumeration.members[i].declaration_pos);
                            printf("and ");
                            print_file_pos(&type->enumeration.members[j].declaration_pos);
                            printf("Members '%s' and '%s' both equal %u\n", name_i, name_j, value_i);

                            valid = false;
                            done = true;
                            break;
                        }
                        
                        if (name_index_i == name_index_j) {
                            u8* member_name = string_table_access(context->string_table, name_index_i);
                            u8* enum_name = string_table_access(context->string_table, type->enumeration.name);

                            print_file_pos(&type->enumeration.members[i].declaration_pos);
                            printf("and ");
                            print_file_pos(&type->enumeration.members[j].declaration_pos);
                            printf("Enum '%s' has multiple members with the name '%s'\n", enum_name, member_name);

                            valid = false;
                            done = true;
                            break;
                        }
                    }

                    if (done) break;
                }
            } break;

            default: assert(false);
        }
    }

    if (!valid) return false;
    
    // Function signatures
    buf_foreach (Func, func, context->funcs) {
        for (u32 p = 0; p < func->signature.param_count; p += 1) {
            Type **type = &func->signature.params[p].type;

            if (!resolve_type(context, type, &func->declaration_pos)) {
                valid = false;
            } else if (primitive_is_compound((*type)->kind)) {
                u32 size = type_size_of(*type);
                if (size == 1 || size == 2 || size == 4 || size == 8) {
                    // Just squish the value into a register
                } else {
                    func->signature.params[p].reference_semantics = true;
                    *type = get_pointer_type(context, *type);
                    if (func->kind == FUNC_KIND_NORMAL) {
                        func->body.vars[func->signature.params[p].var_index].type = *type;
                    }
                }
            }
        }

        if (func->signature.has_return) {
            Type **return_type = &func->signature.return_type;

            if (!resolve_type(context, return_type, &func->declaration_pos)) {
                valid = false;
            } else if (primitive_is_compound((*return_type)->kind)) {
                u32 size = type_size_of(*return_type);
                if (size == 1 || size == 2 || size == 4 || size == 8) {
                    // We just squish the struct/array into RAX
                } else {
                    func->signature.return_by_reference = true;
                }
            }
        }
    }

    if (!valid) return false;

    // Global variables
    buf_foreach (Global_Var, global, context->global_vars) {
        global->checked = true;

        bool resolved_type = global->var.type != null;

        if (global->var.type != null && global->var.type->flags & TYPE_FLAG_UNRESOLVED) {
            if (!resolve_type(context, &global->var.type, &global->var.declaration_pos)) {
                valid = false;
                continue;
            }
        }

        if (global->initial_expr != null) {
            resolved_type = false;

            Type* resolve_to = global->var.type;
            if (resolve_to == null) resolve_to = &context->primitive_types[TYPE_VOID];

            if (typecheck_expr(&info, global->initial_expr, resolve_to) != TYPECHECK_EXPR_BAD) {
                if (global->var.type == null) {
                    global->var.type = global->initial_expr->type;
                    resolved_type = true;
                } else if (!type_can_assign(global->var.type, global->initial_expr->type)) {
                    print_file_pos(&global->var.declaration_pos);
                    printf("Right hand side of global variable declaration doesn't have correct type. Expected ");
                    print_type(context, global->var.type);
                    printf(" but got ");
                    print_type(context, global->initial_expr->type);
                    printf("\n");
                } else {
                    resolved_type = true;
                }
            }
        }

        if (!resolved_type) {
            valid = false;
            continue;
        }

        u64 type_size = type_size_of(global->var.type);
        u64 type_align = type_align_of(global->var.type);
        assert(type_size > 0);

        global->data_offset = add_exe_data(context, null, type_size, type_align);
        u8* result_into = &context->seg_data[global->data_offset];

        //printf("%s at .data + %u\n", string_table_access(context->string_table, global->var.name), (u64) global->data_offset);

        if (global->initial_expr != null) {
            arena_stack_push(&context->stack);
            Eval_Result result = eval_compile_time_expr(&info, global->initial_expr, result_into);
            arena_stack_pop(&context->stack);

            switch (result) {
                case EVAL_OK: {
                    global->valid = true;
                    global->compute_at_runtime = false;
                } break;

                case EVAL_BAD: {
                    valid = false;
                } break;

                case EVAL_DO_AT_RUNTIME: {
                    global->valid = true;
                    global->compute_at_runtime = true;
                } break;
            }
        } else {
            global->valid = true;
            global->compute_at_runtime = false;
        }
    }

    if (!valid) return false;

    // Functions
    for (u32 f = 0; f < buf_length(context->funcs); f += 1) {
        info.func = context->funcs + f;

        if (info.func->kind != FUNC_KIND_NORMAL) {
            continue;
        }

        arena_stack_push(&context->stack); // for allocating scopes

        info.scope = scope_new(context, info.func->body.var_count);

        // Parameters are allways in scope
        for (u32 i = 0; i < info.func->signature.param_count; i += 1) {
            u32 var_index = info.func->signature.params[i].var_index;
            info.scope->map[var_index] = true;
        }

        // Body types
        for (Stmt* stmt = info.func->body.first_stmt; stmt->kind != STMT_END; stmt = stmt->next) {
            if (!typecheck_stmt(&info, stmt)) {
                valid = false;
            }
        }

        // Control flow
        Control_Flow_Result result = check_control_flow(info.func->body.first_stmt, null, true);
        if (result == CONTROL_FLOW_INVALID) {
            valid = false;
        } else if (info.func->signature.has_return && result != CONTROL_FLOW_WILL_RETURN) {
            u8* name = string_table_access(info.context->string_table, info.func->name);
            print_file_pos(&info.func->declaration_pos);
            printf("Function '%s' might not return\n", name);
            valid = false;
        }

        arena_stack_pop(&context->stack);
    }

    return valid;
}



void build_enum_member_name_table(Context* context, Type* type) {
    assert(type->kind == TYPE_ENUM);
    assert(type->enumeration.name_table_data_offset == U64_MAX);

    u64 max_value = 0;
    for (u32 m = 0; m < type->enumeration.member_count; m += 1) {
        u64 value = type->enumeration.members[m].value;
        max_value = max(value, max_value);
    }

    u64 table_size = max_value + 1;
    u64 table_offset = add_exe_data(context, null, table_size * sizeof(u16), sizeof(u16));
    type->enumeration.name_table_data_offset = table_offset;

    mem_fill(context->seg_data + table_offset, 0xff, table_size * sizeof(u16));

    u32 type_name_length;
    u8* type_name = string_table_access_and_get_length(context->string_table, type->enumeration.name, &type_name_length);
    u64 invalid_string_offset = add_exe_data(context, "<unknown ", 9, 1);
    add_exe_data(context, type_name, type_name_length, 1);
    add_exe_data(context, ">\0", 2, 1);

    for (u32 m = 0; m < type->enumeration.member_count; m += 1) {
        u64 value = type->enumeration.members[m].value;
        u32 name_length = 0;
        u8* name = string_table_access_and_get_length(context->string_table, type->enumeration.members[m].name, &name_length);

        u64 string_offset = add_exe_data(context, name, name_length + 1, 1);

        u16 relative_offset = string_offset - table_offset - value*sizeof(u16);
        assert(relative_offset < U16_MAX);

        u16* table_value = ((u16*) (context->seg_data + table_offset)) + value;
        *table_value = relative_offset;
    }

    u16* table = (u16*) (context->seg_data + table_offset);
    for (u32 i = 0; i < table_size; i += 1) {
        if (table[i] == 0xffff) {
            u16 a = invalid_string_offset - table_offset;
            u16 relative_offset = a - i*sizeof(u16);
            table[i] = relative_offset;
        }
    }

    type->enumeration.name_table_entries = table_size;
    type->enumeration.name_table_invalid_offset = invalid_string_offset;
}


enum {
    RUNTIME_BUILTIN_MEM_CLEAR,
    RUNTIME_BUILTIN_MEM_COPY,
    RUNTIME_BUILTIN_COUNT,
};

typedef enum Register {
    REGISTER_NONE = 0,

    // These have special meanings for X64_Address.base
    RSP_OFFSET_INPUTS,  // RSP, but we add some value (calculated later) to the immediate offset
    RSP_OFFSET_LOCALS,
    RIP_OFFSET_DATA,    // relative to .data

    // General purpose registers, up to 64 bits
    RAX, RCX, RDX, RBX,
    RSP, RBP, RSI, RDI,
    R8,  R9,  R10, R11,
    R12, R13, R14, R15,

    AH, CH, DH, BH, // Not sure if we need these yet

    // XMM media registers, up to 128 bits
    XMM0,  XMM1,  XMM2,  XMM3, 
    XMM4,  XMM5,  XMM6,  XMM7, 
    XMM8,  XMM9,  XMM10, XMM11,
    XMM12, XMM13, XMM14, XMM15,

    ALLOCATABLE_REGISTER_COUNT,

    // For when the 'modrm/reg' field is used to extend the opcode
    REGISTER_OPCODE_0, REGISTER_OPCODE_1, REGISTER_OPCODE_2,
    REGISTER_OPCODE_3, REGISTER_OPCODE_4, REGISTER_OPCODE_5,
    REGISTER_OPCODE_6, REGISTER_OPCODE_7,

    REGISTER_COUNT,
} Register;

typedef enum Register_Kind {
    REGISTER_KIND_GPR,
    REGISTER_KIND_XMM,
} Register_Kind;

u8 REGISTER_INDICES[REGISTER_COUNT] = {
    [RAX] = 0,  [RCX] = 1,  [RDX] = 2,  [RBX] = 3,
    [RSP] = 4,  [RBP] = 5,  [RSI] = 6,  [RDI] = 7,
    [R8]  = 8,  [R9]  = 9,  [R10] = 10, [R11] = 11,
    [R12] = 12, [R13] = 13, [R14] = 14, [R15] = 15,

    [AH] = 4, [CH] = 5, [DH] = 6, [BH] = 7,

    [XMM0] = 0,   [XMM1] = 1,   [XMM2] = 2,   [XMM3] = 3,
    [XMM4] = 4,   [XMM5] = 5,   [XMM6] = 6,   [XMM7] = 7,
    [XMM8] = 8,   [XMM9] = 9,   [XMM10] = 10, [XMM11] = 11,
    [XMM12] = 12, [XMM13] = 13, [XMM14] = 14, [XMM15] = 15,

    [REGISTER_OPCODE_0] = 0, [REGISTER_OPCODE_1] = 1, [REGISTER_OPCODE_2] = 2,
    [REGISTER_OPCODE_3] = 3, [REGISTER_OPCODE_4] = 4, [REGISTER_OPCODE_5] = 5,
    [REGISTER_OPCODE_6] = 6, [REGISTER_OPCODE_7] = 7,

    [RSP_OFFSET_INPUTS] = 4,
    [RSP_OFFSET_LOCALS] = 4,
    [RIP_OFFSET_DATA]   = 5,
};

u8 *REGISTER_NAMES[REGISTER_COUNT][4] = {
    [RAX] = { "al",   "ax",   "eax",  "rax" },
    [RCX] = { "cl",   "cx",   "ecx",  "rcx" },
    [RDX] = { "dl",   "dx",   "edx",  "rdx" },
    [RBX] = { "bl",   "bx",   "ebx",  "rbx" },
    [RSP] = { "spl",  "sp",   "esp",  "rsp" },
    [RBP] = { "bpl",  "bp",   "ebp",  "rbp" },
    [RSI] = { "sil",  "si",   "esi",  "rsi" },
    [RDI] = { "dil",  "di",   "edi",  "rdi" },
    [R8]  = { "r8b",  "r8w",  "r8d",  "r8" },
    [R9]  = { "r9b",  "r9w",  "r9d",  "r9" },
    [R10] = { "r10b", "r10w", "r10d", "r10" },
    [R11] = { "r11b", "r11w", "r11d", "r11" },
    [R12] = { "r12b", "r12w", "r12d", "r12" },
    [R13] = { "r13b", "r13w", "r13d", "r13" },
    [R14] = { "r14b", "r14w", "r14d", "r14" },
    [R15] = { "r15b", "r15w", "r15d", "r15" },

    [AH] = { "ah", null, null, null },
    [CH] = { "ch", null, null, null },
    [DH] = { "dh", null, null, null },
    [BH] = { "bh", null, null, null },
 
    [XMM0]  = { "xmm0", null, null, null },
    [XMM1]  = { "xmm1", null, null, null },
    [XMM2]  = { "xmm2", null, null, null },
    [XMM3]  = { "xmm3", null, null, null },
    [XMM4]  = { "xmm4", null, null, null },
    [XMM5]  = { "xmm5", null, null, null },
    [XMM6]  = { "xmm6", null, null, null },
    [XMM7]  = { "xmm7", null, null, null },
    [XMM8]  = { "xmm8", null, null, null },
    [XMM9]  = { "xmm9", null, null, null },
    [XMM10] = { "xmm10", null, null, null },
    [XMM11] = { "xmm11", null, null, null },
    [XMM12] = { "xmm12", null, null, null },
    [XMM13] = { "xmm13", null, null, null },
    [XMM14] = { "xmm14", null, null, null },
    [XMM15] = { "xmm15", null, null, null },

    [RIP_OFFSET_DATA] = { null, null, null, "rip" },
};

u8 *register_name(Register reg, u8 size) {
    if (reg == RSP_OFFSET_LOCALS || reg == RSP_OFFSET_INPUTS) {
        assert(size == 8);
        reg = RSP;
    }

    u8 size_index;
    switch (size) {
        case 1: size_index = 0; break;
        case 2: size_index = 1; break;
        case 4: size_index = 2; break;
        case 8: size_index = 3; break;
        default: assert(false);
    }
    return REGISTER_NAMES[reg][size_index];
}

// NB The first four registers in 'VOLATILE_REGISTERS' are used to pass parameters
#define VOLATILE_REGISTER_COUNT 7
#define NONVOLATILE_REGISTER_COUNT 9
Register VOLATILE_REGISTERS[VOLATILE_REGISTER_COUNT]       = { RCX, RDX, R8, R9, RAX, R10, R11 };
Register NONVOLATILE_REGISTERS[NONVOLATILE_REGISTER_COUNT] = { RBX, RBP, RDI, RSI, RSP, R12, R13, R14, R15 };

enum {
    REX_BASE = 0x40,
    REX_W    = 0x08, // selects 64-bit operands over 32-bit operands
    REX_R    = 0x04, // Most significant, fourth, bit of modrm/reg
    REX_X    = 0x02, // Most significant, fourth, bit of SIB/index
    REX_B    = 0x01, // Most significant, fourth, bit of modrm/rm, SIB base or opcode reg

    WORD_OPERAND_PREFIX = 0x66, // selects 16-bit operands over 32-bit operands

    // Keep in mind that when modrm/rm is RSP or RBP, R12 or R13 using MODRM_RM_POINTER_* has special semantics
    MODRM_MOD_POINTER          = 0x00,
    MODRM_MOD_POINTER_PLUS_I8  = 0x40,
    MODRM_MOD_POINTER_PLUS_I32 = 0x80,
    MODRM_MOD_VALUE            = 0xc0,
    MODRM_RM_USE_SIB = 0x04,

    SIB_SCALE_1 = 0x00,
    SIB_SCALE_2 = 0x40,
    SIB_SCALE_4 = 0x80,
    SIB_SCALE_8 = 0xc0,
    SIB_NO_INDEX = 0x20,
};

typedef enum Mov_Mode { MOVE_FROM_MEM, MOVE_TO_MEM } Mov_Mode;

// Anything encodable in a X64 addressing mode
typedef struct X64_Address {
    Register base;
    Register index;
    u8 scale;

    i32 immediate_offset;
} X64_Address;

typedef struct X64_Place {
    enum {
        PLACE_NOWHERE = 0,
        PLACE_REGISTER,
        PLACE_ADDRESS,
    } kind;

    union {
        Register reg;
        X64_Address address;
    };
} X64_Place;

#define x64_place_reg(r) (X64_Place) { .kind = PLACE_REGISTER, .reg = (r) }
#define x64_place_address(a) (X64_Place) { .kind = PLACE_ADDRESS, .address = (a) }


#define PRINT_GENERATED_INSTRUCTIONS

#ifdef PRINT_GENERATED_INSTRUCTIONS
void dump_instruction_bytes(Context *context) {
    static u64 last_length = 0;
    u64 new_length = buf_length(context->seg_text);

    u64 pad = 8;

    for (u64 i = last_length; i < new_length; i += 1) {
        u8 byte = context->seg_text[i];
        printf("%b ", byte);

        pad -= 1;
    }

    if (pad < 60) {
        u8 *spaces = "                                                            | ";
        printf(spaces + 60 - (pad*3));
    } else {
        printf("| ");
    }

    last_length = new_length;
}
#endif


void print_x64_address(X64_Address address) {
    printf("[%s", register_name(address.base, POINTER_SIZE));

    if (address.index != REGISTER_NONE) {
        printf(" + %s*%u", register_name(address.index, POINTER_SIZE), (u64) address.scale);
    }

    if (address.immediate_offset > 0) {
        printf(" + %x", (u64) address.immediate_offset);
    } else if (address.immediate_offset < 0) {
        printf(" - %x", (u64) (-address.immediate_offset));
    }

    switch (address.base) {
        case RSP_OFFSET_LOCALS:  printf(" + local offset");  break;
        case RSP_OFFSET_INPUTS:  printf(" + input offset");  break;
        case RIP_OFFSET_DATA:    printf(" + .data offset");  break;
    }

    printf("]");
}

void encode_instruction_reg_mem(Context *context, u8 rex, u32 opcode, X64_Address mem, Register reg) {
    u8 modrm = 0;
    u8 sib = 0;
    bool use_sib = false;
    u8 offset_bytes = 0;


    modrm |= (REGISTER_INDICES[reg] & 0x07) << 3;
    if (REGISTER_INDICES[reg] & 0x08) {
        rex |= REX_R;
    }


    bool force_i32_offset = false;
    Stack_Access_Fixup stack_access_fixup = {0};
    stack_access_fixup.kind = -1;
    Fixup data_fixup = {0};
    data_fixup.kind = -1;

    if (mem.base == RSP_OFFSET_LOCALS || mem.base == RSP_OFFSET_INPUTS) {
        switch (mem.base) {
            case RSP_OFFSET_INPUTS: stack_access_fixup.kind = STACK_ACCESS_FIXUP_INPUT_SECTION; break;
            case RSP_OFFSET_LOCALS: stack_access_fixup.kind = STACK_ACCESS_FIXUP_LOCAL_SECTION; break;
            default: assert(false);
        }

        force_i32_offset = true;
    }

    if (mem.base == RIP_OFFSET_DATA) {
        data_fixup.kind = FIXUP_DATA;
        data_fixup.data_offset = mem.immediate_offset;

        mem.immediate_offset = 0;
        assert(mem.index == REGISTER_NONE);

        force_i32_offset = false;
    }

    assert((mem.base >= RAX && mem.base <= R15) || mem.base == RSP_OFFSET_INPUTS || mem.base == RSP_OFFSET_LOCALS || mem.base == RIP_OFFSET_DATA);
    assert(mem.base != REGISTER_NONE);
    assert((mem.index >= RAX && mem.index <= R15) || mem.index == REGISTER_NONE);

    if (mem.immediate_offset > I8_MAX || mem.immediate_offset < I8_MIN || force_i32_offset) {
        modrm |= MODRM_MOD_POINTER_PLUS_I32;
        offset_bytes = sizeof(i32);
    } else if (mem.immediate_offset != 0) {
        modrm |= MODRM_MOD_POINTER_PLUS_I8;
        offset_bytes = sizeof(i8);
    } else {
        assert(mem.base != RBP); // This specifies rip-relative addressing
        modrm |= MODRM_MOD_POINTER;
    }

    if (mem.index == REGISTER_NONE) {
        assert(mem.scale == 0);
        u8 reg_index = REGISTER_INDICES[mem.base];

        if ((reg_index & 0x07) == MODRM_RM_USE_SIB) {
            use_sib = true;
        } else {
            modrm |= reg_index & 0x07;
            if (reg_index & 0x08) {
                rex |= REX_B;
            }
        }
    } else {
        use_sib = true;
    }

    if (use_sib) {
        modrm |= MODRM_RM_USE_SIB;

        if (mem.index == REGISTER_NONE) {
            assert(mem.scale == 0);
            sib |= SIB_NO_INDEX;
        } else {
            switch (mem.scale) {
                case 1: sib |= SIB_SCALE_1; break;
                case 2: sib |= SIB_SCALE_2; break;
                case 4: sib |= SIB_SCALE_4; break;
                case 8: sib |= SIB_SCALE_8; break;
                default: assert(false);
            }

            u8 reg_index = REGISTER_INDICES[mem.index];
            assert((reg_index & 0x07) != REGISTER_INDICES[RSP]);

            sib |= (reg_index & 0x07) << 3;
            if (reg_index & 0x08) {
                rex |= REX_X;
            }
        }

        assert(mem.base != RBX);
        sib |= REGISTER_INDICES[mem.base] & 0x07;
        if (REGISTER_INDICES[mem.base] & 0x08) {
            rex |= REX_B;
        }
    }


    if (rex != REX_BASE) {
        buf_push(context->seg_text, rex);
    }

    do {
        buf_push(context->seg_text, (u8) (opcode & 0xff));
        opcode >>= 8;
    } while(opcode != 0);

    buf_push(context->seg_text, modrm);
    if (use_sib) {
        buf_push(context->seg_text, sib);
    }

    if (offset_bytes > 0) {
        stack_access_fixup.text_location = buf_length(context->seg_text);

        str_push_integer(&context->seg_text, offset_bytes, *((u32*) &mem.immediate_offset));

        if (stack_access_fixup.kind != -1) {
            buf_push(context->stack_access_fixups, stack_access_fixup);
        }
    }

    if (data_fixup.kind != -1) {
        data_fixup.text_location = buf_length(context->seg_text);
        str_push_integer(&context->seg_text, sizeof(u32), 0xdeadbeef);
        buf_push(context->fixups, data_fixup);
    }
}

void encode_instruction_reg_reg(Context *context, u8 rex, u32 opcode, Register mem, Register reg) {
    u8 modrm = 0xc0;

    modrm |= (REGISTER_INDICES[reg] & 0x07) << 3;
    if (REGISTER_INDICES[reg] & 0x08) {
        rex |= REX_R;
    }

    modrm |= REGISTER_INDICES[mem] & 0x07;
    if (REGISTER_INDICES[mem] & 0x08) {
        rex |= REX_B;
    }

    if (rex != REX_BASE) {
        buf_push(context->seg_text, rex);
    }

    do {
        buf_push(context->seg_text, (u8) (opcode & 0xff));
        opcode >>= 8;
    } while(opcode != 0);

    buf_push(context->seg_text, modrm);
}


void instruction_int3(Context *context) {
    buf_push(context->seg_text, 0xcc);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("int 3\n");
    #endif
}

void instruction_nop(Context *context) {
    buf_push(context->seg_text, 0x90);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("nop\n");
    #endif
}

void instruction_ret(Context *context) {
    buf_push(context->seg_text, 0xc3);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("ret\n");
    #endif
}

// Returns an index to a position where a i32 jump offset should be written
u64 instruction_jmp_i32(Context *context) {
    buf_push(context->seg_text, 0xe9);
    str_push_integer(&context->seg_text, sizeof(i32), 0xdeadbeef);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("jmp ??\n");
    #endif

    return buf_length(context->seg_text) - sizeof(i32);
}

// Returns an index to a position where a i8 jump offset should be written
u64 instruction_jmp_i8(Context *context) {
    buf_push(context->seg_text, 0xeb);
    buf_push(context->seg_text, 0x00);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("jmp ??\n");
    #endif

    return buf_length(context->seg_text) - 1;
}

// Jumps if RCX equals zero
// Returns an index to a position where a i8 jump offset should be written
u64 instruction_jrcxz(Context *context) {
    buf_push(context->seg_text, 0xe3);
    buf_push(context->seg_text, 0x00);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("jrcxz ??\n");
    #endif

    return buf_length(context->seg_text) - 1;
}

u64 instruction_jcc(Context *context, Condition condition) {
    u8 opcode;
    switch (condition) {
        case COND_E:  opcode = 0x84; break;
        case COND_NE: opcode = 0x85; break;
        case COND_G:  opcode = 0x8f; break;
        case COND_GE: opcode = 0x8d; break;
        case COND_L:  opcode = 0x8c; break;
        case COND_LE: opcode = 0x8e; break;
        case COND_A:  opcode = 0x87; break;
        case COND_AE: opcode = 0x83; break;
        case COND_B:  opcode = 0x82; break;
        case COND_BE: opcode = 0x86; break;
        default: assert(false);
    }

    buf_push(context->seg_text, 0x0f);
    buf_push(context->seg_text, opcode);
    str_push_integer(&context->seg_text, sizeof(i32), 0xdeadbeef);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("j%s ??\n", CONDITION_POSTFIXES[condition]);
    #endif

    return buf_length(context->seg_text) - sizeof(i32);
}

void instruction_setcc(Context *context, Condition condition, X64_Place place) {
    u32 opcode;
    switch (condition) {
        case COND_E:  opcode = 0x940f; break;
        case COND_NE: opcode = 0x950f; break;
        case COND_G:  opcode = 0x9f0f; break;
        case COND_GE: opcode = 0x9d0f; break;
        case COND_L:  opcode = 0x9c0f; break;
        case COND_LE: opcode = 0x9e0f; break;
        case COND_A:  opcode = 0x970f; break;
        case COND_AE: opcode = 0x930f; break;
        case COND_B:  opcode = 0x920f; break;
        case COND_BE: opcode = 0x960f; break;
        default: assert(false);
    }

    switch (place.kind) {
        case PLACE_REGISTER: {
            encode_instruction_reg_reg(context, REX_BASE, opcode, place.reg, REGISTER_OPCODE_0);

            #ifdef PRINT_GENERATED_INSTRUCTIONS
            dump_instruction_bytes(context);
            printf("set%s %s\n", CONDITION_POSTFIXES[condition], register_name(place.reg, 1));
            #endif
        } break;

        case PLACE_ADDRESS: {
            encode_instruction_reg_mem(context, REX_BASE, opcode, place.address, REGISTER_OPCODE_0);

            #ifdef PRINT_GENERATED_INSTRUCTIONS
            dump_instruction_bytes(context);
            printf("set%s ", CONDITION_POSTFIXES[condition]);
            print_x64_address(place.address);
            printf("\n");
            #endif
        } break;

        case PLACE_NOWHERE: assert(false);
        default: assert(false);
    }

}

void instruction_cmp_reg_reg(Context *context, Register left, Register right, u8 op_size) {
    u8 opcode = 0x39;
    u8 rex = REX_BASE;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_reg_reg(context, rex, opcode, left, right);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("cmp %s, %s\n", register_name(left, op_size), register_name(right, op_size));
    #endif
}

void instruction_cmp_reg_mem(Context *context, X64_Address left, Register right, u8 op_size) {
    u8 opcode = 0x39;
    u8 rex = REX_BASE;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_reg_mem(context, rex, opcode, left, right);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("cmp ");
    print_x64_address(left);
    printf(", %s\n", register_name(right, op_size));
    #endif
}

void instruction_cmp_imm(Context *context, X64_Place place, u64 imm, u8 op_size) {
    u8 opcode = 0x81;
    u8 rex = REX_BASE;
    u8 imm_size = op_size;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    if (op_size > 1 && imm <= I8_MAX) {
        opcode = 0x83;
        imm_size = 1;
    }

    if (op_size == 8) {
        assert(imm < I32_MAX);
    }

    if (place.kind == PLACE_REGISTER) {
        encode_instruction_reg_reg(context, rex, opcode, place.reg, REGISTER_OPCODE_7);
    } else if (place.kind == PLACE_ADDRESS) {
        encode_instruction_reg_mem(context, rex, opcode, place.address, REGISTER_OPCODE_7);
    } else {
        assert(false);
    }
    str_push_integer(&context->seg_text, imm_size, imm);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("cmp ");
    if (place.kind == PLACE_REGISTER) {
        printf("%s", register_name(place.reg, op_size));
    } else if (place.kind == PLACE_ADDRESS) {
        print_x64_address(place.address);
    } else {
        assert(false);
    }
    printf(", %u\n", imm);
    #endif
}

void instruction_call(Context* context, bool builtin, u32 func_index) {
    bool near = true;
    if (!builtin) {
        Func *callee = &context->funcs[func_index];
        if (callee->kind == FUNC_KIND_IMPORTED) {
            near = false;

            buf_push(context->seg_text, 0xff);
            buf_push(context->seg_text, 0x15);
            str_push_integer(&context->seg_text, sizeof(i32), 0xdeadbeef);

            Fixup fixup = {0};
            fixup.text_location = buf_length(context->seg_text) - sizeof(i32);
            fixup.kind = FIXUP_IMPORTED_FUNCTION;
            fixup.import_index = callee->import_info.index;
            buf_push(context->fixups, fixup);
        }
    }

    if (near) {
        buf_push(context->seg_text, 0xe8);
        str_push_integer(&context->seg_text, sizeof(i32), 0xdeadbeef);

        Call_Fixup fixup = {0};
        fixup.text_location = buf_length(context->seg_text) - sizeof(i32);
        fixup.builtin = builtin;
        fixup.func_index = func_index;
        buf_push(context->call_fixups, fixup);
    }

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    u8 *name;
    if (builtin) {
        switch (func_index) {
            case RUNTIME_BUILTIN_MEM_COPY:  name = "builtin_mem_copy"; break;
            case RUNTIME_BUILTIN_MEM_CLEAR: name = "builtin_mem_clear"; break;
            default: assert(false);
        }
    } else {
        u32 name_index = context->funcs[func_index].name;
        name = string_table_access(context->string_table, name_index);
    }

    dump_instruction_bytes(context);
    printf("call %s\n", name);
    #endif
}

void instruction_inc_or_dec(Context *context, bool inc, Register reg, u8 op_size) {
    u8 rex = REX_BASE;
    u8 opcode = 0xff;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_reg_reg(context, rex, opcode, reg, inc? REGISTER_OPCODE_0 : REGISTER_OPCODE_1);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("%s %s\n", inc? "inc" : "dec", register_name(reg, op_size));
    #endif
}

void instruction_imul_pointer_imm(Context *context, Register reg, i64 mul_by) {
    if (mul_by <= I8_MAX && mul_by >= I8_MIN) {
        encode_instruction_reg_reg(context, REX_BASE | REX_W, 0x6b, reg, reg);
        str_push_integer(&context->seg_text, sizeof(i8), *((u64*) &mul_by));
    } else if (mul_by <= I32_MAX && mul_by >= I32_MIN) {
        encode_instruction_reg_reg(context, REX_BASE | REX_W, 0x69, reg, reg);
        str_push_integer(&context->seg_text, sizeof(i32), *((u64*) &mul_by));
    } else {
        assert(false); // NB the immediate operand to the imul instruction can at most be a i32
    }

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    u8 *reg_name = register_name(reg, POINTER_SIZE);
    printf("imul %s, %s, %i\n", reg_name, reg_name, mul_by);
    #endif
}

void instruction_negative(Context *context, bool unary, X64_Place place, u8 op_size) {
    u8 opcode = 0xf7;
    u8 rex = REX_BASE;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    Register reg = unary? REGISTER_OPCODE_2 : REGISTER_OPCODE_3;

    switch (place.kind) {
        case PLACE_REGISTER: {
            encode_instruction_reg_reg(context, rex, opcode, place.reg, reg);

            #ifdef PRINT_GENERATED_INSTRUCTIONS
            dump_instruction_bytes(context);
            printf("%s %s\n", unary? "not" : "neg", register_name(place.reg, op_size));
            #endif
        } break;

        case PLACE_ADDRESS: {
            encode_instruction_reg_mem(context, rex, opcode, place.address, reg);

            #ifdef PRINT_GENERATED_INSTRUCTIONS
            dump_instruction_bytes(context);
            printf("%s ", unary? "not" : "neg");
            print_x64_address(place.address);
            printf("\n");
            #endif
        } break;

        case PLACE_NOWHERE: assert(false);
        default: assert(false);
    }
}

void instruction_xor(Context *context, Register left, Register right, u8 op_size) {
    u8 rex = REX_BASE;
    u8 opcode = 0x31;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_reg_reg(context, rex, opcode, left, right);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("xor %s, %s\n", register_name(left, op_size), register_name(right, op_size));
    #endif
}

void instruction_lea(Context *context, X64_Address mem, Register reg) {
    encode_instruction_reg_mem(context, REX_BASE | REX_W, 0x8d, mem, reg);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("lea %s, ", register_name(reg, POINTER_SIZE));
    print_x64_address(mem);
    printf("\n");
    #endif
}

void instruction_mov_reg_mem(Context *context, Mov_Mode mode, X64_Address mem, Register reg, u8 op_size) {
    u8 rex = REX_BASE;

    u8 opcode;
    switch (mode) {
        case MOVE_FROM_MEM: opcode = 0x8b; break;
        case MOVE_TO_MEM:   opcode = 0x89; break;
        default: assert(false);
    }

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_reg_mem(context, rex, opcode, mem, reg);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    if (mode == MOVE_FROM_MEM) {
        printf("mov %s, ", register_name(reg, op_size));
        print_x64_address(mem);
        printf("\n");
    } else {
        printf("mov ");
        print_x64_address(mem);
        printf(", %s\n", register_name(reg, op_size));
    }
    #endif
}

void instruction_mov_reg_reg(Context *context, Register src, Register dst, u8 op_size) {
    u8 opcode = 0x89;
    u8 rex = REX_BASE;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_reg_reg(context, rex, opcode, dst, src);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("mov %s, %s\n", register_name(dst, op_size), register_name(src, op_size));
    #endif
}

void instruction_mov_imm_mem(Context *context, X64_Address mem, u64 immediate, u8 op_size) {
    u8 imm_size = op_size;

    if (op_size == 8) {
        // NB there is no 'mov mem64, imm64' instruction, so we have to improvize
        // Also, 'mov mem64, imm32' sign-extends, hens I32_MAX
        if (immediate > I32_MAX) {
            instruction_mov_imm_mem(context, mem, immediate & U32_MAX, 4);
            mem.immediate_offset += 4;
            instruction_mov_imm_mem(context, mem, immediate >> 32, 4);
            return;
        } else {
            imm_size = 4;
        }
    }

    u8 rex = REX_BASE;
    u8 opcode = 0xc7;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_reg_mem(context, rex, opcode, mem, REGISTER_OPCODE_0);
    str_push_integer(&context->seg_text, imm_size, immediate);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("mov%u ", (u64) op_size*8);
    print_x64_address(mem);
    printf(", %x\n", immediate);
    #endif
}

void instruction_mov_imm_reg(Context *context, Register reg, u64 immediate, u8 op_size) {
    if (immediate < U32_MAX && op_size == 8) {
        // 32-bit instructions still clear the upper bits, so this is fine, and costs us 4-5 bytes less (depending on whether we still need REX)
        op_size = 4;
    }

    u8 rex = REX_BASE;
    u8 opcode = 0xb8;

    switch (op_size) {
        case 1: opcode = 0xb0; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    opcode |= REGISTER_INDICES[reg] & 0x07;
    if (REGISTER_INDICES[reg] & 0x08) {
        reg |= REX_B;
    }

    if (rex != REX_BASE) {
        buf_push(context->seg_text, rex);
    }
    buf_push(context->seg_text, opcode);
    str_push_integer(&context->seg_text, op_size, immediate);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    printf("mov %s, %x\n", register_name(reg, op_size), (u64) immediate);
    #endif
}


typedef struct Simple_Binary_Info {
    enum {
        SIMPLE_BINARY_ADD = BINARY_ADD,
        SIMPLE_BINARY_SUB = BINARY_SUB,
    } kind;

    enum {
        SIMPLE_BINARY_A_IS_DST,
        SIMPLE_BINARY_B_IS_DST,
    } direction;

    Register a;

    bool b_is_address;
    union {
        Register reg;
        X64_Address address;
    } b;

    u8 op_size;
} Simple_Binary_Info;

void instruction_simple_binary(Context *context, Simple_Binary_Info info) {
    bool mr = info.direction == SIMPLE_BINARY_B_IS_DST;
    u8 opcode;
    switch (info.kind) {
        case SIMPLE_BINARY_ADD: opcode = mr? 0x01 : 0x03; break;
        case SIMPLE_BINARY_SUB: opcode = mr? 0x29 : 0x2a; break;
        default: assert(false);
    }

    u8 rex = REX_BASE;

    switch (info.op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    if (info.b_is_address) {
        encode_instruction_reg_mem(context, rex, opcode, info.b.address, info.a);
    } else {
        encode_instruction_reg_reg(context, rex, opcode, info.b.reg, info.a);
    }

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);
    u8 *name;
    switch (info.kind) {
        case SIMPLE_BINARY_ADD: name = "add"; break;
        case SIMPLE_BINARY_SUB: name = "sub"; break;
        default: assert(false);
    }
    printf("%s ", name);

    if (info.direction == SIMPLE_BINARY_A_IS_DST) {
        printf("%s, ", register_name(info.a, info.op_size));
        if (info.b_is_address) {
            print_x64_address(info.b.address);
            printf("\n");
        } else {
            printf("%s\n", register_name(info.b.reg, info.op_size));
        }
    } else {
        if (info.b_is_address) {
            print_x64_address(info.b.address);
        } else {
            printf("%s", register_name(info.b.reg, info.op_size));
        }
        printf(", %s\n", register_name(info.a, info.op_size));
    }
    #endif
}

void instruction_multiply(Context *context, X64_Place mul_by, bool is_signed, u8 op_size) {
    u8 opcode_extension = is_signed? REGISTER_OPCODE_5 : REGISTER_OPCODE_4;
    u8 opcode = 0xf7;
    u8 rex = REX_BASE;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    if (mul_by.kind == PLACE_REGISTER) {
        encode_instruction_reg_reg(context, rex, opcode, mul_by.reg,     opcode_extension);
    } else if (mul_by.kind == PLACE_ADDRESS) {
        encode_instruction_reg_mem(context, rex, opcode, mul_by.address, opcode_extension);
    } else {
        assert(false);
    }

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(context);

    printf(is_signed? "imul " : "mul ");
    if (mul_by.kind == PLACE_REGISTER) {
        printf("%s\n", register_name(mul_by.reg, op_size));
    } else {
        print_x64_address(mul_by.address);
        printf("\n");
    }
    #endif
}


typedef struct Reg_Allocator_Frame Reg_Allocator_Frame;
struct Reg_Allocator_Frame {
    i32 stack_size;

    struct {
        bool allocated;

        bool flushed;
        X64_Address flushed_to;
    } states[ALLOCATABLE_REGISTER_COUNT];

    Reg_Allocator_Frame *next, *previous;
};

typedef struct Reg_Allocator {
    Reg_Allocator_Frame *head;

    struct {
        u64 size;
        X64_Address address;
    } *var_mem_infos;
    u64 allocated_var_mem_infos;

    i32 max_stack_size;
    u32 max_callee_param_count;
} Reg_Allocator;

void register_allocator_enter_frame(Context *context, Reg_Allocator *allocator) {
    if (allocator->head == null) {
        allocator->head = arena_new(&context->arena, Reg_Allocator_Frame);
        allocator->head->stack_size = allocator->max_stack_size;
    }

    if (allocator->head->next == null) {
        allocator->head->next = arena_new(&context->arena, Reg_Allocator_Frame);
        allocator->head->next->previous = allocator->head;
    }

    mem_copy((u8*) allocator->head, (u8*) allocator->head->next, sizeof(Reg_Allocator_Frame) - 2*sizeof(void*));
    allocator->head = allocator->head->next;

    for (u32 i = 0; i < ALLOCATABLE_REGISTER_COUNT; i += 1) {
        allocator->head->states[i].flushed = false;
    }
}

void register_allocator_leave_frame(Context *context, Reg_Allocator *allocator) {
    for (int reg = 0; reg < ALLOCATABLE_REGISTER_COUNT; reg += 1) {
        if (allocator->head->states[reg].flushed) {
            X64_Address tmp_address = allocator->head->states[reg].flushed_to;
            instruction_mov_reg_mem(context, MOVE_FROM_MEM, tmp_address, reg, POINTER_SIZE);
        }
    }

    assert(allocator->head->previous != null);
    allocator->head = allocator->head->previous;
}

X64_Address register_allocator_allocate_temporary_stack_space(Reg_Allocator *allocator, u64 size, u64 align) {
    i32 *offset = &allocator->head->stack_size;
    *offset = (i32) round_to_next(*offset, align);

    i32 immediate_offset = *offset;
    X64_Address address = { .base = RSP_OFFSET_LOCALS, .immediate_offset = immediate_offset };

    *offset += size;
    if (*offset > allocator->max_stack_size) {
        allocator->max_stack_size = *offset;
    }

    return address;
}

Register register_allocate(Reg_Allocator *allocator, Register_Kind kind, bool dont_rax) {
    Register start, end;
    switch (kind) {
        case REGISTER_KIND_GPR: { start = RAX;  end = R15;   } break;
        case REGISTER_KIND_XMM: { start = XMM0; end = XMM15; } break;
    }

    for (Register reg = start; reg < end; reg += 1) {
        if (reg == RSP || reg == RBP) continue;
        if (reg == RAX && dont_rax) continue;

        if (!allocator->head->states[reg].allocated) {
            allocator->head->states[reg].allocated = true;
            return reg;
        }
    }

    panic("Out of registers to allocate\n");
    return REGISTER_NONE;
}

void register_allocate_specific(Context *context, Reg_Allocator *allocator, Register reg) {
    if (allocator->head->states[reg].allocated) {
        assert(!allocator->head->states[reg].flushed);

        X64_Address tmp_address = register_allocator_allocate_temporary_stack_space(allocator, POINTER_SIZE, POINTER_SIZE);
        instruction_mov_reg_mem(context, MOVE_TO_MEM, tmp_address, reg, POINTER_SIZE);

        allocator->head->states[reg].flushed = true;
        allocator->head->states[reg].flushed_to = tmp_address;
    }

    allocator->head->states[reg].allocated = true;
}

bool register_is_allocated(Reg_Allocator *allocator, Register reg) {
    return allocator->head->states[reg].allocated;
}



void machinecode_immediate_to_place(Context *context, X64_Place place, u64 immediate, u8 bytes) {
    switch (place.kind) {
        case PLACE_REGISTER: instruction_mov_imm_reg(context, place.reg, immediate, bytes); break;
        case PLACE_ADDRESS:  instruction_mov_imm_mem(context, place.address, immediate, bytes); break;

        case PLACE_NOWHERE: assert(false);
        default: assert(false);
    }
}

void machinecode_cast(Context *context, Register reg, Type_Kind from, Type_Kind to) {
    u8 from_size = primitive_size_of(from);
    u8 to_size = primitive_size_of(to);

    if (from == TYPE_POINTER && to == TYPE_POINTER) {
        // This is a no-op
    } else if (primitive_is_float(from) || primitive_is_float(to)) {
        unimplemented(); // TODO floating point casts
    } else {
        // Zero-extend or sign-extendto correct width, if needed
        
        bool word_prefix = false;
        bool rex_w = false;
        u32 opcode = 0;

        bool sign_extend = primitive_is_signed(from);

        #define CASE(a, b) if(from_size == a && to_size == b)
        if (sign_extend) {
            CASE(1, 2) { opcode = 0xbe0f; rex_w = false; word_prefix = true;  }
            CASE(1, 4) { opcode = 0xbe0f; rex_w = false; word_prefix = false; }
            CASE(1, 8) { opcode = 0xbe0f; rex_w = true;  word_prefix = false; }
            CASE(2, 4) { opcode = 0xbf0f; rex_w = false; word_prefix = false; }
            CASE(2, 8) { opcode = 0xbf0f; rex_w = true;  word_prefix = false; }
            CASE(4, 8) { opcode = 0x63;   rex_w = true;  word_prefix = false; }
        } else {
            CASE(1, 2) { opcode = 0xb60f; rex_w = false; word_prefix = true;  }
            CASE(1, 4) { opcode = 0xb60f; rex_w = false; word_prefix = false; }
            CASE(1, 8) { opcode = 0xb60f; rex_w = true;  word_prefix = false; }
            CASE(2, 4) { opcode = 0xb70f; rex_w = false; word_prefix = false; }
            CASE(2, 8) { opcode = 0xb70f; rex_w = true;  word_prefix = false; }
        }
        #undef CASE

        if (opcode != 0) {
            if (word_prefix) {
                buf_push(context->seg_text, WORD_OPERAND_PREFIX);
            }

            encode_instruction_reg_reg(context, rex_w? (REX_BASE | REX_W) : REX_BASE, opcode, reg, reg);

            #ifdef PRINT_GENERATED_INSTRUCTIONS
            dump_instruction_bytes(context);
            printf("%s %s, %s\n", sign_extend? "movsx" : "movzx", register_name(reg, to_size), register_name(reg, from_size));
            #endif
        }
    }
}

void machinecode_move(Context *context, Reg_Allocator *reg_allocator, X64_Place src, X64_Place dst, u64 size) {
    if (size == 1 || size == 2 || size == 4 || size == 8) {
        if (src.kind == PLACE_ADDRESS && dst.kind == PLACE_ADDRESS) {
            register_allocator_enter_frame(context, reg_allocator);

            Register reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, false);
            instruction_mov_reg_mem(context, MOVE_FROM_MEM, src.address, reg, (u8) size);
            instruction_mov_reg_mem(context, MOVE_TO_MEM, dst.address, reg, (u8) size);

            register_allocator_leave_frame(context, reg_allocator);
        } else if (src.kind == PLACE_REGISTER && dst.kind == PLACE_ADDRESS) {
            instruction_mov_reg_mem(context, MOVE_TO_MEM, dst.address, src.reg, (u8) size);
        } else if (src.kind == PLACE_ADDRESS && dst.kind == PLACE_REGISTER) {
            instruction_mov_reg_mem(context, MOVE_FROM_MEM, src.address, dst.reg, (u8) size);
        } else if (src.kind == PLACE_REGISTER && dst.kind == PLACE_REGISTER) {
            instruction_mov_reg_reg(context, src.reg, dst.reg, (u8) size);
        } else {
            assert(false);
        }
    } else {
        // TODO special case small moves by simply inserting some sequential moves

        register_allocator_enter_frame(context, reg_allocator);
        register_allocate_specific(context, reg_allocator, RAX);
        register_allocate_specific(context, reg_allocator, RDX);
        register_allocate_specific(context, reg_allocator, RCX);
        register_allocate_specific(context, reg_allocator, RBX);

        assert(src.kind == PLACE_ADDRESS && dst.kind == PLACE_ADDRESS);
        instruction_lea(context, src.address, RAX);
        instruction_lea(context, dst.address, RDX);

        instruction_mov_imm_reg(context, RCX, size, POINTER_SIZE);

        instruction_call(context, true, RUNTIME_BUILTIN_MEM_COPY);
        register_allocator_leave_frame(context, reg_allocator);
    }
}

void machinecode_lea(Context *context, Reg_Allocator *reg_allocator, X64_Address address, X64_Place place) {
    if (place.kind == PLACE_REGISTER) {
        instruction_lea(context, address, place.reg);
    } else {
        register_allocator_enter_frame(context, reg_allocator);
        Register reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, false);
        instruction_lea(context, address, reg);
        machinecode_move(context, reg_allocator, x64_place_reg(reg), place, POINTER_SIZE);
        register_allocator_leave_frame(context, reg_allocator);
    }
}

void machinecode_binary(Context *context, Reg_Allocator *reg_allocator, Binary_Op op, Type_Kind primitive, X64_Place src, X64_Place dst) {
    if (primitive_is_float(primitive)) unimplemented();

    switch (op) {
        case BINARY_ADD:
        case BINARY_SUB:
        {
            register_allocator_enter_frame(context, reg_allocator);

            Register tmp_reg = REGISTER_NONE;
            if (src.kind == PLACE_ADDRESS && dst.kind == PLACE_ADDRESS) {
                tmp_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, false);
                instruction_mov_reg_mem(context, MOVE_FROM_MEM, src.address, tmp_reg, primitive_size_of(primitive));
                src = x64_place_reg(tmp_reg);
            }

            assert(src.kind == PLACE_REGISTER || dst.kind == PLACE_REGISTER);

            Simple_Binary_Info info = {0};
            info.kind = op;
            info.op_size = primitive_size_of(primitive);

            if (src.kind == PLACE_ADDRESS) {
                info.a = dst.reg;
                info.b_is_address = true;
                info.b.address = src.address;
                info.direction = SIMPLE_BINARY_A_IS_DST;
            } else if (dst.kind == PLACE_ADDRESS) {
                info.a = src.reg;
                info.b_is_address = true;
                info.b.address = dst.address;
                info.direction = SIMPLE_BINARY_B_IS_DST;
            } else {
                info.a = src.reg;
                info.b_is_address = false;
                info.b.reg = dst.reg;
                info.direction = SIMPLE_BINARY_B_IS_DST;
            }
            instruction_simple_binary(context, info);

            register_allocator_leave_frame(context, reg_allocator);
        } break;

        // NB remember that we need to clear RDX, there are instructions for that!
        case BINARY_DIV: unimplemented(); break;
        case BINARY_MOD: unimplemented(); break;

        case BINARY_MUL:
        {
            u8 op_size = primitive_size_of(primitive);
            bool dst_is_not_rax = !(dst.kind == PLACE_REGISTER && dst.reg == RAX);

            register_allocator_enter_frame(context, reg_allocator);

            if (dst_is_not_rax) {
                register_allocate_specific(context, reg_allocator, RAX);
                machinecode_move(context, reg_allocator, dst, x64_place_reg(RAX), op_size);
            }

            if (op_size > 1 && !(src.kind == PLACE_REGISTER && src.reg == RDX)) {
                register_allocate_specific(context, reg_allocator, RDX); // We will clobber RDX
            }

            instruction_multiply(context, src, primitive_is_signed(primitive), op_size);

            if (dst_is_not_rax) {
                machinecode_move(context, reg_allocator, x64_place_reg(RAX), dst, op_size);
            }

            register_allocator_leave_frame(context, reg_allocator);
        } break;

        case BINARY_EQ:
        case BINARY_NEQ:
        case BINARY_GT:
        case BINARY_GTEQ:
        case BINARY_LT:
        case BINARY_LTEQ:
        {
            register_allocator_enter_frame(context, reg_allocator);

            Register tmp_reg = REGISTER_NONE;
            if (src.kind == PLACE_ADDRESS && dst.kind == PLACE_ADDRESS) {
                tmp_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, false);
                instruction_mov_reg_mem(context, MOVE_FROM_MEM, src.address, tmp_reg, primitive_size_of(primitive));
                src = x64_place_reg(tmp_reg);
            }

            u8 inner_size = primitive_size_of(primitive);
            Condition condition = find_condition_for_op_and_type(op, primitive);

            if (src.kind == PLACE_REGISTER && dst.kind == PLACE_REGISTER) {
                instruction_cmp_reg_reg(context, dst.reg, src.reg, inner_size);
            } else if (src.kind == PLACE_ADDRESS && dst.kind == PLACE_REGISTER) {
                instruction_cmp_reg_mem(context, src.address, dst.reg, inner_size);
                condition = condition_not(condition);
            } else if (src.kind == PLACE_REGISTER && dst.kind == PLACE_ADDRESS) {
                instruction_cmp_reg_mem(context, dst.address, src.reg, inner_size);
            } else {
                assert(false);
            }

            instruction_setcc(context, condition, dst);

            register_allocator_leave_frame(context, reg_allocator);
        } break;

        default: assert(false);
    }
}


bool machinecode_expr_needs_rax(Expr *expr) {
    switch (expr->kind) {
        case EXPR_VARIABLE:
        case EXPR_LITERAL:
        case EXPR_STRING_LITERAL:
        case EXPR_STATIC_MEMBER_ACCESS:
        case EXPR_TYPE_INFO_OF_TYPE:
        case EXPR_TYPE_INFO_OF_VALUE:
        case EXPR_ENUM_LENGTH:
        {
            return false;
        } break;

        case EXPR_COMPOUND: {
            for (u32 i = 0; i < expr->compound.count; i += 1) {
                if (machinecode_expr_needs_rax(expr->compound.content[i].expr)) {
                    return true;
                }
            }
            return false;
        } break;

        case EXPR_BINARY:           return expr->binary.op == BINARY_MUL ||
                                           expr->binary.op == BINARY_DIV ||
                                           expr->binary.op == BINARY_MOD ||
                                           machinecode_expr_needs_rax(expr->binary.left) ||
                                           machinecode_expr_needs_rax(expr->binary.right);
        case EXPR_UNARY:            return machinecode_expr_needs_rax(expr->unary.inner);
        case EXPR_CALL:             return true;
        case EXPR_CAST:             return machinecode_expr_needs_rax(expr->cast_from);
        case EXPR_SUBSCRIPT:        return machinecode_expr_needs_rax(expr->subscript.array) ||
                                           machinecode_expr_needs_rax(expr->subscript.index);
        case EXPR_MEMBER_ACCESS:    return machinecode_expr_needs_rax(expr->member_access.parent);
        case EXPR_ENUM_MEMBER_NAME: return machinecode_expr_needs_rax(expr->enum_member);
    }

    assert(false);
    return false;
}

void machinecode_for_expr(Context *context, Func *func, Expr *expr, Reg_Allocator *reg_allocator, X64_Place place);

X64_Place machinecode_for_assignable_expr(Context *context, Func *func, Expr *expr, Reg_Allocator *reg_allocator, bool reserve_rax) {
    assert(expr->flags & EXPR_FLAG_ASSIGNABLE);

    switch (expr->kind) {
        case EXPR_VARIABLE: {
            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));

            X64_Place place = {0};
            place.kind = PLACE_ADDRESS;
            place.address = reg_allocator->var_mem_infos[expr->variable.index].address;
            return place;
        } break;

        case EXPR_UNARY: {
            switch (expr->unary.op) {
                case UNARY_DEREFERENCE: {
                    Register reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserve_rax);

                    X64_Place place_value = {0};
                    place_value.kind = PLACE_REGISTER;
                    place_value.reg = reg;
                    machinecode_for_expr(context, func, expr->unary.inner, reg_allocator, place_value);

                    X64_Place place_pointer = {0};
                    place_pointer.kind = PLACE_ADDRESS;
                    place_pointer.address = (X64_Address) { .base = reg };
                    return place_pointer;
                } break;
            }
        } break;

        case EXPR_SUBSCRIPT: {
            X64_Place place = machinecode_for_assignable_expr(context, func, expr->subscript.array, reg_allocator, reserve_rax);
            assert(place.kind == PLACE_ADDRESS);

            Type *array_type = expr->subscript.array->type;
            Type *child_type;
            if (array_type->kind == TYPE_POINTER) {
                assert(array_type->pointer_to->kind == TYPE_ARRAY);
                child_type = array_type->pointer_to->array.of;

                Register address_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserve_rax);
                instruction_mov_reg_mem(context, MOVE_FROM_MEM, place.address, address_reg, POINTER_SIZE);
                place.address = (X64_Address) { .base = address_reg };
            } else {
                assert(array_type->kind == TYPE_ARRAY);
                child_type = array_type->array.of;
            }
            u64 step = type_size_of(child_type);

            if (expr->subscript.index->kind == EXPR_LITERAL) {
                u64 offset = expr->subscript.index->literal.masked_value * step;
                assert((((i64) place.address.immediate_offset) + ((i64) offset)) <= I32_MAX);
                place.address.immediate_offset += offset;
            } else {
                if (place.address.index != REGISTER_NONE) {
                    Register new_base = place.address.index;
                    instruction_lea(context, place.address, new_base);
                    place.address = (X64_Address) {0};
                    place.address.base = new_base;
                }
                assert(place.address.index == REGISTER_NONE);

                Register offset_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserve_rax);

                X64_Place offset_place = x64_place_reg(offset_reg);
                machinecode_for_expr(context, func, expr->subscript.index, reg_allocator, offset_place);

                place.address.index = offset_reg;

                if (step == 1 || step == 2 || step == 4 || step == 8) {
                    place.address.scale = (u8) step;
                } else {
                    place.address.scale = 1;
                    instruction_imul_pointer_imm(context, place.address.index, step);
                }
            }

            return place;
        } break;

        case EXPR_MEMBER_ACCESS: {
            X64_Place place = machinecode_for_assignable_expr(context, func, expr->member_access.parent, reg_allocator, reserve_rax);
            assert(place.kind == PLACE_ADDRESS);

            Type *parent_type = expr->member_access.parent->type;
            if (parent_type->kind == TYPE_POINTER) {
                parent_type = parent_type->pointer_to;

                Register address_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, false);
                instruction_mov_reg_mem(context, MOVE_FROM_MEM, place.address, address_reg, POINTER_SIZE);
                place.address = (X64_Address) { .base = address_reg };
            }

            assert(parent_type->kind == TYPE_STRUCT);

            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));
            u32 member_index = expr->member_access.member_index;
            u64 offset = parent_type->structure.members[member_index].offset;

            assert((((i64) place.address.immediate_offset) + ((i64) offset)) <= I32_MAX);
            place.address.immediate_offset += offset;

            return place;
        } break;
    }

    assert(false);
    return (X64_Place) {0};
}

void machinecode_for_expr(Context *context, Func *func, Expr *expr, Reg_Allocator *reg_allocator, X64_Place place) {
    switch (expr->kind) {
        case EXPR_VARIABLE: {
            if (place.kind == PLACE_NOWHERE) return;

            u64 size = type_size_of(expr->type);
            X64_Place from = machinecode_for_assignable_expr(context, func, expr, reg_allocator, false);
            machinecode_move(context, reg_allocator, from, place, size);
        } break;

        case EXPR_LITERAL: {
            if (place.kind == PLACE_NOWHERE) return;

            u64 size = type_size_of(expr->type);
            assert(size <= 8);
            machinecode_immediate_to_place(context, place, expr->literal.masked_value, (u8) size);
        } break;

        case EXPR_STRING_LITERAL: {
            if (place.kind == PLACE_NOWHERE) return;

            u64 data_offset = add_exe_data(context, expr->string.bytes, expr->string.length + 1, 1);

            assert(data_offset < I32_MAX);
            X64_Address data_address = { .base = RIP_OFFSET_DATA, .immediate_offset = data_offset };

            machinecode_lea(context, reg_allocator, data_address, place);
        } break;

        case EXPR_COMPOUND: {
            if (place.kind == PLACE_NOWHERE) {
                for (u32 i = 0; i < expr->compound.count; i += 1) {
                    Expr *child = expr->compound.content[i].expr;
                    machinecode_for_expr(context, func, child, reg_allocator, place);
                }
                return;
            }

            register_allocator_enter_frame(context, reg_allocator);

            u64 size = type_size_of(expr->type);
            u64 align = type_align_of(expr->type);

            X64_Place real_place = place;
            bool return_to_real_place = false;

            if (place.kind != PLACE_ADDRESS) {
                assert(size == 1 || size == 2 || size == 4 || size == 8);

                return_to_real_place = true;

                place.kind = PLACE_ADDRESS;
                place.address = register_allocator_allocate_temporary_stack_space(reg_allocator, size, align);
            }

            assert(place.kind == PLACE_ADDRESS);
            switch (expr->type->kind) {
                case TYPE_ARRAY: {
                    Type* child_type = expr->type->array.of;
                    u64 child_size = type_size_of(child_type);

                    for (u32 i = 0; i < expr->compound.count; i += 1) {
                        assert(expr->compound.content[i].name_mode == EXPR_COMPOUND_NO_NAME);

                        Expr *child = expr->compound.content[i].expr;
                        machinecode_for_expr(context, func, child, reg_allocator, place);

                        assert((((i64) place.address.immediate_offset) + ((i64) child_size)) < I32_MAX);
                        place.address.immediate_offset += child_size;
                    }
                } break;

                case TYPE_STRUCT: {
                    for (u32 i = 0; i < expr->compound.count; i += 1) {
                        assert(expr->compound.content[i].name_mode != EXPR_COMPOUND_UNRESOLVED_NAME);

                        u32 type_member_index = expr->compound.content[i].member_index;
                        i32 member_offset = expr->type->structure.members[type_member_index].offset;

                        assert((place.address.immediate_offset + member_offset) < I32_MAX);
                        X64_Place offset_place = place;
                        offset_place.address.immediate_offset += (i32) member_offset;

                        Expr* child = expr->compound.content[i].expr;
                        machinecode_for_expr(context, func, child, reg_allocator, offset_place);
                    }
                } break;

                default: assert(false);
            }

            if (return_to_real_place) {
                machinecode_move(context, reg_allocator, place, real_place, size);
            }

            register_allocator_leave_frame(context, reg_allocator);
        } break;

        case EXPR_BINARY: {
            if (place.kind == PLACE_NOWHERE) {
                machinecode_for_expr(context, func, expr->binary.left, reg_allocator, place);
                machinecode_for_expr(context, func, expr->binary.right, reg_allocator, place);
                return;
            }

            Register_Kind reg_kind = primitive_is_float(primitive_of(expr->binary.left->type))? REGISTER_KIND_XMM : REGISTER_KIND_GPR;

            X64_Place left_place;
            Register left_reg = REGISTER_NONE;
            if (place.kind == PLACE_ADDRESS) {
                register_allocator_enter_frame(context, reg_allocator);

                bool reserve_rax_for_rhs = machinecode_expr_needs_rax(expr->binary.right);
                left_reg = register_allocate(reg_allocator, reg_kind, reserve_rax_for_rhs);
                left_place = x64_place_reg(left_reg);
            } else {
                left_place = place;
            }

            machinecode_for_expr(context, func, expr->binary.left, reg_allocator, left_place);

            register_allocator_enter_frame(context, reg_allocator);

            Register right_reg = register_allocate(reg_allocator, reg_kind, false);
            X64_Place right_place = { .kind = PLACE_REGISTER, .reg = right_reg };
            machinecode_for_expr(context, func, expr->binary.right, reg_allocator, right_place);

            Type_Kind primitive = primitive_of(expr->binary.left->type);
            machinecode_binary(context, reg_allocator, expr->binary.op, primitive, right_place, left_place);

            register_allocator_leave_frame(context, reg_allocator);

            if (left_reg != REGISTER_NONE) {
                u64 size = type_size_of(expr->type);
                assert(size <= 8);
                machinecode_move(context, reg_allocator, left_place, place, (u8) size);
                register_allocator_leave_frame(context, reg_allocator);
            }
        } break;

        case EXPR_UNARY: {
            if (place.kind == PLACE_NOWHERE) {
                machinecode_for_expr(context, func, expr->unary.inner, reg_allocator, place);
                return;
            }

            switch (expr->unary.op) {
                case UNARY_NOT:
                case UNARY_NEG:
                {
                    machinecode_for_expr(context, func, expr->unary.inner, reg_allocator, place);

                    Type_Kind primitive = expr->type->kind;
                    if (expr->unary.op == UNARY_NOT && primitive == TYPE_BOOL) {
                        assert(primitive_size_of(primitive) == 1);

                        instruction_cmp_imm(context, place, 0, 1);
                        instruction_setcc(context, COND_E, place);
                    } else {
                        bool unary = expr->unary.op == UNARY_NOT;
                        instruction_negative(context, unary, place, primitive_size_of(primitive));
                    }
                } break;

                case UNARY_DEREFERENCE: {
                    register_allocator_enter_frame(context, reg_allocator);
                    X64_Place inner_place = {0};
                    inner_place.kind = PLACE_REGISTER;
                    if (place.kind == PLACE_REGISTER) {
                        inner_place.reg = place.reg;
                    } else {
                        inner_place.reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, false);
                    }

                    machinecode_for_expr(context, func, expr->unary.inner, reg_allocator, inner_place);

                    Register inner_reg = inner_place.reg;
                    inner_place = (X64_Place) {0};
                    inner_place.kind = PLACE_ADDRESS;
                    inner_place.address.base = inner_reg;

                    u64 dereferenced_size = type_size_of(expr->type);
                    machinecode_move(context, reg_allocator, inner_place,place, dereferenced_size);

                    register_allocator_leave_frame(context, reg_allocator);
                } break;

                case UNARY_ADDRESS_OF: {
                    X64_Place inner_place = machinecode_for_assignable_expr(context, func, expr->unary.inner, reg_allocator, false);
                    assert(inner_place.kind == PLACE_ADDRESS);

                    switch (place.kind) {
                        case PLACE_REGISTER: {
                            instruction_lea(context, inner_place.address, place.reg);
                        } break;

                        case PLACE_ADDRESS: {
                            register_allocator_enter_frame(context, reg_allocator);
                            Register reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, false);
                            instruction_lea(context, inner_place.address, reg);
                            instruction_mov_reg_mem(context, MOVE_TO_MEM, place.address, reg, POINTER_SIZE);
                            register_allocator_leave_frame(context, reg_allocator);
                        } break;

                        case PLACE_NOWHERE: assert(false);
                        default: assert(false);
                    }
                } break;

                default: assert(false);
            }
        } break;

        case EXPR_CALL: {
            register_allocator_enter_frame(context, reg_allocator);

            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));
            u32 func_index = expr->call.func_index;
            Func *callee = &context->funcs[func_index];

            reg_allocator->max_callee_param_count = max(reg_allocator->max_callee_param_count, callee->signature.param_count);

            // Compute parameters
            bool used_volatile_registers[4] = { false };
            for (u32 p = 0; p < callee->signature.param_count; p += 1) {
                Type *param_type = callee->signature.params[p].type;
                bool reference_semantics = callee->signature.params[p].reference_semantics;

                if (reference_semantics) {
                    assert(param_type->kind == TYPE_POINTER);
                    param_type = param_type->pointer_to;
                }

                X64_Place target_place;
                if (p < 4) {
                    Register reg;
                    if (primitive_is_float(param_type->kind)) {
                        reg = XMM0 + p;
                    } else {
                        switch (p) {
                            case 0: reg = RCX; break;
                            case 1: reg = RDX; break;
                            case 2: reg = R8;  break;
                            case 3: reg = R9;  break;
                            default: assert(false);
                        }
                    }

                    used_volatile_registers[p] = true;
                    target_place = x64_place_reg(reg);
                } else {
                    target_place = (X64_Place) { .kind = PLACE_ADDRESS, .address = { .base = RSP, .immediate_offset = p*POINTER_SIZE } };
                }

                if (callee->signature.params[p].reference_semantics) {
                    u64 size = type_size_of(param_type);
                    u64 align = type_align_of(param_type);
                    X64_Address tmp_address = register_allocator_allocate_temporary_stack_space(reg_allocator, size, align);
                    X64_Place tmp_place = { .kind = PLACE_ADDRESS, .address = tmp_address };

                    machinecode_for_expr(context, func, expr->call.params[p], reg_allocator, tmp_place);
                    if (target_place.kind == PLACE_REGISTER) register_allocate_specific(context, reg_allocator, target_place.reg);
                    machinecode_lea(context, reg_allocator, tmp_address, target_place);
                } else {
                    if (target_place.kind == PLACE_REGISTER) register_allocate_specific(context, reg_allocator, target_place.reg);
                    machinecode_for_expr(context, func, expr->call.params[p], reg_allocator, target_place);
                }
            }

            // Save volatile registers, unless we are using them for parameters
            for (u32 i = 0; i < VOLATILE_REGISTER_COUNT; i += 1) {
                Register reg = VOLATILE_REGISTERS[i];

                if (used_volatile_registers[i] || (place.kind == PLACE_REGISTER && place.reg == reg) || reg == RAX) {
                    continue;
                }

                register_allocate_specific(context, reg_allocator, reg);
            }

            // Call function and handle return value
            if (place.kind == PLACE_REGISTER && place.reg == RAX) {
                instruction_call(context, false, func_index);
            } else {
                register_allocate_specific(context, reg_allocator, RAX);
                X64_Place return_place = { .kind = PLACE_REGISTER, .reg = RAX };

                instruction_call(context, false, func_index);

                if (place.kind != PLACE_NOWHERE && callee->signature.has_return) {
                    Type *return_type = callee->signature.return_type;
                    u64 return_size = type_size_of(callee->signature.return_type);

                    if (callee->signature.return_by_reference) {
                        unimplemented(); // TODO reference-semantics. What does the windows spec say here?
                    } else {
                        machinecode_move(context, reg_allocator, return_place, place, return_size);
                    }
                }
            }

            register_allocator_leave_frame(context, reg_allocator);
        } break;

        case EXPR_CAST: {
            if (place.kind == PLACE_NOWHERE) {
                machinecode_for_expr(context, func, expr->cast_from, reg_allocator, place);
                return;
            }

            if (expr->type->kind == expr->cast_from->type->kind) {
                machinecode_for_expr(context, func, expr->cast_from, reg_allocator, place);
            } else {
                register_allocator_enter_frame(context, reg_allocator);

                X64_Place inner_place;
                bool inner_doesnt_match_outer;

                if (place.kind == PLACE_ADDRESS) {
                    inner_place.kind = PLACE_REGISTER;
                    inner_place.reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, false);
                    inner_doesnt_match_outer = true;
                } else {
                    inner_place = place;
                    inner_doesnt_match_outer = false;
                }

                machinecode_for_expr(context, func, expr->cast_from, reg_allocator, inner_place);

                if (place.kind == PLACE_NOWHERE) return;
                assert(inner_place.kind == PLACE_REGISTER);
                Register inner_reg = inner_place.reg;

                machinecode_cast(context, inner_reg, expr->cast_from->type->kind, expr->type->kind);
                machinecode_move(context, reg_allocator, inner_place, place, primitive_size_of(expr->type->kind));

                register_allocator_leave_frame(context, reg_allocator);
            }
        } break;

        case EXPR_SUBSCRIPT: {
            if (place.kind == PLACE_NOWHERE) {
                machinecode_for_expr(context, func, expr->subscript.array, reg_allocator, place);
                machinecode_for_expr(context, func, expr->subscript.index, reg_allocator, place);
                return;
            }

            unimplemented();
        } break;

        case EXPR_MEMBER_ACCESS: {
            if (place.kind == PLACE_NOWHERE) {
                machinecode_for_expr(context, func, expr->member_access.parent, reg_allocator, place);
                return;
            }

            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));
            u64 member_size = type_size_of(expr->type);

            if (expr->flags & EXPR_FLAG_ASSIGNABLE) {
                X64_Place dst = place;
                X64_Place src = machinecode_for_assignable_expr(context, func, expr, reg_allocator, false);
                machinecode_move(context, reg_allocator, src, dst, member_size);
            } else {
                Expr *parent = expr->member_access.parent;

                Type *parent_type = parent->type;
                bool parent_is_pointer = parent_type->kind == TYPE_POINTER;
                if (parent_is_pointer) parent_type = parent_type->pointer_to;

                assert(parent_type->kind == TYPE_STRUCT);

                i32 member_offset = parent_type->structure.members[expr->member_access.member_index].offset;

                if (parent_is_pointer) {
                    register_allocator_enter_frame(context, reg_allocator);

                    Register pointer_reg;
                    if (place.kind == PLACE_REGISTER) {
                        pointer_reg = place.reg;
                    } else {
                        pointer_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, false);
                    }

                    machinecode_for_expr(context, func, parent, reg_allocator, x64_place_reg(pointer_reg));

                    X64_Place member_place = { .kind = PLACE_ADDRESS };
                    member_place.address.base = pointer_reg;
                    member_place.address.immediate_offset = member_offset;

                    machinecode_move(context, reg_allocator, member_place, place, member_size);

                    register_allocator_leave_frame(context, reg_allocator);
                } else {
                    register_allocator_enter_frame(context, reg_allocator);

                    X64_Address tmp_address = register_allocator_allocate_temporary_stack_space(reg_allocator, parent_type->structure.size, parent_type->structure.align);
                    machinecode_for_expr(context, func, parent, reg_allocator, x64_place_address(tmp_address));

                    X64_Place member_place = { .kind = PLACE_ADDRESS };
                    member_place.address = tmp_address;
                    member_place.address.immediate_offset += member_offset;
                    machinecode_move(context, reg_allocator, member_place, place, member_size);

                    register_allocator_leave_frame(context, reg_allocator);
                }
            }
        } break;

        case EXPR_STATIC_MEMBER_ACCESS: {
            if (place.kind == PLACE_NOWHERE) return;

            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));

            Type* type = expr->static_member_access.parent_type;
            assert(type->kind == TYPE_ENUM);
            u32 member_index = expr->static_member_access.member_index;
            u64 member_value = type->enumeration.members[member_index].value;
            u8 size = primitive_size_of(type->enumeration.value_primitive);

            machinecode_immediate_to_place(context, place, member_value, size);
        } break;

        case EXPR_TYPE_INFO_OF_TYPE: {
            if (place.kind == PLACE_NOWHERE) return;

            Type_Kind primitive = expr->type_info_of_type->kind;
            machinecode_immediate_to_place(context, place, (u64) primitive, 1);
        } break;

        case EXPR_TYPE_INFO_OF_VALUE: {
            if (place.kind == PLACE_NOWHERE) return;

            Type_Kind primitive = expr->type_info_of_value->type->kind;
            machinecode_immediate_to_place(context, place, (u64) primitive, 1);
        } break;

        case EXPR_ENUM_LENGTH: {
            if (place.kind == PLACE_NOWHERE) return;

            unimplemented();
        } break;

        case EXPR_ENUM_MEMBER_NAME: {
            if (place.kind == PLACE_NOWHERE) {
                machinecode_for_expr(context, func, expr->enum_member, reg_allocator, place);
                return;
            }

            unimplemented(); // Maybe wait until we have proper strings until we do this...
            // expr->enum_member
        } break;
    }
}

Jump_Fixup machinecode_for_conditional_jump(Context *context, Func *func, Expr *expr, bool invert, Reg_Allocator *reg_allocator) { 
    Condition condition;
    if (expr->kind == EXPR_BINARY && BINARY_OP_COMPARATIVE[expr->binary.op]) {
        Expr *left  = expr->binary.left;
        Expr *right = expr->binary.right;
        assert(left->type->kind == right->type->kind);
        Type_Kind primitive = left->type->kind;
        u8 primitive_size = primitive_size_of(primitive);

        condition = find_condition_for_op_and_type(expr->binary.op, left->type->kind);

        if (primitive_is_float(primitive)) {
            unimplemented(); // TODO what are the floating point instructions for comparasions?
        } else if (primitive_is_integer(primitive)) {
            register_allocator_enter_frame(context, reg_allocator);

            // TODO We need to special case when both the lhs and the rhs are simple stack loads, so that we 
            // use one memory operand for the compare in that case.
            // Also, do a similar check for when one of the sides is a literal

            bool reserve_rax_for_rhs = machinecode_expr_needs_rax(right);

            Register left_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserve_rax_for_rhs);
            X64_Place left_place = { .kind = PLACE_REGISTER, .reg = left_reg };
            machinecode_for_expr(context, func, left, reg_allocator, left_place);

            Register right_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, false);
            machinecode_for_expr(context, func, right, reg_allocator, x64_place_reg(right_reg));

            instruction_cmp_reg_reg(context, left_reg, right_reg, primitive_size);

            register_allocator_leave_frame(context, reg_allocator);
        } else {
            assert(false); // NB We don't support comparasion operators on compound literals, see the typechecker
        }
    } else {
        while (expr->kind == EXPR_UNARY && expr->unary.op == UNARY_NOT) {
            invert = !invert;
            expr = expr->unary.inner;
        }

        Type_Kind primitive = expr->type->kind;
        u8 primitive_size = primitive_size_of(primitive);

        Register reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, false);
        machinecode_for_expr(context, func, expr, reg_allocator, x64_place_reg(reg));
        instruction_cmp_imm(context, x64_place_reg(reg), 0, primitive_size);
        condition = COND_NE;
    }

    if (invert) {
        condition = condition_not(condition);
    }

    u64 jump_distance_text_location = instruction_jcc(context, condition);
    u64 jump_from = buf_length(context->seg_text);

    Jump_Fixup fixup = {0};
    fixup.text_location = jump_distance_text_location;
    fixup.jump_from = jump_from;
    return fixup;
}

void machinecode_for_stmt(Context *context, Func *func, Stmt *stmt, Reg_Allocator *reg_allocator) {
    register_allocator_enter_frame(context, reg_allocator);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("; ");
    print_stmt(context, func, stmt, 0);
    #endif

    switch (stmt->kind) {
        case STMT_DECLARATION: {
            Var *var = &func->body.vars[stmt->declaration.var_index];

            u64 size = type_size_of(var->type);
            u64 align = type_align_of(var->type);

            X64_Place place = {0};
            place.kind = PLACE_ADDRESS;
            place.address = reg_allocator->var_mem_infos[stmt->declaration.var_index].address;

            if (stmt->declaration.right == null) {
                if (size != align || size > 8) {
                    register_allocator_enter_frame(context, reg_allocator);

                    register_allocate_specific(context, reg_allocator, RAX);
                    register_allocate_specific(context, reg_allocator, RCX);

                    instruction_lea(context, place.address, RAX);
                    instruction_mov_imm_reg(context, RCX, size, POINTER_SIZE);
                    instruction_call(context, true, RUNTIME_BUILTIN_MEM_CLEAR);

                    register_allocator_leave_frame(context, reg_allocator);
                } else {
                    machinecode_immediate_to_place(context, place, 0, (u8) size);
                }
            } else {
                machinecode_for_expr(context, func, stmt->declaration.right, reg_allocator, place);
            }
        } break;

        case STMT_EXPR: {
            X64_Place nowhere = { .kind = PLACE_NOWHERE };
            machinecode_for_expr(context, func, stmt->expr, reg_allocator, nowhere);
        } break;

        case STMT_ASSIGNMENT: {
            Expr *left  = stmt->assignment.left;
            Expr *right = stmt->assignment.right;
            Type *type = right->type;

            bool needs_temporary =
                primitive_is_compound(type->kind) &&
                !(right->kind == EXPR_VARIABLE);

            if (needs_temporary) {
                u64 size = type_size_of(type);
                u64 align = type_align_of(type);

                X64_Address tmp_address = register_allocator_allocate_temporary_stack_space(reg_allocator, size, align);
                X64_Place tmp_place = { .kind = PLACE_ADDRESS, .address = tmp_address };

                machinecode_for_expr(context, func, right, reg_allocator, tmp_place);

                X64_Place left_place = machinecode_for_assignable_expr(context, func, left, reg_allocator, false);
                machinecode_move(context, reg_allocator, tmp_place, left_place, size);
            } else {
                bool reserve_rax_for_rhs = machinecode_expr_needs_rax(right);
                X64_Place left_place = machinecode_for_assignable_expr(context, func, left, reg_allocator, reserve_rax_for_rhs);
                machinecode_for_expr(context, func, right, reg_allocator, left_place);
            }
        } break;

        case STMT_BLOCK: {
            unimplemented();
        } break;

        case STMT_IF: {
            Jump_Fixup first_jump_fixup = machinecode_for_conditional_jump(context, func, stmt->conditional.condition, true, reg_allocator);

            for (Stmt *inner = stmt->conditional.then; inner->kind != STMT_END; inner = inner->next) {
                machinecode_for_stmt(context, func, inner, reg_allocator);
            }

            u64 second_jump_text_location_index, second_jump_from;
            if (stmt->conditional.else_then != null) {
                second_jump_text_location_index = instruction_jmp_i32(context);
                second_jump_from = buf_length(context->seg_text);
            }

            i64 first_jump_by = ((i64) buf_length(context->seg_text)) - ((i64) first_jump_fixup.jump_from);
            assert(first_jump_by <= I32_MAX && first_jump_by >= I32_MIN);
            i32 *first_jump_text_location = (i32*) (&context->seg_text[first_jump_fixup.text_location]);
            *first_jump_text_location = first_jump_by;

            if (stmt->conditional.else_then != null) {
                for (Stmt *inner = stmt->conditional.else_then; inner->kind != STMT_END; inner = inner->next) {
                    machinecode_for_stmt(context, func, inner, reg_allocator);
                }

                i64 second_jump_by = ((i64) buf_length(context->seg_text)) - ((i64) second_jump_from);
                assert(second_jump_by <= I32_MAX && second_jump_by >= I32_MIN);
                i32 *second_jump_text_location = (i32*) (&context->seg_text[second_jump_text_location_index]);
                *second_jump_text_location = second_jump_by;
            }
        } break;

        case STMT_LOOP: {
            u64 loop_start = buf_length(context->seg_text);

            if (stmt->loop.condition != null) {
                Jump_Fixup fixup = machinecode_for_conditional_jump(context, func, stmt->loop.condition, true, reg_allocator);
                fixup.jump_to = JUMP_TO_END_OF_LOOP;
                buf_push(context->jump_fixups, fixup);
            }

            for (Stmt *inner = stmt->loop.body; inner->kind != STMT_END; inner = inner->next) {
                machinecode_for_stmt(context, func, inner, reg_allocator);
            }

            u64 backward_jump_index = instruction_jmp_i32(context);
            u64 loop_end = buf_length(context->seg_text);

            u64 jump_by = loop_end - loop_start;
            assert(jump_by < I32_MAX);
            *((i32*) &context->seg_text[backward_jump_index]) = -((i32) jump_by);

            buf_foreach (Jump_Fixup, fixup, context->jump_fixups) {
                u64 jump_to;
                if (fixup->jump_to == JUMP_TO_END_OF_LOOP) {
                    jump_to = loop_end;
                } else if (fixup->jump_to == JUMP_TO_START_OF_LOOP) {
                    jump_to = loop_start;
                } else {
                    continue;
                }

                i64 jump_by = ((i64) jump_to) - ((i64) fixup->jump_from);
                assert(jump_by <= I32_MAX && jump_by >= I32_MIN);

                i32 *jump_text_location = (i32*) (&context->seg_text[fixup->text_location]);
                *jump_text_location = jump_by;

                buf_foreach_remove(context->jump_fixups, fixup);
            }
        } break;

        case STMT_RETURN: {
            if (stmt->return_stmt.value != null) {
                register_allocator_enter_frame(context, reg_allocator);
                register_allocate_specific(context, reg_allocator, RAX);
                X64_Place return_location = x64_place_reg(RAX);
                machinecode_for_expr(context, func, stmt->return_stmt.value, reg_allocator, return_location);
                register_allocator_leave_frame(context, reg_allocator);
            }

            if (!stmt->return_stmt.trailing) {
                Jump_Fixup fixup = {0};
                fixup.text_location = instruction_jmp_i32(context);
                fixup.jump_from = buf_length(context->seg_text);
                fixup.jump_to = JUMP_TO_END_OF_FUNCTION;
                buf_push(context->jump_fixups, fixup);
            }
        } break;

        case STMT_BREAK: {
            Jump_Fixup fixup = {0};
            fixup.text_location = instruction_jmp_i32(context);
            fixup.jump_from = buf_length(context->seg_text);
            fixup.jump_to = JUMP_TO_END_OF_LOOP;
            buf_push(context->jump_fixups, fixup);
        } break;

        case STMT_CONTINUE: {
            assert(false); // TODO untested code
            Jump_Fixup fixup = {0};
            fixup.text_location = instruction_jmp_i32(context);
            fixup.jump_from = buf_length(context->seg_text);
            fixup.jump_to = JUMP_TO_START_OF_LOOP;
            buf_push(context->jump_fixups, fixup);
        } break;
    }

    register_allocator_leave_frame(context, reg_allocator);
}


void build_machinecode(Context *context) {
    // Builtins
    u32 runtime_builtin_text_starts[RUNTIME_BUILTIN_COUNT] = {0};

    // TODO we can optimize builtin mem copy/clear by using a bigger mov and looping fewer times.
    // We have to consider alignment then though...
    // The amd performance guide has a section on fast memory copies.

    { // mem clear
        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("; --- builtin mem clear ---\n");
        #endif

        // RAX is pointer to memory, RCX is count. Both are modified in the process
        
        runtime_builtin_text_starts[RUNTIME_BUILTIN_MEM_CLEAR] = buf_length(context->seg_text);

        u64 before_loop = buf_length(context->seg_text);
        u64 forward_jump_index = instruction_jrcxz(context);
        u64 loop_start = buf_length(context->seg_text);

        instruction_mov_imm_mem(context, (X64_Address) { .base = RAX }, 0, 1);
        instruction_inc_or_dec(context, true, RAX, POINTER_SIZE);
        instruction_inc_or_dec(context, false, RCX, POINTER_SIZE);

        u64 backward_jump_index = instruction_jmp_i8(context);
        u64 loop_end = buf_length(context->seg_text);

        i8 forward_jump_by = loop_end - loop_start;
        i8 backward_jump_by = -((i8) (loop_end - before_loop));
        context->seg_text[forward_jump_index]  = *((u8*) &forward_jump_by);
        context->seg_text[backward_jump_index] = *((u8*) &backward_jump_by);

        instruction_ret(context);
    }

    { // mem copy
        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("; --- builtin mem copy ---\n");
        #endif

        // RAX is src pointer, RDX is dst pointer, RCX is count, RBX is clobbered.

        runtime_builtin_text_starts[RUNTIME_BUILTIN_MEM_COPY] = buf_length(context->seg_text);

        u64 before_loop = buf_length(context->seg_text);
        u64 forward_jump_index = instruction_jrcxz(context);
        u64 loop_start = buf_length(context->seg_text);

        instruction_mov_reg_mem(context, MOVE_FROM_MEM, (X64_Address) { .base = RAX }, RBX, 1);
        instruction_mov_reg_mem(context, MOVE_TO_MEM,   (X64_Address) { .base = RDX }, RBX, 1);
        instruction_inc_or_dec(context, true, RAX, POINTER_SIZE);
        instruction_inc_or_dec(context, true, RDX, POINTER_SIZE);
        instruction_inc_or_dec(context, false, RCX, POINTER_SIZE);

        u64 backward_jump_index = instruction_jmp_i8(context);
        u64 loop_end = buf_length(context->seg_text);
        i8 forward_jump_by = loop_end - loop_start;
        i8 backward_jump_by = -((i8) (loop_end - before_loop));

        context->seg_text[forward_jump_index]  = *((u8*) &forward_jump_by);
        context->seg_text[backward_jump_index] = *((u8*) &backward_jump_by);

        instruction_ret(context);
    }

    // Normal functions
    Reg_Allocator reg_allocator = {0};

    u32 main_func_index = find_func(context, string_table_search(context->string_table, "main")); 
    if (main_func_index == STRING_TABLE_NO_MATCH) {
        panic("No main function");
    }
    Func* main_func = context->funcs + main_func_index;
    assert(main_func->kind == FUNC_KIND_NORMAL); // TODO I'm not sure if this is strictly speaking neccesary!

    buf_foreach (Func, func, context->funcs) {
        if (func->kind != FUNC_KIND_NORMAL) continue;

        func->body.text_start = buf_length(context->seg_text);

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        u8* name = string_table_access(context->string_table, func->name);
        printf("; --- fn %s ---\n", name);
        #endif

        // Lay out stack
        if (reg_allocator.allocated_var_mem_infos < func->body.var_count) {
            // TODO this leaks memory. We should allocate on 'context->stack', but it probably doesn't really matter in this case
            u32 alloc_count = func->body.var_count * 2;
            reg_allocator.allocated_var_mem_infos = alloc_count;
            reg_allocator.var_mem_infos = (void*) arena_alloc(&context->arena, alloc_count * sizeof(*reg_allocator.var_mem_infos));
        }
        mem_clear((u8*) reg_allocator.var_mem_infos, sizeof(*reg_allocator.var_mem_infos) * reg_allocator.allocated_var_mem_infos);

        reg_allocator.max_callee_param_count = 0;

        // Mark parameter variables so they don't get allocated normaly
        for (u32 p = 0; p < func->signature.param_count; p += 1) {
            u32 var_index = func->signature.params[p].var_index;

            X64_Address address = { .base = RSP_OFFSET_INPUTS, .immediate_offset = var_index * POINTER_SIZE };

            reg_allocator.var_mem_infos[var_index].size = POINTER_SIZE;
            reg_allocator.var_mem_infos[var_index].address = address;
        }

        // Variables
        i32 next_stack_offset = 0;
        for (u32 v = 0; v < func->body.var_count; v += 1) {
            if (reg_allocator.var_mem_infos[v].address.base != REGISTER_NONE) continue; // Ignore parameters, see previous loop

            u64 size = type_size_of(func->body.vars[v].type);
            u64 align = type_align_of(func->body.vars[v].type);
            next_stack_offset = (i32) round_to_next(next_stack_offset, align);

            X64_Address address = { .base = RSP_OFFSET_LOCALS, .immediate_offset = next_stack_offset };

            reg_allocator.var_mem_infos[v].size = size;
            reg_allocator.var_mem_infos[v].address = address;

            next_stack_offset += size;
        }

        reg_allocator.max_stack_size = next_stack_offset;
        if (reg_allocator.head != null) reg_allocator.head->stack_size = next_stack_offset;

        u64 insert_stack_size_at_index;
        {
            buf_push(context->seg_text, 0x48);
            buf_push(context->seg_text, 0x81);
            buf_push(context->seg_text, 0xec);
            insert_stack_size_at_index = buf_length(context->seg_text);
            str_push_integer(&context->seg_text, sizeof(i32), 0xdeadbeef);

            #ifdef PRINT_GENERATED_INSTRUCTIONS
            dump_instruction_bytes(context);
            printf("sub rsp, ??? (We fill in stack size after generating all code!)\n");
            #endif
        }
        
        // TODO calling convention -- Preserve non-volatile registers! Also, we need to allocate stack space for that!

        // Copy parameters onto stack
        for (u32 p = 0; p < min(func->signature.param_count, 4); p += 1) {
            u32 var_index = func->signature.params[p].var_index;
            X64_Address address = reg_allocator.var_mem_infos[var_index].address;

            u64 operand_size = type_size_of(func->signature.params[p].type);
            Type_Kind operand_primitive = primitive_of(func->signature.params[p].type);
            assert(operand_size <= 8);

            if (primitive_is_float(operand_primitive)) {
                unimplemented(); // TODO floating point parameters
            } else {
                Register reg;
                switch (p) {
                    case 0: reg = RCX; break;
                    case 1: reg = RDX; break;
                    case 2: reg = R8; break;
                    case 3: reg = R9; break;
                    default: assert(false);
                }
                instruction_mov_reg_mem(context, MOVE_TO_MEM, address, reg, (u8) operand_size);
            }
        }

        // Write out operations
        for (Stmt* stmt = func->body.first_stmt; stmt->kind != STMT_END; stmt = stmt->next) {
            machinecode_for_stmt(context, func, stmt, &reg_allocator);
        }

        buf_foreach (Jump_Fixup, fixup, context->jump_fixups) {
            assert(fixup->jump_to == JUMP_TO_END_OF_FUNCTION);

            i64 jump_by = ((i64) buf_length(context->seg_text)) - ((i64) fixup->jump_from);
            assert(jump_by <= I32_MAX && jump_by >= I32_MIN);

            i32 *jump_text_location = (i32*) (&context->seg_text[fixup->text_location]);
            *jump_text_location = jump_by;
        }
        buf_clear(context->jump_fixups);

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("; (epilog)\n");
        #endif

        if (!func->signature.has_return) {
            instruction_xor(context, RAX, RAX, POINTER_SIZE);
        }

        // Reset stack and fix up stack accesses
        u64 stack_space_for_params = 0;
        if (reg_allocator.max_callee_param_count > 0) {
            stack_space_for_params = POINTER_SIZE * max(reg_allocator.max_callee_param_count, 4);
        }
        u64 total_stack_bytes = ((u64) reg_allocator.max_stack_size) + stack_space_for_params;
        total_stack_bytes = ((total_stack_bytes + 7) & (~0x0f)) + 8; // Aligns so last nibble is 8

        i32 *insert_stack_size_here = (i32*) (&context->seg_text[insert_stack_size_at_index]);
        assert(total_stack_bytes < I32_MAX);
        *insert_stack_size_here = total_stack_bytes;

        buf_foreach (Stack_Access_Fixup, fixup, context->stack_access_fixups) {
            i32* target = (i32*) (context->seg_text + fixup->text_location);

            u64 offset;
            switch (fixup->kind) {
                case STACK_ACCESS_FIXUP_INPUT_SECTION: offset = total_stack_bytes + POINTER_SIZE; break;
                case STACK_ACCESS_FIXUP_LOCAL_SECTION: offset = stack_space_for_params; break;
                default: assert(false);
            }

            *target += offset;
        }
        buf_clear(context->stack_access_fixups);

        buf_push(context->seg_text, 0x48);
        buf_push(context->seg_text, 0x81);
        buf_push(context->seg_text, 0xc4);
        str_push_integer(&context->seg_text, sizeof(i32), total_stack_bytes);
        #ifdef PRINT_GENERATED_INSTRUCTIONS
        dump_instruction_bytes(context);
        printf("add rsp, %x\n", total_stack_bytes);
        #endif

        // Return to caller
        instruction_ret(context);
    }

    // Call fixups
    buf_foreach (Call_Fixup, fixup, context->call_fixups) {
        i32* target = (i32*) (context->seg_text + fixup->text_location);
        assert(*target == 0xdeadbeef);

        u32 jump_to;
        if (fixup->builtin) {
            jump_to = runtime_builtin_text_starts[fixup->func_index];
        } else {
            Func* callee = &context->funcs[fixup->func_index];
            assert(callee->kind == FUNC_KIND_NORMAL);
            jump_to = callee->body.text_start;
        }

        u32 jump_from = fixup->text_location + sizeof(i32);
        i32 jump_by = ((i32) jump_to) - ((i32) jump_from);
        *target = jump_by;
    }
    buf_free(context->call_fixups);
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
    u8* raw_lib_name = string_table_access(context->string_table, import->lib_name);
    u8* source_path = import->importing_source_file;
    u8* source_folder = path_get_folder(&context->arena, source_path);
    u8* path = path_join(&context->arena, source_folder, raw_lib_name);

    u8* file;
    u32 file_length;

    IO_Result read_result;

    read_result = read_entire_file(path, &file, &file_length);
    if (read_result == IO_NOT_FOUND) {
        // TODO TODO TODO This is a really big hack. We should check %LIB%
        // TODO TODO TODO This is a really big hack. We should check %LIB%
        // TODO TODO TODO This is a really big hack. We should check %LIB%
        // TODO TODO TODO This is a really big hack. We should check %LIB%

        //u8* system_lib_folder = "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.16299.0/um/x64";
        u8* system_lib_folder = "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.10240.0/um/x64";

        path = path_join(&context->arena, system_lib_folder, raw_lib_name);
        read_result = read_entire_file(path, &file, &file_length);
    }

    if (read_result != IO_OK) {
        printf("Couldn't open \"%s\": %s\n", path, io_result_message(read_result));
        return false;
    }


    if (file_length < 8 || !mem_cmp(file, "!<arch>\n", 8)) goto invalid;

    u8* cursor = file + 8;
    u32 cursor_length = file_length - 8;

    u8* symbol_data;
    u32 symbol_data_length;

    if (!read_archive_member_header(&cursor, &cursor_length, null, null)) goto invalid;
    if (!read_archive_member_header(&cursor, &cursor_length, &symbol_data, &symbol_data_length)) goto invalid;
    if (!read_archive_member_header(&cursor, &cursor_length, null, null)) goto invalid;

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

        u16 index = symbol_indices[s] - 1;
        s += 1;

        if (index >= archive_member_count) goto invalid;
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
    enum { MAX_SECTION_COUNT = 4 }; // So we can use it as an array length

    u64 text_length = buf_length(context->seg_text);
    u64 data_length = buf_length(context->seg_data);

    u32 section_count = 3;
    if (data_length > 0) section_count += 1;

    u64 in_file_alignment = 0x200;
    // NB If this becomes lower than the page size, stuff like page protection won't work anymore. That will also
    // disable address space layout randomization.
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

    u64 text_file_start  = header_space;
    u64 data_file_start  = text_file_start  + round_to_next(text_length,  in_file_alignment);
    u64 pdata_file_start = data_file_start  + round_to_next(data_length,  in_file_alignment);
    u64 idata_file_start = pdata_file_start + round_to_next(pdata_length, in_file_alignment);

    u64 text_memory_start  = round_to_next(total_header_size, in_memory_alignment);
    u64 data_memory_start  = text_memory_start  + round_to_next(text_length,  in_memory_alignment);
    u64 pdata_memory_start = data_memory_start  + round_to_next(data_length,  in_memory_alignment);
    u64 idata_memory_start = pdata_memory_start + round_to_next(pdata_length, in_memory_alignment);

    // Verify that fixups are not bogus data, so we don't have to do that later...
    buf_foreach (Fixup, fixup, context->fixups) {
        if (fixup->text_location >= text_length) {
            panic("Can't apply fixup at %x which is beyond end of text section at %x\n", fixup->text_location, text_length);
        }

        i32 text_value = *((u32*) (context->seg_text + fixup->text_location));
        if (text_value != 0xdeadbeef) {
            panic("All fixup override locations should be set to 0xdeadbeef as a sentinel. Found %x instead\n", text_value);
        }

        switch (fixup->kind) {
            case FIXUP_IMPORTED_FUNCTION: {
                u32 l = fixup->import_index.library;
                u32 f = fixup->import_index.function;

                assert(l < buf_length(context->imports));
                assert(f < buf_length(context->imports[l].function_names));
            } break;

            case FIXUP_DATA: {
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
        buf_foreach (Fixup, fixup, context->fixups) {
            if (fixup->kind != FIXUP_IMPORTED_FUNCTION || fixup->import_index.library != i) { continue; }

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
    buf_foreach (Fixup, fixup, context->fixups) {
        i32* text_value = (u32*) (context->seg_text + fixup->text_location);

        switch (fixup->kind) {
            case FIXUP_IMPORTED_FUNCTION: break;

            case FIXUP_DATA: {
                *text_value = data_memory_start + fixup->data_offset;
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

    if (data_length > 0) {
        Section_Header* data_header = &section_headers[section_index];
        section_index += 1;
        mem_copy(".data", data_header->name, 5);
        data_header->flags = SECTION_FLAGS_READ | SECTION_FLAGS_WRITE | SECTION_FLAGS_INITIALIZED_DATA;
        data_header->virtual_size = data_length;
        data_header->virtual_address = data_memory_start;
        data_header->size_of_raw_data = round_to_next(data_length, in_file_alignment);
        data_header->pointer_to_raw_data = data_file_start;
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

    // NB switching this disables address-space randomization, which might be nice for debugging
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
    image.size_of_initialized_data = data_length + idata_length + pdata_length;
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

    #if 0
    if (write_debug_info) {
        /*
        In test project
        debug_size = 38
        debug_offset = 984B0
        
        There, we find the following raw data
        characteristics     00 00 00 00
        timestamp           7E 56 1E 5B         (which is a valid unix timestamp, for about now, in little endian)
        major version       00 00
        minor version       00 00
        type                02 00 00 00         (visual c++ debug information)
        size of data        34 00 00 00         (not included in the debug directory itself) - What does this mean???
        rva of debug data   EC 8F 09 00
        file pointer data   EC CF 06 00
        more data           00 00 00 00 7E 56 1E 5B 00 00 (looks like the start of another debug directory, not sure if we should look at it)

        This points to the following raw data, which appears to contain a reference to the .pdb file
        "RSDS"                              52 53 44 53
        Some UUID                           99 B3 A7 A8 D4 BB C4 41 97 67 92 E3 93 6C 08 A7
        ????                                01 00 00 00
        "W:\asm2\debug_test\main.pdb\0"     57 3A 5C 61 73 6D 32 5C 64 65 62 75 67 5F 74 65 73 74 5C 6D 61 69 6E 2E 70 64 62 00
        */

        image.data_directories[6].virtual_address = rdata_memory_start + rdata_debug_offset;
        image.data_directories[6].size = debug_size;
    }
    #endif

    // Write headers
    u64 header_offset = dos_prepend_size;

    mem_copy((u8*) &coff, output_file + header_offset, sizeof(COFF_Header));
    header_offset += sizeof(COFF_Header);

    mem_copy((u8*) &image, output_file + header_offset, sizeof(Image_Header));
    header_offset += sizeof(Image_Header);

    mem_copy((u8*) section_headers, output_file + header_offset, section_count * sizeof(Section_Header));

    // Write data
    mem_copy(context->seg_text, output_file + text_file_start, text_length);
    mem_copy(context->seg_data, output_file + data_file_start, data_length);
    mem_copy(pdata, output_file + pdata_file_start, pdata_length);
    mem_copy(idata, output_file + idata_file_start, idata_length);

    IO_Result result = write_entire_file(path, output_file, file_image_size);
    if (result != IO_OK) {
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

        switch (func->kind) {
            case FUNC_KIND_NORMAL:
            {
                printf("    %u variables: ", (u64) func->body.var_count);
                for (u32 v = 0; v < func->body.var_count; v += 1) {
                    Var* var = &func->body.vars[v];
                    u8* name = string_table_access(context->string_table, var->name);

                    if (v > 0) printf(",");
                    printf("%s: ", name);
                    print_type(context, var->type);
                }
                printf("\n");

                printf("    Statements:\n");
                for (Stmt *stmt = func->body.first_stmt; stmt->kind != STMT_END; stmt = stmt->next) {
                    print_stmt(context, func, stmt, 2);
                }
            } break;

            case FUNC_KIND_IMPORTED: {
                printf("    (Imported)\n");
            } break;
        }
    }
}

bool build_file_to_executable(u8* source_path, u8* exe_path) {
    Context context = {0};

    if (!build_ast(&context, source_path)) return false;
    if (!typecheck(&context)) return false;
    //print_verbose_info(&context);
    build_machinecode(&context);
    if (!write_executable(exe_path, &context)) return false;

    printf("Generated %u bytes of machine code\n", buf_length(context.seg_text));

    return true;
}

bool run_executable(u8* exe_path) {
    Startup_Info startup_info = {0};
    startup_info.size = sizeof(Startup_Info);
    Process_Info process_info = {0};
    bool result = CreateProcessA(exe_path, "", null, null, false, 0, null, null, &startup_info, &process_info);
    if (!result) {
        printf("Failed to start generated executable\n");
        return false;
    }

    WaitForSingleObject(process_info.process, U32_MAX);

    return true;
}

void compile_and_run(u8 *source_path, u8 *exe_path, i64 *compile_time, i64 *run_time) {
    i64 start_time, middle_time, end_time;
    start_time = perf_time();

    printf("    Compiling %s to %s\n", source_path, exe_path);
    if (build_file_to_executable(source_path, exe_path)) {
        middle_time = perf_time();
        printf("    Running %s:\n", exe_path);
        run_executable(exe_path);
        end_time = perf_time();
    } else {
        middle_time = end_time = perf_time();
    }

    *compile_time = (middle_time - start_time) * 1000 / perf_frequency;
    *run_time = (end_time - middle_time) * 1000 / perf_frequency;
}


void main() {
    i64 compile_time, run_time;

    compile_and_run("W:/compiler/src/minimal.foo", "build/minimal_out.exe", &compile_time, &run_time);
    //compile_and_run("W:/compiler/src/code.foo", "build/foo_out.exe", &compile_time, &run_time);
    //compile_and_run("W:/compiler/src/link_test/backend.foo", "W:/compiler/src/link_test/build/out.exe", &compile_time, &run_time);
    //compile_and_run("W:/compiler/src/glfw_test/main.foo", "W:/compiler/src/glfw_test/out.exe", &compile_time, &run_time);

    printf("Compiled in %i ms, ran in %i ms\n", compile_time, run_time);
}
