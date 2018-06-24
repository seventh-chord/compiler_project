
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
#define I32_MAX 2147483647
#define I32_MIN -2147483648

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

enum Type_Kind (u8) {
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
            case 2:  return io_not_found; // File not found
            case 3:  return io_not_found; // Path not found
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
    u8* file_name;
    u32 line;
} File_Pos;

enum { KEYWORD_COUNT = 15 };

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
        token_dot       = '.',
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

        token_static_access, // "::"

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
        token_literal_int,
        token_literal_float,
        token_string,

        token_keyword_fn,
        token_keyword_extern,
        token_keyword_let,
        token_keyword_if,
        token_keyword_else,
        token_keyword_for,
        token_keyword_return,
        token_keyword_continue,
        token_keyword_break,
        token_keyword_struct,
        token_keyword_enum,
        token_keyword_union,
        token_keyword_null,
        token_keyword_true,
        token_keyword_false,

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
    [token_identifier] = null,
    [token_literal_int] = null,
    [token_literal_float] = null,
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

    [token_dot]                  = "a dot '.'",
    [token_semicolon]            = "a semicolon ';'",
    [token_comma]                = "a comma ','",
    [token_colon]                = "a colon ':'",
    [token_static_access]        = "::",

    [token_bracket_round_open]   = "an opening parenthesis '('",
    [token_bracket_round_close]  = "a closing parenthesis ')'",
    [token_bracket_square_open]  = "an opening square bracket '['",
    [token_bracket_square_close] = "a closing square bracket ']'",
    [token_bracket_curly_open]   = "an opening curly brace '{'",
    [token_bracket_curly_close]  = "a closing curly brace '}'",

    [token_keyword_fn]           = "fn",
    [token_keyword_extern]       = "extern",
    [token_keyword_let]          = "let",
    [token_keyword_if]           = "if",
    [token_keyword_else]         = "else",
    [token_keyword_for]          = "for",
    [token_keyword_return]       = "return",
    [token_keyword_continue]     = "continue",
    [token_keyword_break]        = "break",
    [token_keyword_struct]       = "struct",
    [token_keyword_enum]         = "enum",
    [token_keyword_union]        = "union",
    [token_keyword_true]         = "true",
    [token_keyword_false]        = "false",
    [token_keyword_null]         = "null",
};


typedef enum Builtin_Func {
    builtin_invalid = 0,

    builtin_type_info_of_type,
    builtin_type_info_of_value,
    builtin_enum_member_name,
    builtin_enum_length,
    builtin_cast,

    BUILTIN_COUNT,
} Builtin_Func;


// NB NB NB This MUST always be synchronized with the values in preload.foo
typedef enum Type_Kind {
    type_invalid = 0,
    type_void = 1,
    type_bool = 2,

    type_u8  = 4,
    type_u16 = 5,
    type_u32 = 6,
    type_u64 = 7,
    type_i8  = 8,
    type_i16 = 9,
    type_i32 = 10,
    type_i64 = 11,

    type_f32 = 13,
    type_f64 = 14,

    type_pointer = 15,
    type_array = 16,
    type_unresolved_name = 17,
    type_struct = 18,
    type_enum = 19,

    TYPE_KIND_COUNT = 20,
} Type_Kind;

enum { POINTER_SIZE = 8 };
Type_Kind DEFAULT_INT_TYPE = type_u64; // TODO make this type_i64
Type_Kind DEFAULT_FLOAT_TYPE   = type_f32;

u8* PRIMITIVE_NAMES[TYPE_KIND_COUNT] = {
    [type_void] = "void",
    [type_bool] = "bool",

    [type_u8]  = "u8",
    [type_u16] = "u16",
    [type_u32] = "u32",
    [type_u64] = "u64",
    [type_i8]  = "i8",
    [type_i16] = "i16",
    [type_i32] = "i32",
    [type_i64] = "i64",

    [type_f32] = "f32",
    [type_f64] = "f64",

    [type_invalid]          = "<invalid>",
    [type_pointer]          = "<pointer>",
    [type_array]            = "<array>",

    [type_unresolved_name]  = "<unresolved>",
    [type_struct]           = "<struct>",
    [type_enum]             = "<enum>",
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
                u64 offset;
                File_Pos declaration_pos;
            } *members;

            u64 size, align;
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
    [binary_sub] = true, [binary_div] = true, [binary_mod] = true,
    [binary_mul] = false, [binary_add] = false,
    [binary_neq] = false, [binary_eq] = false, [binary_gt] = false, [binary_gteq] = false, [binary_lt] = false, [binary_lteq] = false,
};

bool BINARY_OP_COMPARATIVE[BINARY_OP_COUNT] = {
    [binary_sub] = false, [binary_div] = false, [binary_mod] = false, [binary_mul] = false, [binary_add] = false,
    [binary_neq] = true, [binary_eq] = true, [binary_gt] = true, [binary_gteq] = true, [binary_lt] = true, [binary_lteq] = true,
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


typedef struct Compound_Member {
    Expr* expr;

    enum {
        expr_compound_no_name,
        expr_compound_unresolved_name,
        expr_compound_name
    } name_mode;

    union {
        u32 unresolved_name;
        u32 member_index;
    };
} Compound_Member;

#define EXPR_FLAG_UNRESOLVED 0x01
#define EXPR_FLAG_ASSIGNABLE 0x02

typedef enum Expr_Kind {
    expr_variable,
    expr_literal,
    expr_string_literal,
    expr_compound,
    expr_binary,
    expr_unary,
    expr_call,
    expr_cast,
    expr_subscript,
    expr_member_access, // a.b
    expr_static_member_access, // a::b

    expr_type_info_of_type,
    expr_type_info_of_value,
    expr_enum_length,
    expr_enum_member_name,
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
                expr_literal_integer,
                expr_literal_pointer,
                expr_literal_bool,
                expr_literal_float, // 'value' is the bitpattern of a 'f64'
            } kind;
        } literal;

        struct {
            u8* bytes; // null-terminated
            u64 length;
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
        stmt_end = 0, // Sentinel, returned to mark that no more statements can be parsed

        stmt_declaration,
        stmt_expr,
        stmt_assignment,

        stmt_block,
        stmt_if,
        stmt_loop,

        stmt_return,
        stmt_break,
        stmt_continue,
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

        Stmt* block;

        struct {
            Expr* condition;
            Stmt* then;
            Stmt* else_then;
        } conditional;

        struct {
            Expr* condition;
            Stmt* body;
        } loop;

        Expr* return_value;
    };

    File_Pos pos;

    Stmt* next;
};


typedef enum Condition {
    condition_e, condition_ne,

    // Signed
    condition_g, condition_ge,
    condition_l, condition_le,

    // Unsigned
    condition_a, condition_ae,
    condition_b, condition_be,

    CONDITION_COUNT,
} Condition;

u8* CONDITION_NAMES[CONDITION_COUNT] = {
    [condition_e]   = "==",
    [condition_ne]  = "!=",
    [condition_g]   = "> (signed)",
    [condition_ge]  = ">= (signed)",
    [condition_l]   = "< (signed)",
    [condition_le]  = "<= (signed)",
    [condition_a]   = "> (unsigned)",
    [condition_ae]  = ">= (unsigned)",
    [condition_b]   = "< (unsigned)",
    [condition_be]  = "<= (unsigned)",
};

u8* CONDITION_POSTFIXES[CONDITION_COUNT] = {
    [condition_e]   = "e",
    [condition_ne]  = "ne",
    [condition_g]   = "g",
    [condition_ge]  = "ge",
    [condition_l]   = "l",
    [condition_le]  = "le",
    [condition_a]   = "a",
    [condition_ae]  = "ae",
    [condition_b]   = "b",
    [condition_le]  = "be",
};

Condition condition_not(Condition c) {
    switch (c) {
        case condition_e:  return condition_ne;
        case condition_ne: return condition_e;
        case condition_g:  return condition_le;
        case condition_ge: return condition_l;
        case condition_l:  return condition_ge;
        case condition_le: return condition_g;
        case condition_a:  return condition_be;
        case condition_ae: return condition_b;
        case condition_b:  return condition_ae;
        case condition_be: return condition_a;
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
    bool builtin;
    u32 func_index;
} Call_Fixup;


typedef struct Func {
    u32 name;
    File_Pos declaration_pos;

    enum {
        func_kind_normal, // use '.body'
        func_kind_imported, // use '.import_info'
    } kind;

    struct {
        bool has_output;
        Type* output_type;

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
            u32 output_var_index;

            Stmt* first_stmt;

            u32 text_start;
        } body;
    };
} Func;


typedef struct Context {
    Arena arena, stack; // arena is for permanent storage, stack for temporary

    u8* string_table; // stretchy-buffer string table
    u32 keyword_token_table[KEYWORD_COUNT][2];
    u32 builtin_names[BUILTIN_COUNT];

    // AST & intermediate representation
    Func* funcs; // stretchy-buffer
    Type primitive_types[TYPE_KIND_COUNT];
    Type *void_pointer_type, *string_type, *type_info_type;
    Type **user_types; // stretchy-buffer

    // These are only for temporary use, we copy to arena buffers & clear
    Global_Var* global_vars;
    Var* tmp_vars; // stretchy-buffer

    // Low level representation
    u8* seg_text; // stretchy-buffer
    u8* seg_data; // stretchy-buffer
    Fixup* fixups; // stretchy-buffer

    Library_Import* imports; // stretchy-buffer
    Call_Fixup* call_fixups; // stretchy-buffer
} Context;



Type* get_pointer_type(Context* context, Type* type) {
    if (type->pointer_type == null) {
        type->pointer_type = arena_new(&context->arena, Type);
        type->pointer_type->kind = type_pointer;
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

    new->type.kind = type_array;
    new->type.array.length = length;
    new->type.array.of = type;

    if (type->flags & TYPE_FLAG_UNRESOLVED) {
        new->type.flags = TYPE_FLAG_UNRESOLVED;
    }

    return &new->type;
}

void init_primitive_types(Context* context) {
    #define init_primitive(kind) context->primitive_types[kind] = (Type) { kind, .primitive_name = string_table_intern_cstr(&context->string_table, PRIMITIVE_NAMES[kind]) };

    init_primitive(type_invalid);
    init_primitive(type_void);
    init_primitive(type_bool);
    init_primitive(type_u8);
    init_primitive(type_u16);
    init_primitive(type_u32);
    init_primitive(type_u64);
    init_primitive(type_i8);
    init_primitive(type_i16);
    init_primitive(type_i32);
    init_primitive(type_i64);
    init_primitive(type_f32);
    init_primitive(type_f64);

    #undef init_primitives

    context->void_pointer_type = get_pointer_type(context, &context->primitive_types[type_void]);
    context->string_type = get_pointer_type(context, &context->primitive_types[type_u8]);
}

void init_builtin_func_names(Context* context) {
    context->builtin_names[builtin_type_info_of_type]  = string_table_intern_cstr(&context->string_table, "type_info_of_type");
    context->builtin_names[builtin_type_info_of_value] = string_table_intern_cstr(&context->string_table, "type_info_of_value");
    context->builtin_names[builtin_enum_member_name]   = string_table_intern_cstr(&context->string_table, "enum_member_name");
    context->builtin_names[builtin_enum_length]        = string_table_intern_cstr(&context->string_table, "enum_length");
    context->builtin_names[builtin_cast]               = string_table_intern_cstr(&context->string_table, "cast");
}

void init_keyword_names(Context* context) {
    u32 i = 0;

    #define add_keyword(token, name) \
    context->keyword_token_table[i][0] = token; \
    context->keyword_token_table[i][1] = string_table_intern_cstr(&context->string_table, name); \
    i += 1;

    add_keyword(token_keyword_fn,       "fn");
    add_keyword(token_keyword_extern,   "extern");
    add_keyword(token_keyword_let,      "let");
    add_keyword(token_keyword_if,       "if");
    add_keyword(token_keyword_else,     "else");
    add_keyword(token_keyword_for,      "for");
    add_keyword(token_keyword_return,   "return");
    add_keyword(token_keyword_continue, "continue");
    add_keyword(token_keyword_break,    "break");
    add_keyword(token_keyword_struct,   "struct");
    add_keyword(token_keyword_enum,     "enum");
    add_keyword(token_keyword_union,    "union");
    add_keyword(token_keyword_null,     "null");
    add_keyword(token_keyword_true,     "true");
    add_keyword(token_keyword_false,    "false");

    #undef add_keyword
}

Condition find_condition_for_op_and_type(Binary_Op op, Type_Kind type) {
    if (primitive_is_signed(type)) {
        switch (op) {
            case binary_eq:   return condition_e;
            case binary_neq:  return condition_ne;
            case binary_gt:   return condition_g;
            case binary_gteq: return condition_ge;
            case binary_lt:   return condition_l;
            case binary_lteq: return condition_le;
            default: assert(false);
        }
    } else {
        switch (op) {
            case binary_eq:   return condition_e;
            case binary_neq:  return condition_ne;
            case binary_gt:   return condition_a;
            case binary_gteq: return condition_ae;
            case binary_lt:   return condition_l;
            case binary_lteq: return condition_le;
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
            case type_pointer: {
                a = a->pointer_to;
                b = b->pointer_to;
                if (a->kind == type_array) a = a->array.of;
                if (b->kind == type_array) b = b->array.of;
            } break;

            case type_array: {
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
        case type_bool: return 1;
        case type_void: return 0;
        case type_u8:  return 1;
        case type_u16: return 2;
        case type_u32: return 4;
        case type_u64: return 8;
        case type_i8:  return 1;
        case type_i16: return 2;
        case type_i32: return 4;
        case type_i64: return 8;
        case type_f32: return 4;
        case type_f64: return 8;
        case type_pointer: return POINTER_SIZE;
        case type_invalid: assert(false); return 0;
        case type_array: assert(false); return 0;
        case type_struct: assert(false); return 0;
        case type_enum: assert(false); return 0;
        default: assert(false); return 0;
    }
}

u8* compound_member_name(Context* context, Expr* expr, Compound_Member* member) {
    u32 name_index;
    switch (member->name_mode) {
        case expr_compound_name: {
            assert(expr->type->kind == type_struct);
            u32 member_index = member->member_index;
            name_index = expr->type->structure.members[member_index].name;
        } break;

        case expr_compound_unresolved_name: {
            name_index = member->unresolved_name;
        } break;

        case expr_compound_no_name: {
            return null;
        } break;

        default: assert(false);
    }
    return string_table_access(context->string_table, name_index);
}

u64 type_size_of(Type* type) {
    u64 array_multiplier = 1;

    while (true) {
        if (type->kind == type_array) {
            array_multiplier *= type->array.length;
            type = type->array.of;

        } else {
            assert(!(type->flags & TYPE_FLAG_SIZE_NOT_COMPUTED));

            u64 base_size;
            switch (type->kind) {
                case type_struct: base_size = type->structure.size; break;
                case type_enum:   base_size = primitive_size_of(type->enumeration.value_primitive); break;
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
        if (type->kind == type_array) {
            type = type->array.of;
        } else {
            assert(!(type->flags & TYPE_FLAG_SIZE_NOT_COMPUTED));

            if (type->kind == type_struct) {
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
        case type_struct: name = type->structure.name; break;
        case type_enum:   name = type->enumeration.name; break;
        default: assert(false);
    }
    return name;
}
 
Type_Kind primitive_of(Type* type) {
    if (type->kind == type_enum) {
        return type->enumeration.value_primitive;
    } else {
        return type->kind;
    }
}

bool primitive_is_compound(Type_Kind primitive) {
    switch (primitive) {
        case type_array: return true;
        case type_struct: return true;

        case type_u8:  return false;
        case type_u16: return false;
        case type_u32: return false;
        case type_u64: return false;
        case type_i8:  return false;
        case type_i16: return false;
        case type_i32: return false;
        case type_i64: return false;
        case type_f32: return false;
        case type_f64: return false;
        case type_bool: return false;
        case type_void: return false;
        case type_enum: return false;
        case type_pointer: return false;
        case type_invalid: assert(false); return false;
        case type_unresolved_name: assert(false); return false;

        default: assert(false); return false;
    }
}

bool primitive_is_integer(Type_Kind primitive) {
    switch (primitive) {
        case type_u8: case type_u16: case type_u32: case type_u64:
        case type_i8: case type_i16: case type_i32: case type_i64:
            return true;
        default: return false;
    }
}

bool primitive_is_float(Type_Kind primitive) {
    switch (primitive) {
        case type_f32: case type_f64: return true;
        default: return false;
    }
}

bool primitive_is_signed(Type_Kind primitive) {
    switch (primitive) {
        case type_i8: case type_i16: case type_i32: case type_i64: return true;
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
            case type_pointer: {
                printf("*");
                type = type->pointer_to;
            } break;

            case type_array: {
                printf("[%u]", type->array.length);
                type = type->array.of;
            } break;

            case type_struct: {
                u8* name = string_table_access(context->string_table, type->structure.name);
                printf(name);
                type = null;
            } break;

            case type_enum: {
                u8* name = string_table_access(context->string_table, type->enumeration.name);
                printf(name);
                type = null;
            } break;

            case type_unresolved_name: {
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
        case token_identifier: {
            u32 index = t->identifier_string_table_index;
            printf("'%s'", string_table_access(string_table, index));
        } break;
        case token_string: {
            printf("\"%z\"", t->string.length, t->string.bytes);
        } break;

        case token_literal_int:   printf("%u", t->literal_int); break;
        case token_literal_float: printf("%f", t->literal_float); break;

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

                if (var != null) {
                    u8* name = string_table_access(context->string_table, var->name);
                    printf("%s", name);
                }
            }
        } break;

        case expr_literal: {
            switch (expr->literal.kind) {
                case expr_literal_integer: {
                    printf("%u", expr->literal.masked_value);
                } break;
                case expr_literal_pointer: {
                    if (expr->literal.masked_value == 0) {
                        printf("null");
                    } else {
                        printf("%x", expr->literal.masked_value);
                    }
                } break;
                case expr_literal_bool: {
                    assert(expr->literal.masked_value == true || expr->literal.masked_value == false);
                    printf(expr->literal.masked_value? "true" : "false");
                } break;
                default: assert(false);
            }
        } break;

        case expr_compound: {
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
            for (u32 i = 0; i < expr->call.param_count; i += 1) {
                if (i > 0) printf(", ");
                Expr* child = expr->call.params[i];
                print_expr(context, func, child);
            }
            printf(")");
        } break;

        case expr_cast: {
            print_type(context, expr->type);
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

        case expr_member_access: {
            print_expr(context, func, expr->member_access.parent);
            printf(".");
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u8* name = string_table_access(context->string_table, expr->member_access.member_name);
                printf("<unresolved %s>", name);
            } else {
                Type* s = expr->member_access.parent->type;
                if (s->kind == type_pointer) {
                    s = s->pointer_to;
                }
                assert(s->kind == type_struct);

                u32 name_index = s->structure.members[expr->member_access.member_index].name;
                u8* name = string_table_access(context->string_table, name_index);
                printf(name);
            }
        } break;

        case expr_static_member_access: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u8* parent_name = string_table_access(context->string_table, expr->static_member_access.parent_name);
                u8* member_name = string_table_access(context->string_table, expr->static_member_access.member_name);
                printf("<unresolved %s::%s>", parent_name, member_name);
            } else {
                Type* parent = expr->static_member_access.parent_type;
                assert(parent->kind == type_enum);

                u8* parent_name = string_table_access(context->string_table, parent->enumeration.name);

                u32 m = expr->static_member_access.member_index;
                u32 member_name_index = parent->enumeration.members[m].name;
                u8* member_name = string_table_access(context->string_table, member_name_index);
                printf("%s::%s", parent_name, member_name);
            }

        } break;

        case expr_type_info_of_type: {
            printf("type_info_of_type(");
            print_type(context, expr->type_info_of_type);
            printf(")");
        } break;

        case expr_type_info_of_value: {
            printf("type_info_of_value(");
            print_expr(context, func, expr->type_info_of_value);
            printf(")");
        } break;

        case expr_enum_length: {
            printf("enum_length(");
            print_type(context, expr->enum_length_of);
            printf(")");
        } break;

        case expr_enum_member_name: {
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
            printf("let %s: ", name);

            print_type(context, var->type);

            if (stmt->declaration.right != null) {
                printf(" = ");
                print_expr(context, func, stmt->declaration.right);
            }

            printf(";");
        } break;

        case stmt_block: {
            printf("{\n");

            for (Stmt *inner = stmt->block; inner->kind != stmt_end; inner = inner->next) {
                print_stmt(context, func, inner, indent_level + 1);
            }

            for (u32 i = 0; i < indent_level; i += 1) printf("    ");
            printf("}");
        } break;

        case stmt_if: {
            printf("if (");
            print_expr(context, func, stmt->conditional.condition);
            printf(") {\n");

            for (Stmt *inner = stmt->conditional.then; inner->kind != stmt_end; inner = inner->next) {
                print_stmt(context, func, inner, indent_level + 1);
            }

            for (u32 i = 0; i < indent_level; i += 1) printf("    ");
            printf("}");

            if (stmt->conditional.else_then != null) {
                printf(" else {\n");

                for (Stmt *inner = stmt->conditional.else_then; inner->kind != stmt_end; inner = inner->next) {
                    print_stmt(context, func, inner, indent_level + 1);
                }

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

            for (Stmt *inner = stmt->loop.body; inner->kind != stmt_end; inner = inner->next) {
                print_stmt(context, func, inner, indent_level + 1);
            }

            for (u32 i = 0; i < indent_level; i += 1) printf("    ");
            printf("}");
        } break;

        case stmt_return: {
            if (stmt->return_value != null) {
                printf("return ");
                print_expr(context, func, stmt->return_value);
                printf(";");
            } else {
                printf("return;");
            }
        } break;

        case stmt_continue: printf("continue;"); break;
        case stmt_break:    printf("break;"); break;

        case stmt_end: printf("<end>"); break;

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

    return builtin_invalid;
}

Type* parse_user_type_name(Context* context, u32 name_index) {
    buf_foreach (Type*, user_type, context->user_types) {
        u32 user_type_name = 0;
        switch ((*user_type)->kind) {
            case type_struct: {
                user_type_name = (*user_type)->structure.name;
            } break;
            case type_enum: {
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
        enum { prefix_pointer, prefix_array } kind;
        u64 array_length;
        Prefix* link;
    };
    Prefix* prefix = null;

    arena_stack_push(&context->stack);

    Type* base_type = null;
    while (base_type == null) {
        switch (t->kind) {
            case token_identifier: {
                base_type = parse_primitive_name(context, t->identifier_string_table_index);

                if (base_type == null) {
                    base_type = parse_user_type_name(context, t->identifier_string_table_index);
                }

                if (base_type == null) {
                    base_type = arena_new(&context->arena, Type);
                    base_type->kind = type_unresolved_name;
                    base_type->unresolved_name = t->identifier_string_table_index;
                    base_type->flags |= TYPE_FLAG_UNRESOLVED;
                }

                t += 1;
            } break;

            case token_bracket_square_open: {
                t += 1;

                if (t->kind != token_literal_int) {
                    print_file_pos(&t->pos);
                    printf("Expected array size, but got ");
                    print_token(context->string_table, t);
                    printf("\n");
                    *length = t - t_start;
                    return null;
                }
                u64 array_length = t->literal_int;
                t += 1;

                if (!expect_single_token(context, t, token_bracket_square_close, "after array size")) {
                    *length = t - t_start;
                    return null;
                }
                t += 1;

                Prefix* new = arena_new(&context->stack, Prefix);
                new->kind = prefix_array;
                new->array_length = array_length;
                new->link = prefix;
                prefix = new;
            }  break;

            case token_mul: {
                t += 1;

                Prefix* new = arena_new(&context->stack, Prefix);
                new->kind = prefix_pointer;
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
            case prefix_pointer: type = get_pointer_type(context, type); break;
            case prefix_array:   type = get_array_type(context, type, prefix->array_length); break;
        }
        prefix = prefix->link;
    }

    arena_stack_pop(&context->stack);

    *length = t - t_start;
    return type;
}

Type* parse_struct_declaration(Context* context, Token* t, u32* length) {
    Token* t_start = t;

    assert(t->kind == token_keyword_struct);
    t += 1;

    Type* type = arena_new(&context->arena, Type);
    type->kind = type_struct;

    if (t->kind != token_identifier) {
        print_file_pos(&t->pos);
        printf("Expected struct name, but got ");
        print_token(context->string_table, t);
        printf("\n");
        return null;
    }
    type->structure.name = t->identifier_string_table_index;
    t += 1;

    if (!expect_single_token(context, t, token_bracket_curly_open, "after struct name")) return null;
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

    while (t->kind != token_bracket_curly_close) {
        u32 names_given = 0;
        while (true) {
            if (t->kind != token_identifier) {
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

            if (t->kind == token_comma) {
                t += 1;
                continue;
            } else {
                break;
            }
        }

        if (!expect_single_token(context, t, token_colon, names_given > 1? "after member names" : "after member name")) return null;
        t += 1;

        u32 type_length = 0;
        Type* member_type = parse_type(context, t, &type_length);
        t += type_length;
        if (member_type == null) return null;

        if (!expect_single_token(context, t, token_semicolon, "after member declaration")) return null;

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

    assert(t->kind == token_keyword_enum);
    t += 1;

    Type* type = arena_new(&context->arena, Type);
    type->kind = type_enum;
    type->enumeration.name_table_data_offset = U64_MAX;

    if (t->kind != token_identifier) {
        print_file_pos(&t->pos);
        printf("Expected enum name, but got ");
        print_token(context->string_table, t);
        printf("\n");
        *length = t - t_start;
        return null;
    }
    type->enumeration.name = t->identifier_string_table_index;
    t += 1;

    if (t->kind == token_bracket_round_open) {
        t += 1;
        File_Pos type_start_pos = t->pos;

        if (t->kind != token_identifier) {
            print_file_pos(&type_start_pos);
            printf("Expected primitive name, but got ");
            print_token(context->string_table, t);
            printf("\n");
            *length = t - t_start;
            return null;
        }
        u32 type_name_index = t->identifier_string_table_index;
        t += 1;

        if (!expect_single_token(context, t, token_bracket_round_close, "after enum primitive")) {
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
        type->enumeration.value_primitive = type_u32;
    }

    if (!expect_single_token(context, t, token_bracket_curly_open, "after enum name/type")) {
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

    while (t->kind != token_bracket_curly_close) {
        if (t->kind != token_identifier) {
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

        if (t->kind == token_assign) {
            t += 1;

            if (t->kind != token_literal_int) {
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

        if (t->kind != token_bracket_curly_close) {
            if (t->kind == token_comma) {
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
        if ((*array)->kind == expr_unary) {
            array = &((*array)->unary.inner);
        } else {
            break;
        }
    }

    Expr* expr = arena_new(&context->arena, Expr);
    expr->kind = expr_subscript;
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
        if ((*structure)->kind == expr_unary) {
            structure = &((*structure)->unary.inner);
        } else {
            break;
        }
    }

    Expr* expr = arena_new(&context->arena, Expr);
    expr->kind = expr_member_access;
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
    expr->kind = expr_binary;

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
                case token_identifier: {
                    File_Pos start_pos = t->pos;

                    u32 name_index = t->identifier_string_table_index;

                    switch ((t + 1)->kind) {
                        // Some call (either a function or a builtin)
                        case token_bracket_round_open: {
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
                        case token_bracket_curly_open: {
                            File_Pos start_pos = t->pos;

                            Type* type = parse_user_type_name(context, t->identifier_string_table_index);
                            if (type == null) {
                                type = arena_new(&context->arena, Type);
                                type->kind = type_unresolved_name;
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

                        case token_static_access: {
                            File_Pos start_pos = t->pos;
                            t += 2;

                            if (t->kind != token_identifier) {
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
                            expr->kind = expr_static_member_access;
                            expr->static_member_access.parent_name = name_index;;
                            expr->static_member_access.member_name = member_name_index;;
                            expr->flags |= EXPR_FLAG_UNRESOLVED;
                            expr->pos = start_pos;

                            shunting_yard_push_expr(context, yard, expr);
                        } break;

                        default: {
                            Expr* expr = arena_new(&context->arena, Expr);
                            expr->kind = expr_variable;
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

                case token_literal_int:
                case token_literal_float:
                case token_keyword_null:
                case token_keyword_true:
                case token_keyword_false:
                {
                    Expr* expr = arena_new(&context->arena, Expr);
                    expr->kind = expr_literal;
                    expr->literal.kind = expr_literal_pointer;
                    expr->pos = t->pos;

                    switch (t->kind) {
                        case token_literal_int: {
                            expr->literal.raw_value = t->literal_int;
                            expr->literal.kind = expr_literal_integer;
                        } break;

                        case token_literal_float: {
                            expr->literal.raw_value = *((u64*) &t->literal_float);
                            expr->literal.kind = expr_literal_float;
                        } break;

                        case token_keyword_null: {
                            expr->literal.raw_value = 0;
                            expr->literal.kind = expr_literal_pointer;
                        } break;

                        case token_keyword_false: {
                            expr->literal.raw_value = 0;
                            expr->literal.kind = expr_literal_bool;
                        } break;

                        case token_keyword_true: {
                            expr->literal.raw_value = 1;
                            expr->literal.kind = expr_literal_bool;
                        } break;

                        default: assert(false);
                    }

                    expr->literal.masked_value = expr->literal.raw_value;

                    shunting_yard_push_expr(context, yard, expr);

                    t += 1;
                    could_parse = true;
                    expect_value = false;
                } break;

                case token_string: {
                    Expr* expr = arena_new(&context->arena, Expr);
                    expr->type = context->string_type;
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

                // Array literal, or untyped compound literals
                case token_bracket_curly_open:
                case token_bracket_square_open:
                {
                    Type* type = null;
                    if (t->kind == token_bracket_square_open) {
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
                        t += 1;
                    }
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

                case token_dot: {
                    t += 1;

                    if (t->kind != token_identifier) {
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

    if (!expect_single_token(context, t, token_bracket_curly_open, "after type of array literal")) {
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

    while (t->kind != token_bracket_curly_close) {
        u32 name_index = U32_MAX;
        if (t->kind == token_identifier && (t + 1)->kind == token_colon) {
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

        if (t->kind != token_bracket_curly_close) {
            if (t->kind != token_comma) {
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

    if (!expect_single_token(context, t, token_bracket_curly_close, "to close array literal")) {
        *length = t - t_start;
        return null;
    }
    t += 1;

    Expr* expr = arena_new(&context->arena, Expr);
    expr->kind = expr_compound;
    expr->pos = t_start->pos;

    expr->compound.count = member_count;
    expr->compound.content = (void*) arena_alloc(&context->arena, member_count * sizeof(Compound_Member));

    Member_Expr* p = first_member;
    for (u32 i = 0; i < member_count; i += 1, p = p->next) {
        Compound_Member* member = &expr->compound.content[i];
        member->expr = p->expr;

        if (p->name_index == U32_MAX) {
            member->name_mode = expr_compound_no_name;
        } else {
            member->unresolved_name = p->name_index;
            member->name_mode = expr_compound_unresolved_name;
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
    assert(t->kind == token_identifier);
    u32 name_index = t->identifier_string_table_index;

    Token* t_start = t;
    File_Pos start_pos = t->pos;

    t += 1;
    assert(t->kind == token_bracket_round_open);
    t += 1;

    switch (parse_builtin_func_name(context, name_index)) {
        case builtin_type_info_of_type: {
            u32 type_length = 0;
            Type* type = parse_type(context, t, &type_length);
            t += type_length;

            if (type == null) {
                *length = t - t_start;
                return null;
            }

            if (!expect_single_token(context, t, token_bracket_round_close, "after type in 'type_info_of_type'")) {
                *length = t - t_start;
                return null;
            }
            t += 1;

            Expr* expr = arena_new(&context->arena, Expr);
            expr->pos = start_pos;
            expr->kind = expr_type_info_of_type;
            expr->type_info_of_type = type;
            expr->type = context->type_info_type;

            *length = t - t_start;
            return expr;
        } break;

        case builtin_type_info_of_value: {
            u32 inner_length = 0;
            Expr* inner = parse_expr(context, t, &inner_length);
            t += inner_length;

            if (inner == null) {
                *length = t - t_start;
                return null;
            }

            if (!expect_single_token(context, t, token_bracket_round_close, "after type in 'type_info_of_value'")) {
                *length = t - t_start;
                return null;
            }
            t += 1;

            Expr* expr = arena_new(&context->arena, Expr);
            expr->pos = start_pos;
            expr->kind = expr_type_info_of_value;
            expr->type_info_of_value = inner;
            expr->type = context->type_info_type;

            *length = t - t_start;
            return expr;
        } break;

        case builtin_enum_length: {
            u32 type_length = 0;
            Type* type = parse_type(context, t, &type_length);
            t += type_length;

            if (type == null) {
                *length = t - t_start;
                return null;
            }

            if (!expect_single_token(context, t, token_bracket_round_close, "after type in 'enum_length'")) {
                *length = t - t_start;
                return null;
            }
            t += 1;

            Expr* expr = arena_new(&context->arena, Expr);
            expr->pos = start_pos;
            expr->kind = expr_enum_length;
            expr->enum_length_of = type;
            expr->type = &context->primitive_types[type_u64];

            *length = t - t_start;
            return expr;
        } break;

        case builtin_enum_member_name: {
            u32 inner_expr_length = 0;
            Expr* inner = parse_expr(context, t, &inner_expr_length);
            t += inner_expr_length;

            if (inner == null) {
                *length = t - t_start;
                return null;
            }

            if (!expect_single_token(context, t, token_bracket_round_close, "after type in 'enum_member_name'")) {
                *length = t - t_start;
                return null;
            }
            t += 1;

            Expr* expr = arena_new(&context->arena, Expr);
            expr->pos = start_pos;
            expr->kind = expr_enum_member_name;
            expr->enum_member = inner;
            expr->type = context->string_type;

            *length = t - t_start;
            return expr;
        } break;

        case builtin_cast: {
            u32 type_length = 0;
            Type* cast_to = parse_type(context, t, &type_length);
            t += type_length;

            if (cast_to == null) {
                *length = t - t_start;
                return null;
            }

            if (!expect_single_token(context, t, token_comma, "after type in cast")) {
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

            if (!expect_single_token(context, t, token_bracket_round_close, "after cast")) {
                *length = t - t_start;
                return null;
            }
            t += 1;

            Expr* expr = arena_new(&context->arena, Expr);
            expr->pos = start_pos;
            expr->kind = expr_cast;
            expr->cast_from = cast_from;
            expr->type = cast_to;

            *length = t - t_start;
            return expr;
        } break;

        // A normal function call or a simple cast
        case builtin_invalid: {
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
                expr->kind = expr_cast;
                expr->cast_from = params[0];
                expr->type = cast_to_primitive;

                *length = t - t_start;
                return expr;
            } else {
                Expr* expr = arena_new(&context->arena, Expr);
                expr->pos = start_pos;
                expr->kind = expr_call;
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
        while (t->kind == token_semicolon) {
            t += 1;
            continue;
        }

        Token* t_start = t;
        stmt->pos = t->pos;

        switch (t->kind) {
            case token_bracket_curly_close: {
                stmt->kind = stmt_end;
            } break;

            case token_bracket_curly_open: {
                u32 block_length = 0;
                Stmt* inner = parse_basic_block(context, t, &block_length);
                t += block_length;
                if (inner == null) {
                    *length = t - t_first_stmt_start;
                    return null;
                }

                stmt->kind = stmt_block;
                stmt->block = inner;
            } break;

            case token_keyword_if: {
                Stmt* if_stmt = stmt;

                while (true) {
                    if_stmt->kind = stmt_if;

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
                    if (t->kind == token_keyword_else) {
                        t += 1;

                        switch (t->kind) {
                            case token_bracket_curly_open: {
                                u32 block_length = 0;
                                if_stmt->conditional.else_then = parse_basic_block(context, t, &block_length);
                                t += block_length;
                                if (if_stmt->conditional.else_then == null) {
                                    *length = t - t_first_stmt_start;
                                    return null;
                                }
                            } break;

                            case token_keyword_if: {
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

            case token_keyword_for: {
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

                        stmt->kind = stmt_loop;
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

                        stmt->kind = stmt_loop;
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

            case token_keyword_return: {
                stmt->kind = stmt_return;
                t += 1;

                if (t->kind != token_semicolon) {
                    u32 expr_length = 0;
                    stmt->return_value = parse_expr(context, t, &expr_length);
                    t += expr_length;
                    if (stmt->return_value == null) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }
                }

                if (!expect_single_token(context, t, token_semicolon, "after variable declaration")) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
                t += 1;
            } break;

            case token_keyword_break: {
                stmt->kind = stmt_break;
                t += 1;

                if (!expect_single_token(context, t, token_semicolon, "after variable declaration")) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
                t += 1;
            } break;

            case token_keyword_continue: {
                stmt->kind = stmt_continue;
                t += 1;

                if (!expect_single_token(context, t, token_semicolon, "after variable declaration")) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
                t += 1;
            } break;

            case token_keyword_let: {
                t += 1;

                if (t->kind != token_identifier) {
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
                if (t->kind == token_colon) {
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
                if (t->kind == token_assign) {
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

                stmt->kind = stmt_declaration;
                stmt->declaration.var_index = var_index;
                stmt->declaration.right = expr;

                if (!expect_single_token(context, t, token_semicolon, "after variable declaration")) {
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
                    case token_assign: {
                        t += 1;

                        u32 right_length = 0;
                        Expr* right = parse_expr(context, t, &right_length);
                        t += right_length;

                        if (right == null) {
                            *length = t - t_first_stmt_start;
                            return null;
                        }

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

                        if (right == null) {
                            *length = t - t_first_stmt_start;
                            return null;
                        }

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

                if (!expect_single_token(context, t, token_semicolon, "after statement")) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
                t += 1;
            } break;
        }

        // Try parsing more statements after this one
        if (stmt->kind != stmt_end) {
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

    if (!expect_single_token(context, t, token_bracket_round_open, "after function name")) {
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

    if (t->kind == token_bracket_round_close) {
        t += 1;
    } else while (true) {
        u32 names_given = 0;
        while (true) {
            if (t->kind != token_identifier) {
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

            if (t->kind == token_comma) {
                t += 1;
                continue;
            } else {
                break;
            }
        }

        if (!expect_single_token(context, t, token_colon, names_given > 1? "after parameter names" : "after parameter name")) {
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

        if (t->kind == token_bracket_round_close) {
            t += 1;
            break;
        } else {
            if (!expect_single_token(context, t, token_comma, "after member declaration")) return false;
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

    if (parse_primitive_name(context, name_index) != null || context->builtin_names[builtin_cast] == name_index) {
        u8* name = string_table_access(context->string_table, name_index);
        print_file_pos(&start->pos);
        printf("Can't use '%s' as a function name, as it is reserved for casts\n", name);
        valid = false;
    } else if (parse_builtin_func_name(context, name_index) != builtin_invalid) {
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
    func->signature.has_output = false;
    func->signature.output_type = &context->primitive_types[type_void];
    func->body.output_var_index = U32_MAX;

    if (t->kind == token_arrow) {
        t += 1;

        u32 output_type_length = 0;
        Type* output_type = parse_type(context, t, &output_type_length);
        t += output_type_length;

        if (output_type == null) {
            return null;
        } else if (output_type->kind != type_void) {
            func->signature.has_output = true;
            func->signature.output_type = output_type;
            func->body.output_var_index = buf_length(context->tmp_vars);

            Var output_var = {0};
            output_var.name = U32_MAX;
            output_var.type = output_type;
            buf_push(context->tmp_vars, output_var);
        }
    }

    // Functions without a body
    if (t->kind == token_semicolon) {
        func->kind = func_kind_imported;

    // Body
    } else {
        func->kind = func_kind_normal;

        if (t->kind != token_bracket_curly_open) {
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
    if (t->kind != token_bracket_curly_open) {
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
            case token_keyword_fn: {
                u32 length;
                Func* func = parse_function(context, &body[i], &length);

                if (func == null) {
                    valid = false;
                } else if (func->kind != func_kind_imported) {
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
                while (i < body_length && body[i].kind != token_semicolon) { i += 1; }
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
    if (read_result != io_ok) {
        printf("Couldn't load \"%s\": %s\n", file_name, io_result_message(read_result));
        return false;
    }

    bool valid = true;

    valid &= lex_and_parse_text(context, "<preload>", preload_code_text, str_length(preload_code_text));

    u32 type_kind_name_index = string_table_intern_cstr(&context->string_table, "Type_Kind");
    context->type_info_type = parse_user_type_name(context, type_kind_name_index);
    assert(context->type_info_type != null);
    assert(context->type_info_type->kind == type_enum);
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
                buf_push(tokens, ((Token) { token_identifier, .identifier_string_table_index = string_table_index, .pos = file_pos }));
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
                    .kind = token_literal_float,
                    .literal_float = float_value,
                    .pos = file_pos
                }));
            } else {
                buf_push(tokens, ((Token) {
                    .kind = token_literal_int,
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
                    token_string,
                    .string.bytes = arena_pointer,
                    .string.length = collapsed_length,
                    .pos = file_pos,
                }));
            }
        } break;

        case ',': {
            i += 1;
            buf_push(tokens, ((Token) { token_comma, .pos = file_pos }));
        } break;

        case '.': {
            i += 1;
            buf_push(tokens, ((Token) { token_dot, .pos = file_pos }));
        } break;

        case ':': {
            if (i + 1 < file_length && file[i + 1] == ':') {
                i += 2;
                buf_push(tokens, ((Token) { token_static_access, .pos = file_pos }));
            } else {
                i += 1;
                buf_push(tokens, ((Token) { token_colon, .pos = file_pos }));
            }
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
            print_file_pos(&file_pos);
            printf("Unexpected character: %c\n", file[i]);
            valid = false;
            i += 1;
        } break;
    }
    buf_push(tokens, ((Token) { token_end_of_stream, .pos = file_pos }));


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
    for (Token* t = tokens; t->kind != token_end_of_stream; t += 1) {
        print_token_pos(&t->pos);
        printf("  ");
        print_token(string_table, t);
        printf("\n");
    }
    #endif

    // Parse
    Token* t = tokens;
    while (t->kind != token_end_of_stream && valid) switch (t->kind) {
        case token_keyword_fn: {
            u32 length = 0;
            Func* func = parse_function(context, t, &length);

            if (func == null) {
                valid = false;
            } else if (func->kind != func_kind_normal) {
                u8* name = string_table_access(context->string_table, func->name);
                print_file_pos(&t->pos);
                printf("Function '%s' doesn't have a body. Functions without bodies can only be inside 'extern' blocks\n", name);
                valid = false;
            }

            t += length;
        } break;

        case token_keyword_extern: {
            u32 length = 0;
            valid &= parse_extern(context, file_name, t, &length);
            t += length;
        } break;

        case token_keyword_let: {
            File_Pos start_pos = t->pos;
            t += 1;

            if (t->kind != token_identifier) {
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
            if (t->kind == token_colon) {
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
            if (t->kind == token_assign) {
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

            if (!expect_single_token(context, t, token_semicolon, "after global variable declaration")) {
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

        case token_keyword_enum:
        case token_keyword_struct:
        {
            File_Pos start_pos = t->pos;

            u32 length = 0;
            Type* type;
            switch (t->kind) {
                case token_keyword_enum:   type = parse_enum_declaration(context, t, &length); break;
                case token_keyword_struct: type = parse_struct_declaration(context, t, &length); break;
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

        case token_keyword_union: {
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

bool resolve_type(Context* context, Type** type_slot, File_Pos* pos) {
    // The reason we have a pretty complex system here is because we want types to be pointer-equal

    Type* type = *type_slot;

    if (!(type->flags & TYPE_FLAG_UNRESOLVED)) {
        return true;
    }

    typedef struct Prefix Prefix;
    struct Prefix {
        enum { prefix_pointer, prefix_array } kind;
        u64 array_length;
        Prefix* link;
    };
    Prefix* prefix = null;

    arena_stack_push(&context->stack); // We allocate prefixes, if any, on the stack

    while (true) {
        bool done = false;

        switch (type->kind) {
            case type_pointer: {
                Prefix* new = arena_new(&context->stack, Prefix);
                new->kind = prefix_pointer;
                new->link = prefix;
                prefix = new;

                type = type->pointer_to;
            } break;

            case type_array: {
                Prefix* new = arena_new(&context->stack, Prefix);
                new->kind = prefix_array;
                new->array_length = type->array.length;
                new->link = prefix;
                prefix = new;

                type = type->array.of;
            } break;

            case type_unresolved_name: {
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
            case prefix_pointer: type = get_pointer_type(context, type); break;
            case prefix_array:   type = get_array_type(context, type, prefix->array_length); break;
        }
        prefix = prefix->link;
    }

    arena_stack_pop(&context->stack);

    *type_slot = type;
    return true;
}

typedef enum Typecheck_Expr_Result {
    typecheck_expr_strong, // Found types, can't change types (i.e. a variable of known type)
    typecheck_expr_weak, // Found types, but can change types (i.e. an integer literal)
    typecheck_expr_bad, // Couldn't fix types
} Typecheck_Expr_Result;

Typecheck_Expr_Result typecheck_expr(Typecheck_Info* info, Expr* expr, Type* solidify_to) {
    bool strong = true;

    switch (expr->kind) {
        case expr_variable: {
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
                    return typecheck_expr_bad;
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

                        return typecheck_expr_bad;
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

                    return typecheck_expr_bad;
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

        case expr_literal: {
            Type_Kind to_primitive = solidify_to->kind;

            expr->literal.masked_value = expr->literal.raw_value;

            switch (expr->literal.kind) {
                case expr_literal_pointer: {
                    if (to_primitive == type_pointer) {
                        expr->type = solidify_to;
                    } else {
                        expr->type = info->context->void_pointer_type;
                    }
                } break;

                case expr_literal_bool: {
                    assert(expr->literal.raw_value == true || expr->literal.raw_value == false);
                    expr->type = &info->context->primitive_types[type_bool];
                } break;

                case expr_literal_integer: {
                    strong = false;

                    if (primitive_is_integer(to_primitive)) {
                        expr->type = solidify_to;
                    } else if (to_primitive == type_pointer) {
                        // Handles 'pointer + integer' and similar cases
                        expr->type = &info->context->primitive_types[type_u64];
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

                case expr_literal_float: {
                    strong = false;

                    if (primitive_is_float(to_primitive)) {
                        expr->type = solidify_to;
                    } else {
                        expr->type = &info->context->primitive_types[DEFAULT_FLOAT_TYPE];
                    }

                    switch (expr->type->kind) {
                        case type_f64: expr->literal.masked_value = expr->literal.raw_value; break;
                        case type_f32: {
                            f64 big = *((f64*) &expr->literal.raw_value);
                            f32 small = (f32) big;
                            expr->literal.masked_value = (u64) *((u32*) &small);
                        } break;
                    }
                } break;

                default: assert(false);
            }
        } break;

        case expr_string_literal: {
            assert(expr->type == info->context->string_type);
        } break;

        case expr_compound: {
            if (expr->type == null) {
                if (solidify_to->kind == type_void) {
                    print_file_pos(&expr->pos);
                    printf("No type given for compound literal\n");
                    return typecheck_expr_bad;
                }
                expr->type = solidify_to;
            }

            if (!resolve_type(info->context, &expr->type, &expr->pos)) return typecheck_expr_bad;

            switch (expr->type->kind) {
                case type_array: {
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
                        return typecheck_expr_bad;
                    }

                    for (u32 m = 0; m < expr->compound.count; m += 1) {
                        Compound_Member* member = &expr->compound.content[m];

                        if (member->name_mode != expr_compound_no_name) {
                            print_file_pos(&expr->pos);
                            printf("Unexpected member name '%s' given inside array literal\n", compound_member_name(info->context, expr, member));
                            return typecheck_expr_bad;
                        }

                        if (typecheck_expr(info, member->expr, expected_child_type) == typecheck_expr_bad) return typecheck_expr_bad;

                        if (expected_child_type != member->expr->type) {
                            print_file_pos(&expr->pos);
                            printf("Invalid type inside compound literal: Expected ");
                            print_type(info->context, expected_child_type);
                            printf(" but got ");
                            print_type(info->context, member->expr->type);
                            printf("\n");
                            return typecheck_expr_bad;
                        }
                    }
                } break;

                case type_struct: {
                    if (expr->compound.count > expr->type->structure.member_count) {
                        u64 expected = expr->type->structure.member_count;
                        u64 given = expr->compound.count;
                        print_file_pos(&expr->pos);
                        printf("Expected at most %u %s, but got %u for struct literal\n", expected, expected == 1? "member" : "members", given);
                        return typecheck_expr_bad;
                    }

                    bool any_named = false;
                    bool any_unnamed = false;

                    u8* set_map = arena_alloc(&info->context->stack, expr->type->structure.member_count);
                    mem_clear(set_map, expr->type->structure.member_count);

                    for (u32 i = 0; i < expr->compound.count; i += 1) {
                        Expr* child = expr->compound.content[i].expr;

                        if (expr->compound.content[i].name_mode == expr_compound_unresolved_name) {
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
                                return typecheck_expr_bad;
                            } else {
                                expr->compound.content[i].name_mode = expr_compound_name;
                                expr->compound.content[i].member_index = member_index;
                            }
                        }

                        if (expr->compound.content[i].name_mode == expr_compound_no_name) {
                            assert(expr->compound.content[i].member_index == 0);
                            expr->compound.content[i].member_index = i;
                            any_unnamed = true;
                        } else {
                            any_named = true;
                        }

                        u32 m = expr->compound.content[i].member_index;
                        Type* member_type = expr->type->structure.members[m].type;
                        
                        if (typecheck_expr(info, child, member_type) == typecheck_expr_bad) {
                            return typecheck_expr_bad;
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
                            return typecheck_expr_bad;
                        }

                        if (set_map[i]) {
                            u32 name_index = expr->type->structure.members[m].name;
                            u8* member_name = string_table_access(info->context->string_table, name_index);

                            print_file_pos(&child->pos);
                            printf("'%s' is set more than once in struct literal\n", member_name);
                            return typecheck_expr_bad;
                        }
                        set_map[i] = true;
                    }

                    if (any_named && any_unnamed) {
                        print_file_pos(&expr->pos);
                        printf("Struct literal can't have both named and unnamed members\n");
                        return typecheck_expr_bad;
                    }

                    if (any_unnamed && expr->compound.count != expr->type->structure.member_count) {
                        print_file_pos(&expr->pos);
                        printf("Expected %u members, but got %u for struct literal\n", expr->type->structure.member_count, expr->compound.count);
                        return typecheck_expr_bad;
                    }
                } break;

                default: {
                    print_file_pos(&expr->pos);
                    printf("Invalid type for compound literal: ");
                    print_type(info->context, expr->type);
                    printf("\n");
                    return typecheck_expr_bad;
                } break;
            }
        } break;

        case expr_binary: {
            if (BINARY_OP_COMPARATIVE[expr->binary.op]) {
                solidify_to = &info->context->primitive_types[type_void];
            }

            Typecheck_Expr_Result left_result, right_result;

            left_result = typecheck_expr(info, expr->binary.left, solidify_to);
            right_result = typecheck_expr(info, expr->binary.right, solidify_to);

            if (left_result == typecheck_expr_bad || right_result == typecheck_expr_bad) {
                return typecheck_expr_bad;
            }

            if (left_result == typecheck_expr_weak && right_result == typecheck_expr_weak) {
                right_result = typecheck_expr(info, expr->binary.right, expr->binary.left->type);
            } else if (left_result == typecheck_expr_weak && right_result == typecheck_expr_strong) {
                left_result = typecheck_expr(info, expr->binary.left, expr->binary.right->type);
            } else if (left_result == typecheck_expr_strong && right_result == typecheck_expr_weak) {
                right_result = typecheck_expr(info, expr->binary.right, expr->binary.left->type);
            }

            assert(left_result != typecheck_expr_bad && right_result != typecheck_expr_bad);
            if (left_result == typecheck_expr_weak && right_result == typecheck_expr_weak) {
                strong = false;
            }

            bool valid_types = false;

            if (BINARY_OP_COMPARATIVE[expr->binary.op]) {
                expr->type = &info->context->primitive_types[type_bool];

                if (expr->binary.left->type == expr->binary.right->type && !primitive_is_compound(expr->binary.left->type->kind)) {
                    valid_types = true;
                }
                if (expr->binary.left->type->kind == type_pointer && expr->binary.left->type->kind == type_pointer) {
                    valid_types = true;
                }
                if (expr->binary.op != binary_eq && !primitive_is_integer(expr->binary.left->type->kind)) {
                    valid_types = false;
                }
            } else {
                if (expr->binary.left->type == expr->binary.right->type && (primitive_is_integer(expr->binary.left->type->kind) || primitive_is_float(expr->binary.left->type->kind))) {
                    expr->type = expr->binary.left->type;
                    valid_types = true;

                // Special-case pointer-pointer arithmetic
                } else switch (expr->binary.op) {
                    case binary_add: {
                        if (expr->binary.left->type->kind == type_pointer && expr->binary.right->type->kind == type_u64) {
                            expr->type = expr->binary.left->type;
                            valid_types = true;
                        }
                        if (expr->binary.left->type->kind == type_u64 && expr->binary.right->type->kind == type_pointer) {
                            expr->type = expr->binary.right->type;
                            valid_types = true;
                        }
                    } break;

                    case binary_sub: {
                        if (expr->binary.left->type->kind == type_pointer && expr->binary.right->type->kind == type_u64) {
                            expr->type = expr->binary.left->type;
                            valid_types = true;
                        }
                    } break;

                    case binary_mul: {} break;
                    case binary_div: {} break;
                    case binary_mod: {} break;

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
                    return typecheck_expr_bad;
                } else {
                    print_file_pos(&expr->pos);
                    printf("Can't use operator %s on ", BINARY_OP_SYMBOL[expr->binary.op]);
                    print_type(info->context, expr->binary.left->type);
                    printf("\n");
                    return typecheck_expr_bad;
                }
            }
        } break;

        case expr_unary: {
            switch (expr->unary.op) {
                case unary_dereference: {
                    solidify_to = get_pointer_type(info->context, solidify_to);
                } break;

                case unary_address_of: {
                    if (solidify_to->kind == type_pointer) {
                        solidify_to = solidify_to->pointer_to;
                    }
                } break;
            }

            if (typecheck_expr(info, expr->unary.inner, solidify_to) == typecheck_expr_bad) return typecheck_expr_bad;

            switch (expr->unary.op) {
                case unary_not: {
                    // TODO allow using unary_not to do a bitwise not on integers
                    expr->type = expr->unary.inner->type;
                    if (expr->type->kind != type_bool) {
                        print_file_pos(&expr->unary.inner->pos);
                        printf("Can only apply unary not (!) to ");
                        print_type(info->context, expr->type);
                        printf(", its not a bool\n");
                        return typecheck_expr_bad;
                    }
                } break;

                case unary_neg: {
                    expr->type = expr->unary.inner->type;
                    if (!primitive_is_integer(expr->type->kind)) {
                        print_file_pos(&expr->unary.inner->pos);
                        printf("Can only apply unary negative (-) to ");
                        print_type(info->context, expr->type);
                        printf(", its not a bool\n");
                        return typecheck_expr_bad;
                    }
                } break;

                case unary_dereference: {
                    expr->type = expr->unary.inner->type->pointer_to;
                    expr->flags |= EXPR_FLAG_ASSIGNABLE;

                    Type_Kind child_primitive = expr->unary.inner->type->kind;
                    if (child_primitive != type_pointer) {
                        print_file_pos(&expr->pos);
                        printf("Can't dereference non-pointer ");
                        print_expr(info->context, info->func, expr->unary.inner);
                        printf("\n");
                        return typecheck_expr_bad;
                    }

                    Type_Kind pointer_to = expr->unary.inner->type->pointer_to->kind;
                    if (pointer_to == type_void) {
                        print_file_pos(&expr->pos);
                        printf("Can't dereference a void pointer ");
                        print_expr(info->context, info->func, expr->unary.inner);
                        printf("\n");
                        return typecheck_expr_bad;
                    }
                } break;

                case unary_address_of: {
                    expr->type = get_pointer_type(info->context, expr->unary.inner->type);
                    if (!(expr->unary.inner->flags & EXPR_FLAG_ASSIGNABLE)) {
                        print_file_pos(&expr->pos);
                        printf("Can't take address of ");
                        print_expr(info->context, info->func, expr->unary.inner);
                        printf("\n");
                        return typecheck_expr_bad;
                    }
                } break;

                default: assert(false);
            }
        } break;

        case expr_call: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u32 func_index = find_func(info->context, expr->call.unresolved_name);
                if (func_index == U32_MAX) {
                    u8* name = string_table_access(info->context->string_table, expr->call.unresolved_name);
                    print_file_pos(&expr->pos);
                    printf("Can't find function '%s'\n", name);
                    return typecheck_expr_bad;
                }

                expr->call.func_index = func_index;
                expr->flags &= ~EXPR_FLAG_UNRESOLVED;
            }

            Func* callee = &info->context->funcs[expr->call.func_index];
            expr->type = callee->signature.output_type;

            if (expr->call.param_count != callee->signature.param_count) {
                u8* name = string_table_access(info->context->string_table, callee->name);
                print_file_pos(&expr->pos);
                printf(
                    "Function '%s' takes %u parameters, but %u were given\n",
                    name, (u64) callee->signature.param_count, (u64) expr->call.param_count
                );
                return typecheck_expr_bad;
            }

            for (u32 p = 0; p < expr->call.param_count; p += 1) {
                Expr* param_expr = expr->call.params[p];

                u32 var_index = callee->signature.params[p].var_index;

                Type* expected_type = callee->signature.params[p].type;
                if (callee->signature.params[p].reference_semantics) {
                    assert(expected_type->kind == type_pointer);
                    expected_type = expected_type->pointer_to;
                }

                if (typecheck_expr(info, param_expr, expected_type) == typecheck_expr_bad) return typecheck_expr_bad;

                Type* actual_type = param_expr->type;
                if (!type_can_assign(expected_type, actual_type)) {
                    u8* func_name = string_table_access(info->context->string_table, callee->name);
                    print_file_pos(&expr->pos);
                    printf("Invalid type for %n parameter to '%s' Expected ", (u64) (p + 1), func_name);
                    print_type(info->context, expected_type);
                    printf(" but got ");
                    print_type(info->context, actual_type);
                    printf("\n");

                    return typecheck_expr_bad;
                }
            }
        } break;

        case expr_cast: {
            if (!resolve_type(info->context, &expr->type, &expr->pos)) return typecheck_expr_bad;
            if (typecheck_expr(info, expr->cast_from, expr->type) == typecheck_expr_bad) return typecheck_expr_bad;

            Type_Kind from = expr->cast_from->type->kind;
            Type_Kind to   = expr->type->kind;

            bool valid =
                (from == type_pointer && to == type_pointer) ||
                (from == type_pointer && to == type_u64) ||
                (from == type_u64 && to == type_pointer) ||
                (primitive_is_integer(from) && primitive_is_integer(to)) ||
                (primitive_is_integer(from) && to == type_enum) ||
                (primitive_is_integer(to) && from == type_enum);

            u32 result = -1;
            if (valid) {
                result = 0;
            } else if (to == type_pointer || to == type_enum || primitive_is_integer(to) || primitive_is_float(to)) {
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
                    return typecheck_expr_bad;
                } break;
                case 2: {
                    print_file_pos(&expr->pos);
                    printf("Invalid cast. Can't cast from ");
                    print_type(info->context, expr->cast_from->type);
                    printf(" to ");
                    print_type(info->context, expr->type);
                    printf("\n");
                    return typecheck_expr_bad;
                } break;
                default: assert(false);
            }
        } break;

        case expr_subscript: {
            if (typecheck_expr(info, expr->subscript.array, &info->context->primitive_types[type_void]) == typecheck_expr_bad) return typecheck_expr_bad;
            if (typecheck_expr(info, expr->subscript.index, &info->context->primitive_types[DEFAULT_INT_TYPE]) == typecheck_expr_bad) return typecheck_expr_bad;

            if (expr->subscript.array->flags & EXPR_FLAG_ASSIGNABLE) {
                expr->flags |= EXPR_FLAG_ASSIGNABLE;
            }

            Type* array_type = expr->subscript.array->type;
            if (array_type->kind == type_array) {
                expr->type = array_type->array.of;
            } else if (array_type->kind == type_pointer && array_type->pointer_to->kind == type_array) {
                expr->type = array_type->pointer_to->array.of;
            } else {
                print_file_pos(&expr->pos);
                printf("Can't index a ");
                print_type(info->context, array_type);
                printf("\n");
                return typecheck_expr_bad;
            }

            if (expr->subscript.index->type->kind != type_u64) {
                // TODO should we allow other integer types and insert automatic promotions as neccesary here??
                print_file_pos(&expr->subscript.index->pos);
                printf("Can only use u64 as an array index, not ");
                print_type(info->context, expr->subscript.index->type);
                printf("\n");
                return typecheck_expr_bad;
            }
        } break;

        case expr_member_access: {
            Expr* parent = expr->member_access.parent;
            if (typecheck_expr(info, parent, &info->context->primitive_types[type_void]) == typecheck_expr_bad) return typecheck_expr_bad;

            if (parent->flags & EXPR_FLAG_ASSIGNABLE) {
                expr->flags |= EXPR_FLAG_ASSIGNABLE;
            }

            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u32 access_name = expr->member_access.member_name;

                Type* s = parent->type;
                if (s->kind == type_pointer && s->pointer_to->kind == type_struct) {
                    s = s->pointer_to;
                }

                bool has_member = false;
                if (s->kind == type_struct) {
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
                    return typecheck_expr_bad;
                }
            }
        } break;

        case expr_static_member_access: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                Type* parent = parse_user_type_name(info->context, expr->static_member_access.parent_name);

                if (parent == null) {
                    u8* name_string = string_table_access(info->context->string_table, expr->static_member_access.parent_name);
                    print_file_pos(&expr->pos);
                    printf("No such type: '%s'\n", name_string);
                    return typecheck_expr_bad;
                }

                if (parent->kind != type_enum) {
                    print_file_pos(&expr->pos);
                    printf("Can't use operator :: on non-enum type ");
                    print_type(info->context, parent);
                    printf("\n");
                    return typecheck_expr_bad;
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
                    return typecheck_expr_bad;
                }

                expr->static_member_access.parent_type = parent;
                expr->static_member_access.member_index = member_index;

                expr->flags &= ~EXPR_FLAG_UNRESOLVED;
            }

            expr->type = expr->static_member_access.parent_type;
        } break;


        case expr_type_info_of_type: {
            if (!resolve_type(info->context, &expr->type_info_of_type, &expr->pos)) return typecheck_expr_bad;
        } break;

        case expr_type_info_of_value: {
            Type *void_type = &info->context->primitive_types[type_void];
            if (typecheck_expr(info, expr->type_info_of_value, void_type) == typecheck_expr_bad) return typecheck_expr_bad;
        } break;

        case expr_enum_length: {
            if (!resolve_type(info->context, &expr->enum_length_of, &expr->pos)) return typecheck_expr_bad;

            if (expr->enum_length_of->kind != type_enum) {
                print_file_pos(&expr->pos);
                printf("Can't call 'enum_length' on ");
                print_type(info->context, expr->enum_length_of);
                printf(", it's not an enum");
                return typecheck_expr_bad;
            }
        } break;

        case expr_enum_member_name: {
            if (typecheck_expr(info, expr->enum_member, &info->context->primitive_types[type_invalid]) == typecheck_expr_bad) return typecheck_expr_bad;

            if (expr->enum_member->type->kind != type_enum) {
                print_file_pos(&expr->enum_member->pos);
                printf("Can't call 'enum_member_name' on a ");
                print_type(info->context, expr->enum_member->type);
                printf("\n");
                return typecheck_expr_bad;
            }
        } break;

        default: assert(false);
    }

    if (!resolve_type(info->context, &expr->type, &expr->pos)) return typecheck_expr_bad;

    // Autocast from '*void' to any other pointer kind
    if (expr->type == info->context->void_pointer_type && expr->type != solidify_to && solidify_to->kind == type_pointer) {
        expr->type = solidify_to;
    }

    if (strong) {
        return typecheck_expr_strong;
    } else {
        return typecheck_expr_weak;
    }
}

bool typecheck_stmt(Typecheck_Info* info, Stmt* stmt) {
    Type *void_type = &info->context->primitive_types[type_void];

    switch (stmt->kind) {
        case stmt_assignment: {
            if (typecheck_expr(info, stmt->assignment.left, void_type) == typecheck_expr_bad) return false;
            Type* left_type = stmt->assignment.left->type;
            if (typecheck_expr(info, stmt->assignment.right, left_type) == typecheck_expr_bad) return false;
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

        case stmt_expr: {
            if (typecheck_expr(info, stmt->expr, void_type) == typecheck_expr_bad) return false;
        } break;

        case stmt_declaration: {
            u32 var_index = stmt->declaration.var_index;
            Var* var = &info->func->body.vars[var_index];
            Expr* right = stmt->declaration.right;

            bool good_types = true;

            if (right != null) {
                good_types = false;

                Type* resolve_to = var->type;
                if (resolve_to == null) resolve_to = &info->context->primitive_types[type_void];

                if (typecheck_expr(info, right, resolve_to) != typecheck_expr_bad) {
                    if (var->type == null) {
                        var->type = right->type;
                        good_types = true;
                    } else {
                        if (!type_can_assign(var->type, right->type)) {
                            print_file_pos(&stmt->pos);
                            printf("Right hand side of variable declaration doesn't have correct type. Expected ");
                            print_type(info->context, var->type);
                            printf(" but got ");
                            print_type(info->context, right->type);
                            printf("\n");
                        } else {
                            good_types = true;
                        }
                    }
                }
            } else {
                assert(var->type != null);
                if (var->type->flags & TYPE_FLAG_UNRESOLVED) {
                    if (!resolve_type(info->context, &var->type, &var->declaration_pos)) {
                        good_types = true;
                    } else {
                        var->type->flags &= ~TYPE_FLAG_UNRESOLVED;
                    }
                }
            }

            assert(!info->scope->map[stmt->declaration.var_index]);
            info->scope->map[stmt->declaration.var_index] = true;

            if (!good_types) {
                if (var->type == null) {
                    // This only is here to prevent the compiler from crashing when typechecking further statements
                    var->type = &info->context->primitive_types[type_invalid];
                }
                return false;
            }
        } break;

        case stmt_block: {
            typecheck_scope_push(info);
            for (Stmt* inner = stmt->block; inner->kind != stmt_end; inner = inner->next) {
                if (!typecheck_stmt(info, inner)) return false;
            }
            typecheck_scope_pop(info);
        } break;

        case stmt_if: {
            Type* bool_type = &info->context->primitive_types[type_bool];
            if (typecheck_expr(info, stmt->conditional.condition, bool_type) == typecheck_expr_bad) return false;

            Type_Kind condition_primitive = stmt->conditional.condition->type->kind;
            if (condition_primitive != type_bool) {
                print_file_pos(&stmt->conditional.condition->pos);
                printf("Expected bool but got ");
                print_type(info->context, stmt->conditional.condition->type);
                printf(" in 'if'-statement\n");
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
                Type* bool_type = &info->context->primitive_types[type_bool];
                if (typecheck_expr(info, stmt->loop.condition, bool_type) == typecheck_expr_bad) return false;

                Type_Kind condition_primitive = stmt->loop.condition->type->kind;
                if (condition_primitive != type_bool) {
                    print_file_pos(&stmt->loop.condition->pos);
                    printf("Expected bool but got ");
                    print_type(info->context, stmt->loop.condition->type);
                    printf(" in 'for'-loop\n");
                    return false;
                }
            }

            typecheck_scope_push(info);
            for (Stmt* inner = stmt->loop.body; inner->kind != stmt_end; inner = inner->next) {
                if (!typecheck_stmt(info, inner)) return false;
            }
            typecheck_scope_pop(info);
        } break;

        case stmt_return: {
            if (!info->func->signature.has_output) {
                if (stmt->return_value != null) {
                    u8* name = string_table_access(info->context->string_table, info->func->name);
                    print_file_pos(&stmt->pos);
                    printf("Function '%s' is not declared to return anything, but tried to return a value\n", name);
                    return false;
                }

            } else {
                Type* expected_type = info->func->signature.output_type;

                if (stmt->return_value == null) {
                    u8* name = string_table_access(info->context->string_table, info->func->name);
                    print_file_pos(&stmt->pos);
                    printf("Function '%s' is declared to return a ", name);
                    print_type(info->context, expected_type);
                    printf(", but tried to return a value. value\n");
                    return false;
                }

                if (typecheck_expr(info, stmt->return_value, expected_type) == typecheck_expr_bad) return false;

                if (!type_can_assign(expected_type, stmt->return_value->type)) {
                    u8* name = string_table_access(info->context->string_table, info->func->name);
                    print_file_pos(&stmt->pos);
                    printf("Expected ");
                    print_type(info->context, expected_type);
                    printf(" but got ");
                    print_type(info->context, stmt->return_value->type);
                    printf(" for return value in function '%s'\n", name);
                    return false;
                }
            }
        } break;

        case stmt_continue:
        case stmt_break:
        {} break; // Any fancy logic goes in 'check_control_flow'

        default: assert(false);
    }

    return true;
}

typedef enum Eval_Result {
    eval_ok,
    eval_bad,
    eval_do_at_runtime,
} Eval_Result;

// NB This will allocate on context->stack, push/pop before/after
Eval_Result eval_compile_time_expr(Typecheck_Info* info, Expr* expr, u8* result_into) {
    u64 type_size = type_size_of(expr->type);
    assert(type_size > 0);

    switch (expr->kind) {
        case expr_literal: {
            assert(type_size <= 8);
            mem_copy((u8*) &expr->literal.masked_value, result_into, type_size);
            return eval_ok;
        } break;

        case expr_variable: {
            if (expr->variable.index & VAR_INDEX_GLOBAL_FLAG) {
                u32 global_index = expr->variable.index & (~VAR_INDEX_GLOBAL_FLAG);
                Global_Var* global = &info->context->global_vars[global_index];

                if (global->compute_at_runtime) {
                    return eval_do_at_runtime;
                } else if (global->valid) {
                    u64 other_size = type_size_of(global->var.type);
                    assert(other_size == type_size);
                    u8* other_value = &info->context->seg_data[global->data_offset];
                    mem_copy(other_value, result_into, type_size);
                    return eval_ok;
                } else {
                    if (!global->checked) {
                        u8* name = string_table_access(info->context->string_table, global->var.name);
                        print_file_pos(&expr->pos);
                        printf(
                            "Can't use global variable '%s' in a compile time expression before its declaration on line %u\n",
                            name, (u64) global->var.declaration_pos.line
                        );
                    }
                    return eval_bad;
                }
            } else {
                print_file_pos(&expr->pos);
                printf("Can't use local variables in constant expressions\n");
                return eval_bad;
            }
        } break;

        case expr_cast: {
            Type_Kind primitive = primitive_of(expr->type);
            Type_Kind inner_primitive = primitive_of(expr->cast_from->type);

            u64 inner_type_size = type_size_of(expr->cast_from->type);
            assert(type_size <= 8 && inner_type_size <= 8);
            assert(primitive_is_integer(primitive) && primitive_is_integer(inner_primitive));

            u64 inner = 0;
            Eval_Result result = eval_compile_time_expr(info, expr->cast_from, (u8*) &inner);
            if (result != eval_ok) return result;

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

            return eval_ok;
        } break;

        case expr_subscript: {
            Eval_Result result;

            u64 array_size = type_size_of(expr->subscript.array->type);
            u64 index_size = type_size_of(expr->subscript.index->type);

            assert(index_size <= 8);

            u8* inner_data = arena_alloc(&info->context->stack, array_size);
            mem_clear(inner_data, array_size);
            result = eval_compile_time_expr(info, expr->subscript.array, inner_data);
            if (result != eval_ok) return result;

            u64 index = 0;
            result = eval_compile_time_expr(info, expr->subscript.index, (u8*) &index);
            if (result != eval_ok) return result;

            Type* array_type = expr->subscript.array->type;
            Type_Kind array_literal_primitive = array_type->kind;
            assert(array_literal_primitive == type_array);

            Type* child_type = array_type->array.of;
            u64 child_size = type_size_of(child_type);
            assert(child_size == type_size);

            mem_copy(inner_data + index*child_size, result_into, type_size);

            return eval_ok;
        } break;

        case expr_unary: {
            Type_Kind primitive = expr->type->kind;
            Type_Kind inner_primitive = expr->unary.inner->type->kind;

            u64 inner_type_size = type_size_of(expr->unary.inner->type);

            if (expr->unary.op == unary_dereference) {
                return eval_do_at_runtime;
            } else if (expr->unary.op == unary_address_of) {
                return eval_do_at_runtime;
            } else {
                assert(inner_type_size <= 8);
                assert(inner_type_size == type_size);

                Eval_Result result = eval_compile_time_expr(info, expr->unary.inner, result_into);
                if (result != eval_ok) return result;

                switch (expr->unary.op) {
                    case unary_neg: {
                        switch (type_size) {
                            case 1: *((i8*)  result_into) = -(*((i8*)  result_into)); break;
                            case 2: *((i16*) result_into) = -(*((i16*) result_into)); break;
                            case 4: *((i32*) result_into) = -(*((i32*) result_into)); break;
                            case 8: *((i64*) result_into) = -(*((i64*) result_into)); break;
                            default: assert(false);
                        }
                    } break;

                    case unary_not: {
                        assert(inner_type_size == 1);
                        *result_into = (*result_into == 0)? 1 : 0;
                    } break;

                    default: assert(false);
                }
            }

            return eval_ok;
        } break;

        case expr_binary: {
            u64 child_size = type_size_of(expr->binary.left->type);

            assert(type_size <= 8 && child_size <= 8);

            u64 left_result, right_result;

            Eval_Result eval_result;
            eval_result = eval_compile_time_expr(info, expr->binary.left, (u8*) &left_result);
            if (eval_result != eval_ok) return eval_result;
            eval_result = eval_compile_time_expr(info, expr->binary.right, (u8*) &right_result);
            if (eval_result != eval_ok) return eval_result;

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
            return eval_ok;
        } break;

        case expr_compound: {
            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));

            switch (expr->type->kind) {
                case type_array: {
                    Type* child_type = expr->type->array.of;
                    u64 child_size = type_size_of(child_type);

                    u8* mem = result_into;
                    for (u32 i = 0; i < expr->compound.count; i += 1) {
                        assert(expr->compound.content[i].name_mode == expr_compound_no_name);
                        Expr* child = expr->compound.content[i].expr;
                        Eval_Result result = eval_compile_time_expr(info, child, mem);
                        if (result != eval_ok) return result;
                        mem += child_size;
                    }
                } break;

                case type_struct: {
                    u8* mem = result_into;

                    for (u32 i = 0; i < expr->compound.count; i += 1) {
                        assert(expr->compound.content[i].name_mode != expr_compound_unresolved_name);
                        u32 m = expr->compound.content[i].member_index;
                        u64 offset = expr->type->structure.members[m].offset;

                        Expr* child = expr->compound.content[i].expr;
                        Eval_Result result = eval_compile_time_expr(info, child, mem + offset);
                        if (result != eval_ok) return result;
                    }
                } break;

                default: assert(false);
            }

            return eval_ok;
        } break;

        case expr_string_literal: {
            return eval_do_at_runtime;
        } break;

        case expr_call: {
            return eval_do_at_runtime;
        } break;

        case expr_member_access: {
            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));
            assert(expr->member_access.parent->type->kind == type_struct);

            u64 parent_size = type_size_of(expr->member_access.parent->type);
            u8* inner_data = arena_alloc(&info->context->stack, parent_size);
            mem_clear(inner_data, parent_size);
            Eval_Result result = eval_compile_time_expr(info, expr->member_access.parent, inner_data);
            if (result != eval_ok) return result;

            u32 m = expr->member_access.member_index;
            u64 offset = expr->member_access.parent->type->structure.members[m].offset;

            mem_copy(inner_data + offset, result_into, type_size);

            return eval_ok;
        } break;

        case expr_static_member_access: {
            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));

            Type* type = expr->static_member_access.parent_type;
            u32 member_index = expr->static_member_access.member_index;
            assert(type->kind == type_enum);

            u64 member_value = type->enumeration.members[member_index].value;
            mem_copy((u8*) &member_value, result_into, type_size);

            return eval_ok;
        } break;

        case expr_type_info_of_type:
        case expr_type_info_of_value:
        {
            return eval_do_at_runtime;
        } break;

        case expr_enum_length: {
            if (expr->enum_length_of->kind == type_unresolved_name) {
                return eval_do_at_runtime;
            } else {
                assert(expr->enum_length_of->kind == type_enum);

                u64 length = 0;
                for (u32 m = 0; m < expr->enum_length_of->enumeration.member_count; m += 1) {
                    u64 value = expr->enum_length_of->enumeration.members[m].value;
                    length = max(value + 1, length);
                }

                assert(expr->type->kind == type_u64);
                mem_copy((u8*) &length, result_into, type_size);

                return eval_ok;
            }
        } break;

        case expr_enum_member_name: {
            return eval_do_at_runtime;
        } break;

        default: assert(false); return eval_bad;
    }
}

typedef enum Control_Flow_Result {
    control_flow_will_return,
    control_flow_might_return,
    control_flow_invalid,
} Control_Flow_Result;

Control_Flow_Result check_control_flow(Stmt* stmt, Stmt* parent_loop) {
    bool has_returned = false;
    bool has_skipped_out = false; // continue or break

    for (; stmt->kind != stmt_end; stmt = stmt->next) {
        if (has_returned || has_skipped_out) {
            print_file_pos(&stmt->pos);
            printf("Unreachable code\n");
            return control_flow_invalid;
        }

        switch (stmt->kind) {
            case stmt_declaration:
            case stmt_expr:
            case stmt_assignment:
            {} break;

            case stmt_block: {
                Control_Flow_Result result = check_control_flow(stmt->block, parent_loop);
                switch (result) {
                    case control_flow_will_return: has_returned = true; break;
                    case control_flow_might_return: break;
                    case control_flow_invalid: return control_flow_invalid; break;
                    default: assert(false);
                }
            } break;

            case stmt_if: {
                Control_Flow_Result then_result = check_control_flow(stmt->conditional.then, parent_loop);
                if (then_result == control_flow_invalid) return then_result;

                Control_Flow_Result else_result = control_flow_might_return;
                if (stmt->conditional.else_then != null) {
                    else_result = check_control_flow(stmt->conditional.else_then, parent_loop);
                    if (else_result == control_flow_invalid) return else_result;
                }

                if (then_result == control_flow_will_return && else_result == control_flow_will_return) {
                    has_returned = true;
                }
            } break;

            case stmt_loop: {
                Control_Flow_Result result = check_control_flow(stmt->loop.body, stmt);
                switch (result) {
                    case control_flow_will_return: has_returned = true; break;
                    case control_flow_might_return: break;
                    case control_flow_invalid: return control_flow_invalid; break;
                    default: assert(false);
                }
            } break;

            case stmt_return: {
                has_returned = true;
            } break;

            case stmt_break:
            case stmt_continue:
            {
                if (parent_loop == null) {
                    print_file_pos(&stmt->pos);
                    printf("%s outside of loop\n", stmt->kind == stmt_break? "break" : "continue");
                    return control_flow_invalid;
                } else {
                    has_skipped_out = true;
                }
            } break;
        }
    }

    if (has_returned) {
        return control_flow_will_return;
    } else {
        return control_flow_might_return;
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
            case type_struct: {
                if (type->flags & TYPE_FLAG_SIZE_NOT_COMPUTED) {
                    u64 max_align = 0;
                    u64 size = 0;

                    for (u32 m = 0; m < type->structure.member_count; m += 1) {
                        File_Pos* member_pos = &type->structure.members[m].declaration_pos;
                        Type* member_type = type->structure.members[m].type;

                        if (!resolve_type(context, &member_type, member_pos)) {
                            valid = false;
                            break;
                        }

                        type->structure.members[m].offset = size;

                        u64 member_size = 0;
                        u64 member_align = 0;

                        u64 array_multiplier = 1;
                        while (true) {
                            if (member_type->kind == type_array) {
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
                                if (member_type->kind == type_struct) {
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

            case type_enum: {
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
            Type** type = &func->signature.params[p].type;

            if ((*type)->flags & TYPE_FLAG_UNRESOLVED) {
                if (resolve_type(context, type, &func->declaration_pos)) {
                    (*type)->flags &= ~TYPE_FLAG_UNRESOLVED;
                } else {
                    valid = false;
                }
            }

            if (primitive_is_compound((*type)->kind)) {
                func->signature.params[p].reference_semantics = true;
                *type = get_pointer_type(context, *type);

                if (func->kind == func_kind_normal) {
                    func->body.vars[func->signature.params[p].var_index].type = *type;
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
            if (resolve_to == null) resolve_to = &context->primitive_types[type_void];

            if (typecheck_expr(&info, global->initial_expr, resolve_to) != typecheck_expr_bad) {
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
                case eval_ok: {
                    global->valid = true;
                    global->compute_at_runtime = false;
                } break;

                case eval_bad: {
                    valid = false;
                } break;

                case eval_do_at_runtime: {
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

        if (info.func->kind != func_kind_normal) {
            continue;
        }

        arena_stack_push(&context->stack); // for allocating scopes

        info.scope = scope_new(context, info.func->body.var_count);

        // output and parameters are allways in scope
        if (info.func->signature.has_output) {
            info.scope->map[info.func->body.output_var_index] = true;
        }
        for (u32 i = 0; i < info.func->signature.param_count; i += 1) {
            u32 var_index = info.func->signature.params[i].var_index;
            info.scope->map[var_index] = true;
        }

        // Body types
        for (Stmt* stmt = info.func->body.first_stmt; stmt->kind != stmt_end; stmt = stmt->next) {
            if (!typecheck_stmt(&info, stmt)) {
                valid = false;
            }
        }

        // Control flow
        Control_Flow_Result result = check_control_flow(info.func->body.first_stmt, null);
        if (result == control_flow_invalid) {
            valid = false;
        } else if (info.func->signature.has_output && result != control_flow_will_return) {
            u8* name = string_table_access(info.context->string_table, info.func->name);
            print_file_pos(&info.func->declaration_pos);
            printf("Function '%s' is missing a return statement\n", name);
            valid = false;
        }

        arena_stack_pop(&context->stack);
    }

    return valid;
}



void build_enum_member_name_table(Context* context, Type* type) {
    assert(type->kind == type_enum);
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
    runtime_builtin_mem_clear,
    runtime_builtin_mem_copy,
    RUNTIME_BUILTIN_COUNT,
};

typedef enum Register {
    REGISTER_NONE = 0,

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

int REGISTER_KIND_RANGES[2][2] = {
    [REGISTER_KIND_GPR] = { RAX,  R15   },
    [REGISTER_KIND_XMM] = { XMM0, XMM15 },
};

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
};

u8 *register_name(Register reg, u8 size) {
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

typedef enum Mov_Mode { MOV_FROM_MEM, MOV_TO_MEM } Mov_Mode;

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


typedef struct Reg_Allocator_Frame Reg_Allocator_Frame;
struct Reg_Allocator_Frame {
    struct {
        bool allocated;
    } states[ALLOCATABLE_REGISTER_COUNT];

    Reg_Allocator_Frame *next, *previous;
};

typedef struct Reg_Allocator {
    Reg_Allocator_Frame *head;

    i32 next_stack_offset;
    struct {
        u64 size;
        X64_Address address;
    } *var_mem_infos;
    u64 allocated_var_mem_infos;
} Reg_Allocator;

void register_allocator_enter_frame(Context *context, Reg_Allocator *allocator) {
    if (allocator->head == null) {
        allocator->head = arena_new(&context->arena, Reg_Allocator_Frame);
    }

    if (allocator->head->next == null) {
        allocator->head->next = arena_new(&context->arena, Reg_Allocator_Frame);
        allocator->head->next->previous = allocator->head;
    }

    mem_copy((u8*) allocator->head, (u8*) allocator->head->next, sizeof(Reg_Allocator_Frame) - 2*sizeof(void*));
    allocator->head = allocator->head->next;
}

void register_allocator_leave_frame(Context *context, Reg_Allocator *allocator) {
    assert(allocator->head->previous != null);
    allocator->head = allocator->head->previous;
}

Register register_allocate(Reg_Allocator *allocator, Register_Kind kind) {
    Register start = REGISTER_KIND_RANGES[kind][0];
    Register end = REGISTER_KIND_RANGES[kind][1];

    for (Register reg = start; reg <= end; reg += 1) {
        if (!allocator->head->states[reg].allocated) {
            allocator->head->states[reg].allocated = true;
            return reg;
        }
    }

    panic("Out of registers to allocate\n");
    return REGISTER_NONE;
}

void register_ensure_free(Reg_Allocator *allocator, Register reg) {
    // TODO In the future we properly want to flush the old contents of the register, and return
    // them when we leave the current allocator frame!
    assert(!allocator->head->states[reg].allocated);
}



#define PRINT_GENERATED_INSTRUCTIONS

#ifdef PRINT_GENERATED_INSTRUCTIONS
void dump_instruction_bytes(u8 **b) {
    static u64 last_length = 0;
    u64 new_length = buf_length(*b);

    u64 pad = 8;

    for (u64 i = last_length; i < new_length; i += 1) {
        u8 byte = (*b)[i];
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

    printf("]");
}

void encode_instruction_reg_mem(u8 **b, u8 rex, u32 opcode, X64_Address mem, Register reg) {
    assert(mem.base >= RAX && mem.base <= R15);
    assert(mem.base != REGISTER_NONE);
    assert((mem.index >= RAX && mem.index <= R15) || mem.index == REGISTER_NONE);

    u8 modrm = 0;
    u8 sib = 0;
    bool use_sib = false;
    u8 offset_bytes = 0;


    modrm |= (REGISTER_INDICES[reg] & 0x07) << 3;
    if (REGISTER_INDICES[reg] & 0x08) {
        rex |= REX_R;
    }


    if (mem.immediate_offset > I8_MAX || mem.immediate_offset < I8_MIN) {
        modrm |= MODRM_MOD_POINTER_PLUS_I32;
        offset_bytes = sizeof(i32);
    } else if (mem.immediate_offset != 0) {
        modrm |= MODRM_MOD_POINTER_PLUS_I8;
        offset_bytes = sizeof(i8);
    } else {
        assert(mem.base != RBX); // This specifies rip-relative addressing
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
        buf_push(*b, rex);
    }

    do {
        buf_push(*b, (u8) (opcode & 0xff));
        opcode >>= 8;
    } while(opcode != 0);

    buf_push(*b, modrm);
    if (use_sib) {
        buf_push(*b, sib);
    }
    if (offset_bytes > 0) {
        str_push_integer(b, offset_bytes, *((u32*) &mem.immediate_offset));
    }
}

void encode_instruction_reg_reg(u8 **b, u8 rex, u32 opcode, Register mem, Register reg) {
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
        buf_push(*b, rex);
    }

    do {
        buf_push(*b, (u8) (opcode & 0xff));
        opcode >>= 8;
    } while(opcode != 0);

    buf_push(*b, modrm);
}


void instruction_int3(u8 **b) {
    buf_push(*b, 0xcc);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(b);
    printf("int 3\n");
    #endif
}

void instruction_nop(u8 **b) {
    buf_push(*b, 0x90);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(b);
    printf("nop\n");
    #endif
}

void instruction_ret(u8 **b) {
    buf_push(*b, 0xc3);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(b);
    printf("ret\n");
    #endif
}

// Returns an index to a position where a i8 jump offset should be written
u64 instruction_jmp_i8(u8 **b) {
    buf_push(*b, 0xeb);
    buf_push(*b, 0x00);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(b);
    printf("jmp ??\n");
    #endif

    return buf_length(*b) - 1;
}

// Jumps if RCX equals zero
// Returns an index to a position where a i8 jump offset should be written
u64 instruction_jrcxz(u8 **b) {
    buf_push(*b, 0xe3);
    buf_push(*b, 0x00);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(b);
    printf("jrcxz ??\n");
    #endif

    return buf_length(*b) - 1;
}

void instruction_call(Context* context, bool builtin, u32 func_index) {
    buf_push(context->seg_text, 0xe8);
    buf_push(context->seg_text, 0xde);
    buf_push(context->seg_text, 0xad);
    buf_push(context->seg_text, 0xbe);
    buf_push(context->seg_text, 0xef);

    Call_Fixup fixup = {0};
    fixup.text_location = buf_length(context->seg_text) - sizeof(i32);
    fixup.builtin = builtin;
    fixup.func_index = func_index;
    buf_push(context->call_fixups, fixup);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    u8 *name;
    if (builtin) {
        switch (func_index) {
            case runtime_builtin_mem_copy:  name = "builtin_mem_copy"; break;
            case runtime_builtin_mem_clear: name = "builtin_mem_clear"; break;
            default: assert(false);
        }
    } else {
        u32 name_index = context->funcs[func_index].name;
        name = string_table_access(context->string_table, name_index);
    }

    dump_instruction_bytes(&context->seg_text);
    printf("call %s\n", name);
    #endif
}

void instruction_inc_or_dec(u8 **b, bool inc, Register reg, u8 op_size) {
    u8 rex = REX_BASE;
    u8 opcode = 0xff;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(*b, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_reg_reg(b, rex, opcode, reg, inc? REGISTER_OPCODE_0 : REGISTER_OPCODE_1);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(b);
    printf("%su %s\n", inc? "inc" : "dec", register_name(reg, op_size));
    #endif
}

void instruction_imul_pointer_imm(u8 **b, Register reg, i64 mul_by) {
    if (mul_by <= I8_MAX && mul_by >= I8_MIN) {
        encode_instruction_reg_reg(b, REX_BASE | REX_W, 0x6b, reg, reg);
        str_push_integer(b, sizeof(i8), *((u64*) &mul_by));
    } else if (mul_by <= I32_MAX && mul_by >= I32_MIN) {
        encode_instruction_reg_reg(b, REX_BASE | REX_W, 0x69, reg, reg);
        str_push_integer(b, sizeof(i32), *((u64*) &mul_by));
    } else {
        assert(false); // NB the immediate operand to the imul instruction can at most be a i32
    }

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(b);
    u8 *reg_name = register_name(reg, POINTER_SIZE);
    printf("imul %s, %s, %i\n", reg_name, reg_name, mul_by);
    #endif
}

void instruction_xor(u8 **b, Register left, Register right, u8 op_size) {
    u8 rex = REX_BASE;
    u8 opcode = 0x31;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(*b, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_reg_reg(b, rex, opcode, left, right);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(b);
    printf("xor %s, %s\n", register_name(left, op_size), register_name(right, op_size));
    #endif
}

void instruction_lea(u8 **b, X64_Address mem, Register reg) {
    encode_instruction_reg_mem(b, REX_BASE | REX_W, 0x8d, mem, reg);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(b);
    printf("lea %s, ", register_name(reg, POINTER_SIZE));
    print_x64_address(mem);
    printf("\n");
    #endif
}

void instruction_mov_reg_mem(u8 **b, Mov_Mode mode, X64_Address mem, Register reg, u8 op_size) {
    u8 rex = REX_BASE;

    u8 opcode;
    switch (mode) {
        case MOV_FROM_MEM: opcode = 0x8b; break;
        case MOV_TO_MEM:   opcode = 0x89; break;
        default: assert(false);
    }

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(*b, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_reg_mem(b, rex, opcode, mem, reg);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(b);
    if (mode == MOV_FROM_MEM) {
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

void instruction_mov_imm_mem(u8 **b, X64_Address mem, u64 immediate, u8 op_size) {
    u8 imm_size = op_size;

    if (op_size == 8) {
        // NB there is no 'mov mem64, imm64' instruction, so we have to improvize
        // Also, 'mov mem64, imm32' sign-extends, hens I32_MAX
        if (immediate > I32_MAX) {
            instruction_mov_imm_mem(b, mem, immediate & U32_MAX, 4);
            mem.immediate_offset += 4;
            instruction_mov_imm_mem(b, mem, immediate >> 32, 4);
            return;
        } else {
            imm_size = 4;
        }
    }

    u8 rex = REX_BASE;
    u8 opcode = 0xc7;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(*b, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_reg_mem(b, rex, opcode, mem, REGISTER_OPCODE_0);
    str_push_integer(b, imm_size, immediate);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(b);
    printf("mov%u ", (u64) op_size*8);
    print_x64_address(mem);
    printf(", %x\n", immediate);
    #endif
}

void instruction_mov_imm_reg(u8 **b, Register reg, u64 immediate, u8 op_size) {
    if (immediate < U32_MAX && op_size == 8) {
        // 32-bit instructions still clear the upper bits, so this is fine, and costs us 4-5 bytes less (depending on whether we still need REX)
        op_size = 4;
    }

    u8 rex = REX_BASE;
    u8 opcode = 0xb8;

    switch (op_size) {
        case 1: opcode = 0xb0; break;
        case 2: buf_push(*b, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    opcode |= REGISTER_INDICES[reg] & 0x07;
    if (REGISTER_INDICES[reg] & 0x08) {
        reg |= REX_B;
    }

    if (rex != REX_BASE) {
        buf_push(*b, rex);
    }
    buf_push(*b, opcode);
    str_push_integer(b, op_size, immediate);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(b);
    printf("mov %s, %x\n", register_name(reg, op_size), (u64) immediate);
    #endif
}


typedef struct Simple_Binary_Info {
    enum {
        SIMPLE_BINARY_ADD = binary_add,
        SIMPLE_BINARY_SUB = binary_sub,
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

void instruction_simple_binary(u8 **b, Simple_Binary_Info info) {
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
        case 2: buf_push(*b, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    if (info.b_is_address) {
        encode_instruction_reg_mem(b, rex, opcode, info.b.address, info.a);
    } else {
        encode_instruction_reg_reg(b, rex, opcode, info.b.reg, info.a);
    }

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    dump_instruction_bytes(b);
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


void machinecode_immediate_to_place(Context *context, X64_Place place, u64 immediate, u8 bytes) {
    switch (place.kind) {
        case PLACE_REGISTER: instruction_mov_imm_reg(&context->seg_text, place.reg, immediate, bytes); break;
        case PLACE_ADDRESS:  instruction_mov_imm_mem(&context->seg_text, place.address, immediate, bytes); break;

        case PLACE_NOWHERE: assert(false);
        default: assert(false);
    }
}

void machinecode_cast(Context *context, Register reg, Type_Kind from, Type_Kind to) {
    u8 from_size = primitive_size_of(from);
    u8 to_size = primitive_size_of(to);

    if (from == type_pointer && to == type_pointer) {
        // This is a no-op
    } else if (primitive_is_float(from) || primitive_is_float(to)) {
        unimplemented(); // TODO floating point casts
    } else if (primitive_is_signed(from) || primitive_is_signed(to)) {
        unimplemented(); // TODO signed casts
    } else {
        bool word_prefix = false;
        bool rex_w = false;
        u8 opcode = 0;

        switch (from_size) {
            case 1: switch (to_size) {
                case 1: break;
                case 2: { word_prefix = true; opcode = 0xb6; } break;
                case 4: { opcode = 0xb6; } break;
                case 8: { rex_w = true; opcode = 0xb6; } break;
                deafult: assert(false);
            } break;
            case 2: switch (to_size) {
                case 1: break;
                case 2: break;
                case 4: { opcode = 0xb7; } break;
                case 8: { rex_w = true; opcode = 0xb7; } break;
                default: assert(false);
            } break;
            case 4: break;
            case 8: break;
            default: assert(false);
        }

        if (opcode != 0) {
            u32 big_opcode = 0x0f | (((u32) opcode) << 8);
            encode_instruction_reg_reg(&context->seg_text, rex_w? (REX_BASE | REX_W) : 0, big_opcode, reg, reg);

            #ifdef PRINT_GENERATED_INSTRUCTIONS
            dump_instruction_bytes(&context->seg_text);
            printf("movzx %s, %s\n", register_name(reg, to_size), register_name(reg, from_size));
            #endif
        }
    }
}

void machinecode_move(Context *context, Reg_Allocator *reg_allocator, X64_Place src, X64_Place dst, u64 size) {
    if (size <= 8) {
        if (src.kind == PLACE_ADDRESS && dst.kind == PLACE_ADDRESS) {
            register_allocator_enter_frame(context, reg_allocator);

            Register reg = register_allocate(reg_allocator, REGISTER_KIND_GPR);
            instruction_mov_reg_mem(&context->seg_text, MOV_FROM_MEM, src.address, reg, (u8) size);
            instruction_mov_reg_mem(&context->seg_text, MOV_TO_MEM, dst.address, reg, (u8) size);

            register_allocator_leave_frame(context, reg_allocator);
        } else if (src.kind == PLACE_REGISTER && dst.kind == PLACE_ADDRESS) {
            instruction_mov_reg_mem(&context->seg_text, MOV_TO_MEM, dst.address, src.reg, (u8) size);
        } else if (src.kind == PLACE_ADDRESS && dst.kind == PLACE_REGISTER) {
            instruction_mov_reg_mem(&context->seg_text, MOV_FROM_MEM, src.address, dst.reg, (u8) size);
        } else if (src.kind == PLACE_REGISTER && dst.kind == PLACE_REGISTER) {
            unimplemented();
            // TODO mov_reg_reg
        } else {
            assert(false);
        }
    } else {
        // TODO special case small moves by simply inserting some sequential moves

        register_ensure_free(reg_allocator, RAX);
        register_ensure_free(reg_allocator, RDX);
        register_ensure_free(reg_allocator, RCX);
        register_ensure_free(reg_allocator, RDX);

        assert(src.kind == PLACE_ADDRESS && dst.kind == PLACE_ADDRESS);
        instruction_lea(&context->seg_text, src.address, RAX);
        instruction_lea(&context->seg_text, dst.address, RDX);

        instruction_mov_imm_reg(&context->seg_text, RCX, size, POINTER_SIZE);

        register_allocator_enter_frame(context, reg_allocator);

        instruction_call(context, true, runtime_builtin_mem_copy);
        register_allocator_leave_frame(context, reg_allocator);
    }
}

void machinecode_binary(Context *context, Reg_Allocator *reg_allocator, Binary_Op op, Type_Kind primitive, X64_Place src, X64_Place dst) {
    switch (op) {
        case binary_add:
        case binary_sub:
        {
            if (primitive_is_float(primitive)) {
                unimplemented();
            } else {
                register_allocator_enter_frame(context, reg_allocator);

                Register tmp_reg = REGISTER_NONE;
                if (src.kind == PLACE_ADDRESS && dst.kind == PLACE_ADDRESS) {
                    tmp_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR);
                    instruction_mov_reg_mem(&context->seg_text, MOV_FROM_MEM, src.address, tmp_reg, primitive_size_of(primitive));
                    src = (X64_Place) { .kind = PLACE_REGISTER, .reg = tmp_reg };
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
                instruction_simple_binary(&context->seg_text, info);

                register_allocator_leave_frame(context, reg_allocator);
            }
        } break;

        case binary_mul: unimplemented(); break;
        case binary_div: unimplemented(); break;
        case binary_mod: unimplemented(); break;

        case binary_eq: unimplemented(); break;
        case binary_neq: unimplemented(); break;
        case binary_gt: unimplemented(); break;
        case binary_gteq: unimplemented(); break;
        case binary_lt: unimplemented(); break;
        case binary_lteq: unimplemented(); break;

        default: assert(false);
    }
}

void machinecode_for_expr(Context *context, Func *func, Expr *expr, Reg_Allocator *reg_allocator, X64_Place place);

X64_Place machinecode_for_assignable_expr(Context *context, Func *func, Expr *expr, Reg_Allocator *reg_allocator) {
    assert(expr->flags & EXPR_FLAG_ASSIGNABLE);

    switch (expr->kind) {
        case expr_variable: {
            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));

            X64_Place place = {0};
            place.kind = PLACE_ADDRESS;
            place.address = reg_allocator->var_mem_infos[expr->variable.index].address;
            return place;
        } break;

        case expr_unary: {
            switch (expr->unary.op) {
                case unary_dereference: {
                    Register reg = register_allocate(reg_allocator, REGISTER_KIND_GPR);

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

        case expr_subscript: {
            X64_Place place = machinecode_for_assignable_expr(context, func, expr->subscript.array, reg_allocator);
            assert(place.kind == PLACE_ADDRESS);

            Type *array_type = expr->subscript.array->type;
            Type *child_type;
            if (array_type->kind == type_pointer) {
                assert(array_type->pointer_to->kind == type_array);
                child_type = array_type->pointer_to->array.of;

                Register address_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR);
                instruction_mov_reg_mem(&context->seg_text, MOV_FROM_MEM, place.address, address_reg, POINTER_SIZE);
                place.address = (X64_Address) { .base = address_reg };
            } else {
                assert(array_type->kind == type_array);
                child_type = array_type->array.of;
            }
            u64 step = type_size_of(child_type);

            if (expr->subscript.index->kind == expr_literal) {
                u64 offset = expr->subscript.index->literal.masked_value * step;
                assert((((i64) place.address.immediate_offset) + ((i64) offset)) <= I32_MAX);
                place.address.immediate_offset += offset;
            } else {
                if (place.address.index != REGISTER_NONE) {
                    Register new_base = place.address.index;
                    instruction_lea(&context->seg_text, place.address, new_base);
                    place.address = (X64_Address) {0};
                    place.address.base = new_base;
                }
                assert(place.address.index == REGISTER_NONE);

                Register offset_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR);

                X64_Place offset_place = (X64_Place) { .kind = PLACE_REGISTER, .reg = offset_reg };
                machinecode_for_expr(context, func, expr->subscript.index, reg_allocator, offset_place);

                place.address.index = offset_reg;

                if (step == 1 || step == 2 || step == 4 || step == 8) {
                    place.address.scale = (u8) step;
                } else {
                    place.address.scale = 1;
                    instruction_imul_pointer_imm(&context->seg_text, place.address.index, step);
                }
            }

            return place;
        } break;

        case expr_member_access: {
            X64_Place place = machinecode_for_assignable_expr(context, func, expr->member_access.parent, reg_allocator);
            assert(place.kind == PLACE_ADDRESS);

            Type *parent_type = expr->member_access.parent->type;
            if (parent_type->kind == type_pointer) {
                parent_type = parent_type->pointer_to;

                Register address_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR);
                instruction_mov_reg_mem(&context->seg_text, MOV_FROM_MEM, place.address, address_reg, POINTER_SIZE);
                place.address = (X64_Address) { .base = address_reg };
            }

            assert(parent_type->kind == type_struct);

            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));
            u32 member_index = expr->member_access.member_index;
            u64 offset = parent_type->structure.members[member_index].offset;

            assert((((i64) place.address.immediate_offset) + ((i64) offset)) <= I32_MAX);
            place.address.immediate_offset += offset;

            return place;
        } break;
    }

    return (X64_Place) { .kind = PLACE_NOWHERE };
}

void machinecode_for_expr(Context *context, Func *func, Expr *expr, Reg_Allocator *reg_allocator, X64_Place place) {
    switch (expr->kind) {
        case expr_variable: {
            u64 size = type_size_of(expr->type);
            X64_Place from = machinecode_for_assignable_expr(context, func, expr, reg_allocator);
            machinecode_move(context, reg_allocator, from, place, size);
        } break;

        case expr_literal: {
            u64 size = type_size_of(expr->type);
            assert(size <= 8);
            machinecode_immediate_to_place(context, place, expr->literal.masked_value, (u8) size);
        } break;

        case expr_string_literal: {
            unimplemented();
        } break;

        case expr_compound: {
            assert(place.kind == PLACE_ADDRESS);

            switch (expr->type->kind) {
                case type_array: {
                    Type* child_type = expr->type->array.of;
                    u64 child_size = type_size_of(child_type);

                    for (u32 i = 0; i < expr->compound.count; i += 1) {
                        assert(expr->compound.content[i].name_mode == expr_compound_no_name);

                        Expr* child = expr->compound.content[i].expr;
                        machinecode_for_expr(context, func, child, reg_allocator, place);

                        assert((((i64) place.address.immediate_offset) + ((i64) child_size)) < I32_MAX);
                        place.address.immediate_offset += child_size;
                    }
                } break;

                case type_struct: {
                    for (u32 i = 0; i < expr->compound.count; i += 1) {
                        assert(expr->compound.content[i].name_mode != expr_compound_unresolved_name);

                        u32 type_member_index = expr->compound.content[i].member_index;
                        u64 member_offset = expr->type->structure.members[type_member_index].offset;

                        assert((((i64) place.address.immediate_offset) + ((i64) member_offset)) < I32_MAX);
                        X64_Place offset_place = place;
                        offset_place.address.immediate_offset += (i32) member_offset;

                        Expr* child = expr->compound.content[i].expr;
                        machinecode_for_expr(context, func, child, reg_allocator, offset_place);
                    }
                } break;

                default: assert(false);
            }
        } break;

        case expr_binary: {
            Register_Kind reg_kind = primitive_is_float(primitive_of(expr->binary.left->type))? REGISTER_KIND_XMM : REGISTER_KIND_GPR;

            X64_Place left_place;
            Register left_reg = REGISTER_NONE;
            if (place.kind == PLACE_ADDRESS) {
                register_allocator_enter_frame(context, reg_allocator);
                left_reg = register_allocate(reg_allocator, reg_kind);
                left_place = (X64_Place) { .kind = PLACE_REGISTER, .reg = left_reg };
            } else {
                left_place = place;
            }

            machinecode_for_expr(context, func, expr->binary.left, reg_allocator, left_place);

            register_allocator_enter_frame(context, reg_allocator);

            Register right_reg = register_allocate(reg_allocator, reg_kind);
            X64_Place right_place = { .kind = PLACE_REGISTER, .reg = right_reg };
            machinecode_for_expr(context, func, expr->binary.right, reg_allocator, right_place);

            Type_Kind primitive = primitive_of(expr->type);
            machinecode_binary(context, reg_allocator, expr->binary.op, primitive, right_place, left_place);

            register_allocator_leave_frame(context, reg_allocator);

            if (left_reg != REGISTER_NONE) {
                u64 size = type_size_of(expr->type);
                assert(size <= 8);
                machinecode_move(context, reg_allocator, left_place, place, (u8) size);
                register_allocator_leave_frame(context, reg_allocator);
            }
        } break;

        case expr_unary: {
            switch (expr->unary.op) {
                case unary_not: {
                    unimplemented();
                } break;

                case unary_neg: {
                    unimplemented();
                } break;

                case unary_dereference: {
                    register_allocator_enter_frame(context, reg_allocator);
                    X64_Place inner_place = {0};
                    inner_place.kind = PLACE_REGISTER;
                    if (place.kind == PLACE_REGISTER) {
                        inner_place.reg = place.reg;
                    } else {
                        inner_place.reg = register_allocate(reg_allocator, REGISTER_KIND_GPR);
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

                case unary_address_of: {
                    X64_Place inner_place = machinecode_for_assignable_expr(context, func, expr->unary.inner, reg_allocator);
                    assert(inner_place.kind == PLACE_ADDRESS);

                    switch (place.kind) {
                        case PLACE_REGISTER: {
                            instruction_lea(&context->seg_text, inner_place.address, place.reg);
                        } break;

                        case PLACE_ADDRESS: {
                            register_allocator_enter_frame(context, reg_allocator);
                            Register reg = register_allocate(reg_allocator, REGISTER_KIND_GPR);
                            instruction_lea(&context->seg_text, inner_place.address, reg);
                            instruction_mov_reg_mem(&context->seg_text, MOV_TO_MEM, place.address, reg, POINTER_SIZE);
                            register_allocator_leave_frame(context, reg_allocator);
                        } break;

                        case PLACE_NOWHERE: assert(false);
                        default: assert(false);
                    }
                } break;

                default: assert(false);
            }
        } break;

        case expr_call: {
            unimplemented();
        } break;

        case expr_cast: {
            register_allocator_enter_frame(context, reg_allocator);

            X64_Place inner_place;
            bool inner_doesnt_match_outer;

            if (place.kind == PLACE_ADDRESS) {
                inner_place.kind = PLACE_REGISTER;
                inner_place.reg = register_allocate(reg_allocator, REGISTER_KIND_GPR);
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
        } break;

        case expr_subscript: {
            unimplemented();
        } break;

        case expr_member_access: {
            // TODO does this actually work in complicated cases. At first, I would think it doesn't, but it might actually be fine...

            X64_Place dst = place;
            X64_Place src = machinecode_for_assignable_expr(context, func, expr, reg_allocator);
            u64 size = type_size_of(expr->type);

            machinecode_move(context, reg_allocator, src, dst, size);
        } break;

        case expr_static_member_access: {
            unimplemented();
        } break;

        case expr_type_info_of_type: {
            unimplemented();
        } break;

        case expr_type_info_of_value: {
            unimplemented();
        } break;

        case expr_enum_length: {
            unimplemented();
        } break;

        case expr_enum_member_name: {
            unimplemented();
        } break;
    }
}

void machinecode_for_stmt(Context *context, Func *func, Stmt *stmt, Reg_Allocator *reg_allocator) {
    register_allocator_enter_frame(context, reg_allocator);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("; ");
    print_stmt(context, func, stmt, 0);
    #endif

    switch (stmt->kind) {
        case stmt_declaration: {
            Var *var = &func->body.vars[stmt->declaration.var_index];

            u64 size = type_size_of(var->type);
            u64 align = type_align_of(var->type);

            X64_Place place = {0};
            place.kind = PLACE_ADDRESS;
            place.address = reg_allocator->var_mem_infos[stmt->declaration.var_index].address;

            if (stmt->declaration.right == null) {
                if (size != align || size > 8) {
                    register_ensure_free(reg_allocator, RAX);
                    register_ensure_free(reg_allocator, RCX);

                    instruction_lea(&context->seg_text, place.address, RAX);
                    instruction_mov_imm_reg(&context->seg_text, RCX, size, POINTER_SIZE);
                    instruction_call(context, true, runtime_builtin_mem_clear);
                } else {
                    machinecode_immediate_to_place(context, place, 0, (u8) size);
                }
            } else {
                machinecode_for_expr(context, func, stmt->declaration.right, reg_allocator, place);
            }
        } break;

        case stmt_expr: {
            X64_Place nowhere = { .kind = PLACE_NOWHERE };
            machinecode_for_expr(context, func, stmt->expr, reg_allocator, nowhere);
        } break;

        case stmt_assignment: {
            if (primitive_is_compound(stmt->assignment.right->type->kind)) {
                unimplemented();
                //X64_Place left = ;
            } else {
                X64_Place left = machinecode_for_assignable_expr(context, func, stmt->assignment.left, reg_allocator);
                machinecode_for_expr(context, func, stmt->assignment.right, reg_allocator, left);
            }
        } break;

        case stmt_block: {
            unimplemented();
        } break;

        case stmt_if: {
            unimplemented();
        } break;

        case stmt_loop: {
            unimplemented();
        } break;

        case stmt_return: {
            unimplemented();
        } break;

        case stmt_break: {
            unimplemented();
        } break;

        case stmt_continue: {
            unimplemented();
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
        
        runtime_builtin_text_starts[runtime_builtin_mem_clear] = buf_length(context->seg_text);

        u64 before_loop = buf_length(context->seg_text);
        u64 forward_jump_index = instruction_jrcxz(&context->seg_text);
        u64 loop_start = buf_length(context->seg_text);

        instruction_mov_imm_mem(&context->seg_text, (X64_Address) { .base = RAX }, 0, 1);
        instruction_inc_or_dec(&context->seg_text, true, RAX, POINTER_SIZE);
        instruction_inc_or_dec(&context->seg_text, false, RCX, POINTER_SIZE);

        u64 backward_jump_index = instruction_jmp_i8(&context->seg_text);
        u64 loop_end = buf_length(context->seg_text);

        *((i8*) &context->seg_text[forward_jump_index]) = (i8) (loop_end - loop_start);
        *((i8*) &context->seg_text[backward_jump_index]) = -(i8) (loop_end - before_loop);

        instruction_ret(&context->seg_text);
    }

    { // mem copy
        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("; --- builtin mem copy ---\n");
        #endif

        // RAX is src pointer, RDX is dst pointer, RCX is count, RBX is clobbered.

        runtime_builtin_text_starts[runtime_builtin_mem_copy] = buf_length(context->seg_text);

        u64 before_loop = buf_length(context->seg_text);
        u64 forward_jump_index = instruction_jrcxz(&context->seg_text);
        u64 loop_start = buf_length(context->seg_text);

        instruction_mov_reg_mem(&context->seg_text, MOV_FROM_MEM, (X64_Address) { .base = RAX }, RBX, 1);
        instruction_mov_reg_mem(&context->seg_text, MOV_TO_MEM,   (X64_Address) { .base = RDX }, RBX, 1);
        instruction_inc_or_dec(&context->seg_text, true, RAX, POINTER_SIZE);
        instruction_inc_or_dec(&context->seg_text, true, RDX, POINTER_SIZE);
        instruction_inc_or_dec(&context->seg_text, false, RCX, POINTER_SIZE);

        u64 backward_jump_index = instruction_jmp_i8(&context->seg_text);
        u64 loop_end = buf_length(context->seg_text);

        *((i8*) &context->seg_text[forward_jump_index]) = (i8) (loop_end - loop_start);
        *((i8*) &context->seg_text[backward_jump_index]) = -(i8) (loop_end - before_loop);

        instruction_ret(&context->seg_text);
    }

    // Normal functions
    Reg_Allocator reg_allocator = {0};

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
        if (reg_allocator.allocated_var_mem_infos < func->body.var_count) {
            // TODO this leaks memory. We should allocate on 'context->stack', but it probably doesn't really matter in this case
            u32 alloc_count = func->body.var_count * 2;
            reg_allocator.allocated_var_mem_infos = alloc_count;
            reg_allocator.var_mem_infos = (void*) arena_alloc(&context->arena, alloc_count * sizeof(*reg_allocator.var_mem_infos));
        }
        mem_clear((u8*) reg_allocator.var_mem_infos, sizeof(*reg_allocator.var_mem_infos) * reg_allocator.allocated_var_mem_infos);

        reg_allocator.next_stack_offset = 0;

        // Allocate shadow space for calling other functions
        reg_allocator.next_stack_offset += 4*POINTER_SIZE;

        // Mark parameter variables so they don't get allocated normaly
        for (u32 p = 0; p < func->signature.param_count; p += 1) {
            u32 var_index = func->signature.params[p].var_index;

            X64_Address address = { .base = RBP, .immediate_offset = var_index * POINTER_SIZE };

            reg_allocator.var_mem_infos[var_index].size = POINTER_SIZE;
            reg_allocator.var_mem_infos[var_index].address = address;

            // TODO this also requires us to properly set up RBP at the beginning of functions...
            // Also, figure out what the actual immediate offset should be!
            // The unimplemented() is just so I remember this
            // While we are at it, we gotta figure out how that shadow space for calling other functions is going to work...
            // At the moment we just allocate space for four parameters :/ :/ :/
            unimplemented();
        }

        // Variables
        for (u32 v = 0; v < func->body.var_count; v += 1) {
            if (reg_allocator.var_mem_infos[v].address.base != REGISTER_NONE) continue; // Ignore parameters, see previous loop

            u64 size = type_size_of(func->body.vars[v].type);
            reg_allocator.next_stack_offset = (i32) round_to_next(reg_allocator.next_stack_offset, min(size, POINTER_SIZE));

            X64_Address address = { .base = RSP, .immediate_offset = reg_allocator.next_stack_offset };

            reg_allocator.var_mem_infos[v].size = size;
            reg_allocator.var_mem_infos[v].address = address;

            reg_allocator.next_stack_offset += size;
        }

        buf_push(context->seg_text, 0x48);
        buf_push(context->seg_text, 0x81);
        buf_push(context->seg_text, 0xec);
        u64 insert_stack_size_at_index = buf_length(context->seg_text);
        str_push_integer(&context->seg_text, sizeof(i32), 0xdeadbeef);

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        dump_instruction_bytes(&context->seg_text);
        printf("sub rsp, ??? (We fill in stack size after generating all code!)\n");
        #endif
        
        // TODO calling convention -- Preserve non-volatile registers! Also, we need to allocate stack space for that!

        // Copy parameters onto stack
        for (u32 p = 0; p < func->signature.param_count; p += 1) {
            unimplemented();

            /*
            u32 var_index = func->signature.params[p].var_index;

            u64 operand_size = type_size_of(func->signature.params[p].type);
            Type_Kind operand_primitive = primitive_of(func->signature.params[p].type);
            assert(operand_size <= 8);

            if (p < 4) {
                if (primitive_is_float(operand_primitive)) {
                    assert(operand_primitive == type_f32);
                    instruction_load_sse(context, func, mov_to, local, XMM0 + p);
                } else {
                    u8 reg;
                    switch (p) {
                        case 0: reg = RCX; break;
                        case 1: reg = RDX; break;
                        case 2: reg = R8; break;
                        case 3: reg = R9; break;
                        default: assert(false);
                    }
                    instruction_mov_stack(&context->seg_text, mov_to, reg, offset, (u8) operand_size);
                }
            }
            */
        }

        // Write out operations
        for (Stmt* stmt = func->body.first_stmt; stmt->kind != stmt_end; stmt = stmt->next) {
            machinecode_for_stmt(context, func, stmt, &reg_allocator);
        }

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("; (epilog)\n");
        #endif

        u64 total_stack_bytes = ((((u64) reg_allocator.next_stack_offset) + 7) & (~0x0f)) + 8; // Aligns so last nibble is 8

        i32 *insert_stack_size_here = (i32*) (&context->seg_text[insert_stack_size_at_index]);
        assert(total_stack_bytes < I32_MAX);
        *insert_stack_size_here = total_stack_bytes;

        // Pass output
        if (func->signature.has_output) {
            unimplemented();

            /*
            u32 var_index = func->body.output_var_index;
            Local output_local = { local_variable, false, var_index };
            Type_Kind output_primitive = primitive_of(func->signature.output_type);

            if (primitive_is_compound(output_primitive)) {
                if (output_primitive == type_array) {
                    unimplemented(); // TODO by-reference semantics
                } else {
                    assert(false);
                }
            } else {
                u8 operand_size = primitive_size_of(output_primitive);
                instruction_mov_mem(context, func, mov_from, output_local, RAX, operand_size);
            }
            */
        } else {
            instruction_xor(&context->seg_text, RAX, RAX, POINTER_SIZE);
        }

        // Reset stack
        buf_push(context->seg_text, 0x48);
        buf_push(context->seg_text, 0x81);
        buf_push(context->seg_text, 0xc4);
        str_push_integer(&context->seg_text, sizeof(i32), total_stack_bytes);
        #ifdef PRINT_GENERATED_INSTRUCTIONS
        dump_instruction_bytes(&context->seg_text);
        printf("add rsp, %x\n", total_stack_bytes);
        #endif

        // Return to caller
        instruction_ret(&context->seg_text);
    }

    // Call fixups
    buf_foreach (Call_Fixup, fixup, context->call_fixups) {
        i32* target = (i32*) (context->seg_text + fixup->text_location);
        assert(*target == 0xefbeadde);

        u32 jump_to;
        if (fixup->builtin) {
            jump_to = runtime_builtin_text_starts[fixup->func_index];
        } else {
            Func* callee = &context->funcs[fixup->func_index];
            assert(callee->kind == func_kind_normal);
            jump_to = callee->body.text_start;
        }

        u32 jump_from = fixup->text_location + sizeof(i32);
        i32 jump_by = ((i32) jump_to) - ((i32) jump_from);
        *target = jump_by;
    }
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
    if (read_result == io_not_found) {
        // TODO TODO TODO This is a really big hack. We should check %LIB%
        // TODO TODO TODO This is a really big hack. We should check %LIB%
        // TODO TODO TODO This is a really big hack. We should check %LIB%
        // TODO TODO TODO This is a really big hack. We should check %LIB%

        u8* system_lib_folder = "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.16299.0/um/x64";
        path = path_join(&context->arena, system_lib_folder, raw_lib_name);
        read_result = read_entire_file(path, &file, &file_length);
    }

    if (read_result != io_ok) {
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
        buf_foreach (Fixup, fixup, context->fixups) {
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
    buf_foreach (Fixup, fixup, context->fixups) {
        i32* text_value = (u32*) (context->seg_text + fixup->text_location);

        switch (fixup->kind) {
            case fixup_imported_function: break;

            case fixup_data: {
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

        switch (func->kind) {
            case func_kind_normal:
            {
                printf("    %u variables: ", (u64) func->body.var_count);
                for (u32 v = 0; v < func->body.var_count; v += 1) {
                    if (v == func->body.output_var_index) continue;

                    Var* var = &func->body.vars[v];
                    u8* name = string_table_access(context->string_table, var->name);

                    if (v > 0) printf(",");
                    printf("%s: ", name);
                    print_type(context, var->type);
                }
                printf("\n");

                printf("    Statements:\n");
                for (Stmt *stmt = func->body.first_stmt; stmt->kind != stmt_end; stmt = stmt->next) {
                    print_stmt(context, func, stmt, 2);
                }
            } break;

            case func_kind_imported: {
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
    u8 value = 3;
    u8 *pointer = &value;
    *pointer = 2 + *pointer;

    i64 compile_time, run_time;

    compile_and_run("W:/compiler/src/minimal.foo", "build/minimal_out.exe", &compile_time, &run_time);
    //compile_and_run("W:/compiler/src/code.foo", "build/foo_out.exe", &compile_time, &run_time);
    //compile_and_run("W:/compiler/src/link_test/backend.foo", "W:/compiler/src/link_test/build/out.exe", &compile_time, &run_time);
    //compile_and_run("W:/compiler/src/glfw_test/main.foo", "W:/compiler/src/glfw_test/out.exe", &compile_time, &run_time);

    printf("Compiled in %i ms, ran in %i ms\n", compile_time, run_time);
}
