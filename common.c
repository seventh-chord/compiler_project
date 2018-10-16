#ifndef SC_COMMON_C
#define SC_COMMON_C

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

const u8 U8_MAX = 0xff;
const u16 U16_MAX = 0xffff;
const u32 U32_MAX = 0xffffffff;
const u64 U64_MAX = 0xffffffffffffffff;

const i8 I8_MAX = 127;
const i8 I8_MIN = -128;
const i16 I16_MAX = 32767;
const i16 I16_MIN = -32768;
const i32 I32_MAX = 2147483647ull;
const i32 I32_MIN = -2147483648ll;
const i64 I64_MAX = 9223372036854775807ull;
const i64 I64_MIN = -9223372036854775808ll;

#define max(a, b)  ((a) > (b)? (a) : (b))
#define min(a, b)  ((a) > (b)? (b) : (a))
#define abs(a)     ((a) > 0? (a) : -(a))

#define array_length(x) (sizeof((x)) / sizeof((x)[0]))

int _fltused; // To make floating point work without the crt

#include <stdarg.h>
#include <xmmintrin.h>
#include <emmintrin.h>


// NB These are platform independent
void buf_printf(u8 **buffer, u8 *string, ...);

void printf(u8* string, ...);
void printf_flush();

void buf_printf_internal(u8 **buffer, u8 *string, va_list args);

typedef enum IO_Result {
    IO_OK = 0,

    IO_ERROR,
    IO_INVALID_FILE_PATH_ENCODING,
    IO_NOT_FOUND,
    IO_ALREADY_OPEN,
} IO_Result;
u8 *io_result_message(IO_Result result);

// Forward declarations for platform dependent stuff
i64 perf_frequency;
i64 perf_time(); // divide by 'perf_frequency' to get value in seconds
u64 unix_time(); // in seconds
void sleep(u32 milliseconds); // in milliseconds

void print(u8 *buffer, u32 buffer_length);
void print_debug(u8 *buffer);

void *sc_alloc(u64 size);
void *sc_realloc(void *mem, u64 size);
bool sc_free(void *mem);

u8 *get_cmd_args();
u32 get_env_variable(u8 *name, u8 *buffer, u32 buffer_length);

IO_Result get_temp_path(u8* path_into, u32* length);
IO_Result read_entire_file(u8 *file_name, u8 **contents, u32 *length);
IO_Result write_entire_file(u8 *file_name, u8 *contents, u32 length);
IO_Result delete_file(u8 *file_name);


// Our substitute for windows.h
// NB We have another '#if WINDOWS' block further down, for implementing the
// functions we forward declared above
#if WINDOWS
    // NB Im not sure if we need these, stuff works just fine without them it seems...
    #define WINAPI_PRE  __declspec(dllimport)
    #define WINAPI_POST //__stdcall // Is ignored on x64, but needed on x86

    typedef void* Handle;

    WINAPI_PRE void WINAPI_POST ExitProcess(u32 exit_code);
    WINAPI_PRE u32 WINAPI_POST GetLastError();

    // NB bytes must be u32 on win32
    WINAPI_PRE void* WINAPI_POST HeapAlloc(Handle heap, u32 flags, u64 bytes);
    WINAPI_PRE void* WINAPI_POST HeapReAlloc(Handle heap, u32 flags, void *memory, u64 bytes);
    WINAPI_PRE bool  WINAPI_POST HeapFree(Handle heap, u32 flags, void *memory);
    WINAPI_PRE Handle WINAPI_POST GetProcessHeap();


    WINAPI_PRE void* WINAPI_POST VirtualAlloc(void *address, u64 size, u32 type, u32 protect);
    #define MEM_COMMIT     0x00001000
    #define MEM_RESERVE    0x00002000

    WINAPI_PRE bool WINAPI_POST VirtualFree(void *address, u64 size, u32 type);
    #define MEM_RELEASE    0x00008000

    WINAPI_PRE bool WINAPI_POST VirtualProtect(void *address, u64 size, u32 new, u32 *old);
    #define PAGE_EXECUTE            0x10
    #define PAGE_EXECUTE_READ       0x20
    #define PAGE_EXECUTE_READWRITE  0x40
    #define PAGE_EXECUTE_WRITECOPY  0x80
    #define PAGE_NOACCESS           0x01
    #define PAGE_READONLY           0x02
    #define PAGE_READWRITE          0x04
    #define PAGE_WRITECOPY          0x08


    WINAPI_PRE Handle WINAPI_POST GetStdHandle(u32 key);
    #define STD_INPUT_HANDLE  ((u32)-10)
    #define STD_OUTPUT_HANDLE ((u32)-11)
    #define STD_ERROR_HANDLE  ((u32)-12)

    WINAPI_PRE u32 WINAPI_POST GetTempPathW(u32 buffer_length, u16 *buffer);

    WINAPI_PRE Handle WINAPI_POST CreateFileW(
        u16 *file_name,             // Zero-terminated string
        u32 access,                 // GENERIC_READ/WRITE/EXECUTE
        u32 share_mode,             // 0
        void *security_attributes,  // We don't use this, so it can be null
        u32 creation_disposition,   // OPEN_EXISTING, etc
        u32 flags_and_attributes,   // FILE_ATTRIBUTE_NORMAL
        Handle template_file        // null
    );
    WINAPI_PRE bool WINAPI_POST DeleteFileW(u16 *file_name);

    WINAPI_PRE bool WINAPI_POST CloseHandle(Handle handle);

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

    WINAPI_PRE bool WINAPI_POST WriteConsoleW(
        Handle console,
        u16 *buffer,
        u32 chars_to_write,
        u32 *chars_written,
        void *reserved
    );

    typedef struct Startup_Info Startup_Info;
    typedef struct Process_Info Process_Info;

    WINAPI_PRE bool WINAPI_POST CreateProcessW(
      u16 *application_name,
      u16 *arguments,
      void *process_attributes,
      void *thread_attributes,
      bool inherit_handles,
      u32 creation_flags,
      void *environment,
      u16 *current_directory,
      Startup_Info *startup_info,
      Process_Info *process_info
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
    WINAPI_PRE bool WINAPI_POST QueryPerformanceCounter(i64 *counter);
    WINAPI_PRE bool WINAPI_POST QueryPerformanceFrequency(i64 *frequency);

    WINAPI_PRE void WINAPI_POST DebugBreak();
    WINAPI_PRE void WINAPI_POST OutputDebugStringW(u16 *string);


    typedef struct System_Info {
        union {
            u32 oem_id;
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

    WINAPI_PRE void WINAPI_POST GetSystemInfo(System_Info *info);

    typedef struct File_Time {
        u32 lo;
        u32 hi;
    } File_Time;

    WINAPI_PRE void WINAPI_POST GetSystemTimeAsFileTime(File_Time *time);
    WINAPI_PRE void WINAPI_POST Sleep(u32 milliseconds);

    WINAPI_PRE u8* WINAPI_POST GetCommandLineA();
    WINAPI_PRE u32 WINAPI_POST GetEnvironmentVariableA(u8 *name, u8 *buffer, u32 size);

    typedef struct Win32_Find_Data {
        u32 file_attributes;
        File_Time creation_time;
        File_Time last_access_time;
        File_Time last_write_time;
        u32 file_size_high;
        u32 file_size_low;
        u32 reserved0;
        u32 reserved1;
        u8 file_name[0x104];
        u8 alternate_file_name[14];
        u32 file_type;
        u32 creator_type;
        u16 finder_flags;
    } Win32_Find_Data;
    WINAPI_PRE Handle WINAPI_POST FindFirstFileW(u16 *directory, Win32_Find_Data *find_data);
    WINAPI_PRE bool WINAPI_POST FindNextFileW(Handle file, Win32_Find_Data *find_data);
    WINAPI_PRE bool WINAPI_POST FindClose(Handle file);

    #ifdef DEBUG
    #define trap_or_exit()   (DebugBreak(), ExitProcess(-1))
    #else
    #define trap_or_exit()   (ExitProcess(-1))
    #endif
#endif

#if !defined(trap_or_exit)
#error trap_or_exit should have been defined earlier in this file
#endif

#define assert(x)        ((x)? (null) : (printf("%s(%u): assert(%s)\n", __FILE__, (u64) __LINE__, #x), printf_flush(), trap_or_exit(), null))
#define panic(x, ...)    (printf("%s(%u): Panic: ", __FILE__, (u64) __LINE__), printf(x, __VA_ARGS__), printf_flush(), trap_or_exit())
#define unimplemented()  (printf("%s(%u): Reached unimplemented code\n", __FILE__, (u64) __LINE__), printf_flush(), trap_or_exit(), null)



void mem_copy(u8 *from, u8 *to, u64 count) {
    if (from < to) {
        u8 *from_end = from + count;
        u8 *to_end = to + count;

        while (from_end != from && (from_end - from) > 8) {
            from_end -= 8;
            to_end -= 8;
            *((u64*) to_end) = *((u64*) from_end);
        }

        while (from_end != from) {
            from_end -= 1;
            to_end -= 1;
            *to_end = *from_end;
        }
    } else {
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
}

void mem_clear(u8 *ptr, u64 count) {
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

void mem_fill(u8 *ptr, u8 value, u64 count) {
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

bool mem_cmp(u8 *a, u8 *b, u64 count) {
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

// Returns 1-4 for bytes which are at the start of a codepoint,
// and 0 for bytes which are in the middle of a multi-byte codepoint.
//
// Returns -1 for bytes which can never appear in a utf8 sequence,
// including the start-byte for 2-long overlong sequences (0xc0 and 0xc1).
// We can NOT detect other overlong sequences without looking at the
// entire string though!
i32 utf8_byte_length(u8 byte) {
    if ((byte & 0x80) == 0x00) return  1; // 0x00 to 0x7f
    if ((byte & 0x40) == 0x00) return  0; // 0x80 to 0xbf
    if (byte == 0xc0 || byte == 0xc1 || byte >= 0xf6) return -1; // Invalid sequences (either overlong, or larger than unicode max values)
    if ((byte & 0x20) == 0x00) return  2; // 0xc2 to 0xdf
    if ((byte & 0x10) == 0x00) return  3; // 0xe0 to 0xef
    assert((byte & 0x08) == 0x00);
    return  4; // 0xf0 to 0xf4
}

bool utf8_byte_is_continuation(u8 byte) {
    return (byte & 0xc0) == 0x80;
}

// Counts the number of utf8 codepoints (a codepoint is one to four bytes)
// If the string is not valid utf8, we return U64_MAX.
u64 utf8_codepoint_count(u8 *string, u64 length) {
    u64 utf32_length = 0;

    for (u64 i = 0; i < length; i += 1)  {
        utf32_length += 1;

        u32 codepoint = 0;

        u8 first = string[i];
        i32 encoded_length = utf8_byte_length(first);
        switch (encoded_length) {
            case 1: {
                codepoint = first;
            } break;

            case 2: {
                if (i + 1 >= length) return U64_MAX;
                u8 second = string[++i];

                if (!utf8_byte_is_continuation(second)) return U64_MAX;

                codepoint = ((first & 0x1f) << 6) | (second & 0x3f);
            } break;

            case 3: {
                if (i + 2 >= length) return U64_MAX;
                u8 second = string[++i];
                u8 third  = string[++i];

                if (!utf8_byte_is_continuation(second)) return U64_MAX;
                if (!utf8_byte_is_continuation(third))  return U64_MAX;

                codepoint = ((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f);
            } break;

            case 4: {
                if (i + 3 >= length) return U64_MAX;
                u8 second = string[++i];
                u8 third  = string[++i];
                u8 fourth = string[++i];

                if (!utf8_byte_is_continuation(second)) return U64_MAX;
                if (!utf8_byte_is_continuation(third))  return U64_MAX;
                if (!utf8_byte_is_continuation(fourth)) return U64_MAX;

                codepoint = ((first & 0x07) << 18) | ((second & 0x3f) << 12) | ((third & 0x3f) << 6) | (fourth & 0x3f);
            } break;

            case 0:
            case -1:
            {
                return U64_MAX;
            } break;
        }

        // Overlong encodings
        // if (encoded_length == 2 && codepoint <= 0x7f) return U64_MAX; // We check for this in 'utf8_byte_length'
        if (encoded_length == 3 && codepoint <= 0x7ff) return U64_MAX;
        if (encoded_length == 4 && codepoint <= 0xffff) return U64_MAX;

        // Codepoints reserved for utf16 surogate pairs
        // With this, we are utf8 compliant, without it we are wtf8 compliant
        if (codepoint >= 0xd800 && codepoint <= 0xdfff) return U64_MAX;
    }

    return utf32_length;
}

bool str_cmp(u8 *a, u8 *b) {
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

void u32_fill(u32 *ptr, u64 count, u32 value) {
    for (u64 i = 0; i < count; i += 1) {
        *ptr = value;
        ptr += 1;
    }
}

// Hash map

typedef struct Hash_Map {
    struct { u64 key, value; } *slots;
    u64 length, capacity, collisions;
} Hash_Map;

u64 hash_word(u64 key) {
    key *= 0xff51afd7ed558ccd;
    key ^= key >> 32;
    return key;
}

u64 hash_string(u8 *bytes, u64 length) {
    u64 key = 0xcbf29ce484222325;
    for (u64 i = 0; i < length; i += 1) {
        key ^= bytes[i];
        key *= 0x100000001b3;
        key ^= key >> 32;
    }
    return key;
}

u64 hash_get(Hash_Map *map, u64 key) {
    if (map->capacity == 0) {
        return 0;
    }

    if (key == 0) {
        // NB This is trivial to implement, we just have to add a field
        // to store the associated value, and a flag to indicate whether the
        // zero key is present.
        panic("Hash_Map does not support null-keys\n");
    }

    u64 index = hash_word(key);

    while (true) {
        index &= map->capacity - 1;

        u64 key_in_slot = map->slots[index].key;
        if (key_in_slot == 0) {
            return 0; // No such value
        } else if (key_in_slot == key) {
            return map->slots[index].value;
        }

        index += 1;
    }

    assert(false);
    return 0;
}

void hash_grow(Hash_Map *map, u64 new_capacity);

void hash_insert(Hash_Map *map, u64 key, u64 value) {
    if (key == 0) panic("Hash_Map does not support null-keys\n");

    if (map->length == 0) {
        hash_grow(map, 128);
    }
    if (map->length*2 > map->capacity) {
        hash_grow(map, map->capacity*2);
    }

    u64 index = hash_word(key);
    while (true) {
        index &= map->capacity - 1;

        if (map->slots[index].key == 0) {
            map->slots[index].key = key;
            map->slots[index].value = value;
            break;
        }

        index += 1;
        map->collisions += 1;
    }

    map->length += 1;
}

void hash_grow(Hash_Map *map, u64 new_capacity) {
    assert((new_capacity & (new_capacity - 1)) == 0); // ensure capacity is allways a power of two
    Hash_Map new_map = {
        .slots = (void*) sc_alloc(new_capacity * sizeof(*map->slots)),
        .capacity = new_capacity,
        .length = map->length,
    };
    mem_clear((u8*) new_map.slots, new_capacity * sizeof(*new_map.slots));

    u64 remaining = map->length;
    for (u64 i = 0; i < map->capacity; i += 1) {
        if (remaining <= 0) break;

        if (map->slots[i].key != 0) {
            hash_insert(&new_map, map->slots[i].key, map->slots[i].value);
            remaining -= 1;
        }
    }

    sc_free(map->slots);
    *map = new_map;
}

// Stretchy buffer

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
#define buf_free(b)        ((b)? (sc_free(_buf_header(b)), (b) = null) : (0))
#define buf_end(b)         ((b)? ((b) + buf_length(b)) : null)
#define buf_empty(b)       (buf_length(b) <= 0)
#define buf_clear(b)       ((b)? (_buf_header(b)->length = 0, null) : null)

#define buf_foreach(t, x, b)     for (t* x = (b); x != buf_end(b); x += 1)
#define buf_foreach_remove(b, x) (_buf_remove((b), (x), sizeof(*(b))), (x) -= 1)

#define buf_reserve(b, n)  ((b) = _buf_grow((b), (n), sizeof(*(b))))

void *_buf_grow(void *buf, u64 new_len, u64 element_size) {
    Buf_Header *new_header;

    if (buf == null) {
        u64 new_capacity = max(512, new_len);
        u64 new_bytes = new_capacity*element_size + BUF_HEADER_SIZE;

        new_header = (Buf_Header*) sc_alloc(new_bytes);
        new_header->length = 0;
        new_header->capacity = new_capacity;

    } else {
        u64 new_capacity = 1 + 2*buf_capacity(buf);
        if (new_capacity < new_len) {
            new_capacity = new_len;
        }
        u64 new_bytes = new_capacity*element_size + BUF_HEADER_SIZE;

        Buf_Header *old_header = _buf_header(buf);
        new_header = (Buf_Header*) sc_realloc(old_header, new_bytes);
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
    if (length == 0) return;

    _buf_fit(*buf, length);
    u64* buf_length = &_buf_header(*buf)->length;
    mem_copy(str, *buf + *buf_length, length);
    *buf_length += length;
}

void str_push_zeroes(u8 **buf, u64 length) {
    if (length == 0) return;

    _buf_fit(*buf, length);
    u64* buf_length = &_buf_header(*buf)->length;
    mem_clear(*buf + *buf_length, length);
    *buf_length += length;
}

void str_push_integer(u8 **buf, u8 bytes, u64 value) {
    assert(bytes == 1 || bytes == 2 || bytes == 4 || bytes == 8);

    _buf_fit(*buf, bytes);
    u64* buf_length = &_buf_header(*buf)->length;
    for (u8 i = 0; i < bytes; i += 1) {
        *(*buf + *buf_length + i) = value & 0xff;
        value = value >> 8;
    }
    *buf_length += bytes;
}

// Moves items to the right of the given index 'length' bytes over, creating a gap for inserting new data in the buffer
u8 *str_make_space(u8 **buf, u64 at_index, u64 length) {
    u64 old_length = _buf_header(*buf)->length;

    _buf_fit(*buf, length);
    _buf_header(*buf)->length += length;

    u8 *source = (*buf) + at_index;
    u8 *target = source + length;
    mem_copy(source, target, old_length - at_index);

    return source;
}

// Arena allocator, which doubles as a makeshift stack allocator

enum {
    ARENA_PAGE_SIZE = 8 * 1024 * 1024, // 8 megabytes
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
    Arena_Page *current_page;
    Arena_Stack_Frame frame;
};

struct Arena_Page {
    Arena_Page *previous;
    Arena_Page *next;
    u64 used;
    u8 data[0];
};

#define arena_new(a, T)    (arena_insert_with_size((a), &((T) {0}), sizeof(T)))

// NB frees the entire arena
void arena_free(Arena *arena) {
    Arena_Page *cursor = arena->current_page;
    while (cursor != null) {
        Arena_Page *previous = cursor->previous;
        sc_free(cursor);
        cursor = previous;
    }
}

void arena_make_space(Arena* arena, u64 size) {
    if (arena->current_page == null) {
        Arena_Page* page = (Arena_Page*) sc_alloc(sizeof(Arena_Page) + ARENA_PAGE_SIZE);
        page->used = 0;
        page->previous = null;
        page->next = null;
        arena->current_page = page;
    }

    u64 free_space = ARENA_PAGE_SIZE - arena->current_page->used;

    u8 *start = ((u8*) arena->current_page) + sizeof(Arena_Page) + arena->current_page->used;

    u64 align_offset = ((u64) start) % ARENA_ALIGN;
    if (align_offset != 0) {
        align_offset = ARENA_ALIGN - align_offset;
    }

    if (size + align_offset > free_space) {
        if (arena->current_page->next == null) {
            Arena_Page* page = (Arena_Page*) sc_alloc(sizeof(Arena_Page) + ARENA_PAGE_SIZE);
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

u8 *arena_alloc(Arena *arena, u64 size) {
    assert(size < ARENA_PAGE_SIZE);

    arena_make_space(arena, size);

    u8 *ptr = ((u8*) arena->current_page) + sizeof(Arena_Page) + arena->current_page->used;
    u64 align_offset = ((u64) ptr) % ARENA_ALIGN;
    if (align_offset != 0) {
        align_offset = ARENA_ALIGN - align_offset;
        ptr += align_offset;
    }

    arena->current_page->used += size + align_offset;

    return ptr;
}

void *arena_insert_with_size(Arena *arena, void *element, u64 size) {
    u8* ptr = arena_alloc(arena, size); 
    mem_copy((u8*) element, ptr, size);
    return (void*) ptr;
}

void arena_stack_push(Arena *arena) {
    Arena_Stack_Frame new_frame = {0};
    new_frame.head = arena->current_page;
    new_frame.head_used = arena->current_page? arena->current_page->used : 0;
    new_frame.parent = arena_insert_with_size(arena, &arena->frame, sizeof(Arena_Stack_Frame));
    arena->frame = new_frame;
}

void arena_stack_pop(Arena *arena) {
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

typedef struct String_Table {
    Hash_Map map;
    u8 *arena;
    u64 arena_length;
} String_Table;

enum { STRING_TABLE_ARENA_CAPACITY = 512*1024 };

typedef struct String_Table_Entry String_Table_Entry;
struct String_Table_Entry {
    String_Table_Entry *next; // next entry with the same key
    u64 length;
    u8 string[];
};


u8 *string_intern_with_length(String_Table *table, u8 *string, u64 length) {
    assert(length + 1 <= STRING_TABLE_ARENA_CAPACITY);

    u64 key = hash_string(string, length);
    if (key == 0) key = 1;

    String_Table_Entry *entry = (String_Table_Entry*) hash_get(&table->map, key);
    if (entry != null) {
        while (true) {
            if (entry->length == length && mem_cmp(entry->string, string, length)) {
                return entry->string;
            }

            if (entry->next != null) {
                entry = entry->next;
            } else {
                break;
            }
        }
    }

    u64 entry_length = 16 + length + 1;

    if (table->arena == null || table->arena_length + entry_length > STRING_TABLE_ARENA_CAPACITY) {
        table->arena = (u8*) sc_alloc(STRING_TABLE_ARENA_CAPACITY);
        table->arena_length = 0;
    }

    String_Table_Entry *new_entry = (String_Table_Entry*) (table->arena + table->arena_length);
    table->arena_length += entry_length;

    new_entry->length = length;
    new_entry->next = null;
    mem_copy(string, new_entry->string, length);
    new_entry->string[length] = 0;

    if (entry == null) {
        hash_insert(&table->map, key, (u64) new_entry);
    } else {
        assert(entry->next == null);
        entry->next = new_entry;
    }

    return new_entry->string;
}

u8 *string_intern(String_Table *table, u8 *string) {
    u64 length = str_length(string);
    return string_intern_with_length(table, string, length);
}

// Other utilities

u64 eat_word(u8 **str) {
    u64 length = 0;
    while (**str != ' ' && **str != 0) {
        length += 1;
        *str += 1;
    }
    while (**str == ' ' && **str != 0) {
        *str += 1;
    }
    return length;
}


u8 *str_null_terminate(Arena *arena, u8 *str, u64 length) {
    u8 *result = arena_alloc(arena, length + 1);
    result[length] = 0;
    mem_copy(str, result, length);
    return result;
}

u8 *str_join(Arena *arena, u8 *left, u8 *right) {
    u64 left_length = str_length(left);
    u64 right_length = str_length(right);
    u8 *result = arena_alloc(arena, left_length + right_length + 1);
    mem_copy(left, result, left_length);
    mem_copy(right, result + left_length, left_length);
    result[left_length + right_length] = 0;
    return result;
}


// Printing

u8 *printf_buf; // Heh, this is gnarly af.

u8 char_for_digit(u8 c);

void printf_flush() {
    print(printf_buf, buf_length(printf_buf));
    buf_clear(printf_buf);
}

void printf(u8* string, ...) {
    va_list args = {0};
    va_start(args, string);
    buf_printf_internal(&printf_buf, string, args); 
    va_end(args);

    bool contains_newline = false;
    for (u8 *c = string; *c != 0; c += 1) {
        if (*c == '\n') {
            contains_newline = true;
            break;
        }
    }

    if (buf_length(printf_buf) > 10000 || contains_newline > 0) {
        printf_flush();
    }
}

u8 char_for_digit(u8 c) {
    if (c <= 9) {
        return '0' + c;
    } else {
        return 'a' + (c - 10);
    }
}

void buf_printf(u8 **buffer, u8 *string, ...) {
    va_list args = {0};
    va_start(args, string);
    buf_printf_internal(buffer, string, args); 
    va_end(args);
}

void buf_printf_integer(u8 **buffer, u64 value, u8 base) {
    u64 start_index = buf_length(*buffer);
    u64 length = 0;
    do {
        u8 digit = value % base;
        value = value / base;

        buf_push(*buffer, char_for_digit(digit));

        length += 1;
    } while (value != 0);

    for (u64 i = 0; i < length/2; i += 1) {
        u64 a = start_index + i;
        u64 b = start_index + length - i - 1;
        u8 temp = (*buffer)[b];
        (*buffer)[b] = (*buffer)[a];
        (*buffer)[a] = temp;
    }
}

void buf_printf_internal(u8 **buffer, u8 *string, va_list args) {
    for (u8* t = string; *t != '\0'; t += 1) {
        if (*t != '%') {
            buf_push(*buffer, *t);
        } else {
            u8 type = *(t + 1);

            switch (type) {
                case 'i': {
                    i64 value = va_arg(args, i64);
                    if (value < 0) {
                        buf_push(*buffer, '-');
                        value = -value;
                    }
                    buf_printf_integer(buffer, value, 10);
                } break;

                case 'u': {
                    u64 value = va_arg(args, u64);
                    buf_printf_integer(buffer, value, 10);
                } break;

                // Format numbers as 1st, 2nd, 3rd, 4th, etc...
                case 'n': {
                    u64 value = va_arg(args, u64);
                    buf_printf_integer(buffer, value, 10);

                    switch (value) {
                        case 1:  buf_push(*buffer, 's'); buf_push(*buffer, 't'); break;
                        case 2:  buf_push(*buffer, 'n'); buf_push(*buffer, 'd'); break;
                        case 3:  buf_push(*buffer, 'r'); buf_push(*buffer, 'd'); break;
                        default: buf_push(*buffer, 't'); buf_push(*buffer, 'h'); break;
                    }
                } break;

                case 'c': {
                    u8 value = va_arg(args, u8);

                    if (value >= 0x20) {
                        buf_push(*buffer, value);
                    } else {
                        buf_push(*buffer, '\\');

                        switch (value) {

                        case '\n': buf_push(*buffer, 'n'); break;
                        case '\r': buf_push(*buffer, 'r'); break;
                        case '\t': buf_push(*buffer, 't'); break;

                        default: {
                            buf_push(*buffer, 'x');

                            u8 hi = (value & 0xf0) >> 4;
                            if (hi > 9)  buf_push(*buffer, 'a' + hi);
                            else         buf_push(*buffer, '0' + hi);
                            u8 lo = (value & 0x0f);
                            if (lo > 9)  buf_push(*buffer, 'a' + lo);
                            else         buf_push(*buffer, '0' + lo);
                        } break;

                        }
                    }

                } break;

                case 'f': {
                    f64 value = va_arg(args, f64);
                    u64 bits = *((u64*) &value);

                    buf_push(*buffer, '0');
                    buf_push(*buffer, 'x');
                    buf_printf_integer(buffer, bits, 16);
                } break;

                case 'x': {
                    buf_push(*buffer, '0');
                    buf_push(*buffer, 'x');
                    u64 value = va_arg(args, u64);
                    buf_printf_integer(buffer, value, 16);
                } break;

                case 'b': {
                    u8 byte = va_arg(args, u8);

                    u8 hi = byte >> 4;
                    u8 lo = byte & 0x0f;

                    buf_push(*buffer, char_for_digit(hi));
                    buf_push(*buffer, char_for_digit(lo));
                } break;

                case 's': {
                    u8* other_string = va_arg(args, u8*);
                    assert(other_string != null);
                    str_push_cstr(buffer, other_string);
                } break;

                case 'z': {
                    u64 length = va_arg(args, u64);
                    u8* other_string = va_arg(args, u8*);
                    str_push_str(buffer, other_string, length);
                } break;

                case '%': {
                    buf_push(*buffer, '%');
                } break;

                default: {
                    buf_push(*buffer, type);
                    buf_push(*buffer, '?');
                } break;
            }

            t += 1;
        }
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

u8 *path_get_filename(u8 *path) {
    u8 *filename = path;
    while (*path != 0) {
        if (*path == '/' || *path == '\\') filename = path + 1;
        path += 1;
    }
    return filename;
}

u8 *path_join(Arena *arena, u8 *a, u8 *b) {
    u64 a_length = str_length(a);
    u64 b_length = str_length(b);
    u8 *new_path = arena_alloc(arena, a_length + b_length + 1);

    u64 b_start = a_length;
    if (a[a_length - 1] != '/' && a[a_length - 1] != '\\') {
        new_path[b_start] = '\\';
        b_start += 1;
    }
    if (b[0] == '/' || b[0] == '\\') {
        b += 1;
        b_length -= 1;
    }

    mem_copy(a, new_path, a_length);
    mem_copy(b, new_path + b_start, b_length + 1);

    return new_path;
}

u8 *io_result_message(IO_Result result) {
    switch (result) {
        case IO_OK:                         return "Ok";
        case IO_INVALID_FILE_PATH_ENCODING: return "Invalid file path encoding";
        case IO_ERROR:                      return "IO Error";
        case IO_NOT_FOUND:                  return "File not found";
        case IO_ALREADY_OPEN:               return "File is open in another program";
        default: assert(false);             return null;
    }
}


u64 round_to_next(u64 value, u64 step) {
    if (step > 0) {
        value += step - 1;
        value /= step;
        value *= step;
    }

    return value;
}


#if WINDOWS
    Handle stdout;
    Handle process_heap;

    void main();
    void program_entry() {
        stdout = GetStdHandle(STD_OUTPUT_HANDLE);
        process_heap = GetProcessHeap();
        QueryPerformanceFrequency(&perf_frequency);
        main();
        printf_flush();
        ExitProcess(0);
    }

    i64 perf_time() {
        i64 result = 0;
        QueryPerformanceCounter(&result);
        return result;
    }

    u64 unix_time() {
        // This is a mess, but it's not my fault
       File_Time t;
       GetSystemTimeAsFileTime(&t);
       u64 ticks = t.lo | (((u64) t.hi) << 32);
       return (ticks - 0x019db1ded53e8000) / 10000000;
    }

    void sleep(u32 milliseconds) {
        Sleep(milliseconds);
    }

    void *sc_alloc(u64 size) {
        return HeapAlloc(process_heap, 0, size);
    }
    void *sc_realloc(void *mem, u64 size) {
        return HeapReAlloc(process_heap, 0, mem, size);
    }
    bool sc_free(void *mem) {
        return HeapFree(process_heap, 0, mem);
    }

    u64 utf8_to_wide(u8 *input, u64 input_length, u16 *output, u64 output_length) {
        u64 actual_length = 0;

        for (u64 i = 0; i < input_length; i += 1)  {
            i32 codepoint; // Signed is fine, full unicode is less than 32 bits

            u8 first = input[i];
            i32 encoded_length = utf8_byte_length(first);
            switch (encoded_length) {
                case 1: {
                    codepoint = first;
                } break;

                case 2: {
                    if (i + 1 >= input_length) {
                        codepoint = -1;
                    } else {
                        u8 second = input[i + 1];

                        if (!utf8_byte_is_continuation(second)) {
                            codepoint = -1;
                        } else {
                            codepoint = ((first & 0x1f) << 6) | (second & 0x3f);
                            i += 1;
                        }
                    }
                } break;

                case 3: {
                    if (i + 2 >= input_length) {
                        codepoint = -1;
                    } else {
                        u8 second = input[i + 1];
                        u8 third  = input[i + 2];

                        if (!utf8_byte_is_continuation(second) || !utf8_byte_is_continuation(third)) {
                            codepoint = -1;
                        } else {
                            codepoint = ((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f);
                            i += 2;
                        }
                    }
                } break;

                case 4: {
                    if (i + 3 >= input_length) {
                        codepoint = -1;
                    } else {
                        u8 second = input[i + 1];
                        u8 third  = input[i + 2];
                        u8 fourth = input[i + 3];

                        if (!utf8_byte_is_continuation(second) ||
                            !utf8_byte_is_continuation(third) ||
                            !utf8_byte_is_continuation(fourth)) {
                            codepoint = -1;
                        } else {
                            codepoint = ((first & 0x07) << 18) | ((second & 0x3f) << 12) | ((third & 0x3f) << 6) | (fourth & 0x3f);
                            i += 3;
                        }
                    }
                } break;

                case 0:
                case -1:
                {
                    codepoint = -1;
                } break;
            }

            // Overlong encodings
            // if (encoded_length == 2 && codepoint <= 0x7f) codepoint = -1; // We check for this in 'utf8_byte_length'
            if (encoded_length == 3 && codepoint <= 0x7ff) codepoint = -1;
            if (encoded_length == 4 && codepoint <= 0xffff) codepoint = -1;

            // Codepoints reserved for utf16 surogate pairs
            //if (codepoint >= 0xd800 && codepoint <= 0xdfff) codepoint = -1;
            // We keep these codepoints around, because apparently windows file names can contain
            // them, which means we need to respect them.

            if (codepoint == -1) {
                output[actual_length++] = 0xfffd;

                while (i < input_length && utf8_byte_is_continuation(input[i])) {
                    i += 1;
                }
            } else if ((codepoint & 0xffff) == codepoint) {
                output[actual_length++] = (u16) codepoint;
            } else {
                codepoint -= 0x10000;
                u16 high = 0xd800 | ((codepoint >> 10) & 0x03ff);
                u16 low  = 0xdc00 | (codepoint & 0x03ff);
                output[actual_length++] = (u16) high;
                output[actual_length++] = (u16) low;
            }
        }

        if (actual_length <= output_length) {
            return actual_length;
        } else {
            return U64_MAX;
        }
    }

    u16 *utf8_to_wide_cstr(u8 *input) {
        u64 input_length = 0;
        for (u8 *p = input; *p != 0; p += 1) input_length += 1;

        u16 *result = (u16*) sc_alloc((input_length + 1) * sizeof(u16));
        u64 result_length = utf8_to_wide(input, input_length, result, input_length + 1);
        if (result_length == U64_MAX) {
            return null;
        } else {
            result[result_length] = 0;
            return result;
        }
    }

    void print(u8 *buffer, u32 buffer_length) {
        static u16 *wide_buffer = null;
        static u32 wide_buffer_capacity = 0;
        if (buffer_length + 1 > wide_buffer_capacity) {
            if (wide_buffer != null) sc_free(wide_buffer);
            wide_buffer_capacity = max(max(wide_buffer_capacity*2, buffer_length+1), 128);
            wide_buffer = sc_alloc(sizeof(u16) * wide_buffer_capacity);
        }

        u16 *wide_result = wide_buffer;
        u64 wide_length = utf8_to_wide(buffer, buffer_length, wide_result, wide_buffer_capacity);
        wide_result[wide_length] = 0; // For 'OutputDebugStringW'

        if (wide_length == U64_MAX) {
            wide_result = u"<invalid utf8>";
            wide_length = 14;
        }

        u32 written = 0;
        i32 success = WriteConsoleW(stdout, wide_result, (u32) wide_length, &written, null);
        if (!success || written != wide_length) {
            u32 error_code = GetLastError();
            ExitProcess(error_code);
        }

        #ifdef DEBUG
        OutputDebugStringW(wide_result);
        #endif
    }

    IO_Result get_temp_path(u8 *path_into, u32 *length) {
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

    IO_Result read_entire_file(u8 *file_name, u8 **contents, u32 *length) {
        u16 *wide_name = utf8_to_wide_cstr(file_name);
        if (wide_name == null) {
            return IO_INVALID_FILE_PATH_ENCODING;
        }

        Handle file = CreateFileW(wide_name, GENERIC_READ, 0, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
        sc_free(wide_name);

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

        *contents = sc_alloc(file_size);

        u32 read = 0;
        i32 success = ReadFile(file, *contents, file_size, &read, null);
        if (!success || read != file_size) {
            sc_free(*contents);
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

    IO_Result write_entire_file(u8 *file_name, u8 *contents, u32 length) {
        u16 *wide_name = utf8_to_wide_cstr(file_name);
        if (wide_name == null) {
            return IO_INVALID_FILE_PATH_ENCODING;
        }

        Handle file = CreateFileW(wide_name, GENERIC_WRITE, 0, null, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, null);
        sc_free(wide_name);

        if (file == INVALID_HANDLE_VALUE) {
            u32 error_code = GetLastError();
            switch (error_code) {
                case 2:  return IO_NOT_FOUND; // File not found
                case 3:  return IO_NOT_FOUND; // Path not found
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

    IO_Result delete_file(u8 *file_name) {
        bool result = DeleteFileA(file_name);
        if (!result) {
            u32 error_code = GetLastError();
            switch (error_code) {
                case 2:  return IO_NOT_FOUND; // File not found
                case 3:  return IO_NOT_FOUND; // Path not found
                default: return IO_ERROR;
            }
        } else {
            return IO_OK;
        }
    }

    bool run_executable(u8 *exe_path) {
        Startup_Info startup_info = {0};
        startup_info.size = sizeof(Startup_Info);
        Process_Info process_info = {0};
        bool result = CreateProcessA(exe_path, "", null, null, false, 0, null, null, &startup_info, &process_info);
        if (!result) return false;

        WaitForSingleObject(process_info.process, U32_MAX);

        return true;
    }

    u8 *get_cmd_args() {
        return GetCommandLineA();
    }

    u32 get_env_variable(u8 *name, u8 *buffer, u32 buffer_length) {
        return GetEnvironmentVariableA(name, buffer, buffer_length);
    }
#endif


// We need these for when MSVC auto-inserts them in /O2 builds
/*
#pragma function(memset)
void *memset(void *dest, i32 value, u64 count) {
    mem_fill(dest, (u8) value, count);
    return ((u8*) dest) + count;
}
#pragma function(memcpy)
void *memcpy(void *dest, void *src, u64 count) {
    mem_copy(src, dest, count);
    return ((u8*) dest) + count;
}
*/


#endif // SC_COMMON_C
