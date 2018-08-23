#ifndef COMMON_C
#define COMMON_C

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

int _fltused; // To make floating point work without the crt

#include <stdarg.h>
#include <xmmintrin.h>
#include <emmintrin.h>


// NB These are platform independent
void printf(u8* string, ...);
void printf_flush();

typedef enum IO_Result {
    IO_OK = 0,

    IO_ERROR,
    IO_NOT_FOUND,
    IO_ALREADY_OPEN,
} IO_Result;
u8 *io_result_message(IO_Result result);

// Forward declarations for platform dependent stuff
i64 perf_frequency;
i64 perf_time();
u64 unix_time();

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
    WINAPI_PRE bool WINAPI_POST DeleteFileA(u8 *file_name);

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

    WINAPI_PRE u8* WINAPI_POST GetCommandLineA(void);
    WINAPI_PRE u32 WINAPI_POST GetEnvironmentVariableA(u8 *name, u8 *buffer, u32 size);

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

    #ifdef DEBUG
    #define trap_or_exit()   (DebugBreak(), ExitProcess(-1))
    #else
    #define trap_or_exit()   (ExitProcess(-1))
    #endif

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

    void *sc_alloc(u64 size) {
        return HeapAlloc(process_heap, 0, size);
    }
    void *sc_realloc(void *mem, u64 size) {
        return HeapReAlloc(process_heap, 0, mem, size);
    }
    bool sc_free(void *mem) {
        return HeapFree(process_heap, 0, mem);
    }

    void print(u8 *buffer, u32 buffer_length) {
        u32 written = 0;
        i32 success = WriteFile(stdout, buffer, buffer_length, &written, null);
        if (!success || written != buffer_length) {
            u32 error_code = GetLastError();
            ExitProcess(error_code);
        }
    }

    void print_debug(u8 *buffer) {
        OutputDebugStringA(buffer);
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
        Handle file = CreateFileA(file_name, GENERIC_WRITE, 0, null, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, null);
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
        Arena_Page* page = (Arena_Page*) sc_alloc(sizeof(Arena_Page) + ARENA_PAGE_SIZE);
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

void printf_integer(u64 value, u8 base);
u8 char_for_digit(u8 c);

void printf_flush() {
    #ifdef DEBUG
    buf_push(printf_buf, '\0');
    print_debug(printf_buf);
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
        case IO_OK:             return "Ok";
        case IO_ERROR:          return "IO Error";
        case IO_NOT_FOUND:      return "File not found";
        case IO_ALREADY_OPEN:   return "File is open in another program";
        default: assert(false); return null;
    }
}

#endif // COMMON_C ...
