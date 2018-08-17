
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
#define I64_MAX 9223372036854775807ull
#define I64_MIN -9223372036854775808ll

#define max(a, b)  ((a) > (b)? (a) : (b))
#define min(a, b)  ((a) > (b)? (b) : (a))

int _fltused; // To make floating point work without the crt

#include <stdarg.h>
#include <xmmintrin.h>
#include <emmintrin.h>

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
    VOID        = 1,
    BOOL        = 2,
    U8          = 4,
    U16         = 5,
    U32         = 6,
    U64         = 7,
    I8          = 8,
    I16         = 9,
    I32         = 10,
    I64         = 11,
    F32         = 13,
    F64         = 14,
    POINTER     = 15,
    ARRAY       = 16,
    STRUCT      = 18,
    ENUM        = 19,
    FN_POINTER  = 20,
}

// NB Don't change the definition of this struct. It's exact definition is depended
// upon in 'machinecode_for_expr', when generating code for 'EXPR_STRING_LITERAL',
// 'EXPR_SUBSCRIPT' and 'EXPR_ENUM_MEMBER_NAME'.
struct String {
    data: *u8;
    length: i64;
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
    if (step > 0) {
        value += step - 1;
        value /= step;
        value *= step;
    }

    return value;
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

// Memory
// NB I don't like prefixing these, but msvc polutes my namespaces

void *sc_alloc(u64 size) {
    return HeapAlloc(process_heap, 0, size);
}
void *sc_realloc(void *mem, u64 size) {
    return HeapReAlloc(process_heap, 0, mem, size);
}
bool sc_free(void *mem) {
    return HeapFree(process_heap, 0, mem);
}

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

// NB only works on u8* buffers!
#define str_push_type(b, type, value) (_buf_fit(b, sizeof(type)), *((type*) ((b) + buf_length(b))) = (type) (value), _buf_header(b)->length += sizeof(type))


// Arenas
// Pointers remain valid throughout entire lifetime, but you can't remove individual
// elements, only append to the end. 
// We also have functions to use arenas as stack allocators.

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


u8 *make_null_terminated(Arena *arena, u8 *str, u64 length) {
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


typedef struct File_Pos {
    u8 *file_name;
    u32 line;
    u32 character;
} File_Pos;

void print_file_pos(File_Pos* pos) {
    u8* name = pos->file_name;
    if (name == null) name = "<unkown file>";
    printf("%s(%u): ", name, (u64) pos->line);
}


enum { KEYWORD_COUNT = 19 };

typedef struct Token {
    enum {
        TOKEN_END_OF_STREAM = 0,

        TOKEN_BRACKET_ROUND_OPEN   = '(',
        TOKEN_BRACKET_ROUND_CLOSE  = ')',
        TOKEN_BRACKET_SQUARE_OPEN  = '[',
        TOKEN_BRACKET_SQUARE_CLOSE = ']',
        TOKEN_BRACKET_CURLY_OPEN   = '{',
        TOKEN_BRACKET_CURLY_CLOSE  = '}',

        TOKEN_SEMICOLON    = ';',
        TOKEN_COMMA        = ',',
        TOKEN_DOT          = '.',
        TOKEN_COLON        = ':',
        TOKEN_QUESTIONMARK = '?',
        TOKEN_UNDERSCORE   = '_',

        TOKEN_ADD = '+',
        TOKEN_SUB = '-',
        TOKEN_MUL = '*', // also used for pointers
        TOKEN_DIV = '/',
        TOKEN_MOD = '%',

        TOKEN_AND = '&',
        TOKEN_NOT = '!',
        TOKEN_OR  = '|',
        TOKEN_XOR = '^',

        TOKEN_GREATER = '>',
        TOKEN_LESS = '<',
        TOKEN_ASSIGN = '=',

        __TOKEN_SEPARATOR = 128, // Values before this use literal ascii character codes, to simplify some parsing

        TOKEN_STATIC_ACCESS, // "::"
        TOKEN_RANGE, // ".."

        TOKEN_GREATER_OR_EQUAL, // ">="
        TOKEN_LESS_OR_EQUAL, // "<="
        TOKEN_EQUAL, // "=="
        TOKEN_NOT_EQUAL, // "!="
        TOKEN_ARROW, // "->"

        TOKEN_SHIFT_LEFT, // "<<"
        TOKEN_SHIFT_RIGHT, // ">>"

        TOKEN_LOGICAL_AND,
        TOKEN_LOGICAL_OR,

        TOKEN_IDENTIFIER,
        TOKEN_LITERAL_INT,
        TOKEN_LITERAL_FLOAT,
        TOKEN_LITERAL_CHAR,
        TOKEN_STRING,

        TOKEN_KEYWORD_FN,
        TOKEN_KEYWORD_EXTERN,
        TOKEN_KEYWORD_TYPEDEF,
        TOKEN_KEYWORD_LET,
        TOKEN_KEYWORD_CONST,
        TOKEN_KEYWORD_IF,
        TOKEN_KEYWORD_SWITCH,
        TOKEN_KEYWORD_ELSE,
        TOKEN_KEYWORD_FOR,
        TOKEN_KEYWORD_RETURN,
        TOKEN_KEYWORD_CONTINUE,
        TOKEN_KEYWORD_BREAK,
        TOKEN_KEYWORD_DEBUG_BREAK,
        TOKEN_KEYWORD_STRUCT,
        TOKEN_KEYWORD_ENUM,
        TOKEN_KEYWORD_UNION,
        TOKEN_KEYWORD_NULL,
        TOKEN_KEYWORD_TRUE,
        TOKEN_KEYWORD_FALSE,

        TOKEN_KIND_COUNT,
    } kind;

    union {
        u8 *identifier;

        u64 literal_int;
        f64 literal_float;
        u8 literal_char;

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
    [TOKEN_LOGICAL_AND]          = "&&",
    [TOKEN_LOGICAL_OR]           = "||",

    [TOKEN_DOT]                  = "a dot '.'",
    [TOKEN_SEMICOLON]            = "a semicolon ';'",
    [TOKEN_COMMA]                = "a comma ','",
    [TOKEN_COLON]                = "a colon ':'",
    [TOKEN_QUESTIONMARK]         = "a question mark '?'",
    [TOKEN_UNDERSCORE]           = "a underscore '_'",
    [TOKEN_STATIC_ACCESS]        = "::",
    [TOKEN_RANGE]                = "..",

    [TOKEN_BRACKET_ROUND_OPEN]   = "an opening parenthesis '('",
    [TOKEN_BRACKET_ROUND_CLOSE]  = "a closing parenthesis ')'",
    [TOKEN_BRACKET_SQUARE_OPEN]  = "an opening square bracket '['",
    [TOKEN_BRACKET_SQUARE_CLOSE] = "a closing square bracket ']'",
    [TOKEN_BRACKET_CURLY_OPEN]   = "an opening curly brace '{'",
    [TOKEN_BRACKET_CURLY_CLOSE]  = "a closing curly brace '}'",

    [TOKEN_KEYWORD_FN]           = "fn",
    [TOKEN_KEYWORD_EXTERN]       = "extern",
    [TOKEN_KEYWORD_TYPEDEF]      = "typedef",
    [TOKEN_KEYWORD_LET]          = "let",
    [TOKEN_KEYWORD_CONST]        = "const",
    [TOKEN_KEYWORD_IF]           = "if",
    [TOKEN_KEYWORD_SWITCH]       = "switch",
    [TOKEN_KEYWORD_ELSE]         = "else",
    [TOKEN_KEYWORD_FOR]          = "for",
    [TOKEN_KEYWORD_RETURN]       = "return",
    [TOKEN_KEYWORD_CONTINUE]     = "continue",
    [TOKEN_KEYWORD_BREAK]        = "break",
    [TOKEN_KEYWORD_DEBUG_BREAK]  = "debug_break",
    [TOKEN_KEYWORD_STRUCT]       = "struct",
    [TOKEN_KEYWORD_ENUM]         = "enum",
    [TOKEN_KEYWORD_UNION]        = "union",
    [TOKEN_KEYWORD_TRUE]         = "true",
    [TOKEN_KEYWORD_FALSE]        = "false",
    [TOKEN_KEYWORD_NULL]         = "null",
};


typedef enum Builtin_Fn {
    BUILTIN_INVALID = 0,

    BUILTIN_TYPE_INFO_OF_TYPE,
    BUILTIN_TYPE_INFO_OF_VALUE,
    BUILTIN_ENUM_MEMBER_NAME,
    BUILTIN_ENUM_LENGTH,
    BUILTIN_CAST,
    BUILTIN_SIZE_OF,
    BUILTIN_ALIGN_OF,
    BUILTIN_SQRT,

    BUILTIN_COUNT,
} Builtin_Fn;


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

    TYPE_FN_POINTER = 20,

    TYPE_KIND_COUNT = 21,
} Type_Kind;

enum { POINTER_SIZE = 8 };
#define TYPE_DEFAULT_INT   ((Type_Kind) TYPE_I64)
#define TYPE_CHAR          ((Type_Kind) TYPE_U8)
#define TYPE_DEFAULT_FLOAT ((Type_Kind) TYPE_F32)
#define TYPE_POINTER_DIFF  ((Type_Kind) TYPE_I64)

u8 *PRIMITIVE_NAMES[TYPE_KIND_COUNT] = {
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

    [TYPE_INVALID]    = "<invalid>",
    [TYPE_POINTER]    = "<pointer>",
    [TYPE_ARRAY]      = "<array>",
    [TYPE_FN_POINTER] = "<fn ptr>",

    [TYPE_STRUCT]          = "<struct>",
    [TYPE_ENUM]            = "<enum>",
    [TYPE_UNRESOLVED_NAME] = "<unresolved>",

};


enum {
    TYPE_FLAG_SIZE_NOT_COMPUTED = 0x01,
    TYPE_FLAG_UNRESOLVED        = 0x02,
    TYPE_FLAG_UNRESOLVED_CHILD  = 0x04,
};

typedef struct Type Type;
typedef struct Type_List Type_List;
typedef struct Expr Expr;
typedef struct Stmt Stmt;
typedef struct Fn Fn;
typedef struct Var Var;

typedef struct Decl {
    enum {
        DECL_VAR = 0,
        DECL_FN = 1,
        DECL_TYPE = 2,
    } kind;

    u32 scope_pos;
    u8 *name;
    File_Pos pos;

    union {
        Var *var;
        Fn *fn;
        Type *type;
        Type *def;
    };
} Decl;

typedef struct Scope Scope;
struct Scope {
    Fn *fn;
    Scope *parent;

    Decl *decls;
    u32 decls_length, decls_allocated;

    u32 next_scope_pos; // incremented for each Decl or Stmt
};


typedef struct Fn_Signature {
    bool has_return;
    bool return_by_reference; // otherwise return in RAX, which we can even do for structs. See reference/notes.md
    Type *return_type;

    struct {
        Type *type;
        bool reference_semantics;
    } *params;
    u32 param_count;
} Fn_Signature;

struct Type {
    Type_Kind kind;
    u32 flags;

    union {
        u8 *primitive_name;
        u8 *unresolved_name;

        struct {
            u8 *name;

            u32 member_count;
            struct {
                u8 *name;
                Type* type;
                i32 offset;
                File_Pos declaration_pos;
            } *members;

            u32 size, align;
        } structure;

        struct {
            u8 *name;

            u32 member_count;
            struct {
                u8 *name;
                u64 value;
                File_Pos declaration_pos;
            } *members;

            Type_Kind value_primitive;

            u64 name_table_data_offset; // U64_MAX if we haven't generated the table!
            u64 name_table_invalid_offset;
            u64 name_table_entries;
        } enumeration;
        
        struct {
            union {
                // if 'TYPE_FLAG_UNRESOLVED' is set, we don't use 'length', if 'expr' is null,
                // size has to be infered from a compound literal, if it is not null it is a
                // compile time expr which evaluates to the proper length.
                Expr *length_expr;

                u64 length;
            };
            Type *of;
        } array;

        Type *pointer_to;

        Fn_Signature fn_signature;
    };

    Type *pointer_type;
    Type_List *array_types;
};

struct Type_List {
    Type type;
    Type_List *next;
};


enum {
    VAR_FLAG_REFERENCE  = 0x01, // for parameters
    VAR_FLAG_CONSTANT   = 0x02, // not assignables, in .rdata if global
    VAR_FLAG_GLOBAL     = 0x04, // in .data or .rdata
    VAR_FLAG_LOOSE_TYPE = 0x08, // no type given, rhs is weak
};

struct Var {
    u8 *name;
    Type *type; // We set this to 'null' to indicate that we want to infer the type
    File_Pos declaration_pos;
    u8 flags;
    union { u32 global_index; u32 local_index; };
};

typedef struct Global_Var {
    Var *var;

    u32 data_offset;

    bool checked;
    bool valid;
    bool compute_at_runtime;
    bool in_rdata;
} Global_Var;

typedef struct Global_Let {
    File_Pos pos;
    Scope *scope;

    Var *vars;
    u32 var_count;
    Expr *expr;

    bool compute_at_runtime;
} Global_Let;


typedef enum Unary_Op {
    UNARY_OP_INVALID = 0,

    UNARY_NOT,
    UNARY_NEG,
    UNARY_DEREFERENCE,
    UNARY_ADDRESS_OF,
    UNARY_SQRT,

    UNARY_OP_COUNT,
} Unary_Op;

u8* UNARY_OP_SYMBOL[UNARY_OP_COUNT] = {
    [UNARY_NOT]         = "!",
    [UNARY_NEG]         = "-",
    [UNARY_DEREFERENCE] = "*",
    [UNARY_ADDRESS_OF]  = "&",
    [UNARY_SQRT]        = "<sqrt>",
};

typedef enum Binary_Op {
    BINARY_OP_INVALID = 0,

    BINARY_ADD,
    BINARY_SUB,
    BINARY_MUL,
    BINARY_DIV,
    BINARY_MOD,

    BINARY_AND,
    BINARY_OR,
    BINARY_XOR,

    BINARY_SHR,
    BINARY_SHL,

    BINARY_LOGICAL_AND,
    BINARY_LOGICAL_OR,

    BINARY_EQ,
    BINARY_NEQ,
    BINARY_GT,
    BINARY_GTEQ,
    BINARY_LT,
    BINARY_LTEQ,

    BINARY_OP_COUNT,
} Binary_Op;

u8 BINARY_OP_PRECEDENCE[BINARY_OP_COUNT] = {
    [BINARY_MUL] = 4,
    [BINARY_DIV] = 4,
    [BINARY_MOD] = 4,

    [BINARY_ADD] = 3,
    [BINARY_SUB] = 3,

    // NB we do this differently from what many other languages do, because I don't find
    // that I actually remember what the precedence of these is. Having them be on the
    // same precedence level and then just using parentheses seems simpler.
    [BINARY_AND] = 2,
    [BINARY_XOR] = 2,
    [BINARY_OR]  = 2,
    [BINARY_SHR] = 2,
    [BINARY_SHL] = 2,

    [BINARY_NEQ] = 1,
    [BINARY_EQ] = 1,
    [BINARY_GT] = 1,
    [BINARY_GTEQ] = 1,
    [BINARY_LT] = 1,
    [BINARY_LTEQ] = 1,

    [BINARY_LOGICAL_AND] = 0,
    [BINARY_LOGICAL_OR] = 0,
};

bool BINARY_OP_COMPARATIVE[BINARY_OP_COUNT] = {
    [BINARY_NEQ]  = true,
    [BINARY_EQ]   = true,
    [BINARY_GT]   = true,
    [BINARY_GTEQ] = true,
    [BINARY_LT]   = true,
    [BINARY_LTEQ] = true,
};

bool BINARY_OP_CAN_BE_USED_FOR_OP_ASSIGNMENT[BINARY_OP_COUNT] = {
    [BINARY_ADD] = true,
    [BINARY_SUB] = true,
    [BINARY_MUL] = true,
    [BINARY_DIV] = true,
    [BINARY_MOD] = true,
    [BINARY_AND] = true,
    [BINARY_OR]  = true,
    [BINARY_XOR] = true,
    [BINARY_SHL] = true,
    [BINARY_SHR] = true,
};

u8 *BINARY_OP_SYMBOL[BINARY_OP_COUNT] = {
    [BINARY_ADD] = "+",
    [BINARY_SUB] = "-",
    [BINARY_MUL] = "*",
    [BINARY_DIV] = "/",
    [BINARY_MOD] = "%",

    [BINARY_AND] = "&",
    [BINARY_OR]  = "|",
    [BINARY_XOR] = "^",

    [BINARY_SHL] = "<<",
    [BINARY_SHR] = ">>",

    [BINARY_LOGICAL_AND]  = "&&",
    [BINARY_LOGICAL_OR]   = "||",

    [BINARY_NEQ]  = "!=",
    [BINARY_EQ]   = "==",
    [BINARY_GT]   = ">",
    [BINARY_GTEQ] = ">=",
    [BINARY_LT]   = "<",
    [BINARY_LTEQ] = "<=",
};

Binary_Op TOKEN_TO_BINARY_OP_MAP[TOKEN_KIND_COUNT] = {
    [TOKEN_ADD] = BINARY_ADD,
    [TOKEN_SUB] = BINARY_SUB,
    [TOKEN_MUL] = BINARY_MUL,
    [TOKEN_DIV] = BINARY_DIV,
    [TOKEN_MOD] = BINARY_MOD,

    [TOKEN_AND] = BINARY_AND,
    [TOKEN_OR]  = BINARY_OR,
    [TOKEN_XOR] = BINARY_XOR,

    [TOKEN_SHIFT_RIGHT] = BINARY_SHR,
    [TOKEN_SHIFT_LEFT]  = BINARY_SHL,

    [TOKEN_LOGICAL_AND] = BINARY_LOGICAL_AND,
    [TOKEN_LOGICAL_OR]  = BINARY_LOGICAL_OR,

    [TOKEN_GREATER]          = BINARY_GT,
    [TOKEN_GREATER_OR_EQUAL] = BINARY_GTEQ,
    [TOKEN_LESS]             = BINARY_LT,
    [TOKEN_LESS_OR_EQUAL]    = BINARY_LTEQ,
    [TOKEN_EQUAL]            = BINARY_EQ,
    [TOKEN_NOT_EQUAL]        = BINARY_NEQ,
};



typedef enum Primitive_Group {
    PRIMITIVE_GROUP_INVALID = 0,
    PRIMITIVE_GROUP_INT,
    PRIMITIVE_GROUP_POINTER,
    PRIMITIVE_GROUP_FLOAT,
    PRIMITIVE_GROUP_BOOL,
    PRIMITIVE_GROUP_COUNT,
} Primitive_Group;

Primitive_Group TYPE_KIND_TO_PRIMITIVE_GROUP_MAP[TYPE_KIND_COUNT] = {
    [TYPE_BOOL] = PRIMITIVE_GROUP_BOOL,

    [TYPE_U8]  = PRIMITIVE_GROUP_INT,
    [TYPE_U16] = PRIMITIVE_GROUP_INT,
    [TYPE_U32] = PRIMITIVE_GROUP_INT,
    [TYPE_U64] = PRIMITIVE_GROUP_INT,
    [TYPE_I8]  = PRIMITIVE_GROUP_INT,
    [TYPE_I16] = PRIMITIVE_GROUP_INT,
    [TYPE_I32] = PRIMITIVE_GROUP_INT,
    [TYPE_I64] = PRIMITIVE_GROUP_INT,

    [TYPE_F32] = PRIMITIVE_GROUP_FLOAT,
    [TYPE_F64] = PRIMITIVE_GROUP_FLOAT,

    [TYPE_POINTER]    = PRIMITIVE_GROUP_POINTER,
    //[TYPE_FN_POINTER] = PRIMITIVE_GROUP_POINTER, // NB We only use this map for binary op validity, math on fn pointers makes no sense
};

bool BINARY_OP_VALIDITY_MAP[BINARY_OP_COUNT][PRIMITIVE_GROUP_COUNT] = {
                   /* invalid  int      pointer  float    bool */
    [BINARY_ADD] = { false,    true,    false,   true,    false },
    [BINARY_SUB] = { false,    true,    true,    true,    false },
    [BINARY_DIV] = { false,    true,    false,   true,    false },
    [BINARY_MUL] = { false,    true,    false,   true,    false },
    [BINARY_MOD] = { false,    true,    false,   false,   false },

    [BINARY_AND] = { false,    true,    true,    false,   true  },
    [BINARY_OR]  = { false,    true,    true,    false,   true  },
    [BINARY_XOR] = { false,    true,    true,    false,   true  },

    [BINARY_SHL] = { false,    true,    true,    false,   false  },
    [BINARY_SHR] = { false,    true,    true,    false,   false  },

    [BINARY_LOGICAL_AND] = { false, false, false, false, true },
    [BINARY_LOGICAL_OR]  = { false, false, false, false, true },
};


typedef struct Compound_Member {
    Expr *expr;

    enum {
        EXPR_COMPOUND_NO_NAME,
        EXPR_COMPOUND_UNRESOLVED_NAME,
        EXPR_COMPOUND_NAME
    } name_mode;

    union {
        u8 *unresolved_name;
        u32 member_index;
    };
} Compound_Member;

#define EXPR_FLAG_UNRESOLVED  0x01
#define EXPR_FLAG_ASSIGNABLE  0x02
#define EXPR_FLAG_ADDRESSABLE 0x04

typedef enum Expr_Kind {
    EXPR_VARIABLE,
    EXPR_LITERAL,
    EXPR_STRING_LITERAL,
    EXPR_COMPOUND,
    EXPR_UNARY,
    EXPR_BINARY,
    EXPR_TERNARY, // <foo>? <bar> : <baz>
    EXPR_CALL,
    EXPR_CAST,
    EXPR_SUBSCRIPT,
    EXPR_MEMBER_ACCESS, // a.b
    EXPR_STATIC_MEMBER_ACCESS, // a::b

    EXPR_ADDRESS_OF_FUNCTION,
    EXPR_TYPE_INFO_OF_TYPE,
    EXPR_TYPE_INFO_OF_VALUE,
    EXPR_ENUM_MEMBER_NAME,
    EXPR_QUERY_TYPE_INFO, // enum_length, size_of, align_of
} Expr_Kind;

struct Expr { // 'typedef'd earlier!
    Expr_Kind kind;
    u8 flags;
    Type *type;
    File_Pos pos;

    union {
        union { u8 *unresolved_name; Var *var; } variable; // discriminated by EXPR_FLAG_UNRESOLVED

        struct {
            u64 raw_value;
            u64 masked_value;

            enum {
                EXPR_LITERAL_INTEGER,
                EXPR_LITERAL_POINTER,
                EXPR_LITERAL_BOOL,
                EXPR_LITERAL_FLOAT, // 'value' is the bitpattern of a 'f64'
                EXPR_LITERAL_CHAR,
            } kind;
        } literal;

        struct {
            u8 *bytes; // null-terminated
            u64 length; // not including trailing \0
        } string;

        struct {
            Compound_Member *content;
            u32 count;
        } compound;

        struct {
            Unary_Op op;
            Expr *inner;
        } unary;

        struct {
            Binary_Op op;
            Expr *left, *right;
        } binary;

        struct {
            Expr *condition;
            Expr *left, *right;
        } ternary;


        struct {
            bool pointer_call; // if true, we try to call a function at runtime computed address

            union {
                u8 *unresolved_name; // if EXPR_FLAG_UNRESOLVED
                Expr *pointer_expr;  // else if pointer_call
                Fn *callee;
            };

            Expr **params; // []*Expr
            u32 param_count;
        } call;

        Type *type_info_of_type;
        Expr *type_info_of_value;
        Expr *cast_from;
        Expr *enum_member;
        Fn *address_of_fn;

        struct {
            enum {
                QUERY_TYPE_INFO_ENUM_LENGTH,
                QUERY_TYPE_INFO_SIZE,
                QUERY_TYPE_INFO_ALIGN,
            } query;
            Type *type;
        } query_type_info;

        struct {
            Expr *array;
            Expr *index;
        } subscript;

        struct {
            Expr *parent;
            union { u8 *member_name; u32 member_index; }; // discriminated by EXPR_FLAG_UNRESOLVED
        } member_access;

        struct {
            // Both unions discriminated by EXPR_FLAG_UNRESOLVED
            union { u8 *parent_name; Type *parent_type; };
            union { u8 *member_name; u32 member_index; };
        } static_member_access;
    };
};

typedef struct Switch_Case_Key {
    File_Pos pos;

    bool is_identifier;
    union { u8 *identifier; Expr *expr; };
    u64 value;
} Switch_Case_Key;

typedef struct Switch_Case {
    File_Pos pos;

    u32 key_count;
    Switch_Case_Key *keys;

    Stmt *body;
    Scope *scope;
} Switch_Case;


typedef enum Stmt_Kind {
    STMT_END = 0, // Sentinel, returned to mark that no more statements can be parsed

    STMT_LET,
    STMT_EXPR,
    STMT_ASSIGNMENT,
    STMT_OP_ASSIGNMENT,

    STMT_BLOCK,
    STMT_IF,
    STMT_FOR,
    STMT_SWITCH,

    STMT_RETURN,
    STMT_BREAK,
    STMT_CONTINUE,

    STMT_DEBUG_BREAK,
} Stmt_Kind;

struct Stmt {
    Stmt_Kind kind;
    File_Pos pos;
    Stmt* next;
    u32 scope_pos; // Monotonically inreacing within a scope. Used to disambiguate between shadowing declarations.

    union {
        struct {
            Var *vars;
            u32 var_count;

            Expr *right; // 'right' might be null
        } let;

        Expr *expr;

        struct {
            Expr *left;
            Expr *right;
        } assignment;

        struct {
            Expr *left;
            Expr *right;
            Binary_Op op;
        } op_assignment;

        struct {
            Stmt *stmt;
            Scope scope;
        } block;

        struct {
            Expr *condition;
            Stmt *then, *else_then;
            Scope then_scope, else_then_scope;
        } if_;

        struct {
            Expr *index;

            Switch_Case *default_case;
            Switch_Case *cases;
            u32 case_count;
        } switch_;

        struct {
            enum {
                LOOP_INFINITE,
                LOOP_CONDITIONAL,
                LOOP_RANGE,
            } kind;

            union {
                Expr *condition;
                struct {
                    Var *var;
                    Expr *start, *end;
                } range;
            };

            Stmt *body;
            Scope scope;
        } for_;

        struct {
            Expr *value;
            bool trailing;
        } return_;
    };
};


typedef enum Condition {
    // Equality
    COND_E, COND_NE,
    // Signed integers
    COND_G, COND_GE,
    COND_L, COND_LE,
    // Unsignedi integers, floating point
    COND_A, COND_AE,
    COND_B, COND_BE,
    // Parity
    COND_P, COND_NP,

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
    [COND_BE]  = "be",
    [COND_P]   = "p",
    [COND_NP]  = "np",
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
        case COND_P:  return COND_NP;
        case COND_NP: return COND_P;
        default: assert(false); return 0;
    }
}


typedef struct Import_Index {
    u32 library, function;
} Import_Index;

typedef struct Library_Import {
    u8 *importing_source_file; // NB not interned in the string table
    u8 *lib_name;
    u8 **function_names; // stretchy-buffer

    // Set in 'parse_library'
    u8 *dll_name; // NB not interned in the string table, I think...
    u32 *function_hints;
} Library_Import;

struct Fn {
    u8 *name;
    File_Pos declaration_pos;

    Type *signature_type;
    Fn_Signature *signature; // NB this should always be a pointer into 'signature_type'

    enum {
        FN_KIND_NORMAL, // use '.body'
        FN_KIND_IMPORTED, // use '.import_info'
    } kind;

    union {
        struct {
            Import_Index index;
        } import_info;

        struct {
            Scope scope;

            u32 var_count;
            Var **local_vars; // set in 'typecheck'
            Var **param_var_mappings;

            Stmt *first_stmt;

            u32 text_start;
        } body;
    };
};



typedef struct Rip_Fixup {
    // Both values are indices to 'context.seg_text'
    u64 next_instruction;
    u64 rip_offset;

    enum {
        RIP_FIXUP_IMPORT_CALL,
        RIP_FIXUP_DATA,
        RIP_FIXUP_RDATA,
    } kind;

    union {
        Import_Index import_index;
        i32 data_offset;
    };
} Rip_Fixup;

typedef struct Call_Fixup {
    u64 text_location;
    bool builtin;
    union {
        Fn *fn;
        u32 builtin_index;
    };
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


typedef struct Context {
    Arena arena, stack; // arena is for permanent storage, stack for temporary

    String_Table string_table;
    struct {
        int token;
        u8 *interned_name;
    } keyword_token_table[KEYWORD_COUNT];
    u8 *builtin_names[BUILTIN_COUNT];

    // AST & intermediate representation
    Scope global_scope;
    Fn **all_fns; // generated in 'typecheck', stretchy buffer
    Global_Var *global_vars; // stretchy buffer
    Global_Let *global_lets; // stretchy buffer

    Type **fn_signatures; // stretchy buffer

    Type primitive_types[TYPE_KIND_COUNT];
    Type *void_pointer_type, *string_type, *type_info_type, *char_type;
    Type *void_fn_signature;

    u8 **lib_paths;
    u32 lib_path_count;

    // Low level representation
    u8 *seg_text;
    u8 *seg_data;
    u8 *seg_rdata;

    Library_Import *imports;
    Rip_Fixup *fixups;
    Call_Fixup *call_fixups;
    Stack_Access_Fixup *stack_access_fixups;
    Jump_Fixup *jump_fixups;
} Context;



bool file_pos_is_greater(File_Pos *a, File_Pos *b) {
    assert(a->file_name == b->file_name);
    return a->line > b->line || (a->line == b->line && a->character > b->character);
}


Decl *find_declaration(Scope *scope, u8 *interned_name, int kind) {
    while (true) {
        for (u32 i = 0; i < scope->decls_length; i += 1) {
            Decl *decl = &scope->decls[i];
            if (decl->name == interned_name && decl->kind == kind) {
                return decl;
            }
        }

        if (scope->parent != null) {
            scope = scope->parent;
            continue;
        } else {
            break;
        }
    }

    return null;
}

Var *find_var(Scope *scope, u8 *interned_name, u32 before_position) {
    Scope *start_scope = scope;
    while (true) {
        for (u32 i = scope->decls_length - 1; i < scope->decls_length; i -= 1) {
            Decl *decl = &scope->decls[i];
            if (decl->kind != DECL_VAR) continue;

            if (scope == start_scope && scope->fn != null && decl->scope_pos >= before_position && !(decl->var->flags & VAR_FLAG_CONSTANT)) {
                continue;
            }

            if (decl->name == interned_name && decl->kind == DECL_VAR) {
                return decl->var;
            }
        }

        if (scope->parent != null) {
            scope = scope->parent;
            continue;
        } else {
            break;
        }
    }

    return null;
}

// NB this returns member index, not member value!
u32 find_enum_member(Type *type, u8 *name) {
    assert(type->kind == TYPE_ENUM);

    for (u32 i = 0; i < type->enumeration.member_count; i += 1) {
        if (type->enumeration.members[i].name == name) {
            return i;
        }
    }

    return U32_MAX;
}

Decl *add_declaration(
    Arena *arena, Scope *scope,
    int kind, u8 *name, File_Pos pos,
    bool allow_shadowing
) {
    if (!allow_shadowing) {
        for (u32 i = 0; i < scope->decls_length; i += 1) {
            Decl *other_decl = &scope->decls[i];
            if (other_decl->kind == kind && other_decl->name == name) {
                u8 *kind_name;
                switch (other_decl->kind) {
                    case DECL_VAR:  kind_name = "variable"; break;
                    case DECL_FN:   kind_name = "function"; break;
                    case DECL_TYPE: kind_name = "type"; break;
                    default: assert(false);
                }

                print_file_pos(&pos);
                printf(
                    "Redefinition of %s '%s'. First definition on line %u\n",
                    kind_name, name, (u64) other_decl->pos.line
                );
                return null;
            }
        }
    }

    if (scope->decls_length >= scope->decls_allocated) {
        u32 new_allocated = scope->decls_allocated * 2;
        if (new_allocated == 0) { new_allocated = 16; }

        Decl *new_decls = (void*) arena_alloc(arena, new_allocated * sizeof(Decl));
        mem_copy((u8*) scope->decls, (u8*) new_decls, scope->decls_length * sizeof(Decl));
        scope->decls_allocated = new_allocated;
        scope->decls = new_decls;
    }

    Decl *result = &scope->decls[scope->decls_length];
    scope->decls_length += 1;
    assert(scope->decls_allocated >= scope->decls_length);

    result->kind = kind;
    result->name = name;
    result->pos = pos;

    result->scope_pos = scope->next_scope_pos;
    scope->next_scope_pos += 1;

    return result;
}

Type *get_pointer_type(Context *context, Type *type) {
    if (type->pointer_type == null) {
        type->pointer_type = arena_new(&context->arena, Type);
        type->pointer_type->kind = TYPE_POINTER;
        type->pointer_type->pointer_to = type;

        if (type->flags & (TYPE_FLAG_UNRESOLVED|TYPE_FLAG_UNRESOLVED_CHILD)) {
            type->pointer_type->flags |= TYPE_FLAG_UNRESOLVED_CHILD;
        }
    }

    if (!(type->flags & (TYPE_FLAG_UNRESOLVED|TYPE_FLAG_UNRESOLVED_CHILD))) {
        type->pointer_type->flags &= ~TYPE_FLAG_UNRESOLVED_CHILD;
    }

    return type->pointer_type;
}

Type *get_array_type(Context *context, Type *type, u64 length) {
    for (Type_List* node = type->array_types; node != null; node = node->next) {
        if (node->type.array.length == length) {
            if (!(type->flags & (TYPE_FLAG_UNRESOLVED|TYPE_FLAG_UNRESOLVED_CHILD))) {
                node->type.flags &= ~TYPE_FLAG_UNRESOLVED_CHILD;
            }
            return &node->type;
        }
    }

    Type_List *new = arena_new(&context->arena, Type_List);
    new->next = type->array_types;
    type->array_types = new;

    new->type.kind = TYPE_ARRAY;
    new->type.array.length = length;
    new->type.array.of = type;

    if (type->flags & (TYPE_FLAG_UNRESOLVED|TYPE_FLAG_UNRESOLVED_CHILD)) {
        new->type.flags |= TYPE_FLAG_UNRESOLVED_CHILD;
    }

    return &new->type;
}

void init_primitive_types(Context *context) {
    #define init_primitive(kind) context->primitive_types[kind] = (Type) { kind, .primitive_name = string_intern(&context->string_table, PRIMITIVE_NAMES[kind]) };

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
    context->char_type         = &context->primitive_types[TYPE_CHAR];

    assert(buf_empty(context->fn_signatures));

    context->void_fn_signature = arena_new(&context->arena, Type);
    context->void_fn_signature->kind = TYPE_FN_POINTER;
    buf_push(context->fn_signatures, context->void_fn_signature);
}

void init_builtin_fn_names(Context *context) {
    context->builtin_names[BUILTIN_TYPE_INFO_OF_TYPE]  = string_intern(&context->string_table, "type_info_of_type");
    context->builtin_names[BUILTIN_TYPE_INFO_OF_VALUE] = string_intern(&context->string_table, "type_info_of_value");
    context->builtin_names[BUILTIN_ENUM_MEMBER_NAME]   = string_intern(&context->string_table, "enum_member_name");
    context->builtin_names[BUILTIN_ENUM_LENGTH]        = string_intern(&context->string_table, "enum_length");
    context->builtin_names[BUILTIN_CAST]               = string_intern(&context->string_table, "cast");
    context->builtin_names[BUILTIN_SIZE_OF]            = string_intern(&context->string_table, "size_of");
    context->builtin_names[BUILTIN_ALIGN_OF]           = string_intern(&context->string_table, "align_of");
    context->builtin_names[BUILTIN_SQRT]               = string_intern(&context->string_table, "sqrt");
}

void init_keyword_names(Context *context) {
    u32 i = 0;

    #define add_keyword(t, n) \
    context->keyword_token_table[i].token = t; \
    context->keyword_token_table[i].interned_name = string_intern(&context->string_table, n); \
    i += 1;

    add_keyword(TOKEN_KEYWORD_FN,          "fn");
    add_keyword(TOKEN_KEYWORD_EXTERN,      "extern");
    add_keyword(TOKEN_KEYWORD_TYPEDEF,     "typedef");
    add_keyword(TOKEN_KEYWORD_LET,         "let");
    add_keyword(TOKEN_KEYWORD_CONST,       "const");
    add_keyword(TOKEN_KEYWORD_IF,          "if");
    add_keyword(TOKEN_KEYWORD_SWITCH,      "switch");
    add_keyword(TOKEN_KEYWORD_ELSE,        "else");
    add_keyword(TOKEN_KEYWORD_FOR,         "for");
    add_keyword(TOKEN_KEYWORD_RETURN,      "return");
    add_keyword(TOKEN_KEYWORD_CONTINUE,    "continue");
    add_keyword(TOKEN_KEYWORD_BREAK,       "break");
    add_keyword(TOKEN_KEYWORD_DEBUG_BREAK, "debug_break");
    add_keyword(TOKEN_KEYWORD_STRUCT,      "struct");
    add_keyword(TOKEN_KEYWORD_ENUM,        "enum");
    add_keyword(TOKEN_KEYWORD_UNION,       "union");
    add_keyword(TOKEN_KEYWORD_NULL,        "null");
    add_keyword(TOKEN_KEYWORD_TRUE,        "true");
    add_keyword(TOKEN_KEYWORD_FALSE,       "false");

    #undef add_keyword
}

Condition find_condition_for_op_and_type(Binary_Op op, bool is_signed) {
    if (is_signed) {
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
            case BINARY_LT:   return COND_B;
            case BINARY_LTEQ: return COND_BE;
            default: assert(false);
        }
    }
    return 0;
}

bool fn_signature_cmp(Fn_Signature *a, Fn_Signature *b) {
    bool equal = 
        a->has_return == b->has_return &&
        a->return_type == b->return_type &&
        a->param_count == b->param_count;
    if (!equal) return false;

    for (u32 p = 0; p < a->param_count; p += 1) {
        if (a->params[p].type != b->params[p].type) {
            return false;
        }
    }
    
    return true;
}

Type *fn_signature_canonicalize(Context *context, Fn_Signature *fn_signature) {
    buf_foreach (Type*, other, context->fn_signatures) {
        if (fn_signature_cmp(&((*other)->fn_signature), fn_signature)) {
            return *other;
        }
    }

    Type *canonicalized = arena_new(&context->arena, Type);
    canonicalized->kind = TYPE_FN_POINTER;
    canonicalized->fn_signature = *fn_signature;
    buf_push(context->fn_signatures, canonicalized);
    return canonicalized;
}
 
// Compares types for equality, with the following exceptions
//      '*[N]Foo' is equal to '*Foo'
//      '*void' is equal to '*Foo', for all pointer types
// Note that this can not be used to e.g. compare structs or fn signatures
// for equality. We canonicalize those and expect them to be pointer equal.
bool type_can_assign(Type* a, Type* b) {
    if (a == b) return true;

    while (true) {
        // Make void pointers equal all other pointers
        if ((a->kind == TYPE_POINTER && a->pointer_to->kind == TYPE_VOID) && (b->kind == TYPE_POINTER || b->kind == TYPE_FN_POINTER)) {
            return true;
        }
        if ((b->kind == TYPE_POINTER && b->pointer_to->kind == TYPE_VOID) && (a->kind == TYPE_POINTER || a->kind == TYPE_FN_POINTER)) {
            return true;
        }

        if (a->kind != b->kind) {
            return false;
        }

        if (a->kind == TYPE_ARRAY) {
            if (a->array.length != b->array.length) return false;
            a = a->array.of;
            b = b->array.of;
            continue;
        }

        if (a->kind == TYPE_POINTER) {
            a = a->pointer_to;
            b = b->pointer_to;

            // Make pointers to arrays of foo equal pointers to foo
            if (a->kind == TYPE_ARRAY && b->kind != TYPE_ARRAY) {
                a = a->array.of;
            } else if (a->kind != TYPE_ARRAY && b->kind == TYPE_ARRAY) {
                b = b->array.of;
            }

            continue;
        }

        return a == b;
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
        case TYPE_FN_POINTER:  return POINTER_SIZE;
        case TYPE_INVALID: assert(false); return 0;
        case TYPE_ARRAY: assert(false); return 0;
        case TYPE_STRUCT: assert(false); return 0;
        case TYPE_ENUM: assert(false); return 0;
        default: assert(false); return 0;
    }
}

u8* compound_member_name(Context *context, Expr* expr, Compound_Member* member) {
    switch (member->name_mode) {
        case EXPR_COMPOUND_NAME: {
            assert(expr->type->kind == TYPE_STRUCT);
            u32 member_index = member->member_index;
            return expr->type->structure.members[member_index].name;
        } break;

        case EXPR_COMPOUND_UNRESOLVED_NAME: {
            return member->unresolved_name;
        } break;

        case EXPR_COMPOUND_NO_NAME: {
            return null;
        } break;

        default: {
            assert(false);
            return null;
        } break;
    }
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

u8 *user_type_name(Type* type) {
    switch (type->kind) {
        case TYPE_STRUCT: return type->structure.name;
        case TYPE_ENUM:   return type->enumeration.name;
        default: assert(false); return null;
    }
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
        case TYPE_FN_POINTER: return false;
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
// 'library_name' and 'function_name' should be interned in the string table!
Import_Index add_import(Context *context, u8 *source_path, u8 *library_name, u8 *function_name) {
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
        u8 *other_function_name = import->function_names[i];
        if (other_function_name == function_name) {
            index.function = i;
            return index;
        }
    }

    index.function = buf_length(import->function_names);
    buf_push(import->function_names, function_name);
    return index;
}

u64 add_exe_data(Context *context, bool read_only, u8 *data, u64 length, u64 alignment) {
    u8 **seg = read_only? &context->seg_rdata : &context->seg_data;

    u64 data_offset = buf_length(*seg);

    u64 aligned_data_offset = round_to_next(data_offset, alignment);
    if (aligned_data_offset > data_offset) {
        str_push_zeroes(seg, aligned_data_offset - data_offset);
    }

    if (data == null) {
        str_push_zeroes(seg, length);
    } else {
        str_push_str(seg, data, length);
    }

    return aligned_data_offset;
}

void print_expr(Context *context, Expr *expr);

void print_type(Context *context, Type* type) {
    while (type != null) {
        switch (type->kind) {
            case TYPE_POINTER: {
                printf("*");
                type = type->pointer_to;
            } break;

            case TYPE_FN_POINTER: {
                Fn_Signature *signature = &type->fn_signature;

                printf("*fn(");
                for (u32 i = 0; i < signature->param_count; i += 1) {
                    if (i > 0) printf(", ");
                    print_type(context, signature->params[i].type);
                }
                printf(")");
                if (signature->has_return) {
                    printf(" -> ");
                    print_type(context, signature->return_type);
                }

                type = null;
            } break;

            case TYPE_ARRAY: {
                if (type->flags & TYPE_FLAG_UNRESOLVED && type->array.length_expr == null) {
                    printf("[]");
                } else if (type->flags & TYPE_FLAG_UNRESOLVED) {
                    printf("[");
                    print_expr(context, type->array.length_expr);
                    printf("]");
                } else {
                    printf("[%u]", type->array.length);
                }

                type = type->array.of;
            } break;

            case TYPE_STRUCT: {
                printf(type->structure.name);
                type = null;
            } break;

            case TYPE_ENUM: {
                printf(type->enumeration.name);
                type = null;
            } break;

            case TYPE_UNRESOLVED_NAME: {
                printf("<unresolved %s>", type->unresolved_name);
                type = null;
            } break;

            default: {
                printf(PRIMITIVE_NAMES[type->kind]);
                type = null;
            } break;
        }
    }
}

void print_token(Token* t) {
    u8* s = null;

    switch (t->kind) {
        case TOKEN_IDENTIFIER: {
            printf("'%s'", t->identifier);
        } break;
        case TOKEN_STRING: {
            printf("\"%z\"", t->string.length, t->string.bytes);
        } break;

        case TOKEN_LITERAL_INT:   printf("%u", t->literal_int);     break;
        case TOKEN_LITERAL_FLOAT: printf("%f", t->literal_float);   break;
        case TOKEN_LITERAL_CHAR:  printf("'%c'", t->literal_char);  break;

        default: {
            printf(TOKEN_NAMES[t->kind]);
        } break;
    }
}

void print_expr(Context *context, Expr *expr) {
    switch (expr->kind) {
        case EXPR_VARIABLE: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                printf("<unresolved %s>", expr->variable.unresolved_name);
            } else {
                printf(expr->variable.var->name);
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

                case EXPR_LITERAL_FLOAT: {
                    printf("%f", *((f64*) &expr->literal.masked_value));
                } break;

                case EXPR_LITERAL_CHAR: {
                    printf("'%c'", expr->literal.masked_value);
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
                print_expr(context, child);
            }
            printf(" }");
        } break;

        case EXPR_STRING_LITERAL: {
            printf("\"%z\"", expr->string.length, expr->string.bytes);
        } break;

        case EXPR_BINARY: {
            printf("(");
            print_expr(context, expr->binary.left);
            printf(" %s ", BINARY_OP_SYMBOL[expr->binary.op]);
            print_expr(context, expr->binary.right);
            printf(")");
        } break;

        case EXPR_TERNARY: {
            printf("(");
            print_expr(context, expr->ternary.condition);
            printf("? ");
            print_expr(context, expr->binary.left);
            printf(" : ");
            print_expr(context, expr->binary.right);
            printf(")");
        } break;

        case EXPR_UNARY: {
            printf(UNARY_OP_SYMBOL[expr->unary.op]);
            print_expr(context, expr->unary.inner);
        } break;

        case EXPR_CALL: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                printf("<unresolved %s>", expr->call.unresolved_name);
            } else if (expr->call.pointer_call) {
                bool parenthesize = expr->call.pointer_expr->kind != EXPR_VARIABLE;

                if (parenthesize) printf("(");
                print_expr(context, expr->call.pointer_expr);
                if (parenthesize) printf(")");
            } else {
                printf("%s", expr->call.callee->name);
            }

            printf("(");
            for (u32 i = 0; i < expr->call.param_count; i += 1) {
                if (i > 0) printf(", ");
                Expr* child = expr->call.params[i];
                print_expr(context, child);
            }
            printf(")");
        } break;

        case EXPR_CAST: {
            Type_Kind primitive = expr->type->kind;

            if (primitive_is_integer(primitive)) {
                print_type(context, expr->type);
                printf("(");
                print_expr(context, expr->cast_from);
                printf(")");
            } else {
                printf("cast(");
                print_type(context, expr->type);
                printf(", ");
                print_expr(context, expr->cast_from);
                printf(")");
            }
        } break;

        case EXPR_SUBSCRIPT: {
            print_expr(context, expr->subscript.array);
            printf("[");
            print_expr(context, expr->subscript.index);
            printf("]");
        } break;

        case EXPR_MEMBER_ACCESS: {
            print_expr(context, expr->member_access.parent);
            printf(".");
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                printf("<unresolved %s>", expr->member_access.member_name);
            } else {
                Type* s = expr->member_access.parent->type;
                if (s->kind == TYPE_POINTER) {
                    s = s->pointer_to;
                }
                assert(s->kind == TYPE_STRUCT);

                u8 *name = s->structure.members[expr->member_access.member_index].name;
                printf(name);
            }
        } break;

        case EXPR_STATIC_MEMBER_ACCESS: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u8* parent_name = expr->static_member_access.parent_name;
                u8* member_name = expr->static_member_access.member_name;
                printf("<unresolved %s::%s>", parent_name, member_name);
            } else {
                Type* parent = expr->static_member_access.parent_type;
                assert(parent->kind == TYPE_ENUM);

                u8* parent_name = parent->enumeration.name;

                u32 m = expr->static_member_access.member_index;
                u8 *member_name = parent->enumeration.members[m].name;
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
            print_expr(context, expr->type_info_of_value);
            printf(")");
        } break;

        case EXPR_QUERY_TYPE_INFO: {
            u8 *name;
            switch (expr->query_type_info.query) {
                case QUERY_TYPE_INFO_ENUM_LENGTH:   name = "enum_length"; break;
                case QUERY_TYPE_INFO_SIZE:          name = "size_of"; break;
                case QUERY_TYPE_INFO_ALIGN:         name = "align_of"; break;
                default: assert(false);
            }

            printf("%s(", name);
            print_type(context, expr->query_type_info.type);
            printf(")");
        } break;

        case EXPR_ENUM_MEMBER_NAME: {
            printf("enum_member_name(");
            print_expr(context, expr->enum_member);
            printf(")");
        } break;

        case EXPR_ADDRESS_OF_FUNCTION: {
            u8 *name = expr->address_of_fn->name;
            printf("&%s", name);
        } break;

        default: assert(false);
    }
}

void print_stmt(Context *context, Stmt* stmt, u32 indent_level) {
    for (u32 i = 0; i < indent_level; i += 1) printf("    ");

    switch (stmt->kind) {
        case STMT_ASSIGNMENT: {
            print_expr(context, stmt->assignment.left);
            printf(" = ");
            print_expr(context, stmt->assignment.right);
            printf(";");
        } break;

        case STMT_OP_ASSIGNMENT: {
            print_expr(context, stmt->op_assignment.left);
            printf(" %s= ", BINARY_OP_SYMBOL[stmt->op_assignment.op]);
            print_expr(context, stmt->op_assignment.right);
            printf(";");
        } break;

        case STMT_EXPR: {
            print_expr(context, stmt->expr);
            printf(";");
        } break;

        case STMT_LET: {
            assert(stmt->let.var_count >= 1);

            printf("let ");
            for (u32 i = 0; i < stmt->let.var_count; i += 1) {
                if (i > 0) printf(", ");
                Var *var = &stmt->let.vars[i];
                printf(var->name);
            }
            printf(": ");

            print_type(context, stmt->let.vars[0].type);

            if (stmt->let.right != null) {
                printf(" = ");
                print_expr(context, stmt->let.right);
            }

            printf(";");
        } break;

        case STMT_BLOCK: {
            printf("{\n");

            for (Stmt *inner = stmt->block.stmt; inner->kind != STMT_END; inner = inner->next) {
                print_stmt(context, inner, indent_level + 1);
            }

            for (u32 i = 0; i < indent_level; i += 1) printf("    ");
            printf("}");
        } break;

        case STMT_IF: {
            printf("if (");
            print_expr(context, stmt->if_.condition);
            printf(") {\n");

            for (Stmt *inner = stmt->if_.then; inner->kind != STMT_END; inner = inner->next) {
                print_stmt(context, inner, indent_level + 1);
            }

            for (u32 i = 0; i < indent_level; i += 1) printf("    ");
            printf("}");

            if (stmt->if_.else_then != null) {
                printf(" else {\n");

                for (Stmt *inner = stmt->if_.else_then; inner->kind != STMT_END; inner = inner->next) {
                    print_stmt(context, inner, indent_level + 1);
                }

                for (u32 i = 0; i < indent_level; i += 1) printf("    ");
                printf("}");
            }
        } break;

        case STMT_SWITCH: {
            printf("switch (");
            print_expr(context, stmt->switch_.index);
            printf(") {\n");

            for (u32 i = 0; i < stmt->switch_.case_count; i += 1) {
                for (u32 i = 0; i <= indent_level; i += 1) printf("    ");

                Switch_Case *c = &stmt->switch_.cases[i];

                for (u32 i = 0; i < c->key_count; i += 1) {
                    Switch_Case_Key *key = &c->keys[i];

                    if (i > 0) printf(", ");
                    if (key->is_identifier) {
                        printf(key->identifier);
                    } else {
                        print_expr(context, key->expr);
                    }
                }
                printf(": {\n");

                for (Stmt *inner = c->body; inner->kind != STMT_END; inner = inner->next) {
                    print_stmt(context, inner, indent_level + 2);
                }

                for (u32 i = 0; i <= indent_level; i += 1) printf("    ");
                printf("}\n");
            }

            if (stmt->switch_.default_case != null) {
                for (u32 i = 0; i <= indent_level; i += 1) printf("    ");
                printf("_: {\n");

                for (Stmt *inner = stmt->switch_.default_case->body; inner->kind != STMT_END; inner = inner->next) {
                    print_stmt(context, inner, indent_level + 2);
                }

                for (u32 i = 0; i <= indent_level; i += 1) printf("    ");
                printf("}\n");
            }

            for (u32 i = 0; i < indent_level; i += 1) printf("    ");
            printf("}");
        } break;

        case STMT_FOR: {
            if (stmt->for_.kind == LOOP_CONDITIONAL) {
                printf("for ");
                print_expr(context, stmt->for_.condition);
                printf(" {\n");
            } else if (stmt->for_.kind == LOOP_INFINITE) {
                printf("for {\n");
            } else if (stmt->for_.kind == LOOP_RANGE) {
                u8 *var_name = stmt->for_.range.var->name;

                printf("for %s : ", var_name);
                print_expr(context, stmt->for_.range.start);
                printf("..");
                print_expr(context, stmt->for_.range.end);
                printf(" {\n");
            } else {
                assert(false);
            }

            for (Stmt *inner = stmt->for_.body; inner->kind != STMT_END; inner = inner->next) {
                print_stmt(context, inner, indent_level + 1);
            }

            for (u32 i = 0; i < indent_level; i += 1) printf("    ");
            printf("}");
        } break;

        case STMT_RETURN: {
            if (stmt->return_.value != null) {
                printf("return ");
                print_expr(context, stmt->return_.value);
                printf(";");
            } else {
                printf("return;");
            }
        } break;

        case STMT_CONTINUE: printf("continue;"); break;
        case STMT_BREAK:    printf("break;"); break;

        case STMT_DEBUG_BREAK: printf("debug_break;"); break;

        case STMT_END: printf("<end>"); break;

        default: assert(false);
    }

    printf("\n");
}

u8 resolve_escaped_char(u8 c) {
    switch (c) {
        case 'n':  return 0x0a;
        case 'r':  return 0x0d;
        case 't':  return 0x09;
        case '0':  return 0x00;
        case '\\': return '\\';
        case '"':  return '"';
        case '\'': return '\'';
        default:   return 0xff;
    }
}

bool expect_single_token(Context *context, Token* t, int kind, u8* location) {
    if (t->kind != kind) {
        print_file_pos(&t->pos);
        printf("Expected %s %s, but got ", TOKEN_NAMES[kind], location);
        print_token(t);
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

Type *parse_primitive_name(Context *context, u8 *interned_name) {
    for (u32 i = 0; i < TYPE_KIND_COUNT; i += 1) {
        Type *type = &context->primitive_types[i];
        if (type->primitive_name == interned_name) {
            return type;
        }
    }

    return null;
}

Builtin_Fn parse_builtin_fn_name(Context *context, u8 *name) {
    for (u32 i = 0; i < BUILTIN_COUNT; i += 1) {
        if (context->builtin_names[i] == name) {
            return i;
        }
    }

    return BUILTIN_INVALID;
}

Type *parse_user_type_name(Scope *scope, u8 *interned_name) {
    Decl *decl = find_declaration(scope, interned_name, DECL_TYPE);
    if (decl == null) {
        return null;
    } else {
        assert(decl->kind == DECL_TYPE);
        return decl->type;
    }
}

Type*parse_fn_signature    (Context *context, Scope *scope, Token *t, u32 *length, Fn *fn);
Expr *parse_expr           (Context *context, Scope *scope, Token *t, u32 *length, bool stop_on_open_curly);
Expr *parse_compound       (Context *context, Scope *scope, Token *t, u32 *length);
Expr **parse_parameter_list(Context *context, Scope *scope, Token *t, u32 *length, u32 *count);
Expr *parse_call           (Context *context, Scope *scope, Token *t, u32 *length);
Fn *parse_fn               (Context *context, Scope *scope, Token *t, u32 *length);

Type *parse_type(Context *context, Scope *scope, Token* t, u32* length) {
    Token* t_start = t;

    typedef struct Prefix Prefix;
    struct Prefix {
        enum { PREFIX_POINTER, PREFIX_ARRAY, PREFIX_ARRAY_EXPR, PREFIX_ARRAY_UNSIZED } kind;
        union {
            Expr *array_length_expr;
            u64 array_length;
        };

        Prefix *link;
    };
    Prefix* prefix = null;

    arena_stack_push(&context->stack);

    Type* base_type = null;
    while (base_type == null) {
        switch (t->kind) {
            case TOKEN_IDENTIFIER: {
                base_type = parse_primitive_name(context, t->identifier);

                if (base_type == null) {
                    base_type = parse_user_type_name(scope, t->identifier);
                }

                if (base_type == null) {
                    base_type = arena_new(&context->arena, Type);
                    base_type->kind = TYPE_UNRESOLVED_NAME;
                    base_type->unresolved_name = t->identifier;
                    base_type->flags |= TYPE_FLAG_UNRESOLVED;
                }

                t += 1;
            } break;

            case TOKEN_BRACKET_SQUARE_OPEN: {
                t += 1;

                Prefix *new = arena_new(&context->stack, Prefix);
                new->link = prefix;
                prefix = new;

                // Fixed given size
                if (t->kind == TOKEN_LITERAL_INT) {
                    prefix->kind = PREFIX_ARRAY;
                    prefix->array_length = t->literal_int;
                    t += 1;

                // Size not given, this can only be used in compound literals
                } else if (t->kind == TOKEN_BRACKET_SQUARE_CLOSE) {
                    prefix->kind = PREFIX_ARRAY_UNSIZED;

                // Size given by a compile time expr
                } else {
                    u32 length_expr_length;
                    Expr *length_expr = parse_expr(context, scope, t, &length_expr_length, false);
                    t += length_expr_length;
                    if (length_expr == null) {
                        *length = t - t_start;
                        return null;
                    }

                    prefix->kind = PREFIX_ARRAY_EXPR;
                    prefix->array_length_expr = length_expr;
                }

                if (!expect_single_token(context, t, TOKEN_BRACKET_SQUARE_CLOSE, "after array size")) {
                    *length = t - t_start;
                    return null;
                }
                t += 1;
            }  break;

            case TOKEN_MUL: {
                t += 1;

                if (t->kind == TOKEN_KEYWORD_FN) {
                    u32 signature_length;
                    base_type = parse_fn_signature(context, scope, t, &signature_length, null);
                    t += signature_length;

                    if (base_type == null) {
                        *length = t - t_start;
                        return null;
                    }
                } else {
                    Prefix *new = arena_new(&context->stack, Prefix);
                    new->kind = PREFIX_POINTER;
                    new->link = prefix;
                    prefix = new;
                }
            } break;

            default: {
                print_file_pos(&t->pos);
                printf("Unexpected token in type: ");
                print_token(t);
                printf("\n");

                t += 1;
                *length = t - t_start;
                return null;
            } break;
        }
    }

    Type *type = base_type;
    while (prefix != null) {
        switch (prefix->kind) {
            case PREFIX_POINTER: {
                type = get_pointer_type(context, type);
            } break;

            case PREFIX_ARRAY: {
                type = get_array_type(context, type, prefix->array_length);
            } break;

            case PREFIX_ARRAY_EXPR: {
                Type *array_type = arena_new(&context->arena, Type);
                array_type->kind = TYPE_ARRAY;
                array_type->flags |= TYPE_FLAG_UNRESOLVED;
                array_type->array.length_expr = prefix->array_length_expr;
                array_type->array.of = type;

                type = array_type;
            } break;

            case PREFIX_ARRAY_UNSIZED: {
                Type *array_type = arena_new(&context->arena, Type);
                array_type->kind = TYPE_ARRAY;
                array_type->flags |= TYPE_FLAG_UNRESOLVED;
                array_type->array.length_expr = null;
                array_type->array.of = type;

                type = array_type;
            } break;
        }
        prefix = prefix->link;
    }

    arena_stack_pop(&context->stack);

    *length = t - t_start;
    return type;
}

Type *parse_fn_signature(Context *context, Scope *scope, Token *t, u32 *length, Fn *fn) {
    Token *t_start = t;
    assert(t->kind == TOKEN_KEYWORD_FN);
    t += 1;

    Fn_Signature signature = {0};

    if (t->kind == TOKEN_IDENTIFIER) {
        if (fn != null) fn->name = t->identifier;
        t += 1;
    } else if (fn != null) {
        print_file_pos(&t->pos);
        printf("Expected function name, but found ");
        print_token(t);
        printf("\n");
        return null;
    }

    if (!expect_single_token(context, t, TOKEN_BRACKET_ROUND_OPEN, "after fn")) {
        *length = t - t_start;
        return null;
    }
    t += 1;

    if (t->kind == TOKEN_BRACKET_ROUND_CLOSE) {
        t += 1;
    } else {
        arena_stack_push(&context->stack);

        typedef struct Param Param;
        struct Param {
            u8 *name;
            File_Pos pos;
            Type *type;
            Param *next, *previous;
        };

        Param *first = null;
        Param *last = null;

        while (true) {
            u32 names_given = 0;

            while(true) {
                if (t->kind != TOKEN_IDENTIFIER) {
                    print_file_pos(&t->pos);
                    printf("Expected a parameter name, but got ");
                    print_token(t);
                    printf("\n");
                    *length = t - t_start;
                    return null;
                }

                Param *next = arena_new(&context->stack, Param);
                next->name = t->identifier;
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
                signature.param_count += 1;

                if (t->kind == TOKEN_COMMA) {
                    t += 1;
                    continue;
                } else {
                    break;
                }
            }

            if (!expect_single_token(context, t, TOKEN_COLON, names_given > 1? "after parameter names" : "after parameter name")) {
                *length = t - t_start;
                return null;
            }
            t += 1;

            u32 type_length = 0;
            Type* param_type = parse_type(context, scope, t, &type_length);
            t += type_length;
            if (param_type == null) {
                *length = t - t_start;
                return null;
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
                if (!expect_single_token(context, t, TOKEN_COMMA, "after member declaration")) return null;
                t += 1;
                if (t->kind == TOKEN_BRACKET_ROUND_CLOSE) {
                    // Allow trailing commas
                    t += 1;
                    break;
                }
                continue;
            }
        }

        signature.params = (void*) arena_alloc(&context->arena, signature.param_count * sizeof(*signature.params));
        u32 i = 0;
        for (Param *p = first; p != null; p = p->next, i += 1) {
            signature.params[i].type = p->type;
        }

        if (fn != null) {
            assert(fn->body.param_var_mappings == null);
            fn->body.param_var_mappings = (Var**) arena_alloc(&context->arena, signature.param_count * sizeof(Var*));
            
            u32 i = 0;
            for (Param *p = first; p != null; p = p->next, i += 1) {
                Var *var = arena_new(&context->arena, Var);
                var->name = p->name;
                var->type = p->type;
                var->declaration_pos = p->pos;
                var->local_index = fn->body.var_count;
                fn->body.var_count += 1;

                Decl *decl = add_declaration(&context->arena, &fn->body.scope, DECL_VAR, p->name, p->pos, false);
                assert(decl != null);
                decl->var  = var;

                fn->body.param_var_mappings[i] = var;
            }
        }

        arena_stack_pop(&context->stack);
    }

    if (t->kind == TOKEN_ARROW) {
        t += 1;

        u32 type_length;
        Type *return_type = parse_type(context, scope, t, &type_length);
        t += type_length;

        if (return_type == null) {
            *length = t - t_start;
            return null;
        }

        signature.has_return = true;
        signature.return_type = return_type;
    } else {
        signature.has_return = false;
        signature.return_type = &context->primitive_types[TYPE_VOID];
    }


    *length = t - t_start;


    bool unresolved = false;
    for (u32 p = 0; p < signature.param_count; p += 1) {
        if (signature.params[p].type->flags & (TYPE_FLAG_UNRESOLVED|TYPE_FLAG_UNRESOLVED_CHILD)) {
            unresolved = true;
            break;
        }
    }

    if (signature.has_return && (signature.return_type->flags & (TYPE_FLAG_UNRESOLVED|TYPE_FLAG_UNRESOLVED_CHILD))) {
        unresolved = true;
    }

    if (unresolved) {
        Type *type = arena_new(&context->arena, Type);
        type->flags |= TYPE_FLAG_UNRESOLVED_CHILD;
        type->kind = TYPE_FN_POINTER;
        type->fn_signature = signature;
        return type;
    } else {
        return fn_signature_canonicalize(context, &signature);
    }
}

bool parse_struct_declaration(Context *context, Scope *scope, Token* t, u32* length) {
    File_Pos declaration_pos = t->pos;
    Token* t_start = t;

    assert(t->kind == TOKEN_KEYWORD_STRUCT);
    t += 1;

    Type* type = arena_new(&context->arena, Type);
    type->kind = TYPE_STRUCT;

    if (t->kind != TOKEN_IDENTIFIER) {
        print_file_pos(&t->pos);
        printf("Expected struct name, but got ");
        print_token(t);
        printf("\n");
        return false;
    }
    type->structure.name = t->identifier;
    t += 1;

    if (!expect_single_token(context, t, TOKEN_BRACKET_CURLY_OPEN, "after struct name")) return false;
    t += 1;


    typedef struct Member Member;
    struct Member {
        u8 *name;
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
                print_token(t);
                printf("\n");
                return false;
            }

            Member* next = arena_new(&context->stack, Member);
            next->name = t->identifier;
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

        if (!expect_single_token(context, t, TOKEN_COLON, names_given > 1? "after member names" : "after member name")) return false;
        t += 1;

        u32 type_length = 0;
        Type* member_type = parse_type(context, scope, t, &type_length);
        t += type_length;
        if (member_type == null) return false;

        if (!expect_single_token(context, t, TOKEN_SEMICOLON, "after member declaration")) return false;

        Member* m = last;
        for (u32 i = 0; i < names_given; i += 1) {
            m->type = member_type;
            m = m->previous;
        }

        t += 1;
    }
    t += 1;

    type->structure.members = (void*) arena_alloc(&context->arena, type->structure.member_count * sizeof(*type->structure.members));

    bool unresolved_members = false;

    Member* m = first;
    for (u32 i = 0; i < type->structure.member_count; i += 1, m = m->next) {
        type->structure.members[i].name = m->name;
        type->structure.members[i].type = m->type;
        type->structure.members[i].declaration_pos = m->pos;

        if (m->type->flags & (TYPE_FLAG_UNRESOLVED_CHILD|TYPE_FLAG_UNRESOLVED)) {
            unresolved_members = true;
        }
    }

    arena_stack_pop(&context->stack);

    type->flags |= TYPE_FLAG_SIZE_NOT_COMPUTED;
    if (unresolved_members) {
        type->flags |= TYPE_FLAG_UNRESOLVED_CHILD;
    }

    *length = t - t_start;

    Decl *decl = add_declaration(&context->arena, scope, DECL_TYPE, type->enumeration.name, declaration_pos, false);
    if (decl == null) return false;
    decl->type = type;

    return true;
}

bool parse_enum_declaration(Context *context, Scope *scope, Token* t, u32* length) {
    File_Pos declaration_pos = t->pos;
    Token *t_start = t;

    assert(t->kind == TOKEN_KEYWORD_ENUM);
    t += 1;

    Type* type = arena_new(&context->arena, Type);
    type->kind = TYPE_ENUM;
    type->enumeration.name_table_data_offset = U64_MAX;

    if (t->kind != TOKEN_IDENTIFIER) {
        print_file_pos(&t->pos);
        printf("Expected enum name, but got ");
        print_token(t);
        printf("\n");
        *length = t - t_start;
        return false;
    }
    type->enumeration.name = t->identifier;
    t += 1;

    if (t->kind == TOKEN_BRACKET_ROUND_OPEN) {
        t += 1;
        File_Pos type_start_pos = t->pos;

        if (t->kind != TOKEN_IDENTIFIER) {
            print_file_pos(&type_start_pos);
            printf("Expected primitive name, but got ");
            print_token(t);
            printf("\n");
            *length = t - t_start;
            return false;
        }
        u8 *type_name = t->identifier;
        t += 1;

        if (!expect_single_token(context, t, TOKEN_BRACKET_ROUND_CLOSE, "after enum primitive")) {
            *length = t - t_start;
            return false;
        }
        t += 1;

        Type *primitive = parse_primitive_name(context, type_name);
        if (primitive == null || !primitive_is_integer(primitive->kind)) {
            print_file_pos(&type_start_pos);
            printf("Expected unsigned integer type, but got %s\n", type_name);
            *length = t - t_start;
            return false;
        }

        type->enumeration.value_primitive = primitive->kind;
    } else {
        type->enumeration.value_primitive = TYPE_U32;
    }

    u8 primitive_size = primitive_size_of(type->enumeration.value_primitive);

    if (!expect_single_token(context, t, TOKEN_BRACKET_CURLY_OPEN, "after enum name/type")) {
        *length = t - t_start;
        return false;
    }
    t += 1;


    typedef struct Member Member;
    struct Member {
        u8 *name;
        u64 value;
        File_Pos pos;
        Member *next, *previous;
    };

    Member* first = null;
    Member* last = null;

    arena_stack_push(&context->stack);

    u64 value = 0;

    while (t->kind != TOKEN_BRACKET_CURLY_CLOSE) {
        if (t->kind != TOKEN_IDENTIFIER) {
            print_file_pos(&t->pos);
            printf("Expected a member name, but got ");
            print_token(t);
            printf("\n");
            *length = t - t_start;
            return false;
        }

        Member* next = arena_new(&context->stack, Member);
        next->name = t->identifier;
        next->pos = t->pos;

        t += 1;

        if (t->kind == TOKEN_ASSIGN) {
            t += 1;

            bool negate = false;
            if (t->kind == TOKEN_SUB) {
                t += 1;
                negate = true;
            }

            if (t->kind != TOKEN_LITERAL_INT) {
                print_file_pos(&t->pos);
                printf("Expected literal value, but got ");
                print_token(t);
                printf("\n");
                *length = t - t_start;
                return false;
            }
            value = t->literal_int;
            t += 1;

            if (negate) {
                value = -value;
            }
        }

        next->value = value;
        value += 1;
        value &= size_mask(primitive_size);

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
                print_token(t);
                printf("\n");
                *length = t - t_start;
                return false;
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

    // Check that values are valid
    {
        Type_Kind primitive = type->enumeration.value_primitive;
        u64 mask = size_mask(primitive_size_of(primitive));
        bool is_signed = primitive_is_signed(primitive);
        u32 count = type->enumeration.member_count;

        for (u32 i = 0; i < count; i += 1) {
            u64 member_value = type->enumeration.members[i].value;
            u8 *member_name = type->enumeration.members[i].name;

            bool out_of_range;
            if (is_signed) {
                i64 signed_value = member_value;
                i64 min, max;
                switch (primitive) {
                    case TYPE_I8:  min = I8_MIN;  max = I8_MAX;  break;
                    case TYPE_I16: min = I16_MIN; max = I16_MAX; break;
                    case TYPE_I32: min = I32_MIN; max = I32_MAX; break;
                    case TYPE_I64: min = I64_MIN; max = I64_MAX; break;
                    default: assert(false);
                }
                out_of_range = signed_value < min || signed_value > max;
            } else {
                out_of_range = (member_value & mask) != member_value;
            }

            if (out_of_range) {
                u8 *primitive_name = PRIMITIVE_NAMES[type->enumeration.value_primitive];
                u8 *enum_name = type->enumeration.name;

                print_file_pos(&type->enumeration.members[i].declaration_pos);
                printf(
                    is_signed?
                        "%s = %i is out of range for enum %s(%s)\n" :
                        "%s = %u is out of range for enum %s(%s)\n",
                    member_name, member_value, enum_name, primitive_name
                );
                return false;
            }

            for (u32 j = i + 1; j < count; j += 1) {
                u64 other_member_value = type->enumeration.members[j].value;
                u8 *other_member_name = type->enumeration.members[j].name;

                if (member_name == other_member_name) {
                    print_file_pos(&type->enumeration.members[i].declaration_pos);
                    printf("and ");
                    print_file_pos(&type->enumeration.members[j].declaration_pos);
                    printf("Members '%s' and '%s' both equal %u\n", member_name, other_member_name, member_value);

                    return false;
                }
                
                if (member_name == other_member_name) {
                    u8 *enum_name = type->enumeration.name;

                    print_file_pos(&type->enumeration.members[i].declaration_pos);
                    printf("and ");
                    print_file_pos(&type->enumeration.members[j].declaration_pos);
                    printf("Enum '%s' has multiple members with the name '%s'\n", enum_name, member_name);

                    return false;
                }
            }
        }
    }

    Decl *decl = add_declaration(&context->arena, scope, DECL_TYPE, type->enumeration.name, declaration_pos, false);
    if (decl == null) return false;
    decl->type = type;

    return true;
}

typedef struct Shunting_Yard {
    Expr** expr_queue;
    u32 expr_queue_index, expr_queue_size;

    Binary_Op* op_queue;
    u32 op_queue_index, op_queue_size;

    Expr* unary_prefix;
} Shunting_Yard;

Shunting_Yard* shunting_yard_setup(Context *context) {
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

void shunting_yard_push_subscript(Context *context, Shunting_Yard *yard, Expr *index) {
    assert(yard->unary_prefix == null);
    assert(yard->expr_queue_index > 0);

    Expr **array = &yard->expr_queue[yard->expr_queue_index - 1];
    while (true) {
        if ((*array)->kind == EXPR_UNARY) {
            array = &((*array)->unary.inner);
        } else {
            assert((*array)->kind != EXPR_ADDRESS_OF_FUNCTION); // Supporting this would not be hard, but we don't generate it in the parser rn
            break;
        }
    }

    Expr *expr = arena_new(&context->arena, Expr);
    expr->kind = EXPR_SUBSCRIPT;
    expr->pos = (*array)->pos;
    expr->subscript.array = *array;
    expr->subscript.index = index;

    *array = expr;
}

void shunting_yard_push_pointer_call(Context *context, Shunting_Yard *yard, Expr **params, u32 param_count) {
    assert(yard->unary_prefix == null);
    assert(yard->expr_queue_index > 0);

    Expr **pointer = &yard->expr_queue[yard->expr_queue_index - 1];
    while (true) {
        if ((*pointer)->kind == EXPR_UNARY) {
            pointer = &((*pointer)->unary.inner);
        } else {
            assert((*pointer)->kind != EXPR_ADDRESS_OF_FUNCTION); // Supporting this would not be hard, but we don't generate it in the parser rn
            break;
        }
    }

    Expr *expr = arena_new(&context->arena, Expr);
    expr->kind = EXPR_CALL;
    expr->pos = (*pointer)->pos;
    expr->call.pointer_call = true;
    expr->call.pointer_expr = *pointer;
    expr->call.params = params;
    expr->call.param_count = param_count;

    *pointer = expr;
}

void shunting_yard_push_member_access(Context *context, Shunting_Yard *yard, u8 *member_name) {
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

void shunting_yard_push_expr(Context *context, Shunting_Yard* yard, Expr* new_expr) {
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

void shunting_yard_collapse(Context *context, Shunting_Yard* yard) {
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
    yard->expr_queue[yard->expr_queue_index + 1] = null;
    yard->expr_queue[yard->expr_queue_index + 2] = null;

    expr->pos = expr->binary.left->pos;

    shunting_yard_push_expr(context, yard, expr);
}

void shunting_yard_push_op(Context *context, Shunting_Yard* yard, Binary_Op new_op) {
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

Expr *parse_expr(Context *context, Scope *scope, Token* t, u32* length, bool stop_on_open_curly) {
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
            switch (t[0].kind) {
                // Variable, function call, structure literal
                case TOKEN_IDENTIFIER: {
                    File_Pos start_pos = t->pos;

                    // Some call (either a function or a builtin)
                    if (t[1].kind == TOKEN_BRACKET_ROUND_OPEN) {
                        u32 call_length = 0;
                        Expr* expr = parse_call(context, scope, t, &call_length);
                        t += call_length;

                        if (expr == null) {
                            *length = t - t_start;
                            return null;
                        }

                        shunting_yard_push_expr(context, yard, expr);

                    // Structure literal
                    } else if (t[1].kind == TOKEN_BRACKET_CURLY_OPEN && !stop_on_open_curly) {
                        File_Pos start_pos = t->pos;

                        Type *type = parse_user_type_name(scope, t->identifier);
                        if (type == null) {
                            type = arena_new(&context->arena, Type);
                            type->kind = TYPE_UNRESOLVED_NAME;
                            type->unresolved_name = t->identifier;
                            type->flags |= TYPE_FLAG_UNRESOLVED;
                        }
                        t += 1;

                        u32 struct_length = 0;
                        Expr* expr = parse_compound(context, scope, t, &struct_length);
                        t += struct_length;

                        if (expr == null) {
                            *length = t - t_start;
                            return null;
                        }

                        expr->type = type;
                        shunting_yard_push_expr(context, yard, expr);

                    } else if (t[1].kind == TOKEN_STATIC_ACCESS) {
                        u8 *parent_name = t->identifier;

                        File_Pos start_pos = t->pos;
                        t += 2;

                        if (t->kind != TOKEN_IDENTIFIER) {
                            print_file_pos(&t->pos);
                            printf("Expected struct name, but got ");
                            print_token(t);
                            printf("\n");
                            *length = t - t_start;
                            return null;
                        }

                        u8 *member_name = t->identifier;
                        t += 1;

                        Expr* expr = arena_new(&context->arena, Expr);
                        expr->kind = EXPR_STATIC_MEMBER_ACCESS;
                        expr->static_member_access.parent_name = parent_name;
                        expr->static_member_access.member_name = member_name;
                        expr->flags |= EXPR_FLAG_UNRESOLVED;
                        expr->pos = start_pos;

                        shunting_yard_push_expr(context, yard, expr);

                    } else {
                        u8 *name = t->identifier;

                        Expr* expr = arena_new(&context->arena, Expr);
                        expr->kind = EXPR_VARIABLE;
                        expr->variable.unresolved_name = name;
                        expr->flags |= EXPR_FLAG_UNRESOLVED;
                        expr->pos = t->pos;

                        shunting_yard_push_expr(context, yard, expr);

                        t += 1;
                    }

                    could_parse = true;
                    expect_value = false;
                } break;

                case TOKEN_LITERAL_INT:
                case TOKEN_LITERAL_FLOAT:
                case TOKEN_LITERAL_CHAR:
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

                        case TOKEN_LITERAL_CHAR: {
                            expr->literal.raw_value = (u64) t->literal_char;
                            expr->literal.kind = EXPR_LITERAL_CHAR;
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
                    Expr* inner = parse_expr(context, scope, t, &inner_length, false);
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
                        type = parse_type(context, scope, t, &type_length);
                        t += type_length;

                        if (type == null) {
                            *length = t - t_start;
                            return null;
                        }
                    }

                    u32 array_literal_length = 0;
                    Expr* expr = parse_compound(context, scope, t, &array_literal_length);
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

                case TOKEN_ADD: {
                    // unary +, which we assume to be a no-op
                    could_parse = true;
                    expect_value = true;
                    t += 1;
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
                // Index an array
                case TOKEN_BRACKET_SQUARE_OPEN: {
                    t += 1;

                    u32 index_length = 0;
                    Expr *index = parse_expr(context, scope, t, &index_length, false);
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

                // Call a function pointer
                case TOKEN_BRACKET_ROUND_OPEN: {
                    t += 1;

                    u32 param_list_length = 0;
                    u32 param_count = 0;
                    Expr **params = parse_parameter_list(context, scope, t, &param_list_length, &param_count);
                    t += param_list_length;
                    if (params == null) {
                        *length = t - t_start;
                        return null;
                    }

                    shunting_yard_push_pointer_call(context, yard, params, param_count);

                    expect_value = false;
                    could_parse = true;
                } break;

                // Access a structure member
                case TOKEN_DOT: {
                    t += 1;

                    if (t->kind != TOKEN_IDENTIFIER) {
                        print_file_pos(&t->pos);
                        printf("Expected member name, but got ");
                        print_token(t);
                        printf("\n");
                        *length = t - t_start;
                        return null;
                    }
                    u8 *member_name = t->identifier;
                    t += 1;

                    shunting_yard_push_member_access(context, yard, member_name);

                    expect_value = false;
                    could_parse = true;
                } break;

                // End of expression
                case TOKEN_SEMICOLON:
                case TOKEN_COLON:
                case TOKEN_QUESTIONMARK:
                case TOKEN_UNDERSCORE:
                case TOKEN_COMMA:
                case ')': case ']': case '}':
                case TOKEN_ASSIGN:
                case TOKEN_KEYWORD_LET:
                case TOKEN_KEYWORD_CONST:
                case TOKEN_KEYWORD_FN:
                case TOKEN_RANGE:
                {
                    reached_end = true;
                } break;

                case TOKEN_BRACKET_CURLY_OPEN: {
                    if (stop_on_open_curly) {
                        reached_end = true;
                    }
                } break;

                default: {
                    Binary_Op op = TOKEN_TO_BINARY_OP_MAP[t->kind];
                    if (op != BINARY_OP_INVALID) {
                        if (t[1].kind == TOKEN_ASSIGN) {
                            reached_end = true; // Parse as assignment operator instead
                        } else {
                            shunting_yard_push_op(context, yard, op);
                            could_parse = true;
                            expect_value = true;
                            t += 1;
                        }
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
            print_token(t);
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
    Expr *expr = yard->expr_queue[0];

    arena_stack_pop(&context->stack);


    // Ternary operator, which has really low precedence
    if (t->kind == TOKEN_QUESTIONMARK) {
        t += 1;

        u32 left_length = 0;
        Expr *left = parse_expr(context, scope, t, &left_length, false);
        t += left_length;
        if (left == null) {
            *length = t - t_start;
            return null;
        }

        if (!expect_single_token(context, t, TOKEN_COLON, "between alternatives of ternary operator")) {
            *length = t - t_start;
            return null;
        }
        t += 1;

        u32 right_length = 0;
        Expr *right = parse_expr(context, scope, t, &right_length, false);
        t += right_length;
        if (right == null) {
            *length = t - t_start;
            return null;
        }

        Expr *ternary = arena_new(&context->arena, Expr);
        ternary->kind = EXPR_TERNARY;
        ternary->pos = expr->pos;
        ternary->ternary.condition = expr;
        ternary->ternary.left = left;
        ternary->ternary.right = right;

        expr = ternary;
    }

    *length = t - t_start;
    return expr;
}

Expr* parse_compound(Context *context, Scope *scope, Token* t, u32* length) {
    Token* t_start = t;

    if (!expect_single_token(context, t, TOKEN_BRACKET_CURLY_OPEN, "after type of array literal")) {
        *length = t - t_start;
        return null;
    }
    t += 1;

    typedef struct Member_Expr Member_Expr;
    struct Member_Expr {
        Expr* expr;
        u8 *name;
        Member_Expr *next, *previous;
    };

    u32 member_count = 0;
    Member_Expr* first_member = null;
    Member_Expr* last_member = null;

    arena_stack_push(&context->stack);

    while (t->kind != TOKEN_BRACKET_CURLY_CLOSE) {
        u8 *name = null;
        if (t->kind == TOKEN_IDENTIFIER && (t + 1)->kind == TOKEN_COLON) {
            name = t->identifier;
            t += 2;
        }

        u32 member_length = 0;
        Expr* member = parse_expr(context, scope, t, &member_length, false);
        t += member_length;

        if (member == null) {
            *length = t - t_start;
            return null;
        }

        Member_Expr* next = arena_new(&context->stack, Member_Expr);
        next->name = name;
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
                printf("Expected comma ',' or closing parenthesis '}' after value in compound, but got ");
                print_token(t);
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

        if (p->name == null) {
            member->name_mode = EXPR_COMPOUND_NO_NAME;
        } else {
            member->unresolved_name = p->name;
            member->name_mode = EXPR_COMPOUND_UNRESOLVED_NAME;
        }
    }

    arena_stack_pop(&context->stack);

    *length = t - t_start;
    return expr;
}

Expr **parse_parameter_list(Context *context, Scope *scope, Token* t, u32* length, u32* count) {
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
        Expr* param = parse_expr(context, scope, t, &param_length, false);
        t += param_length;

        if (param == null) {
            *length = t - t_start;
            return null;
        }

        if (t->kind != TOKEN_BRACKET_ROUND_CLOSE) {
            if (t->kind != TOKEN_COMMA) {
                print_file_pos(&t->pos);
                printf("Expected comma ',' or closing parenthesis ')' after parameter in call, but got ");
                print_token(t);
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

Expr* parse_call(Context *context, Scope *scope, Token* t, u32* length) {
    assert(t->kind == TOKEN_IDENTIFIER);
    u8 *fn_name = t->identifier;

    Token* t_start = t;
    File_Pos start_pos = t->pos;

    t += 1;
    assert(t->kind == TOKEN_BRACKET_ROUND_OPEN);
    t += 1;


    Builtin_Fn builtin_name = parse_builtin_fn_name(context, fn_name);
    switch (builtin_name) {
        case BUILTIN_TYPE_INFO_OF_TYPE: {
            u32 type_length = 0;
            Type* type = parse_type(context, scope, t, &type_length);
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
            Expr* inner = parse_expr(context, scope, t, &inner_length, false);
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

        case BUILTIN_SIZE_OF:
        case BUILTIN_ALIGN_OF:
        case BUILTIN_ENUM_LENGTH:
        {
            int query;
            switch (builtin_name) {
                case BUILTIN_SIZE_OF:       query = QUERY_TYPE_INFO_SIZE; break;
                case BUILTIN_ALIGN_OF:      query = QUERY_TYPE_INFO_ALIGN; break;
                case BUILTIN_ENUM_LENGTH:   query = QUERY_TYPE_INFO_ENUM_LENGTH; break;
                default: assert(false);
            }

            u32 type_length = 0;
            Type* type = parse_type(context, scope, t, &type_length);
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
            expr->kind = EXPR_QUERY_TYPE_INFO;
            expr->query_type_info.type = type;
            expr->query_type_info.query = query;
            expr->type = &context->primitive_types[TYPE_DEFAULT_INT];

            *length = t - t_start;
            return expr;
        } break;

        case BUILTIN_SQRT:
        case BUILTIN_ENUM_MEMBER_NAME:
        {
            u32 inner_expr_length = 0;
            Expr* inner = parse_expr(context, scope, t, &inner_expr_length, false);
            t += inner_expr_length;

            if (inner == null) {
                *length = t - t_start;
                return null;
            }

            if (!expect_single_token(context, t, TOKEN_BRACKET_ROUND_CLOSE, "after parameters")) {
                *length = t - t_start;
                return null;
            }
            t += 1;

            Expr* expr = arena_new(&context->arena, Expr);
            expr->pos = start_pos;

            switch (builtin_name) {
                case BUILTIN_ENUM_MEMBER_NAME: {
                    expr->kind = EXPR_ENUM_MEMBER_NAME;
                    expr->enum_member = inner;
                    expr->type = context->string_type;
                } break;

                case BUILTIN_SQRT: {
                    expr->kind = EXPR_UNARY;
                    expr->unary.op = UNARY_SQRT;
                    expr->unary.inner = inner;
                } break;

                default: assert(false);
            }

            *length = t - t_start;
            return expr;
        } break;

        case BUILTIN_CAST: {
            u32 type_length = 0;
            Type* cast_to = parse_type(context, scope, t, &type_length);
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
            Expr* cast_from = parse_expr(context, scope, t, &inner_length, false);
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
            Expr** params = parse_parameter_list(context, scope, t, &param_list_length, &param_count);
            t += param_list_length;
            if (params == null) {
                *length = t - t_start;
                return null;
            }

            Type *cast_to_primitive = parse_primitive_name(context, fn_name);
            if (cast_to_primitive != null) {
                if (!(primitive_is_integer(cast_to_primitive->kind) || primitive_is_float(cast_to_primitive->kind))) {
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
                expr->call.unresolved_name = fn_name;
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

Stmt* parse_stmts(Context *context, Scope *scope, Token* t, u32* length, bool single_stmt);

Stmt* parse_basic_block(Context *context, Scope *scope, Token* t, u32* length) {
    Token* t_start = t;

    if (!expect_single_token(context, t, '{', "before block")) {
        *length = t - t_start;
        return null;
    }
    t += 1;

    u32 inner_length = 0;
    Stmt* stmts = parse_stmts(context, scope, t, &inner_length, false);
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

Stmt *parse_case_body(Context *context, Scope *scope, Token *t, u32 *length) {
    Token *t_start = t;
    Stmt *body = null;

    if (t[0].kind == TOKEN_BRACKET_CURLY_OPEN) {
        t += 1;

        u32 body_length;
        body = parse_stmts(context, scope, t, &body_length, false);
        t += body_length;

        if (body == null) {
            *length = t - t_start;
            return null;
        }

        if (!expect_single_token(context, t, '}', "after case")) {
            *length = t - t_start;
            return null;
        }
        t += 1;
    } else {
        u32 body_length;
        body = parse_stmts(context, scope, t, &body_length, true);
        t += body_length;

        if (body == null) {
            *length = t - t_start;
            return null;
        }
    }

    *length = t - t_start;
    return body;
}

typedef struct Var_Decl_Info {
    bool constant;
    Var *vars;
    u32 var_count;
    Expr *expr;
} Var_Decl_Info;

bool parse_variable_declaration(Context *context, Scope *scope, Token *t, u32 *length, Var_Decl_Info *info) {
    File_Pos decl_pos = t->pos;
    Token *t_start = t;

    info->constant = t->kind == TOKEN_KEYWORD_CONST;
    t += 1;

    arena_stack_push(&context->stack);

    typedef struct Name_Entry Name_Entry;
    struct Name_Entry {
        u8 *name;
        Name_Entry *next;
    };
    Name_Entry *first = null;
    Name_Entry *last = null;
    info->var_count = 0;

    while (true) {
        if (t->kind != TOKEN_IDENTIFIER) {
            print_file_pos(&t->pos);
            printf("Expected variable name, but found ");
            print_token(t);
            printf("\n");
            *length = t - t_start;
            return false;
        }

        u8 *name = t->identifier;
        t += 1;

        Name_Entry *entry = arena_new(&context->stack, Name_Entry);
        entry->name = name;
        last = (first == null? (first = entry) : (last->next = entry));
        info->var_count += 1;

        if (t->kind == TOKEN_COMMA) {
            t += 1;
            continue;
        } else if (t->kind == TOKEN_COLON || t->kind == TOKEN_ASSIGN) {
            break;
        } else {
            print_file_pos(&t->pos);
            printf("Expected a comma ',', a colon ':', or a =, but got a ");
            print_token(t);
            printf("\n");
            return false;
        }
    }

    Type *type = null;
    if (t->kind == TOKEN_COLON) {
        t += 1;

        u32 type_length = 0;
        type = parse_type(context, scope, t, &type_length);
        if (type == null) {
            *length = t - t_start;
            return false;
        }
        t += type_length;
    }

    info->expr = null;
    if (t->kind == TOKEN_ASSIGN) {
        t += 1;

        u32 right_length = 0;
        info->expr = parse_expr(context, scope, t, &right_length, false); 
        if (info->expr == null) {
            *length = t - t_start;
            return false;
        }
        t += right_length;
    }

    if (!expect_single_token(context, t, TOKEN_SEMICOLON, "after variable declaration")) {
        *length = t - t_start;
        return false;
    }
    t += 1;

    if (info->expr == null && type == null) {
        print_file_pos(&t->pos);
        printf("Declared ");
        if (info->var_count > 1) {
            printf("variables ");
            for (Name_Entry *e = first; e->next != null; e = e->next) {
                if (e != first) printf(", ");
                printf("'%s'", e->name);
            }
        } else {
            printf("variable '%s'", first->name);
        }
        printf("without giving type or initial value\n");
        *length = t - t_start;
        return false;
    }

    *length = t - t_start;

    assert(info->var_count >= 0);
    info->vars = (Var*) arena_alloc(&context->arena, info->var_count * sizeof(Var));
    Name_Entry *entry = first;
    for (u32 i = 0; i < info->var_count; i += 1, entry = entry->next) {
        assert(entry != null);
        Var *var = &info->vars[i];
        var->name = entry->name;
        var->declaration_pos = decl_pos;
        var->type = type;
        if (info->constant) var->flags |= VAR_FLAG_CONSTANT;

        if (scope->fn == null || info->constant) {
            var->flags |= VAR_FLAG_GLOBAL;
            var->global_index = buf_length(context->global_vars);
            buf_push(context->global_vars, ((Global_Var) { .var = var, .data_offset = U32_MAX }));
        } else {
            var->local_index = scope->fn->body.var_count;
            scope->fn->body.var_count += 1;
        }

        Decl *decl = add_declaration(&context->arena, scope, DECL_VAR, entry->name, decl_pos, !(scope->fn == null || info->constant));
        if (decl == null) return false;
        decl->var = var;
    }

    arena_stack_pop(&context->stack);

    return true;
}

Stmt* parse_stmts(Context *context, Scope *scope, Token *t, u32 *length, bool single_stmt) {
    assert(scope->fn != null);

    Token* t_first_stmt_start = t;

    u32 parsed_stmts = 0;

    Stmt *first_stmt = arena_new(&context->arena, Stmt);
    first_stmt->pos = t->pos;

    Stmt *stmt = first_stmt;

    while (true) {
        // Semicolons are just empty statements, skip them
        while (t->kind == TOKEN_SEMICOLON) {
            if (single_stmt && parsed_stmts >= 1) break;
            parsed_stmts += 1;
            t += 1;
            continue;
        }

        if (single_stmt && parsed_stmts >= 1) break;

        Token* t_start = t;
        stmt->pos = t->pos;

        stmt->scope_pos = scope->next_scope_pos;
        scope->next_scope_pos += 1;

        bool no_stmt_generated = false;

        switch (t->kind) {
            case TOKEN_BRACKET_CURLY_CLOSE: {
                stmt->kind = STMT_END;
            } break;

            case TOKEN_BRACKET_CURLY_OPEN: {
                stmt->kind = STMT_BLOCK;
                stmt->block.scope.fn = scope->fn;
                stmt->block.scope.parent = scope;

                u32 block_length = 0;
                stmt->block.stmt = parse_basic_block(context, &stmt->block.scope, t, &block_length);
                t += block_length;
                if (stmt->block.stmt == null) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
            } break;

            case TOKEN_KEYWORD_IF: {
                Stmt* if_stmt = stmt;

                while (true) {
                    if_stmt->kind = STMT_IF;
                    if_stmt->if_.then_scope.fn = scope->fn;
                    if_stmt->if_.then_scope.parent = scope;
                    if_stmt->if_.else_then_scope.fn = scope->fn;
                    if_stmt->if_.else_then_scope.parent = scope;
                    t += 1;

                    u32 condition_length = 0;
                    if_stmt->if_.condition = parse_expr(context, scope, t, &condition_length, true);
                    t += condition_length;
                    if (if_stmt->if_.condition == null) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }

                    u32 block_length = 0;
                    if_stmt->if_.then = parse_basic_block(context, &if_stmt->if_.then_scope, t, &block_length);
                    t += block_length;
                    if (if_stmt->if_.then == null) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }

                    bool parse_another_if = false;
                    if (t->kind == TOKEN_KEYWORD_ELSE) {
                        t += 1;

                        switch (t->kind) {
                            case TOKEN_BRACKET_CURLY_OPEN: {
                                u32 block_length = 0;
                                if_stmt->if_.else_then = parse_basic_block(context, &if_stmt->if_.else_then_scope, t, &block_length);
                                t += block_length;
                                if (if_stmt->if_.else_then == null) {
                                    *length = t - t_first_stmt_start;
                                    return null;
                                }
                            } break;

                            case TOKEN_KEYWORD_IF: {
                                parse_another_if = true;

                                Stmt* next_if_stmt = arena_new(&context->arena, Stmt);
                                next_if_stmt->next = arena_new(&context->arena, Stmt); // Sentinel

                                if_stmt->if_.else_then = next_if_stmt;
                                if_stmt = next_if_stmt;
                            } break;

                            default: {
                                print_file_pos(&t->pos);
                                printf("Expected another if-statmenet or a basic block after else, but got ");
                                print_token(t);
                                printf("\n");
                                *length = t - t_first_stmt_start;
                                return null;
                            } break;
                        }
                    }

                    if(!parse_another_if) break;
                }
            } break;

            case TOKEN_KEYWORD_SWITCH: {
                stmt->kind = STMT_SWITCH;
                t += 1;

                u32 index_length = 0;
                stmt->switch_.index = parse_expr(context, scope, t, &index_length, true);
                t += index_length;
                if (stmt->switch_.index == null) {
                    *length = t - t_first_stmt_start;
                    return null;
                }

                if (!expect_single_token(context, t, '{', "after switch key")) {
                    *length = t - t_start;
                    return null;
                }
                t += 1;

                typedef struct Entry Entry;
                typedef struct Key_Entry Key_Entry;

                struct Key_Entry {
                    Switch_Case_Key key;
                    Key_Entry *next;
                };
                struct Entry {
                    Key_Entry *first_key;

                    Switch_Case c;
                    Entry *next;
                };
                Entry *first = null;
                Entry *last = null;

                arena_stack_push(&context->stack);

                while (true) {
                    if (t[0].kind == TOKEN_BRACKET_CURLY_CLOSE) {
                        t += 1;
                        break;
                    }

                    // The default case
                    if (t[0].kind == TOKEN_UNDERSCORE) {
                        File_Pos default_case_pos = t[0].pos;

                        t += 1;
                        if (!expect_single_token(context, t, ':', "after case")) {
                            *length = t - t_start;
                            return null;
                        }
                        t += 1;

                        if (stmt->switch_.default_case != null) {
                            u64 other_line = stmt->switch_.default_case->pos.line;
                            print_file_pos(&default_case_pos);
                            printf("Can't have more than one default case (Other default case on line %u)\n", (u64) other_line);
                            *length = t - t_first_stmt_start;
                            return null;
                        }

                        stmt->switch_.default_case = arena_new(&context->arena, Switch_Case);
                        stmt->switch_.default_case->scope = arena_new(&context->arena, Scope);
                        stmt->switch_.default_case->scope->parent = scope;
                        stmt->switch_.default_case->scope->fn = scope->fn;

                        u32 body_length;
                        stmt->switch_.default_case->body = parse_case_body(context, stmt->switch_.default_case->scope, t, &body_length);
                        t += body_length;
                        if (stmt->switch_.default_case->body == null) {
                            *length = t - t_start;
                            return null;
                        }
                    } else {
                        Entry *entry = arena_new(&context->stack, Entry);
                        if (first == null) { first = entry; } else { last->next = entry; }
                        last = entry;

                        entry->c.pos = t[0].pos;
                        entry->c.scope = arena_new(&context->arena, Scope);
                        entry->c.scope->parent = scope;
                        entry->c.scope->fn = scope->fn;

                        // Parse keys
                        Key_Entry *first_key = null;
                        Key_Entry *last_key = null;

                        while (true) {
                            Key_Entry *key_entry = arena_new(&context->stack, Key_Entry);
                            last_key = ((first_key == null)? (first_key = key_entry) : (last_key->next = key_entry));
                            key_entry->key.pos = t[0].pos;

                            if (t[0].kind == TOKEN_IDENTIFIER && (t[1].kind == TOKEN_COLON || t[1].kind == TOKEN_COMMA)) {
                                key_entry->key.is_identifier = true;
                                key_entry->key.identifier = t[0].identifier;
                                t += 1;
                            } else {
                                u32 key_expr_length;
                                key_entry->key.expr = parse_expr(context, scope, t, &key_expr_length, false);
                                t += key_expr_length;

                                if (key_entry->key.expr == null) {
                                    *length = t - t_first_stmt_start;
                                    return null;
                                }
                            }

                            entry->c.key_count += 1;

                            if (t[0].kind == TOKEN_COLON) {
                                t += 1;
                                break;
                            } else if (t[0].kind == TOKEN_COMMA) {
                                t += 1;
                                continue;
                            } else {
                                print_file_pos(&t->pos);
                                printf("Expected a colon ':' or a comma ',' after case, but got ");
                                print_token(t);
                                printf("\n");
                                *length = t - t_start;
                                return null;
                            }
                        }
                        entry->first_key = first_key;

                        // Parse body
                        u32 body_length;
                        entry->c.body = parse_case_body(context, entry->c.scope, t, &body_length);
                        t += body_length;
                        if (entry->c.body == null) {
                            *length = t - t_start;
                            return null;
                        }

                        stmt->switch_.case_count += 1;
                    }
                }

                stmt->switch_.cases = (void*) arena_alloc(&context->arena, stmt->switch_.case_count * sizeof(Switch_Case));

                Entry *entry = first;
                for (u32 i = 0; i < stmt->switch_.case_count; i += 1) {
                    assert(entry != null);
                    stmt->switch_.cases[i] = entry->c;

                    stmt->switch_.cases[i].keys = (void*) arena_alloc(&context->arena, entry->c.key_count * sizeof(Switch_Case_Key));

                    Key_Entry *key_entry = entry->first_key;
                    for (u32 j = 0; j < entry->c.key_count; j += 1) {
                        assert(key_entry != null);
                        stmt->switch_.cases[i].keys[j] = key_entry->key;
                        key_entry = key_entry->next;
                    }

                    entry = entry->next;
                }

                arena_stack_pop(&context->stack);
            } break;

            case TOKEN_KEYWORD_FOR: {
                stmt->kind = STMT_FOR;
                stmt->for_.scope.parent = scope;
                stmt->for_.scope.fn = scope->fn;

                t += 1;

                // for {}
                if (t[0].kind == TOKEN_BRACKET_CURLY_OPEN) {
                    stmt->for_.kind = LOOP_INFINITE;

                    u32 body_length = 0;
                    stmt->for_.body = parse_basic_block(context, &stmt->for_.scope, t, &body_length);
                    t += body_length;
                    if (stmt->for_.body == null) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }

                // for item : <range> {}
                } else if (t[0].kind == TOKEN_IDENTIFIER && t[1].kind == TOKEN_COLON) {
                    stmt->for_.kind = LOOP_RANGE;

                    u8 *index_var_name = t[0].identifier;
                    File_Pos index_var_pos = t[0].pos;
                    t += 2;

                    u32 start_length;
                    stmt->for_.range.start = parse_expr(context, scope, t, &start_length, false);
                    t += start_length;
                    if (stmt->for_.range.start == null) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }

                    if (!expect_single_token(context, t, TOKEN_RANGE, "after lower bound")) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }
                    t += 1;

                    u32 end_length;
                    stmt->for_.range.end = parse_expr(context, scope, t, &end_length, true);
                    t += end_length;
                    if (stmt->for_.range.end == null) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }

                    Var *var = arena_new(&context->arena, Var);
                    var->name = index_var_name;
                    var->declaration_pos = index_var_pos;
                    var->type = null;
                    var->local_index = scope->fn->body.var_count;
                    scope->fn->body.var_count += 1;

                    Decl *index_decl = add_declaration(&context->arena, &stmt->for_.scope, DECL_VAR, index_var_name, index_var_pos, true);
                    assert(index_decl != null);
                    index_decl->var = var;

                    stmt->for_.range.var = var;

                    u32 body_length = 0;
                    stmt->for_.body = parse_basic_block(context, &stmt->for_.scope, t, &body_length);
                    t += body_length;
                    if (stmt->for_.body == null) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }

                // for <condition> {}
                } else {
                    stmt->for_.kind = LOOP_CONDITIONAL;

                    u32 first_length = 0;
                    stmt->for_.condition = parse_expr(context, scope, t, &first_length, true);
                    t += first_length;
                    if (stmt->for_.condition == null) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }

                    u32 body_length = 0;
                    stmt->for_.body = parse_basic_block(context, &stmt->for_.scope, t, &body_length);
                    t += body_length;
                    if (stmt->for_.body == null) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }
                }
            } break;

            case TOKEN_KEYWORD_RETURN: {
                stmt->kind = STMT_RETURN;
                t += 1;

                if (t->kind != TOKEN_SEMICOLON) {
                    u32 expr_length = 0;
                    stmt->return_.value = parse_expr(context, scope, t, &expr_length, false);
                    t += expr_length;
                    if (stmt->return_.value == null) {
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

                if (!expect_single_token(context, t, TOKEN_SEMICOLON, "after break")) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
                t += 1;
            } break;

            case TOKEN_KEYWORD_CONTINUE: {
                stmt->kind = STMT_CONTINUE;
                t += 1;

                if (!expect_single_token(context, t, TOKEN_SEMICOLON, "after continue")) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
                t += 1;
            } break;

            case TOKEN_KEYWORD_DEBUG_BREAK: {
                stmt->kind = STMT_DEBUG_BREAK;
                t += 1;

                if (!expect_single_token(context, t, TOKEN_SEMICOLON, "after debug_break")) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
                t += 1;
            } break;

            case TOKEN_KEYWORD_CONST:
            case TOKEN_KEYWORD_LET:
            {
                Var_Decl_Info info;

                u32 decl_length;
                bool success = parse_variable_declaration(context, scope, t, &decl_length, &info);
                t += decl_length;

                if (!success) {
                    *length = t - t_first_stmt_start;
                    return null;
                }

                if (info.constant) {
                    no_stmt_generated = true;

                    buf_push(context->global_lets, ((Global_Let) {
                        .pos = stmt->pos,
                        .scope = scope,
                        .vars = info.vars,
                        .var_count = info.var_count,
                        .expr = info.expr,
                    }));
                } else {
                    stmt->kind = STMT_LET;
                    stmt->let.vars = info.vars;
                    stmt->let.var_count = info.var_count;
                    stmt->let.right = info.expr; 
                }
            } break;

            case TOKEN_KEYWORD_ENUM: {
                no_stmt_generated = true;

                u32 decl_length = 0;
                bool valid = parse_enum_declaration(context, scope, t, &decl_length);
                t += decl_length;

                if (!valid) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
            } break;

            case TOKEN_KEYWORD_STRUCT: {
                no_stmt_generated = true;

                u32 decl_length = 0;
                bool valid = parse_struct_declaration(context, &context->global_scope, t, &decl_length);
                t += decl_length;

                if (!valid) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
            } break;

            case TOKEN_KEYWORD_UNION: {
                unimplemented(); // TODO
            } break;

            case TOKEN_KEYWORD_FN: {
                no_stmt_generated = true;

                u32 decl_length = 0;
                Fn *fn = parse_fn(context, scope, t, &decl_length);
                t += decl_length;

                if (fn == null) {
                    *length = t - t_first_stmt_start;
                    return null;
                } else if (fn->kind != FN_KIND_NORMAL) {
                    print_file_pos(&fn->declaration_pos);
                    printf("Function '%s' doesn't have a body. Functions without bodies can only be inside 'extern' blocks\n", fn->name);
                    *length = t - t_first_stmt_start;
                    return null;
                }
            } break;

            default: {
                u32 left_length = 0;
                Expr* left = parse_expr(context, scope, t, &left_length, false);
                t += left_length;

                if (left == null) {
                    *length = t - t_first_stmt_start;
                    return null;
                }

                if (t[0].kind == TOKEN_ASSIGN) {
                    t += 1;

                    u32 right_length = 0;
                    Expr* right = parse_expr(context, scope, t, &right_length, false);
                    t += right_length;

                    if (right == null) {
                        *length = t - t_first_stmt_start;
                        return null;
                    }

                    stmt->kind = STMT_ASSIGNMENT;
                    stmt->assignment.left = left;
                    stmt->assignment.right = right;
                } else {
                    Binary_Op op = TOKEN_TO_BINARY_OP_MAP[t[0].kind];
                    if (t[1].kind == TOKEN_ASSIGN && BINARY_OP_CAN_BE_USED_FOR_OP_ASSIGNMENT[op]) {
                        t += 2;

                        u32 right_length = 0;
                        Expr* right = parse_expr(context, scope, t, &right_length, false);
                        t += right_length;

                        if (right == null) {
                            *length = t - t_first_stmt_start;
                            return null;
                        }

                        stmt->kind = STMT_OP_ASSIGNMENT;
                        stmt->op_assignment.left = left;
                        stmt->op_assignment.right = right;
                        stmt->op_assignment.op = op;
                    } else {
                        stmt->kind = STMT_EXPR;
                        stmt->expr = left;
                    }
                }

                if (!expect_single_token(context, t, TOKEN_SEMICOLON, "after statement")) {
                    *length = t - t_first_stmt_start;
                    return null;
                }
                t += 1;
            } break;
        }

        // Try parsing more statements after this one
        if (no_stmt_generated) {
            assert(stmt->kind == STMT_END);
        } else if (stmt->kind != STMT_END) {
            parsed_stmts += 1;
            stmt->next = arena_new(&context->arena, Stmt);
            stmt = stmt->next;
        } else {
            break;
        }
    }

    *length = t - t_first_stmt_start;
    return first_stmt;
}

Fn *parse_fn(Context *context, Scope *scope, Token *t, u32 *length) {
    assert(t->kind == TOKEN_KEYWORD_FN);
    bool valid = true;

    Token* t_start = t;
    File_Pos declaration_pos = t->pos;

    // Estimate size of function, so we still print reasonable errors on bad function declarations
    // TODO TODO TODO This estimation is completly useless now, as we can have function pointers.
    // We probably just want to bail out on the first error, so we don't have to deal with
    // properly continuing compilation on errors!
    *length = 1;
    for (Token* u = t + 1; !(u->kind == TOKEN_END_OF_STREAM || u->kind == TOKEN_KEYWORD_FN); u += 1) {
        *length += 1;
    }


    Fn *fn = arena_new(&context->arena, Fn);
    fn->declaration_pos = t->pos;

    u32 signature_length = 0;
    Type *signature_type = parse_fn_signature(context, scope, t, &signature_length, fn);
    t += signature_length;

    if (signature_type == null) return null;
    assert(signature_type->kind == TYPE_FN_POINTER);
    fn->signature_type = signature_type;
    fn->signature = &signature_type->fn_signature;

    if (parse_primitive_name(context, fn->name) != null || context->builtin_names[BUILTIN_CAST] == fn->name) {
        print_file_pos(&t_start->pos);
        printf("Can't use '%s' as a function name, as it is reserved for casts\n", fn->name);
        valid = false;
    } else if (parse_builtin_fn_name(context, fn->name) != BUILTIN_INVALID) {
        print_file_pos(&t_start->pos);
        printf("Can't use '%s' as a function name, as it would shadow a builtin function\n", fn->name);
        valid = false;
    }

    // Functions without a body
    if (t->kind == TOKEN_SEMICOLON) {
        fn->kind = FN_KIND_IMPORTED;
        t += 1;

    // Body
    } else {
        fn->kind = FN_KIND_NORMAL;
        fn->body.scope.fn = fn;
        fn->body.scope.parent = scope;

        if (t->kind != TOKEN_BRACKET_CURLY_OPEN) {
            print_file_pos(&t->pos);
            printf("Expected an open curly brace { after 'fn %s ...', but found ", fn->name);
            print_token(t);
            printf("\n");
            return null;
        }

        Token* body = t + 1;
        u32 body_length = t->bracket_offset_to_matching - 1;
        t = t + t->bracket_offset_to_matching;

        u32 stmts_length = 0;
        Stmt *first_stmt = parse_stmts(context, &fn->body.scope, body, &stmts_length, false);

        if (first_stmt == null || stmts_length != body_length) {
            valid = false;
        }

        fn->body.first_stmt = first_stmt;

        if (!expect_single_token(context, t, TOKEN_BRACKET_CURLY_CLOSE, "after function body")) {
            valid = false;
        }
        t += 1;
    }

    *length = t - t_start;
    if (!valid) return null;

    Decl *decl = add_declaration(&context->arena, scope, DECL_FN, fn->name, declaration_pos, false);
    if (decl == null) return null;
    decl->fn = fn;

    return fn;
}

bool parse_typedef(Context *context, Scope *scope, Token *t, u32 *length) {
    File_Pos declaration_pos = t->pos;
    Token *t_start = t;

    // Estimate size
    *length = 0;
    for (Token* u = t; !(u->kind == TOKEN_END_OF_STREAM || u->kind == TOKEN_SEMICOLON); u += 1) {
        *length += 1;
    }

    assert(t->kind == TOKEN_KEYWORD_TYPEDEF);
    t += 1;

    if (t->kind != TOKEN_IDENTIFIER) {
        print_file_pos(&t->pos);
        printf("Expected new type name, but got ");
        print_token(t);
        printf("\n");
        return false;
    }
    u8 *name = t->identifier;
    t += 1;

    if (!expect_single_token(context, t, TOKEN_ASSIGN, "after typedef name")) return false;
    t += 1;

    u32 type_length = 0;
    Type *type = parse_type(context, scope, t, &type_length);
    t += type_length;

    if (!expect_single_token(context, t, TOKEN_SEMICOLON, "after type")) return false;
    t += 1;

    *length = t - t_start;

    Decl *decl = add_declaration(&context->arena, scope, DECL_TYPE, name, declaration_pos, false);
    if (decl == null) return false;
    decl->type = type;

    return true;
}

bool parse_extern(Context *context, Scope *scope, u8 *source_path, Token *t, u32 *length) {
    assert(t->kind == TOKEN_KEYWORD_EXTERN);

    Token *start = t;
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
        print_token(t);
        printf("\n");
        return false;
    }
    u8 *library_name = string_intern_with_length(&context->string_table, t->string.bytes, t->string.length);

    // Body
    t += 1;
    if (t->kind != TOKEN_BRACKET_CURLY_OPEN) {
        print_file_pos(&t->pos);
        printf("Expected an open curly brace { after 'extern \"%s\" ...', but found ", library_name);
        print_token(t);
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
                Fn *fn = parse_fn(context, scope, &body[i], &length);

                if (fn == null) {
                    valid = false;
                } else if (fn->kind != FN_KIND_IMPORTED) {
                    print_file_pos(&body[i].pos);
                    printf("Function '%s' has a body, but functions inside 'extern' blocks can't have bodies\n", fn->name);
                    valid = false;
                } else {
                    Import_Index import_index = add_import(context, source_path, library_name, fn->name);
                    fn->import_info.index = import_index;
                }

                i += length - 1;
            } break;

            default: {
                print_file_pos(&body[i].pos);
                printf("Found invalid token at top level inside 'extern' block: ");
                print_token(&body[i]);
                printf("\n");

                i += 1;
                while (i < body_length && body[i].kind != TOKEN_SEMICOLON) { i += 1; }
            } break;
        }
        // TODO parse function templates
    }

    return valid;
}


bool lex_and_parse_text(Context *context, u8* file_name, u8* file, u32 file_length);

bool build_ast(Context *context, u8* file_name) {
    init_keyword_names(context);
    init_builtin_fn_names(context);
    init_primitive_types(context);

    u8* file;
    u32 file_length;

    IO_Result read_result = read_entire_file(file_name, &file, &file_length);
    if (read_result != IO_OK) {
        printf("Couldn't load \"%s\": %s\n", file_name, io_result_message(read_result));
        return false;
    }

    bool valid = true;

    assert(lex_and_parse_text(context, "<preload>", preload_code_text, str_length(preload_code_text)));

    u8 *string_type_name = string_intern(&context->string_table, "String");
    context->string_type = parse_user_type_name(&context->global_scope, string_type_name);
    assert(context->string_type != null && context->string_type->kind == TYPE_STRUCT);

    u8 *type_kind_type_name = string_intern(&context->string_table, "Type_Kind");
    context->type_info_type = parse_user_type_name(&context->global_scope, type_kind_type_name);
    assert(context->type_info_type != null && context->type_info_type->kind == TYPE_ENUM);


    valid &= lex_and_parse_text(context, file_name, file, file_length);

    sc_free(file);

    if (valid) {
        return true;
    } else {
        printf("Encountered errors while lexing / parsing, exiting compiler!\n");
        return false;
    }
}

bool lex_and_parse_text(Context *context, u8* file_name, u8* file, u32 file_length) {
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
    file_pos.character = 1;

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

    for (u32 i = 0; i < file_length;) {
        u32 start_i = i;
        u32 start_line = file_pos.line;

        switch (file[i]) {
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
                u8 *identifier = &file[first];

                if (length == 1 && *identifier == '_') {
                    buf_push(tokens, ((Token) { TOKEN_UNDERSCORE, .pos = file_pos }));
                    break;
                }

                u8 *interned_identifier = string_intern_with_length(&context->string_table, identifier, length);

                bool is_keyword = false;
                for (u32 k = 0; k < KEYWORD_COUNT; k += 1) {
                    if (interned_identifier == context->keyword_token_table[k].interned_name) {
                        buf_push(tokens, ((Token) { context->keyword_token_table[k].token, .pos = file_pos }));
                        is_keyword = true;
                        break;
                    }
                }

                if (!is_keyword) {
                    buf_push(tokens, ((Token) { TOKEN_IDENTIFIER, .identifier = interned_identifier, .pos = file_pos }));
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
                                if (i + 1 < file_length && file[i + 1] >= '0' && file[i + 1] <= '9') {
                                    floating_point = true;
                                } else {
                                    goto done_with_literal;
                                }
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
                        kind = TOKEN_ADD;
                        i += 1;
                    } break;

                    case '-': {
                        if (b == '>') {
                            kind = TOKEN_ARROW;
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
                                        file_pos.character = 1;
                                        start_line = file_pos.line;
                                        start_i = i;
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

                    case '&': {
                        if (b == '&') {
                            kind = TOKEN_LOGICAL_AND;
                            i += 2;
                        } else {
                            kind = TOKEN_AND;
                            i += 1;
                        }
                    } break;

                    case '|': {
                        if (b == '|') {
                            kind = TOKEN_LOGICAL_OR;
                            i += 2;
                        } else {
                            kind = TOKEN_OR;
                            i += 1;
                        }
                    } break;

                    case '^': {
                        kind = TOKEN_XOR;
                        i += 1;
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
                        if (i + 1 < file_length && (file[i]+file[i + 1] == '\n'+'\r')) {
                            i += 1;
                        }

                        file_pos.line += 1;
                        file_pos.character = 1;
                        start_line = file_pos.line;
                        start_i = i;

                        continue;
                    }

                    if (file[i] == '\\') {
                        i += 1;
                    } else if (file[i] == '"') {
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
                        u8 resolved = resolve_escaped_char(start[i]);
                        i += 1;

                        if (resolved == 0xff) {
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

            case '\'': {
                if ((i + 2 > file_length) || ((file[i + 1] == '\\') && (i + 3 > file_length))) {
                    print_file_pos(&file_pos);
                    printf("Encountered end of file inside charater literal\n");
                    valid = false;
                    break;
                }

                u8 c;
                if (file[i + 1] == '\\') {
                    c = resolve_escaped_char(file[i + 2]);
                    if (c == 0xff) {
                        print_file_pos(&file_pos);
                        printf("Invalid escape sequence: '\\%c'\n", file[i + 2]);
                        valid = false;
                        break;
                    }
                    i += 3;
                } else {
                    c = file[i + 1];
                    i += 2;
                }

                if (file[i] != '\'') {
                    print_file_pos(&file_pos);
                    printf("Expected closing tick ', but got %c\n", file[i]);
                    valid = false;
                    break;
                }
                i += 1;

                buf_push(tokens, ((Token) { TOKEN_LITERAL_CHAR, .pos = file_pos, .literal_char = c  }));
            } break;

            case ',': {
                i += 1;
                buf_push(tokens, ((Token) { TOKEN_COMMA, .pos = file_pos }));
            } break;

            case '.': {
                if (i + 1 < file_length && file[i + 1] == '.') {
                    i += 2;
                    buf_push(tokens, ((Token) { TOKEN_RANGE, .pos = file_pos }));
                } else {
                    i += 1;
                    buf_push(tokens, ((Token) { TOKEN_DOT, .pos = file_pos }));
                }
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

            case '?': {
                i += 1;
                buf_push(tokens, ((Token) { TOKEN_QUESTIONMARK, .pos = file_pos }));
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

        if (file_pos.line == start_line + 1) {
            file_pos.character = 1;
        } else if (file_pos.line == start_line) {
            file_pos.character += i - start_i;
        } else {
            assert(false);
        }
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
        print_token(t);
        printf("\n");
    }
    #endif

    // Parse
    Token* t = tokens;
    while (t->kind != TOKEN_END_OF_STREAM && valid) switch (t->kind) {
        case TOKEN_KEYWORD_FN: {
            u32 length = 0;
            Fn* fn = parse_fn(context, &context->global_scope, t, &length);
            t += length;

            if (fn == null) {
                valid = false;
            } else if (fn->kind != FN_KIND_NORMAL) {
                print_file_pos(&fn->declaration_pos);
                printf("Function '%s' doesn't have a body. Functions without bodies can only be inside 'extern' blocks\n", fn->name);
                valid = false;
            }
        } break;

        case TOKEN_KEYWORD_EXTERN: {
            u32 length = 0;
            valid &= parse_extern(context, &context->global_scope, file_name, t, &length);
            t += length;
        } break;

        case TOKEN_KEYWORD_TYPEDEF: {
            u32 length = 0;
            valid &= parse_typedef(context, &context->global_scope, t, &length);
            t += length;
        } break;

        case TOKEN_KEYWORD_CONST:
        case TOKEN_KEYWORD_LET:
        {
            File_Pos decl_pos = t->pos;

            Var_Decl_Info info;

            u32 decl_length;
            bool success = parse_variable_declaration(context, &context->global_scope, t, &decl_length, &info);
            t += decl_length;

            if (!success) {
                valid = false;
            } else {
                buf_push(context->global_lets, ((Global_Let) {
                    .pos = decl_pos,
                    .scope = &context->global_scope,
                    .vars = info.vars,
                    .var_count = info.var_count,
                    .expr = info.expr,
                }));
            }
        } break;

        case TOKEN_KEYWORD_ENUM: {
            u32 length = 0;
            valid &= parse_enum_declaration(context, &context->global_scope, t, &length);
            t += length;
        } break;

        case TOKEN_KEYWORD_STRUCT: {
            u32 length = 0;
            valid &= parse_struct_declaration(context, &context->global_scope, t, &length);
            t += length;
        } break;

        case TOKEN_KEYWORD_UNION: {
            unimplemented(); // TODO
        } break;

        default: {
            valid = false;

            print_file_pos(&t->pos);
            printf("Found invalid token at global scope: ");
            print_token(t);
            printf("\n");
        } break;
    }

    return valid;
}


typedef enum Eval_Result {
    EVAL_OK,
    EVAL_BAD,
    EVAL_DEPENDENT,
    EVAL_DO_AT_RUNTIME,
} Eval_Result;

// NB This will allocate on context->stack, push/pop before/after
Eval_Result eval_compile_time_expr(Context *context, Expr *expr, u8 *result_into);

typedef enum Typecheck_Result {
    TYPECHECK_RESULT_DONE,
    TYPECHECK_RESULT_DEPENDENT,
    TYPECHECK_RESULT_BAD,
} Typecheck_Result;

typedef enum Typecheck_Expr_Result {
    TYPECHECK_EXPR_DEPENDENT = TYPECHECK_RESULT_DEPENDENT,
    TYPECHECK_EXPR_BAD = TYPECHECK_RESULT_BAD,
    TYPECHECK_EXPR_STRONG,
    TYPECHECK_EXPR_WEAK, // Used for e.g. integer literals, which can solidify to any integer type
} Typecheck_Expr_Result;

Typecheck_Expr_Result typecheck_expr(Context *context, Scope *scope, u32 scope_pos, Expr *expr, Type *solidify_to);

Typecheck_Result compute_size_of_struct(Type *type) {
    u32 max_align = 0;
    u32 size = 0;

    for (u32 m = 0; m < type->structure.member_count; m += 1) {
        File_Pos* member_pos = &type->structure.members[m].declaration_pos;
        Type *member_type = type->structure.members[m].type;

        if (member_type->flags & (TYPE_FLAG_UNRESOLVED|TYPE_FLAG_UNRESOLVED_CHILD)) {
            return TYPECHECK_RESULT_DEPENDENT;
        }

        u32 member_size = 0;
        u32 member_align = 0;

        u32 array_multiplier = 1;
        while (true) {
            if (member_type->kind == TYPE_ARRAY) {
                array_multiplier *= member_type->array.length;
                member_type = member_type->array.of;

            } else {
                if (member_type->flags & TYPE_FLAG_SIZE_NOT_COMPUTED) {
                    return TYPECHECK_RESULT_DEPENDENT;
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

        size = round_to_next(size, member_align);
        type->structure.members[m].offset = (i32) size;
        size += member_size;

        max_align = max(max_align, member_align);
    }

    if (max_align > 0) {
        size = round_to_next(size, max_align);
    }

    type->structure.size = size;
    type->structure.align = max_align;

    type->flags &= ~TYPE_FLAG_SIZE_NOT_COMPUTED;

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

    return TYPECHECK_RESULT_DONE;
}

Typecheck_Result resolve_type(Context *context, Scope *scope, u32 scope_pos, Type **type_slot, File_Pos *pos) {
    // The reason we have a pretty complex system here is because we want types to be pointer-equal

    Type *type = *type_slot;

    if (!(type->flags & (TYPE_FLAG_UNRESOLVED|TYPE_FLAG_UNRESOLVED_CHILD))) {
        return TYPECHECK_RESULT_DONE;
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
                if (type->flags & TYPE_FLAG_UNRESOLVED) {
                    Expr *length_expr = type->array.length_expr;

                    if (length_expr == null) {
                        print_file_pos(pos);
                        printf("Can't infer array size in this context\n");
                        return TYPECHECK_RESULT_BAD;
                    } else {
                        Type *type_default_int = &context->primitive_types[TYPE_U64];
                        Typecheck_Expr_Result check_result = typecheck_expr(context, scope, scope_pos, length_expr, type_default_int);
                        if (check_result == TYPECHECK_EXPR_BAD || check_result == TYPECHECK_EXPR_DEPENDENT) {
                            return check_result;
                        }

                        if (!primitive_is_integer(length_expr->type->kind)) {
                            print_file_pos(&length_expr->pos);
                            printf("Can only use unsigned integers as array sizes\n");
                            return TYPECHECK_RESULT_BAD;
                        }

                        u64 length = 0;
                        arena_stack_push(&context->stack);
                        Eval_Result eval_result = eval_compile_time_expr(context, length_expr, (u8*) &length);
                        arena_stack_pop(&context->stack);

                        switch (eval_result) {
                            case EVAL_BAD:       return TYPECHECK_RESULT_BAD;
                            case EVAL_DEPENDENT: return TYPECHECK_RESULT_DEPENDENT;

                            case EVAL_DO_AT_RUNTIME: {
                                print_file_pos(&length_expr->pos);
                                printf("Can't evaluate expression for array length at compile time\n");
                                return false;
                            } break;

                            case EVAL_OK: {
                                if (primitive_is_signed(length_expr->type->kind)) {
                                    i64 signed_length = length;
                                    switch (length_expr->type->kind) {
                                        case TYPE_I8:  signed_length = (i64) (*((i8*)  &signed_length)); break;
                                        case TYPE_I16: signed_length = (i64) (*((i16*) &signed_length)); break;
                                        case TYPE_I32: signed_length = (i64) (*((i32*) &signed_length)); break;
                                        case TYPE_I64: break;
                                        default: assert(false);
                                    }

                                    if (signed_length < 0) {
                                        print_file_pos(&length_expr->pos);
                                        printf("Can't use negative array length %i\n", signed_length);
                                        return TYPECHECK_RESULT_BAD;
                                    }
                                }

                                type = get_array_type(context, type->array.of, length);
                            } break;

                            default: assert(false);
                        }
                    }
                }

                if (type->flags & TYPE_FLAG_UNRESOLVED_CHILD) {
                    Prefix* new = arena_new(&context->stack, Prefix);
                    new->kind = PREFIX_ARRAY;
                    new->array_length = type->array.length;
                    new->link = prefix;
                    prefix = new;

                    type = type->array.of;
                } else {
                    done = true;
                }
            } break;

            case TYPE_UNRESOLVED_NAME: {
                assert(!(type->flags & TYPE_FLAG_UNRESOLVED_CHILD));

                if (type->flags & TYPE_FLAG_UNRESOLVED) {
                    Type *new = parse_user_type_name(scope, type->unresolved_name);

                    if (new == null) {
                        print_file_pos(pos);
                        printf("No such type in scope: '%s'\n", type->unresolved_name);
                        return TYPECHECK_RESULT_BAD;
                    }

                    type = new;
                }

                done = true;
            } break;

            case TYPE_FN_POINTER: {
                if (type->flags & TYPE_FLAG_UNRESOLVED_CHILD) {
                    Fn_Signature signature = type->fn_signature;

                    for (u32 p = 0; p < signature.param_count; p += 1) {
                        Type **param = &signature.params[p].type;
                        Typecheck_Result r = resolve_type(context, scope, scope_pos, &signature.params[p].type, pos);
                        if (r != TYPECHECK_RESULT_DONE) return r;
                    }

                    Typecheck_Result r = resolve_type(context, scope, scope_pos, &signature.return_type, pos);
                    if (r != TYPECHECK_RESULT_DONE) return r;

                    type = fn_signature_canonicalize(context, &signature);
                }

                done = true;
            } break;

            case TYPE_STRUCT: {
                assert(!(type->flags & TYPE_FLAG_UNRESOLVED));

                if (type->flags & TYPE_FLAG_UNRESOLVED_CHILD) {
                    for (u32 m = 0; m < type->structure.member_count; m += 1) {
                        Typecheck_Result r = resolve_type(context, scope, scope_pos, &type->structure.members[m].type, pos);
                        if (r != TYPECHECK_RESULT_DONE) return r;
                    }

                    type->flags &= ~TYPE_FLAG_UNRESOLVED_CHILD;
                }

                if (type->flags & TYPE_FLAG_SIZE_NOT_COMPUTED) {
                    Typecheck_Result r = compute_size_of_struct(type);
                    if (r != TYPECHECK_RESULT_DONE) return r;
                }

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
    return TYPECHECK_RESULT_DONE;
}


Typecheck_Expr_Result typecheck_expr(Context *context, Scope *scope, u32 scope_pos, Expr* expr, Type* solidify_to) {
    bool strong = true;

    switch (expr->kind) {
        case EXPR_VARIABLE: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                Var *var = find_var(scope, expr->variable.unresolved_name, scope_pos);

                if (var == null) {
                    u8 *var_name = expr->variable.unresolved_name;
                    print_file_pos(&expr->pos);
                    printf("Can't find variable '%s' in scope\n", var_name);
                    return TYPECHECK_EXPR_BAD;
                }

                if (var->flags & VAR_FLAG_GLOBAL) {
                    Global_Var *global = &context->global_vars[var->global_index];
                    if (!global->checked) {
                        return TYPECHECK_EXPR_DEPENDENT;
                    }
                }

                expr->variable.var = var;
                expr->flags &= ~EXPR_FLAG_UNRESOLVED;

                if (!(var->flags & VAR_FLAG_CONSTANT)) expr->flags |= EXPR_FLAG_ASSIGNABLE;
                expr->flags |= EXPR_FLAG_ADDRESSABLE;
            }

            Var *var = expr->variable.var;

            if (
                (var->flags & VAR_FLAG_CONSTANT) &&
                (var->flags & VAR_FLAG_LOOSE_TYPE) &&
                (primitive_is_integer(solidify_to->kind) || solidify_to->kind == TYPE_VOID) &&
                var->type->kind == TYPE_DEFAULT_INT
            ) {
                // NB we play a bit fast and loose here, by allowing constant integers without a specific type
                // given to be used as any integer type (assuming that downcasts from the default integer type
                // is a no-op). This simplifies using constants in c-libraries like opengl, which is particularly
                // wierd about switching around the specific types it expects in function signatures, largely
                // (I pressume) because C does a lot of casts implicitly.
                static_assert(TYPE_DEFAULT_INT == TYPE_I64, "Need to potentially generate upcasts if this assert fails!");

                if (solidify_to->kind == TYPE_VOID) {
                    expr->type = &context->primitive_types[TYPE_DEFAULT_INT];
                } else {
                    expr->type = solidify_to;
                }
                strong = false;
            } else {
                expr->type = var->type;
            }
        } break;

        case EXPR_LITERAL: {
            Type_Kind to_primitive = solidify_to->kind;

            expr->literal.masked_value = expr->literal.raw_value;

            switch (expr->literal.kind) {
                case EXPR_LITERAL_POINTER: {
                    if (to_primitive == TYPE_POINTER || to_primitive == TYPE_FN_POINTER) {
                        expr->type = solidify_to;
                    } else {
                        strong = false;
                        expr->type = context->void_pointer_type;
                    }
                } break;

                case EXPR_LITERAL_BOOL: {
                    assert(expr->literal.raw_value == true || expr->literal.raw_value == false);
                    expr->type = &context->primitive_types[TYPE_BOOL];
                } break;

                case EXPR_LITERAL_CHAR: {
                    expr->type = context->char_type;
                    expr->literal.masked_value = expr->literal.raw_value & 0xff;
                } break;

                case EXPR_LITERAL_INTEGER: {
                    strong = false;

                    if (primitive_is_integer(to_primitive)) {
                        expr->type = solidify_to;
                    } else if (to_primitive == TYPE_POINTER) {
                        // Handles 'pointer + integer' and similar cases
                        expr->type = &context->primitive_types[TYPE_U64];
                    } else {
                        expr->type = &context->primitive_types[TYPE_DEFAULT_INT];
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
                        strong = true;
                    } else {
                        expr->type = &context->primitive_types[TYPE_DEFAULT_FLOAT];
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
            assert(expr->type == context->string_type);
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

            // Infer array length if it is not given, so we can write '[]Foo { ... }', without specifying
            // a length explicitly.
            if (expr->type->kind == TYPE_ARRAY) {
                Type **array_layer = &expr->type;
                Expr *compound_expr = expr;

                while ((*array_layer)->kind == TYPE_ARRAY && compound_expr->kind == EXPR_COMPOUND) {
                    if (((*array_layer)->flags & TYPE_FLAG_UNRESOLVED) && (*array_layer)->array.length_expr == null) {
                        u64 infered_length = compound_expr->compound.count;
                        Type *array_of_type = (*array_layer)->array.of;
                        *array_layer = get_array_type(context, array_of_type, infered_length);
                    }

                    if (compound_expr->compound.count <= 0) {
                        break;
                    }

                    array_layer = &((*array_layer)->array.of);
                    compound_expr = compound_expr->compound.content[0].expr;
                }
            }

            Typecheck_Result r = resolve_type(context, scope, scope_pos, &expr->type, &expr->pos);
            if (r != TYPECHECK_RESULT_DONE) return r;

            if (expr->type->flags & TYPE_FLAG_SIZE_NOT_COMPUTED) {
                return TYPECHECK_EXPR_DEPENDENT;
            }

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
                            printf("Unexpected member name '%s' given inside array literal\n", compound_member_name(context, expr, member));
                            return TYPECHECK_EXPR_BAD;
                        }

                        Typecheck_Expr_Result r = typecheck_expr(context, scope, scope_pos, member->expr, expected_child_type);
                        if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;

                        if (expected_child_type != member->expr->type) {
                            print_file_pos(&expr->pos);
                            printf("Invalid type inside compound literal: Expected ");
                            print_type(context, expected_child_type);
                            printf(" but got ");
                            print_type(context, member->expr->type);
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

                    u8 *set_map = arena_alloc(&context->stack, expr->type->structure.member_count);
                    mem_clear(set_map, expr->type->structure.member_count);

                    for (u32 i = 0; i < expr->compound.count; i += 1) {
                        Expr *child = expr->compound.content[i].expr;

                        if (expr->compound.content[i].name_mode == EXPR_COMPOUND_UNRESOLVED_NAME) {
                            u8 *unresolved_name = expr->compound.content[i].unresolved_name;
                            u32 member_index = U32_MAX;

                            for (u32 m = 0; m < expr->type->structure.member_count; m += 1) {
                                if (expr->type->structure.members[m].name == unresolved_name) {
                                    member_index = m;
                                    break;
                                }
                            }

                            if (member_index == U32_MAX) {
                                u8 *member_name = unresolved_name;
                                u8 *struct_name = expr->type->structure.name;
                                print_file_pos(&expr->pos);
                                printf("Struct '%s' has no member '%s'\n", struct_name, member_name);
                                return TYPECHECK_EXPR_BAD;
                            } else {
                                expr->compound.content[i].name_mode = EXPR_COMPOUND_NAME;
                                expr->compound.content[i].member_index = member_index;
                            }
                        }

                        if (expr->compound.content[i].name_mode == EXPR_COMPOUND_NO_NAME) {
                            expr->compound.content[i].member_index = i;
                            any_unnamed = true;
                        } else {
                            any_named = true;
                        }

                        u32 m = expr->compound.content[i].member_index;
                        Type *member_type = expr->type->structure.members[m].type;
                        
                        Typecheck_Expr_Result r = typecheck_expr(context, scope, scope_pos, child, member_type);
                        if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;

                        if (!type_can_assign(member_type, child->type)) {
                            u8 *member_name = expr->type->structure.members[m].name;
                            u8 *struct_name = expr->type->structure.name;

                            print_file_pos(&child->pos);
                            printf("Expected ");
                            print_type(context, member_type);
                            printf(" but got ");
                            print_type(context, child->type);
                            printf(" for member '%s' of struct '%s'\n", member_name, struct_name);
                            return TYPECHECK_EXPR_BAD;
                        }

                        if (set_map[i]) {
                            u8 *name = expr->type->structure.members[m].name;
                            u8* member_name = name;

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
                    print_type(context, expr->type);
                    printf("\n");
                    return TYPECHECK_EXPR_BAD;
                } break;
            }
        } break;

        case EXPR_TERNARY: {
            Typecheck_Expr_Result condition_result, left_result, right_result;

            Type *type_bool = &context->primitive_types[TYPE_BOOL];;
            condition_result = typecheck_expr(context, scope, scope_pos, expr->ternary.condition, type_bool);
            if (condition_result == TYPECHECK_EXPR_BAD || condition_result == TYPECHECK_EXPR_DEPENDENT) return condition_result;


            left_result = typecheck_expr(context, scope, scope_pos, expr->ternary.left, solidify_to);
            right_result = typecheck_expr(context, scope, scope_pos, expr->ternary.right, solidify_to);

            if (left_result == TYPECHECK_EXPR_BAD || right_result == TYPECHECK_EXPR_BAD)  return TYPECHECK_EXPR_BAD;
            if (left_result == TYPECHECK_EXPR_DEPENDENT || right_result == TYPECHECK_EXPR_DEPENDENT) return TYPECHECK_EXPR_DEPENDENT;

            if (expr->ternary.left->type != expr->ternary.right->type) {
                if (right_result == TYPECHECK_EXPR_WEAK ) {
                    right_result = typecheck_expr(context, scope, scope_pos, expr->ternary.right, expr->ternary.left->type);
                } else if (left_result == TYPECHECK_EXPR_WEAK  && right_result == TYPECHECK_EXPR_STRONG) {
                    left_result = typecheck_expr(context, scope, scope_pos, expr->ternary.left, expr->ternary.right->type);
                }
            }

            assert(left_result != TYPECHECK_EXPR_BAD && left_result != TYPECHECK_EXPR_DEPENDENT);
            assert(right_result != TYPECHECK_EXPR_BAD && right_result != TYPECHECK_EXPR_DEPENDENT);
            if (left_result == TYPECHECK_EXPR_WEAK  && right_result == TYPECHECK_EXPR_WEAK ) {
                strong = false;
            }

            if (expr->ternary.left->type != expr->ternary.right->type) {
                print_file_pos(&expr->pos);
                printf("Different types for halves of ternary operator: ");
                print_type(context, expr->ternary.left->type);
                printf(" vs ");
                print_type(context, expr->ternary.right->type);
                printf("\n");
                return TYPECHECK_EXPR_BAD;
            }

            expr->type = expr->ternary.left->type;
        } break;

        case EXPR_BINARY: {
            if (BINARY_OP_COMPARATIVE[expr->binary.op]) {
                solidify_to = &context->primitive_types[TYPE_VOID];
            }

            Typecheck_Expr_Result left_result, right_result;

            left_result  = typecheck_expr(context, scope, scope_pos, expr->binary.left, solidify_to);
            right_result = typecheck_expr(context, scope, scope_pos, expr->binary.right, solidify_to);

            if (left_result == TYPECHECK_EXPR_BAD || right_result == TYPECHECK_EXPR_BAD)  return TYPECHECK_EXPR_BAD;
            if (left_result == TYPECHECK_EXPR_DEPENDENT || right_result == TYPECHECK_EXPR_DEPENDENT) return TYPECHECK_EXPR_DEPENDENT;

            if (expr->binary.left->type != expr->binary.right->type) {
                if (right_result == TYPECHECK_EXPR_WEAK ) {
                    right_result = typecheck_expr(context, scope, scope_pos, expr->binary.right, expr->binary.left->type);
                } else if (left_result == TYPECHECK_EXPR_WEAK  && right_result == TYPECHECK_EXPR_STRONG) {
                    left_result = typecheck_expr(context, scope, scope_pos, expr->binary.left, expr->binary.right->type);
                }
            }

            assert(left_result != TYPECHECK_EXPR_BAD && left_result != TYPECHECK_EXPR_DEPENDENT);
            assert(right_result != TYPECHECK_EXPR_BAD && right_result != TYPECHECK_EXPR_DEPENDENT);
            if (left_result == TYPECHECK_EXPR_WEAK  && right_result == TYPECHECK_EXPR_WEAK ) {
                strong = false;
            }

            bool valid_types = false;

            if (BINARY_OP_COMPARATIVE[expr->binary.op]) {
                expr->type = &context->primitive_types[TYPE_BOOL];

                Type_Kind primitive = expr->binary.left->type->kind;
                if (expr->binary.left->type == expr->binary.right->type && !primitive_is_compound(primitive)) {
                    valid_types = true;

                    if (!(expr->binary.op == BINARY_EQ || expr->binary.op == BINARY_NEQ)) {
                        if (primitive == TYPE_POINTER || primitive == TYPE_BOOL || primitive == TYPE_FN_POINTER) valid_types = false;
                    }
                }
            } else {
                if (expr->binary.left->type == expr->binary.right->type) {
                    expr->type = expr->binary.left->type;
                    Type_Kind kind = expr->type->kind;

                    Binary_Op op = expr->binary.op;
                    Primitive_Group group = TYPE_KIND_TO_PRIMITIVE_GROUP_MAP[kind];
                    valid_types = BINARY_OP_VALIDITY_MAP[op][group];

                    if (group == PRIMITIVE_GROUP_POINTER && op == BINARY_SUB) {
                        expr->type = &context->primitive_types[TYPE_POINTER_DIFF];
                    }
                // Special-case pointer-pointer arithmetic
                } else {
                    Type_Kind left_kind = expr->binary.left->type->kind;
                    Type_Kind right_kind = expr->binary.right->type->kind;

                    if (expr->binary.op == BINARY_ADD || expr->binary.op == BINARY_SUB) {
                        if (left_kind == TYPE_POINTER && (right_kind == TYPE_U64 || right_kind == TYPE_I64)) {
                            expr->type = expr->binary.left->type;
                            valid_types = true;
                        }
                        if ((left_kind == TYPE_U64 || left_kind == TYPE_I64) && right_kind == TYPE_POINTER) {
                            expr->type = expr->binary.right->type;
                            valid_types = true;
                        }
                    }
                }
            }

            if (!valid_types) {
                if (expr->binary.left->type != expr->binary.right->type) {
                    print_file_pos(&expr->pos);
                    printf("Types for operator %s don't match: ", BINARY_OP_SYMBOL[expr->binary.op]);
                    print_type(context, expr->binary.left->type);
                    printf(" vs ");
                    print_type(context, expr->binary.right->type);
                    printf("\n");
                    return TYPECHECK_EXPR_BAD;
                } else {
                    print_file_pos(&expr->pos);
                    printf("Can't use operator %s on ", BINARY_OP_SYMBOL[expr->binary.op]);
                    print_type(context, expr->binary.left->type);
                    printf("\n");
                    return TYPECHECK_EXPR_BAD;
                }
            }
        } break;

        case EXPR_UNARY: {
            if (
                expr->unary.op == UNARY_ADDRESS_OF &&
                expr->unary.inner->kind == EXPR_VARIABLE &&
                (expr->unary.inner->flags & EXPR_FLAG_UNRESOLVED) &&
                (find_var(scope, expr->unary.inner->variable.unresolved_name, scope_pos) == null)
            ) {
                // Special case: We are trying to take the address of a undefined variable, which means we might
                // be trying to actually get a function pointer. We have to slightly modify the ast in this case.
                // The alternative would be to use a different syntax to get function pointers, or putting
                // functions and variables in the same namespace.

                u8 *name = expr->unary.inner->variable.unresolved_name;
                Decl *fn_decl = find_declaration(scope, name, DECL_FN);

                if (fn_decl != null) {
                    expr->kind = EXPR_ADDRESS_OF_FUNCTION;
                    expr->address_of_fn = fn_decl->fn;
                    expr->type = fn_decl->fn->signature_type;
                    break; // This breaks out of the switch!
                }
            }

            switch (expr->unary.op) {
                case UNARY_DEREFERENCE: {
                    solidify_to = get_pointer_type(context, solidify_to);
                } break;

                case UNARY_ADDRESS_OF: {
                    if (solidify_to->kind == TYPE_POINTER || solidify_to->kind == TYPE_FN_POINTER) {
                        solidify_to = solidify_to->pointer_to;
                    }
                } break;
            }

            Typecheck_Expr_Result inner_result = typecheck_expr(context, scope, scope_pos, expr->unary.inner, solidify_to);
            if (inner_result == TYPECHECK_EXPR_BAD || inner_result == TYPECHECK_EXPR_DEPENDENT) return inner_result;
            if (inner_result == TYPECHECK_EXPR_WEAK) strong = false;

            switch (expr->unary.op) {
                case UNARY_NOT: {
                    // TODO allow using UNARY_NOT to do a bitwise NOT on integers
                    expr->type = expr->unary.inner->type;
                    if (expr->type->kind != TYPE_BOOL) {
                        print_file_pos(&expr->unary.inner->pos);
                        printf("Can't apply unary not (!) to ");
                        print_type(context, expr->type);
                        printf(", only to bool\n");
                        return TYPECHECK_EXPR_BAD;
                    }
                } break;

                case UNARY_NEG: {
                    expr->type = expr->unary.inner->type;
                    if (!(primitive_is_integer(expr->type->kind) || primitive_is_float(expr->type->kind))) {
                        print_file_pos(&expr->unary.inner->pos);
                        printf("Can not apply unary negative (-) to ");
                        print_type(context, expr->type);
                        printf("\n");
                        return TYPECHECK_EXPR_BAD;
                    }
                } break;

                case UNARY_DEREFERENCE: {
                    Type_Kind child_primitive = expr->unary.inner->type->kind;
                    if (child_primitive != TYPE_POINTER) {
                        print_file_pos(&expr->pos);
                        printf("Can't dereference non-pointer type ");
                        print_type(context, expr->unary.inner->type);
                        printf("\n");
                        return TYPECHECK_EXPR_BAD;
                    }

                    Type_Kind pointer_to = expr->unary.inner->type->pointer_to->kind;
                    if (pointer_to == TYPE_VOID) {
                        print_file_pos(&expr->pos);
                        printf("Can't dereference void pointer ");
                        print_expr(context, expr->unary.inner);
                        printf("\n");
                        return TYPECHECK_EXPR_BAD;
                    }

                    expr->type = expr->unary.inner->type->pointer_to;
                    expr->flags |= EXPR_FLAG_ASSIGNABLE;
                    expr->flags |= EXPR_FLAG_ADDRESSABLE;

                } break;

                case UNARY_ADDRESS_OF: {
                    if (!(expr->unary.inner->flags & EXPR_FLAG_ADDRESSABLE)) {
                        print_file_pos(&expr->pos);
                        printf("Can't take address of ");
                        print_expr(context, expr->unary.inner);
                        printf("\n");
                        return TYPECHECK_EXPR_BAD;
                    }

                    expr->type = get_pointer_type(context, expr->unary.inner->type);
                } break;
                
                case UNARY_SQRT: {
                    if (!primitive_is_float(expr->unary.inner->type->kind)) {
                        print_file_pos(&expr->pos);
                        printf("Can't take the square root of a ");
                        print_type(context, expr->type);
                        printf("\n");
                        return TYPECHECK_EXPR_BAD;
                    }

                    expr->type = expr->unary.inner->type;
                } break;

                default: assert(false);
            }
        } break;

        case EXPR_CALL: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                Decl *fn_decl = find_declaration(scope, expr->call.unresolved_name, DECL_FN);

                if (fn_decl != null) {
                    Type *signature = fn_decl->fn->signature_type;
                    if (signature->flags & (TYPE_FLAG_UNRESOLVED|TYPE_FLAG_UNRESOLVED_CHILD)) {
                        return TYPECHECK_EXPR_DEPENDENT;
                    }

                    expr->call.callee = fn_decl->fn;
                } else {
                    Var *var = find_var(scope, expr->call.unresolved_name, scope_pos);

                    if (var == null) {
                        print_file_pos(&expr->pos);
                        printf("No such function or function pointer '%s'\n", expr->call.unresolved_name);
                        return TYPECHECK_EXPR_BAD;
                    } else {
                        // Modify the call to call a function pointer stored in a variable
                        expr->call.pointer_call = true;
                        expr->call.pointer_expr = arena_new(&context->arena, Expr);
                        *expr->call.pointer_expr = (Expr) {
                            .kind = EXPR_VARIABLE,
                            .pos = expr->pos,
                            .flags = EXPR_FLAG_ADDRESSABLE | EXPR_FLAG_ASSIGNABLE,
                            .variable.var = var,
                        };
                    }
                }

                expr->flags &= ~EXPR_FLAG_UNRESOLVED;
            }

            Type *callee_signature_type;
            u8 *callee_name;

            if (expr->call.pointer_call) {
                Typecheck_Expr_Result r = typecheck_expr(context, scope, scope_pos, expr->call.pointer_expr, &context->primitive_types[TYPE_VOID]);
                if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;

                Type *t = expr->call.pointer_expr->type;
                if (t->kind != TYPE_FN_POINTER) {
                    print_file_pos(&expr->call.pointer_expr->pos);
                    printf("Expected function pointer, but got ");
                    print_type(context, t);
                    printf(" on left hand side of call\n");
                    return TYPECHECK_EXPR_BAD;
                }

                callee_signature_type = t;

                if (expr->call.pointer_expr->kind == EXPR_VARIABLE) {
                    assert(!(expr->call.pointer_expr->flags & EXPR_FLAG_UNRESOLVED));
                    Var *var = expr->call.pointer_expr->variable.var;
                    callee_name = var->name;
                } else {
                    callee_name = "<unkown pointer>";
                }
            } else {
                Fn *callee = expr->call.callee;
                callee_signature_type = callee->signature_type;
                callee_name = callee->name;
            }

            assert(callee_signature_type->kind == TYPE_FN_POINTER);
            Fn_Signature *callee_signature = &callee_signature_type->fn_signature;

            if (callee_signature_type->flags & (TYPE_FLAG_UNRESOLVED|TYPE_FLAG_UNRESOLVED_CHILD)) {
                return TYPECHECK_EXPR_DEPENDENT;
            }

            expr->type = callee_signature->return_type;

            if (expr->call.param_count != callee_signature->param_count) {
                print_file_pos(&expr->pos);

                u64 expected = callee_signature->param_count;
                u64 given = expr->call.param_count;
                printf(
                    "Function '%s' takes %u parameters, but %u %s given\n",
                    callee_name, expected, given, given == 1? "was" : "were"
                );
                return TYPECHECK_EXPR_BAD;
            }

            for (u32 p = 0; p < expr->call.param_count; p += 1) {
                Expr *param_expr = expr->call.params[p];

                Type *expected_type = callee_signature->params[p].type;

                Typecheck_Expr_Result r = typecheck_expr(context, scope, scope_pos, param_expr, expected_type);
                if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;

                Type *actual_type = param_expr->type;
                if (!type_can_assign(expected_type, actual_type)) {
                    print_file_pos(&expr->pos);
                    printf("Invalid type for %n parameter to '%s' Expected ", (u64) (p + 1), callee_name);
                    print_type(context, expected_type);
                    printf(" but got ");
                    print_type(context, actual_type);
                    printf("\n");

                    return TYPECHECK_EXPR_BAD;
                }
            }
        } break;

        case EXPR_CAST: {
            Typecheck_Result r1 = resolve_type(context, scope, scope_pos, &expr->type, &expr->pos);
            if (r1 != TYPECHECK_RESULT_DONE) return r1;

            Typecheck_Expr_Result r2 = typecheck_expr(context, scope, scope_pos, expr->cast_from, expr->type);
            if (r2 == TYPECHECK_EXPR_BAD || r2 == TYPECHECK_EXPR_DEPENDENT) return r2;

            Type_Kind from = expr->cast_from->type->kind;
            Type_Kind to   = expr->type->kind;

            bool valid =
                ((from == TYPE_POINTER || from == TYPE_FN_POINTER) && (to == TYPE_POINTER || to == TYPE_FN_POINTER)) ||
                ((from == TYPE_POINTER || from == TYPE_FN_POINTER) && (to == TYPE_U64 || to == TYPE_I64)) ||
                ((from == TYPE_U64 || from == TYPE_I64) && (to == TYPE_POINTER || to == TYPE_FN_POINTER)) ||

                (primitive_is_integer(from) && primitive_is_integer(to)) ||

                (primitive_is_integer(from) && to == TYPE_ENUM) ||
                (primitive_is_integer(to)   && from == TYPE_ENUM) ||

                (primitive_is_integer(from) && primitive_is_float(to)) ||
                (primitive_is_float(from)   && primitive_is_integer(to)) ||
                (primitive_is_float(from)   && primitive_is_float(to));

            if (!valid) {
                print_file_pos(&expr->pos);
                printf("Invalid cast. Can't cast from ");
                print_type(context, expr->cast_from->type);
                printf(" to ");
                print_type(context, expr->type);
                printf("\n");
                return TYPECHECK_EXPR_BAD;
            }
        } break;

        case EXPR_SUBSCRIPT: {
            Typecheck_Expr_Result r;

            r = typecheck_expr(context, scope, scope_pos, expr->subscript.array, &context->primitive_types[TYPE_VOID]);
            if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;
            r = typecheck_expr(context, scope, scope_pos, expr->subscript.index, &context->primitive_types[TYPE_DEFAULT_INT]);
            if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;

            if (expr->subscript.array->flags & EXPR_FLAG_ASSIGNABLE)  expr->flags |= EXPR_FLAG_ASSIGNABLE;
            if (expr->subscript.array->flags & EXPR_FLAG_ADDRESSABLE) expr->flags |= EXPR_FLAG_ADDRESSABLE;

            Type* array_type = expr->subscript.array->type;
            if (array_type->kind == TYPE_ARRAY) {
                expr->type = array_type->array.of;
            } else if (array_type->kind == TYPE_POINTER && array_type->pointer_to->kind == TYPE_ARRAY) {
                expr->type = array_type->pointer_to->array.of;
            } else if (array_type == context->string_type) {
                expr->type = context->char_type;
            } else {
                print_file_pos(&expr->pos);
                printf("Can't index a ");
                print_type(context, array_type);
                printf("\n");
                return TYPECHECK_EXPR_BAD;
            }

            Type_Kind index_type = primitive_of(expr->subscript.index->type);
            if (!primitive_is_integer(index_type)) {
                print_file_pos(&expr->subscript.index->pos);
                printf("Can only use %s and %s as an array index, not ", PRIMITIVE_NAMES[TYPE_U64], PRIMITIVE_NAMES[TYPE_I64]);
                print_type(context, expr->subscript.index->type);
                printf("\n");
                return TYPECHECK_EXPR_BAD;
            }
        } break;

        case EXPR_MEMBER_ACCESS: {
            Expr* parent = expr->member_access.parent;

            Typecheck_Expr_Result bad_but_keep_on_going = TYPECHECK_EXPR_STRONG;
            Typecheck_Expr_Result r = typecheck_expr(context, scope, scope_pos, parent, &context->primitive_types[TYPE_VOID]);
            if (r == TYPECHECK_EXPR_BAD ||  r == TYPECHECK_EXPR_DEPENDENT) {
                if (parent->type == null) {
                    return r;
                } else {
                    bad_but_keep_on_going = r;
                }
            }

            if (parent->flags & EXPR_FLAG_ASSIGNABLE)  expr->flags |= EXPR_FLAG_ASSIGNABLE;
            if (parent->flags & EXPR_FLAG_ADDRESSABLE) expr->flags |= EXPR_FLAG_ADDRESSABLE;

            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u8 *access_name = expr->member_access.member_name;

                Type* s = parent->type;
                if (s->kind == TYPE_POINTER && s->pointer_to->kind == TYPE_STRUCT) {
                    s = s->pointer_to;
                }

                bool has_member = false;
                if (s->kind == TYPE_STRUCT) {
                    for (u32 m = 0; m < s->structure.member_count; m += 1) {
                        u8 *member_name = s->structure.members[m].name;
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
                    print_file_pos(&expr->pos);
                    print_type(context, parent->type);
                    printf(" has no member '%s'\n", access_name);
                    return TYPECHECK_EXPR_BAD;
                }
            }

            if (bad_but_keep_on_going != TYPECHECK_EXPR_STRONG) return bad_but_keep_on_going;
        } break;

        case EXPR_STATIC_MEMBER_ACCESS: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                Type *parent = parse_user_type_name(scope, expr->static_member_access.parent_name);

                if (parent == null) {
                    u8 *name_string = expr->static_member_access.parent_name;
                    print_file_pos(&expr->pos);
                    printf("No such type in scope: '%s'\n", name_string);
                    return TYPECHECK_EXPR_BAD;
                }

                if (parent->kind != TYPE_ENUM) {
                    print_file_pos(&expr->pos);
                    printf("Can't use operator :: on non-enum type ");
                    print_type(context, parent);
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
                    u8 *member_name = expr->static_member_access.member_name;
                    print_file_pos(&expr->pos);
                    print_type(context, parent);
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
            Typecheck_Result r = resolve_type(context, scope, scope_pos, &expr->type_info_of_type, &expr->pos);
            if (r != TYPECHECK_RESULT_DONE) return r;
        } break;

        case EXPR_TYPE_INFO_OF_VALUE: {
            Type *void_type = &context->primitive_types[TYPE_VOID];
            Typecheck_Expr_Result r = typecheck_expr(context, scope, scope_pos, expr->type_info_of_value, void_type);
            if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;
        } break;

        case EXPR_QUERY_TYPE_INFO: {
            Typecheck_Result r = resolve_type(context, scope, scope_pos, &expr->query_type_info.type, &expr->pos);
            if (r != TYPECHECK_RESULT_DONE) return r;

            if (
                expr->query_type_info.query == QUERY_TYPE_INFO_ENUM_LENGTH &&
                expr->query_type_info.type->kind != TYPE_ENUM
            ) {
                print_file_pos(&expr->pos);
                printf("Can't call 'enum_length' on ");
                print_type(context, expr->query_type_info.type);
                printf(", it's not an enum");
                return TYPECHECK_EXPR_BAD;
            }
        } break;

        case EXPR_ENUM_MEMBER_NAME: {
            Typecheck_Expr_Result r = typecheck_expr(context, scope, scope_pos, expr->enum_member, &context->primitive_types[TYPE_INVALID]);
            if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;

            if (expr->enum_member->type->kind != TYPE_ENUM) {
                print_file_pos(&expr->enum_member->pos);
                printf("Can't call 'enum_member_name' on a ");
                print_type(context, expr->enum_member->type);
                printf("\n");
                return TYPECHECK_EXPR_BAD;
            }
        } break;

        case EXPR_ADDRESS_OF_FUNCTION: {
            // We only generate 'EXPR_ADDRESS_OF_FUNCTION' from within 'typecheck_expr',
            // so we don't need to do anything more if we get here, because that means we are
            // allready on a second pass (retrying because we had missing dependencies
            // on the first pass)
        } break;

        default: assert(false);
    }

    Typecheck_Result r = resolve_type(context, scope, scope_pos, &expr->type, &expr->pos);
    if (r != TYPECHECK_RESULT_DONE) return r;

    return strong? TYPECHECK_EXPR_STRONG : TYPECHECK_EXPR_WEAK;
}


Typecheck_Result typecheck_stmt(Context* context, Scope *scope, Stmt* stmt) {
    Type *void_type = &context->primitive_types[TYPE_VOID];
    u32 scope_pos = stmt->scope_pos;

    switch (stmt->kind) {
        case STMT_ASSIGNMENT: {
            Expr *left  = stmt->assignment.left;
            Expr *right = stmt->assignment.right;

            Typecheck_Expr_Result r;

            Type *void_type = &context->primitive_types[TYPE_VOID];
            r = typecheck_expr(context, scope, scope_pos, left, void_type);
            if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;
            Type *left_type = left->type;

            r = typecheck_expr(context, scope, scope_pos, right, left_type);
            if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;
            Type *right_type = right->type;

            if (!type_can_assign(right_type, left_type)) {
                print_file_pos(&left->pos);
                printf("Types in assignment don't match: ");
                print_type(context, left_type);
                printf(" vs ");
                print_type(context, right_type);
                printf("\n");
                return TYPECHECK_RESULT_BAD;
            }

            if (!(left->flags & EXPR_FLAG_ASSIGNABLE)) {
                print_file_pos(&left->pos);
                printf("Can't assign to left hand side");
                if (left->kind == EXPR_VARIABLE && (left->variable.var->flags & VAR_FLAG_CONSTANT)) {
                    u8 *const_name = left->variable.var->name;
                    printf(", %s is const", const_name);
                } else {
                    printf(" of type ");
                    print_type(context, left->type);
                }
                printf("\n");
                return TYPECHECK_RESULT_BAD;
            }
        } break;

        case STMT_OP_ASSIGNMENT: {
            Binary_Op op = stmt->op_assignment.op;
            Expr *left   = stmt->op_assignment.left;
            Expr *right  = stmt->op_assignment.right;

            Typecheck_Expr_Result r;

            Type *void_type = &context->primitive_types[TYPE_VOID];
            r = typecheck_expr(context, scope, scope_pos, left, void_type);
            if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;
            Type *left_type = left->type;

            Type *solidify_right_to;
            if (left_type->kind == TYPE_POINTER || left_type->kind == TYPE_FN_POINTER) {
                solidify_right_to = &context->primitive_types[TYPE_POINTER_DIFF];
            } else {
                solidify_right_to = left_type;
            }

            r = typecheck_expr(context, scope, scope_pos, right, solidify_right_to);
            if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;
            Type *right_type = right->type;

            if (left_type == right_type) {
                Primitive_Group group = TYPE_KIND_TO_PRIMITIVE_GROUP_MAP[left_type->kind];
                bool valid_types = BINARY_OP_VALIDITY_MAP[op][group];

                if (!valid_types) {
                    print_file_pos(&left->pos);
                    printf("Can't use operator %s on ", BINARY_OP_SYMBOL[op]);
                    print_type(context, left_type);
                    printf("\n");
                    return TYPECHECK_RESULT_BAD;
                }
            } else if (
                (op == BINARY_ADD || op == BINARY_SUB) &&
                left_type->kind == TYPE_POINTER &&
                (right_type->kind == TYPE_U64 || right_type->kind == TYPE_I64)
            ) {
                // This is valid!
            } else {
                print_file_pos(&left->pos);
                printf("Types for operator %s don't match: ", BINARY_OP_SYMBOL[op]);
                print_type(context, left_type);
                printf(" vs ");
                print_type(context, right_type);
                printf("\n");
                return TYPECHECK_EXPR_BAD;
            }

            if (!(left->flags & EXPR_FLAG_ASSIGNABLE)) {
                print_file_pos(&stmt->pos);
                printf("Can't assign to left hand side");
                if (left->kind == EXPR_VARIABLE && (left->variable.var->flags & VAR_FLAG_CONSTANT)) {
                    u8 *const_name = left->variable.var->name;
                    printf(", %s is const", const_name);
                } else {
                    printf(" of type ");
                    print_type(context, left->type);
                }
                printf("\n");
                return TYPECHECK_RESULT_BAD;
            }
        } break;

        case STMT_EXPR: {
            Typecheck_Expr_Result r = typecheck_expr(context, scope, scope_pos, stmt->expr, void_type);
            if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;
        } break;

        case STMT_LET: {
            u32 var_count = stmt->let.var_count;
            Var *vars = stmt->let.vars;
            Expr *right = stmt->let.right;

            assert(var_count >= 1);
            Type *var_type = vars[0].type;
            for (u32 i = 1; i < var_count; i += 1) assert(vars[i].type == var_type);

            if (var_type != null) {
                Typecheck_Result r = resolve_type(context, scope, scope_pos, &var_type, &stmt->pos);
                if (r != TYPECHECK_RESULT_DONE) return r;
            }

            bool loose_types = false;

            if (right != null) {
                Type *resolve_to = var_type;
                if (resolve_to == null) resolve_to = &context->primitive_types[TYPE_VOID];

                Typecheck_Expr_Result r = typecheck_expr(context, scope, scope_pos, right, resolve_to);
                if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) {
                    var_type = &context->primitive_types[TYPE_INVALID];
                    return r;
                }

                if (var_type == null || var_type->kind == TYPE_INVALID) {
                    if (r == TYPECHECK_EXPR_WEAK) loose_types = true;
                    var_type = right->type;
                }

                if (!type_can_assign(var_type, right->type)) {
                    print_file_pos(&stmt->pos);
                    printf("Invalid declaration: ");
                    for (u32 i = 0; i < var_count; i += 1) {
                        if (i > 0) printf(", ");
                        printf("'%s'", vars[i].name);
                    }
                    printf(var_count > 1? " have type " : " has type ");
                    print_type(context, var_type);
                    printf(" but right hand side has type ");
                    print_type(context, right->type);
                    printf("\n");
                    return TYPECHECK_RESULT_BAD;
                }
            }

            for (u32 i = 0; i < var_count; i += 1) {
                vars[i].type = var_type;
                if (loose_types) {
                    vars[i].flags |= VAR_FLAG_LOOSE_TYPE;
                } else {
                    vars[i].flags &= ~VAR_FLAG_LOOSE_TYPE;
                }
            }

            return TYPECHECK_RESULT_DONE;
        } break;

        case STMT_BLOCK: {
            for (Stmt* inner = stmt->block.stmt; inner->kind != STMT_END; inner = inner->next) {
                Typecheck_Result r = typecheck_stmt(context, &stmt->block.scope, inner);
                if (r != TYPECHECK_RESULT_DONE) return r;
            }
        } break;

        case STMT_IF: {
            Type *type_bool = &context->primitive_types[TYPE_BOOL];
            Typecheck_Expr_Result r = typecheck_expr(context, scope, scope_pos, stmt->if_.condition, type_bool);
            if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;

            Type_Kind condition_primitive = stmt->if_.condition->type->kind;
            if (condition_primitive != TYPE_BOOL) {
                print_file_pos(&stmt->if_.condition->pos);
                printf("Expected bool but got ");
                print_type(context, stmt->if_.condition->type);
                printf(" in 'if'-statement\n");
                return TYPECHECK_RESULT_BAD;
            }

            for (Stmt* inner = stmt->if_.then; inner->kind != STMT_END; inner = inner->next) {
                Typecheck_Result r = typecheck_stmt(context, &stmt->if_.then_scope, inner);
                if (r != TYPECHECK_RESULT_DONE) return r;
            }

            if (stmt->if_.else_then != null) {
                for (Stmt* inner = stmt->if_.else_then; inner->kind != STMT_END; inner = inner->next) {
                    Typecheck_Result r = typecheck_stmt(context, &stmt->if_.else_then_scope, inner);
                    if (r != TYPECHECK_RESULT_DONE) return r;
                }
            }
        } break;

        case STMT_SWITCH: {
            Type *type_default_int = &context->primitive_types[TYPE_DEFAULT_INT];
            Typecheck_Expr_Result r = typecheck_expr(context, scope, scope_pos, stmt->switch_.index, type_default_int);
            if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;

            Type *automatch_enum = stmt->switch_.index->type;
            if (automatch_enum->kind != TYPE_ENUM) automatch_enum = null;

            for (u32 i = 0; i < stmt->switch_.case_count; i += 1) {
                Switch_Case *c = &stmt->switch_.cases[i];

                for (u32 j = 0; j < c->key_count; j += 1) {
                    Switch_Case_Key *key = &c->keys[j];

                    if (key->is_identifier && automatch_enum != null) {
                        u32 member_index = find_enum_member(automatch_enum, key->identifier);
                        if (member_index != U32_MAX) {
                            key->is_identifier = false;
                            key->expr = arena_new(&context->arena, Expr);
                            *key->expr = (Expr) {
                                .kind = EXPR_STATIC_MEMBER_ACCESS,
                                .type = automatch_enum,
                                .pos = c->pos,
                                .static_member_access = {
                                    .parent_type = automatch_enum,
                                    .member_index = member_index,
                                },
                            };
                        }
                    }

                    if (key->is_identifier) {
                        Var *key_var = find_var(scope, key->identifier, scope_pos);

                        if (key_var != null) {
                            if (key_var->flags & VAR_FLAG_GLOBAL) {
                                Global_Var *global = &context->global_vars[key_var->global_index];
                                if (!global->checked) {
                                    return TYPECHECK_RESULT_DEPENDENT;
                                }
                            }

                            key->is_identifier = false;
                            key->expr = arena_new(&context->arena, Expr);
                            *key->expr = (Expr) {
                                .kind = EXPR_VARIABLE,
                                .flags = EXPR_FLAG_ADDRESSABLE,
                                .type = key_var->type,
                                .pos = c->pos,
                                .variable = { .var = key_var },
                            };
                        } else {
                            print_file_pos(&c->pos);
                            printf("Invalid case, no such variable");
                            if (automatch_enum != null) {
                                printf(" or member of 'enum %s'", automatch_enum->enumeration.name);
                            }
                            printf(": %s\n", key->identifier);
                            return TYPECHECK_EXPR_BAD;
                        }
                    }

                    assert(!key->is_identifier);

                    Typecheck_Expr_Result r = typecheck_expr(context, scope, scope_pos, key->expr, stmt->switch_.index->type);
                    if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;

                    if (stmt->switch_.index->type != key->expr->type) {
                        print_file_pos(&c->pos);
                        printf("Invalid type for case, expected ");
                        print_type(context, stmt->switch_.index->type);
                        printf(" but got ");
                        print_type(context, key->expr->type);
                        printf("\n");
                    }
                    
                    // TODO ensure that the key expr is actually a constant!

                    arena_stack_push(&context->stack);
                    Eval_Result eval_result = eval_compile_time_expr(context, key->expr, (u8*) &key->value);
                    arena_stack_pop(&context->stack);

                    switch (eval_result) {
                        case EVAL_DEPENDENT: return TYPECHECK_RESULT_DEPENDENT;
                        case EVAL_BAD: return TYPECHECK_RESULT_BAD;
                        case EVAL_DO_AT_RUNTIME: {
                            print_file_pos(&key->expr->pos);
                            printf("Can't compute case at compile time\n");
                            return TYPECHECK_RESULT_BAD;
                        } break;
                        case EVAL_OK: break;
                        default: assert(false);
                    }


                    for (u32 i2 = 0; i2 <= i; i2 += 1) {
                        Switch_Case *c2 = &stmt->switch_.cases[i2];
                        u32 max_j = c2 == c? j : c2->key_count;
                        for (u32 j2 = 0; j2 < max_j; j2 += 1) {
                            Switch_Case_Key *key2 = &c2->keys[j2];
                            if (key2->value == key->value) {
                                print_file_pos(&key->pos);
                                printf("Multiple cases with key %u: ", key->value);
                                if (key->is_identifier)  printf(key->identifier);  else print_expr(context, key->expr);
                                printf(" and ");
                                if (key2->is_identifier) printf(key2->identifier); else print_expr(context, key2->expr);
                                printf(". First case on line %u\n", key2->pos.line);
                                return TYPECHECK_RESULT_BAD;
                            }
                        }
                    }
                }

                for (Stmt* inner = c->body; inner->kind != STMT_END; inner = inner->next) {
                    Typecheck_Result r = typecheck_stmt(context, c->scope, inner);
                    if (r != TYPECHECK_RESULT_DONE) return r;
                }
            }

            if (stmt->switch_.default_case != null) {
                for (Stmt* inner = stmt->switch_.default_case->body; inner->kind != STMT_END; inner = inner->next) {
                    Typecheck_Result r = typecheck_stmt(context, stmt->switch_.default_case->scope, inner);
                    if (r != TYPECHECK_RESULT_DONE) return r;
                }
            }
        } break;

        case STMT_FOR: {
            if (stmt->for_.kind == LOOP_CONDITIONAL) {
                Type *type_bool = &context->primitive_types[TYPE_BOOL];
                Typecheck_Expr_Result r = typecheck_expr(context, scope, scope_pos, stmt->for_.condition, type_bool);
                if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;

                Type_Kind condition_primitive = stmt->for_.condition->type->kind;
                if (condition_primitive != TYPE_BOOL) {
                    print_file_pos(&stmt->for_.condition->pos);
                    printf("Expected bool but got ");
                    print_type(context, stmt->for_.condition->type);
                    printf(" in 'for'-loop\n");
                    return TYPECHECK_RESULT_DONE;
                }
            } else if (stmt->for_.kind == LOOP_RANGE) {
                Expr *start = stmt->for_.range.start;
                Expr *end   = stmt->for_.range.end;

                Type *type_default_int = &context->primitive_types[TYPE_DEFAULT_INT];
                Typecheck_Expr_Result start_result, end_result;
                start_result = typecheck_expr(context, scope, scope_pos, start, type_default_int);
                end_result   = typecheck_expr(context, scope, scope_pos, end,   type_default_int);

                if (start_result == TYPECHECK_EXPR_BAD || end_result == TYPECHECK_EXPR_BAD) return TYPECHECK_RESULT_BAD;
                if (start_result == TYPECHECK_EXPR_DEPENDENT || end_result == TYPECHECK_EXPR_DEPENDENT) return TYPECHECK_RESULT_DEPENDENT;

                if (start->type != end->type) {
                    if (end_result == TYPECHECK_EXPR_WEAK) {
                        end_result = typecheck_expr(context, scope, scope_pos, end, start->type);
                    } else if (start_result == TYPECHECK_EXPR_WEAK && end_result == TYPECHECK_EXPR_STRONG) {
                        start_result = typecheck_expr(context, scope, scope_pos, start, end->type);
                    }
                }

                if (start->type != end->type) {
                    print_file_pos(&stmt->for_.range.start->pos);
                    printf("Ends of range have different type: ");
                    print_type(context, start->type);
                    printf(" vs ");
                    print_type(context, end->type);
                    printf("\n");
                    return TYPECHECK_RESULT_BAD;
                }

                Type *index_type = start->type;
                if (!primitive_is_integer(primitive_of(index_type))) {
                    print_file_pos(&stmt->for_.range.start->pos);
                    printf("Can't iterate over a range of ");
                    print_type(context, index_type);
                    printf("\n");
                    return TYPECHECK_RESULT_BAD;
                }

                stmt->for_.range.var->type = index_type;
            } else if (stmt->for_.kind == LOOP_INFINITE) {
                // No special checking
            } else {
                assert(false);
            }

            for (Stmt* inner = stmt->for_.body; inner->kind != STMT_END; inner = inner->next) {
                Typecheck_Result r = typecheck_stmt(context, &stmt->for_.scope, inner);
                if (r != TYPECHECK_RESULT_DONE) return r;
            }
        } break;

        case STMT_RETURN: {
            assert(scope->fn != null);

            if (!scope->fn->signature->has_return) {
                if (stmt->return_.value != null) {
                    u8 *name = scope->fn->name;
                    print_file_pos(&stmt->pos);
                    printf("Function '%s' is not declared to return anything, but tried to return a value\n", name);
                    return TYPECHECK_RESULT_BAD;
                }

            } else {
                Type *expected_type = scope->fn->signature->return_type;

                if (stmt->return_.value == null) {
                    u8 *name = scope->fn->name;
                    print_file_pos(&stmt->pos);
                    printf("Function '%s' is declared to return a ", name);
                    print_type(context, expected_type);
                    printf(", but tried to return a value. value\n");
                    return TYPECHECK_RESULT_BAD;
                }

                Typecheck_Expr_Result r = typecheck_expr(context, scope, scope_pos, stmt->return_.value, expected_type);
                if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) return r;

                if (!type_can_assign(expected_type, stmt->return_.value->type)) {
                    u8 *name = scope->fn->name;
                    print_file_pos(&stmt->pos);
                    printf("Expected ");
                    print_type(context, expected_type);
                    printf(" but got ");
                    print_type(context, stmt->return_.value->type);
                    printf(" for return value in function '%s'\n", name);
                    return TYPECHECK_RESULT_BAD;
                }
            }
        } break;

        case STMT_CONTINUE:
        case STMT_BREAK:
        case STMT_DEBUG_BREAK:
        {} break; // Any fancy logic goes in 'check_control_flow'

        default: assert(false);
    }

    return TYPECHECK_RESULT_DONE;
}

// NB This will allocate on context->stack, push/pop before/after
Eval_Result eval_compile_time_expr(Context* context, Expr* expr, u8* result_into) {
    u64 type_size = type_size_of(expr->type);
    assert(type_size > 0);

    switch (expr->kind) {
        case EXPR_LITERAL: {
            assert(type_size <= 8);
            mem_copy((u8*) &expr->literal.masked_value, result_into, type_size);
            return EVAL_OK;
        } break;

        case EXPR_VARIABLE: {
            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));
            Var *var = expr->variable.var;

            if (!(var->flags & VAR_FLAG_GLOBAL)) {
                print_file_pos(&expr->pos);
                printf("Can't use local variables in constant expressions\n");
                return EVAL_BAD;
            }

            Global_Var *global = &context->global_vars[var->global_index];

            if (global->compute_at_runtime) {
                return EVAL_DO_AT_RUNTIME;
            } else if (global->valid) {
                u8* other_value = &(global->in_rdata? context->seg_rdata : context->seg_data)[global->data_offset];
                mem_copy(other_value, result_into, type_size);
                return EVAL_OK;
            } else if (!global->checked) {
                return EVAL_DEPENDENT;
            } else {
                return EVAL_BAD;
            }
        } break;

        case EXPR_CAST: {
            Type_Kind to   = primitive_of(expr->type);
            Type_Kind from = primitive_of(expr->cast_from->type);

            u64 inner_type_size = type_size_of(expr->cast_from->type);
            assert(type_size <= 8 && inner_type_size <= 8);

            u64 inner = 0;
            Eval_Result result = eval_compile_time_expr(context, expr->cast_from, (u8*) &inner);
            if (result != EVAL_OK) return result;

            u64 outer;

            if ((from == TYPE_POINTER || from == TYPE_FN_POINTER) && (to == TYPE_POINTER || to == TYPE_FN_POINTER)) {
                outer = inner;
            } else if (primitive_is_float(from) && primitive_is_float(to)) {
                if (from == TYPE_F32 && to == TYPE_F64) {
                    f64 r = (f64) *((f32*) (&inner));
                    outer = *((u64*) &r);
                }

                if (from == TYPE_F64 && to == TYPE_F32) {
                    f32 r = (f32) *((f64*) (&inner));
                    outer = *((u32*) &r);
                }
            } else if (primitive_is_float(from) && primitive_is_integer(to)) {
                f64 f;
                if (from == TYPE_F32) {
                    f = (f64) *((f32*) &inner);
                } else if (from == TYPE_F64) {
                    f = *((f64*) &inner);
                } else {
                    assert(false);
                }

                if (primitive_is_signed(to)) {
                    outer = (u64) ((i64) f);
                } else {
                    outer = (u64) f;
                }
            } else if (primitive_is_integer(from) && primitive_is_float(to)) {
                f64 f;

                if (primitive_is_signed(from)) {
                    i64 i;
                    switch (inner_type_size) {
                        case 1: i = (i64) *((i8*)  &inner); break;
                        case 2: i = (i64) *((i16*) &inner); break;
                        case 4: i = (i64) *((i32*) &inner); break;
                        case 8: i = (i64) *((i64*) &inner); break;
                        default: assert(false);
                    }
                    f = (f64) i;
                } else {
                    f = (f64) inner;
                }

                if (to == TYPE_F32) {
                    *((f32*) &outer) = (f32) f;
                } else if (to == TYPE_F64) {
                    *((f64*) &outer) = f;
                } else {
                    assert(false);
                }
            } else {
                if (primitive_is_signed(from) && primitive_is_signed(to)) {
                    i64 inner_signed;
                    // Sign-extend
                    switch (inner_type_size) {
                        case 1: inner_signed = (i64) *((i8*)  &inner); break;
                        case 2: inner_signed = (i64) *((i16*) &inner); break;
                        case 4: inner_signed = (i64) *((i32*) &inner); break;
                        case 8: inner_signed = (i64) *((i64*) &inner); break;
                        default: assert(false);
                    }
                    outer = *((u64*) &inner_signed);
                } else {
                    switch (inner_type_size) {
                        case 1: outer = (u64) *((u8*)  &inner); break;
                        case 2: outer = (u64) *((u16*) &inner); break;
                        case 4: outer = (u64) *((u32*) &inner); break;
                        case 8: outer = (u64) *((u64*) &inner); break;
                        default: assert(false);
                    }
                }
            }

            switch (type_size) {
                case 1: *((u8*)  result_into) = (u8)  outer; break;
                case 2: *((u16*) result_into) = (u16) outer; break;
                case 4: *((u32*) result_into) = (u32) outer; break;
                case 8: *((u64*) result_into) = (u64) outer; break;
                default: assert(false);
            }

            return EVAL_OK;
        } break;

        case EXPR_SUBSCRIPT: {
            Eval_Result result;

            u64 array_size = type_size_of(expr->subscript.array->type);
            u64 index_size = type_size_of(expr->subscript.index->type);
            assert(index_size <= 8);

            u8* inner_data = arena_alloc(&context->stack, array_size);
            mem_clear(inner_data, array_size);
            result = eval_compile_time_expr(context, expr->subscript.array, inner_data);
            if (result != EVAL_OK) return result;

            u64 index = 0;
            result = eval_compile_time_expr(context, expr->subscript.index, (u8*) &index);
            if (result != EVAL_OK) return result;

            if (primitive_is_signed(primitive_of(expr->subscript.index->type))) {
                i64 signed_index;
                switch (index_size) {
                    case 1: signed_index = (i64) *((i8*)  &index); break;
                    case 2: signed_index = (i64) *((i16*) &index); break;
                    case 4: signed_index = (i64) *((i32*) &index); break;
                    case 8: signed_index = (i64) *((i64*) &index); break;
                    default: assert(false);
                }
                index = signed_index;
            }

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

            if (expr->unary.op == UNARY_DEREFERENCE || expr->unary.op == UNARY_ADDRESS_OF) {
                return EVAL_DO_AT_RUNTIME;
            }

            assert(inner_type_size <= 8);
            assert(inner_type_size == type_size);

            Eval_Result result = eval_compile_time_expr(context, expr->unary.inner, result_into);
            if (result != EVAL_OK) return result;

            switch (expr->unary.op) {
                case UNARY_NEG: {
                    if (primitive_is_integer(primitive)) {
                        switch (type_size) {
                            case 1: *((i8*)  result_into) = -(*((i8*)  result_into)); break;
                            case 2: *((i16*) result_into) = -(*((i16*) result_into)); break;
                            case 4: *((i32*) result_into) = -(*((i32*) result_into)); break;
                            case 8: *((i64*) result_into) = -(*((i64*) result_into)); break;
                            default: assert(false);
                        }
                    } else if (primitive_is_float(primitive)) {
                        switch (type_size) {
                            case 4: *((f32*) result_into) = -(*((f32*) result_into)); break;
                            case 8: *((f64*) result_into) = -(*((f64*) result_into)); break;
                            default: assert(false);
                        }
                    } else {
                        assert(false);
                    }
                } break;

                case UNARY_NOT: {
                    assert(inner_type_size == 1 && primitive == TYPE_BOOL);
                    *result_into = (*result_into == 0)? 1 : 0;
                } break;

                case UNARY_SQRT: {
                    if (primitive == TYPE_F32) {
                        f32 f = *((f32*) result_into);
                        f = _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss(f)));
                        *((f32*) result_into) = f;
                    } else if (primitive == TYPE_F64) {
                        f64 f = *((f64*) result_into);
                        f = _mm_cvtsd_f64(_mm_sqrt_sd(_mm_set1_pd(0.0), _mm_set_sd(f)));
                        *((f64*) result_into) = f;
                    } else {
                        assert(false);
                    }
                } break;

                default: assert(false);
            }

            return EVAL_OK;
        } break;

        case EXPR_TERNARY: {
            u8 condition;
            Eval_Result eval_result = eval_compile_time_expr(context, expr->ternary.condition, &condition);
            if (eval_result != EVAL_OK) return eval_result;

            Expr *inner = condition? expr->ternary.left : expr->ternary.right;
            return eval_compile_time_expr(context, inner, result_into);
        } break;

        case EXPR_BINARY: {
            u64 child_size = type_size_of(expr->binary.left->type);

            assert(type_size <= 8 && child_size <= 8);

            u64 left_result, right_result;

            Eval_Result eval_result;
            eval_result = eval_compile_time_expr(context, expr->binary.left, (u8*) &left_result);
            if (eval_result != EVAL_OK) return eval_result;
            eval_result = eval_compile_time_expr(context, expr->binary.right, (u8*) &right_result);
            if (eval_result != EVAL_OK) return eval_result;

            Type_Kind primitive = expr->binary.left->type->kind;

            u64 result = 0;

            if (primitive_is_signed(primitive)) {
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

                    case BINARY_AND:  result = left &  right; break;
                    case BINARY_OR:   result = left |  right; break;
                    case BINARY_XOR:  result = left ^  right; break;

                    case BINARY_SHL:  result = left << right; break;
                    case BINARY_SHR:  result = left >> right; break;

                    case BINARY_LOGICAL_AND: result = left && right; break;
                    case BINARY_LOGICAL_OR:  result = left || right;

                    case BINARY_EQ:   result = left == right; break;
                    case BINARY_NEQ:  result = left != right; break;
                    case BINARY_GT:   result = left >  right; break;
                    case BINARY_GTEQ: result = left >= right; break;
                    case BINARY_LT:   result = left <  right; break;
                    case BINARY_LTEQ: result = left <= right; break;
                    default: assert(false);
                }
            } else if (primitive_is_integer(primitive) || primitive == TYPE_BOOL || primitive == TYPE_POINTER || primitive == TYPE_FN_POINTER) {
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
                    case BINARY_ADD:  result = left + right; break;
                    case BINARY_SUB:  result = left - right; break;
                    case BINARY_MUL:  result = left * right; break;
                    case BINARY_DIV:  result = left / right; break;
                    case BINARY_MOD:  result = left % right; break;

                    case BINARY_AND:  result = left & right; break;
                    case BINARY_OR:   result = left | right; break;
                    case BINARY_XOR:  result = left ^ right; break;

                    case BINARY_SHL:  result = left << right; break;
                    case BINARY_SHR:  result = left >> right; break;

                    case BINARY_LOGICAL_AND: result = left && right; break;
                    case BINARY_LOGICAL_OR:  result = left || right;

                    case BINARY_EQ:   result = left == right; break;
                    case BINARY_NEQ:  result = left != right; break;
                    case BINARY_GT:   result = left >  right; break;
                    case BINARY_GTEQ: result = left >= right; break;
                    case BINARY_LT:   result = left <  right; break;
                    case BINARY_LTEQ: result = left <= right; break;
                    default: assert(false);
                }
            } else if (primitive == TYPE_F32) {
                f32 left  = *((f32*) &left_result);
                f32 right = *((f32*) &right_result);
                f32 f = 0.0;

                switch (expr->binary.op) {
                    case BINARY_ADD:  f = left + right; break;
                    case BINARY_SUB:  f = left - right; break;
                    case BINARY_MUL:  f = left * right; break;
                    case BINARY_DIV:  f = left / right; break;

                    case BINARY_EQ:   result = left == right; break;
                    case BINARY_NEQ:  result = left != right; break;
                    case BINARY_GT:   result = left >  right; break;
                    case BINARY_GTEQ: result = left >= right; break;
                    case BINARY_LT:   result = left <  right; break;
                    case BINARY_LTEQ: result = left <= right; break;

                    default: assert(false);
                }

                if (f != 0.0) {
                    result = *((u32*) &f);
                }
            } else if (primitive == TYPE_F64) {
                f64 left  = *((f64*) &left_result);
                f64 right = *((f64*) &right_result);
                f64 f = 0.0;

                switch (expr->binary.op) {
                    case BINARY_ADD:  f = left + right; break;
                    case BINARY_SUB:  f = left - right; break;
                    case BINARY_MUL:  f = left * right; break;
                    case BINARY_DIV:  f = left / right; break;

                    case BINARY_EQ:   result = left == right; break;
                    case BINARY_NEQ:  result = left != right; break;
                    case BINARY_GT:   result = left >  right; break;
                    case BINARY_GTEQ: result = left >= right; break;
                    case BINARY_LT:   result = left <  right; break;
                    case BINARY_LTEQ: result = left <= right; break;

                    default: assert(false);
                }

                if (f != 0.0) {
                    result = *((u64*) &f);
                }
            } else {
                assert(false);
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
                        Eval_Result result = eval_compile_time_expr(context, child, mem);
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
                        Eval_Result result = eval_compile_time_expr(context, child, mem + offset);
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
            u8* inner_data = arena_alloc(&context->stack, parent_size);
            mem_clear(inner_data, parent_size);
            Eval_Result result = eval_compile_time_expr(context, expr->member_access.parent, inner_data);
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

        case EXPR_QUERY_TYPE_INFO: {
            Type *type = expr->query_type_info.type;

            if (expr->query_type_info.type->kind == TYPE_UNRESOLVED_NAME) {
                return EVAL_DO_AT_RUNTIME;
            } else {
                i64 result;

                switch (expr->query_type_info.query) {
                    case QUERY_TYPE_INFO_ENUM_LENGTH: {
                        assert(type->kind == TYPE_ENUM);
                        result = 0;
                        for (u32 m = 0; m < type->enumeration.member_count; m += 1) {
                            u64 value = type->enumeration.members[m].value;
                            result = max(value + 1, result);
                        }
                    } break;

                    case QUERY_TYPE_INFO_SIZE:  result = type_size_of(type);  break;
                    case QUERY_TYPE_INFO_ALIGN: result = type_align_of(type); break;

                    default: assert(false);
                }

                assert(expr->type->kind == TYPE_DEFAULT_INT);
                mem_copy((u8*) &result, result_into, type_size);

                return EVAL_OK;
            }
        } break;

        case EXPR_ENUM_MEMBER_NAME: {
            return EVAL_DO_AT_RUNTIME;
        } break;

        case EXPR_ADDRESS_OF_FUNCTION: {
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
            case STMT_LET:
            case STMT_EXPR:
            case STMT_ASSIGNMENT:
            case STMT_OP_ASSIGNMENT:
            {} break;

            case STMT_BLOCK: {
                Control_Flow_Result result = check_control_flow(stmt->block.stmt, parent_loop, return_would_be_trailing && is_last_stmt);
                switch (result) {
                    case CONTROL_FLOW_WILL_RETURN: has_returned = true; break;
                    case CONTROL_FLOW_MIGHT_RETURN: break;
                    case CONTROL_FLOW_INVALID: return CONTROL_FLOW_INVALID; break;
                    default: assert(false);
                }
            } break;

            case STMT_IF: {
                bool else_return_would_be_trailing = return_would_be_trailing && is_last_stmt;
                bool then_return_would_be_trailing = else_return_would_be_trailing && (stmt->if_.else_then == null);

                Control_Flow_Result then_result = check_control_flow(stmt->if_.then, parent_loop, then_return_would_be_trailing);
                if (then_result == CONTROL_FLOW_INVALID) return then_result;

                Control_Flow_Result else_result = CONTROL_FLOW_MIGHT_RETURN;
                if (stmt->if_.else_then != null) {
                    else_result = check_control_flow(stmt->if_.else_then, parent_loop, else_return_would_be_trailing);
                    if (else_result == CONTROL_FLOW_INVALID) return else_result;
                }

                if (then_result == CONTROL_FLOW_WILL_RETURN && else_result == CONTROL_FLOW_WILL_RETURN) {
                    has_returned = true;
                }
            } break;

            case STMT_SWITCH: {
                has_returned =
                    stmt->switch_.case_count == primitive_size_of(primitive_of(stmt->switch_.index->type)) ||
                    stmt->switch_.default_case != null;

                if (stmt->switch_.default_case != null) {
                    Switch_Case *c = stmt->switch_.default_case;

                    Control_Flow_Result case_result = check_control_flow(c->body, parent_loop, false);
                    switch (case_result) {
                        case CONTROL_FLOW_WILL_RETURN: break;
                        case CONTROL_FLOW_MIGHT_RETURN: has_returned = false; break;
                        case CONTROL_FLOW_INVALID: return CONTROL_FLOW_INVALID;
                    }
                }

                for (u32 i = 0; i < stmt->switch_.case_count; i += 1) {
                    Switch_Case *c = &stmt->switch_.cases[i];

                    Control_Flow_Result case_result = check_control_flow(c->body, parent_loop, false);
                    switch (case_result) {
                        case CONTROL_FLOW_WILL_RETURN: break;
                        case CONTROL_FLOW_MIGHT_RETURN: has_returned = false; break;
                        case CONTROL_FLOW_INVALID: return CONTROL_FLOW_INVALID;
                    }
                }
            } break;

            case STMT_FOR: {
                Control_Flow_Result result = check_control_flow(stmt->for_.body, stmt, false);
                if (result == CONTROL_FLOW_INVALID) return CONTROL_FLOW_INVALID;
            } break;

            case STMT_RETURN: {
                has_returned = true;
                stmt->return_.trailing = return_would_be_trailing && is_last_stmt;
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

            case STMT_DEBUG_BREAK: {} break;

            default: assert(false);
        }
    }

    if (has_returned) {
        return CONTROL_FLOW_WILL_RETURN;
    } else {
        return CONTROL_FLOW_MIGHT_RETURN;
    }
}


typedef struct Typecheck_Item {
    enum {
        TYPECHECK_RESOLVE_TYPE,
        TYPECHECK_COMPUTE_SIZE,
        TYPECHECK_FN_BODY,
        TYPECHECK_GLOBAL_LET,
    } kind;

    union {
        struct {
            Scope *scope;
            u32 scope_pos;
            Type **slot;
            File_Pos pos;
        } resolve_type;

        Type *compute_size_of;

        Fn *fn;

        Global_Let *global_let;
    };
} Typecheck_Item;

typedef struct Typecheck_Queue {
    Fn **all_fns;
    Typecheck_Item *items, *unresolved; // stretchy-buffer
} Typecheck_Queue;


Typecheck_Result check_global(Context *context, Scope *scope, Global_Let *global_let) {
    assert(global_let->var_count > 0);
    Type *var_type = global_let->vars[0].type;
    for (u32 i = 1; i < global_let->var_count; i += 1) assert(global_let->vars[i].type == var_type);

    if (var_type != null) {
        Typecheck_Result r = resolve_type(context, scope, 0, &var_type, &global_let->pos);
        if (r != TYPECHECK_RESULT_DONE) return r;
    }

    bool loose_types = false;

    if (global_let->expr != null) {
        Type *resolve_to = var_type;
        if (resolve_to == null) resolve_to = &context->primitive_types[TYPE_VOID];

        Typecheck_Expr_Result r = typecheck_expr(context, scope, 0, global_let->expr, resolve_to);
        if (r == TYPECHECK_EXPR_BAD || r == TYPECHECK_EXPR_DEPENDENT) {
            return r;
        }

        if (var_type == null) {
            if (r == TYPECHECK_EXPR_WEAK) loose_types = true;
            var_type = global_let->expr->type;
        }
        
        if (!type_can_assign(var_type, global_let->expr->type)) {
            print_file_pos(&global_let->pos);
            printf("Right hand side of global variable declaration doesn't have correct type. Expected ");
            print_type(context, var_type);
            printf(" but got ");
            print_type(context, global_let->expr->type);
            printf("\n");
            return TYPECHECK_RESULT_BAD;
        }
    }

    if (var_type->flags & TYPE_FLAG_SIZE_NOT_COMPUTED) {
        return TYPECHECK_RESULT_DEPENDENT;
    }


    u64 type_size = type_size_of(var_type);
    u64 type_align = type_align_of(var_type);

    for (u32 i = 0; i < global_let->var_count; i += 1) {
        Var *var = &global_let->vars[i];
        assert(var->flags & VAR_FLAG_GLOBAL);
        var->type = var_type;

        if (loose_types) {
            var->flags |= VAR_FLAG_LOOSE_TYPE;
        } else {
            var->flags &= ~VAR_FLAG_LOOSE_TYPE;
        }

        Global_Var *global = &context->global_vars[var->global_index];
        if (global->data_offset == U32_MAX) {
            global->in_rdata = var->flags & VAR_FLAG_CONSTANT;
            global->data_offset = add_exe_data(context, global->in_rdata, null, type_size, type_align);
        }
    }

    if (global_let->expr != null) {
        Var *var = &global_let->vars[0];
        Global_Var *global = &context->global_vars[var->global_index];
        u8 *result_into = &(global->in_rdata? context->seg_rdata : context->seg_data)[global->data_offset];

        arena_stack_push(&context->stack);
        Eval_Result eval_result = eval_compile_time_expr(context, global_let->expr, result_into);
        arena_stack_pop(&context->stack);

        Typecheck_Result result = -1;
        switch (eval_result) {
            case EVAL_OK: {
                global->checked = true;
                global->valid = true;
                global->compute_at_runtime = false;
                result = TYPECHECK_RESULT_DONE;
            } break;

            case EVAL_DO_AT_RUNTIME: {
                if (var->flags & VAR_FLAG_CONSTANT) {
                    global->checked = true;
                    global->valid = false;
                    global->compute_at_runtime = false;

                    u8 *var_name = global->var->name;
                    print_file_pos(&global->var->declaration_pos);
                    printf("Can't compute right hand side of 'const ");
                    for (u32 i = 0; i < global_let->var_count; i += 1) {
                        if (i > 0) printf(", ");
                        Var *var = &global_let->vars[i];
                        printf(var->name);
                    }
                    printf("' at compile time\n", var_name);
                    result = TYPECHECK_RESULT_BAD;
                } else {
                    global->checked = true;
                    global->valid = true;
                    global->compute_at_runtime = true;
                    global_let->compute_at_runtime = true;
                    result = TYPECHECK_RESULT_DONE;
                }
            } break;

            case EVAL_BAD: {
                global->checked = true;
                result = TYPECHECK_RESULT_BAD;
            } break;

            case EVAL_DEPENDENT: {
                global->checked = false;
                result = TYPECHECK_RESULT_DEPENDENT;
            } break;

            default: assert(false);

        }

        for (u32 i = 1; i < global_let->var_count; i += 1) {
            Var *other_var = &global_let->vars[i];
            Global_Var *other_global = &context->global_vars[other_var->global_index];
            other_global->checked = global->checked;
            other_global->valid = global->valid;
            u8 *other_result_into = &(global->in_rdata? context->seg_rdata : context->seg_data)[other_global->data_offset];
            mem_copy(result_into, other_result_into, type_size);
        }

        assert(result != -1);
        return result;
    } else {
        for (u32 i = 0; i < global_let->var_count; i += 1) {
            Var *var = &global_let->vars[i];
            Global_Var *global = &context->global_vars[var->global_index];
            global->checked = true;
            global->valid = true;
            global->compute_at_runtime = false;
        }
        return TYPECHECK_RESULT_DONE;
    }
}

Typecheck_Result typecheck_item_resolve(Context *context, Typecheck_Item *item) {
    switch (item->kind) {
        case TYPECHECK_RESOLVE_TYPE: {
            return resolve_type(context, item->resolve_type.scope, item->resolve_type.scope_pos, item->resolve_type.slot, &item->resolve_type.pos);
        } break;

        case TYPECHECK_COMPUTE_SIZE: {
            Type *type = item->compute_size_of;
            assert(type->kind == TYPE_STRUCT);

            if (type->flags & TYPE_FLAG_SIZE_NOT_COMPUTED) {
                return compute_size_of_struct(type);
            } else {
                return TYPECHECK_RESULT_DONE;
            }
        } break;

        case TYPECHECK_FN_BODY: {
            Fn *fn = item->fn;
            assert(fn->signature_type->kind == TYPE_FN_POINTER);

            if (fn->signature_type->flags & (TYPE_FLAG_UNRESOLVED|TYPE_FLAG_UNRESOLVED_CHILD)) {
                return TYPECHECK_RESULT_DEPENDENT;
            }
            fn->signature = &fn->signature_type->fn_signature;


            if (fn->kind == FN_KIND_NORMAL) { 
                arena_stack_push(&context->stack); // TODO do we still need this?

                // Body types
                for (Stmt* stmt = fn->body.first_stmt; stmt->kind != STMT_END; stmt = stmt->next) {
                    Typecheck_Result r = typecheck_stmt(context, &fn->body.scope, stmt);
                    if (r != TYPECHECK_RESULT_DONE) return r;
                }

                // Control flow
                Control_Flow_Result result = check_control_flow(fn->body.first_stmt, null, true);
                if (result == CONTROL_FLOW_INVALID) {
                    return TYPECHECK_RESULT_BAD;
                } else if (fn->signature->has_return && result != CONTROL_FLOW_WILL_RETURN) {
                    print_file_pos(&fn->declaration_pos);
                    printf("Function '%s' might not return\n", fn->name);
                    return TYPECHECK_RESULT_BAD;
                }

                arena_stack_pop(&context->stack);
            }

            return TYPECHECK_RESULT_DONE;
        } break;

        case TYPECHECK_GLOBAL_LET: {
            Global_Let *global_let = item->global_let;
            return check_global(context, global_let->scope, global_let);
        } break;
    }

    assert(false);
    return TYPECHECK_RESULT_BAD;
}

void typecheck_queue_include_scope(Context *context, Typecheck_Queue *queue, Scope *scope);
void typecheck_queue_include_stmts(Context *context, Typecheck_Queue *queue, Stmt *stmt);

void typecheck_queue_include_scope(Context *context, Typecheck_Queue *queue, Scope *scope) {
    for (u32 i = 0; i < scope->decls_length; i += 1) {
        Decl *decl = &scope->decls[i];

        switch (decl->kind) {
            case DECL_TYPE: {
                if (decl->type->flags & (TYPE_FLAG_UNRESOLVED|TYPE_FLAG_UNRESOLVED_CHILD)) {
                    buf_push(queue->items, ((Typecheck_Item) {
                        .kind = TYPECHECK_RESOLVE_TYPE,
                        .resolve_type = {
                            .slot = &decl->type,
                            .pos = decl->pos,
                            .scope = scope,
                            .scope_pos = decl->scope_pos,
                        },
                    }));
                }

                if (decl->type->flags & TYPE_FLAG_SIZE_NOT_COMPUTED) {
                    buf_push(queue->items, ((Typecheck_Item) {
                        .kind = TYPECHECK_COMPUTE_SIZE,
                        .compute_size_of = decl->type,
                    }));
                }
            } break;

            case DECL_FN: {
                Fn *fn = decl->fn;

                buf_push(queue->items, ((Typecheck_Item) {
                    .kind = TYPECHECK_RESOLVE_TYPE,
                    .resolve_type = {
                        .slot = &decl->fn->signature_type,
                        .pos = decl->pos,
                        .scope = scope,
                        .scope_pos = decl->scope_pos,
                    },
                }));

                if (fn->kind == FN_KIND_NORMAL) {
                    buf_push(queue->items, ((Typecheck_Item) {
                        .kind = TYPECHECK_FN_BODY,
                        .fn = fn,
                    }));

                    assert(fn->body.local_vars == null);
                    fn->body.local_vars = (Var**) arena_alloc(&context->arena, fn->body.var_count * sizeof(Var*));

                    typecheck_queue_include_stmts(context, queue, fn->body.first_stmt);
                    typecheck_queue_include_scope(context, queue, &fn->body.scope);
                }

                buf_push(queue->all_fns, fn);
            } break;

            case DECL_VAR: {
                Var *var = decl->var;

                if (var->flags & VAR_FLAG_GLOBAL) {
                    // Do nothing, this is handled through context->global_lets
                } else {
                    Fn *fn = scope->fn;
                    assert(fn != null && fn->kind == FN_KIND_NORMAL && fn->body.local_vars != null);
                    fn->body.local_vars[var->local_index] = var;
                }
            } break;
        }
    }
}

void typecheck_queue_include_stmts(Context *context, Typecheck_Queue *queue, Stmt *stmt) {
    for (; stmt->kind != STMT_END; stmt = stmt->next) {
        if (stmt->kind == STMT_BLOCK) {
            typecheck_queue_include_stmts(context, queue, stmt->block.stmt);
            typecheck_queue_include_scope(context, queue, &stmt->block.scope);
        } else if (stmt->kind == STMT_IF) {
            typecheck_queue_include_stmts(context, queue, stmt->if_.then);
            typecheck_queue_include_scope(context, queue, &stmt->if_.then_scope);

            if (stmt->if_.else_then != null) {
                typecheck_queue_include_stmts(context, queue, stmt->if_.else_then);
                typecheck_queue_include_scope(context, queue, &stmt->if_.else_then_scope);
            }
        } else if (stmt->kind == STMT_FOR) {
            typecheck_queue_include_stmts(context, queue, stmt->for_.body);
            typecheck_queue_include_scope(context, queue, &stmt->for_.scope);
        } else if (stmt->kind == STMT_SWITCH) {
            for (u32 i = 0; i < stmt->switch_.case_count; i += 1) {
                typecheck_queue_include_stmts(context, queue, stmt->switch_.cases[i].body);
                typecheck_queue_include_scope(context, queue, stmt->switch_.cases[i].scope);
            }

            if (stmt->switch_.default_case != null) {
                typecheck_queue_include_stmts(context, queue, stmt->switch_.default_case->body);
                typecheck_queue_include_scope(context, queue, stmt->switch_.default_case->scope);
            }
        }
    }
}

bool typecheck(Context *context) {
    Typecheck_Queue queue = {0};
    typecheck_queue_include_scope(context, &queue, &context->global_scope);
    buf_foreach (Global_Let, global_let, context->global_lets) {
        buf_push(queue.items, ((Typecheck_Item) {
            .kind = TYPECHECK_GLOBAL_LET,
            .global_let = global_let,
        }));
    }

    u64 passes = 0;
    while (true) {
        passes += 1;
        //printf("%n pass\n", passes);
        u64 completed_count = 0;

        buf_foreach (Typecheck_Item, item, queue.items) {
            Typecheck_Result result = typecheck_item_resolve(context, item);

            if (result == TYPECHECK_RESULT_DONE) {
                // Good!
                completed_count += 1;
            } else if (result == TYPECHECK_RESULT_DEPENDENT) {
                buf_push(queue.unresolved, *item);
            } else if (result == TYPECHECK_RESULT_BAD) {
                return false;
            }
        }

        u64 unresolved_count = buf_length(queue.unresolved);
        if (completed_count == 0 && unresolved_count > 0) {
            printf("The following items depend on each other cyclically:\n");
            buf_foreach (Typecheck_Item, item, queue.unresolved) {
                switch (item->kind) {
                    case TYPECHECK_RESOLVE_TYPE: {
                        printf("    The type of ");
                        print_type(context, *item->resolve_type.slot);
                        printf("\n");
                    } break;

                    case TYPECHECK_COMPUTE_SIZE: {
                        assert(item->compute_size_of->kind == TYPE_STRUCT);
                        u8 *name = item->compute_size_of->structure.name;
                        printf("    The size of 'struct %s'\n", name);
                    } break;

                    case TYPECHECK_FN_BODY: {
                        u8 *name = item->fn->name;
                        printf("    The body of 'fn %s'\n", name);
                    } break;

                    case TYPECHECK_GLOBAL_LET: {
                        Global_Let *global_let = item->global_let;
                        if (global_let->var_count == 1) {
                            printf("    The global '%s'\n", global_let->vars[0].name);
                        } else {
                            printf("    The globals ");
                            for (u32 i = 0; i < global_let->var_count; i += 1) {
                                if (i > 0) printf(", ");
                                printf("'%s'", global_let->vars[i].name);
                            }
                            printf("\n");
                        }
                    } break;

                    default: assert(false);
                }
            }
            return false;
        }

        buf_clear(queue.items);
        if (buf_length(queue.unresolved) > 0) {
            Typecheck_Item *tmp = queue.items;
            queue.items = queue.unresolved;
            queue.unresolved = tmp;
            continue;
        } else {
            break;
        }
    }

    printf("Completed typechecking in %u %s\n", passes, passes == 1? "pass" : "passes");

    buf_free(queue.items);
    buf_free(queue.unresolved);
    context->all_fns = queue.all_fns;

    // Function signatures
    buf_foreach (Type*, signature_type, context->fn_signatures) {
        assert(!((*signature_type)->flags & (TYPE_FLAG_UNRESOLVED|TYPE_FLAG_UNRESOLVED_CHILD)));

        Fn_Signature *signature = &((*signature_type)->fn_signature);

        for (u32 p = 0; p < signature->param_count; p += 1) {
            Type **type = &signature->params[p].type;
            assert(!((*type)->flags & (TYPE_FLAG_UNRESOLVED|TYPE_FLAG_UNRESOLVED_CHILD)));

            if (primitive_is_compound((*type)->kind)) {
                u32 size = type_size_of(*type);
                if (size == 0 || size == 1 || size == 2 || size == 4 || size == 8) {
                    // Just squish the value into a register
                } else {
                    signature->params[p].reference_semantics = true;
                }
            }
        }

        if (signature->has_return) {
            Type **return_type = &signature->return_type;
            assert(!((*return_type)->flags & (TYPE_FLAG_UNRESOLVED|TYPE_FLAG_UNRESOLVED_CHILD)));

            if (primitive_is_compound((*return_type)->kind)) {
                u32 size = type_size_of(*return_type);
                if (size == 1 || size == 2 || size == 4 || size == 8) {
                    // We just squish the struct/array into RAX
                } else {
                    signature->return_by_reference = true;
                }
            }
        }
    }

    // Mark variables as references according to the signature, now that we have completed signatures
    buf_foreach (Fn*, fn_ptr, context->all_fns) {
        Fn *fn = *fn_ptr;

        for (u32 p = 0; p < fn->signature->param_count; p += 1) {
            if (fn->signature->params[p].reference_semantics && fn->kind == FN_KIND_NORMAL) {
                fn->body.param_var_mappings[p]->flags |= VAR_FLAG_REFERENCE;
            }
        }
    }

    return true;
}



void build_enum_member_name_table(Context *context, Type* type) {
    assert(type->kind == TYPE_ENUM);
    assert(type->enumeration.name_table_data_offset == U64_MAX);

    u64 max_value = 0;
    for (u32 m = 0; m < type->enumeration.member_count; m += 1) {
        u64 value = type->enumeration.members[m].value;
        max_value = max(value, max_value);
    }

    u64 table_size = max_value + 1;
    u64 table_offset = add_exe_data(context, true, null, table_size * sizeof(u16), sizeof(u16));
    type->enumeration.name_table_data_offset = table_offset;

    mem_fill(context->seg_rdata + table_offset, 0xff, table_size * sizeof(u16));

    u8 *type_name = type->enumeration.name;
    u32 type_name_length = str_length(type_name);

    u64 invalid_string_offset = buf_length(context->seg_rdata);
    u64 invalid_string_length = type_name_length + 10;
    buf_push(context->seg_rdata, invalid_string_length & 0xff);
    buf_push(context->seg_rdata, (invalid_string_length >> 8) & 0xff);
    str_push_str(&context->seg_rdata, "<unknown ", 9);
    str_push_str(&context->seg_rdata, type_name, type_name_length);
    str_push_str(&context->seg_rdata, ">\0", 2);

    for (u32 m = 0; m < type->enumeration.member_count; m += 1) {
        u64 value = type->enumeration.members[m].value;
        u8 *name = type->enumeration.members[m].name;
        u32 name_length = str_length(name);

        assert(name_length <= U16_MAX);
        u64 string_offset = buf_length(context->seg_rdata);
        buf_push(context->seg_rdata, name_length & 0xff);
        buf_push(context->seg_rdata, (name_length >> 8) & 0xff);
        str_push_str(&context->seg_rdata, name, name_length + 1);

        u16 relative_offset = string_offset - table_offset - value*sizeof(u16);
        assert(relative_offset < U16_MAX);

        u16* table_value = ((u16*) (context->seg_rdata + table_offset)) + value;
        *table_value = relative_offset;
    }

    u16* table = (u16*) (context->seg_rdata + table_offset);
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
    RIP_OFFSET_RDATA,   // relative to .rdata

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

inline bool is_gpr(Register reg) { return (reg >= RAX && reg <= R15) || (reg >= AH && reg <= BH); }
inline bool is_gpr_high(Register reg) { return reg >= AH && reg <= BH; }
inline bool is_xmm(Register reg) { return reg >= XMM0 && reg <= XMM15; }

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
    [RIP_OFFSET_RDATA]  = 5,
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
 
    [XMM0]  = { null, null, "xmm0", "xmm0" },
    [XMM1]  = { null, null, "xmm1", "xmm1" },
    [XMM2]  = { null, null, "xmm2", "xmm2" },
    [XMM3]  = { null, null, "xmm3", "xmm3" },
    [XMM4]  = { null, null, "xmm4", "xmm4" },
    [XMM5]  = { null, null, "xmm5", "xmm5" },
    [XMM6]  = { null, null, "xmm6", "xmm6" },
    [XMM7]  = { null, null, "xmm7", "xmm7" },
    [XMM8]  = { null, null, "xmm8", "xmm8" },
    [XMM9]  = { null, null, "xmm9", "xmm9" },
    [XMM10] = { null, null, "xmm10", "xmm10" },
    [XMM11] = { null, null, "xmm11", "xmm11" },
    [XMM12] = { null, null, "xmm12", "xmm12" },
    [XMM13] = { null, null, "xmm13", "xmm13" },
    [XMM14] = { null, null, "xmm14", "xmm14" },
    [XMM15] = { null, null, "xmm15", "xmm15" },

    [RIP_OFFSET_DATA]  = { null, null, null, "rip" },
    [RIP_OFFSET_RDATA] = { null, null, null, "rip" },
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

#define VOLATILE_REGISTER_COUNT 13
#define NONVOLATILE_REGISTER_COUNT 19
#define INPUT_REGISTER_COUNT 4

Register VOLATILE_REGISTERS[VOLATILE_REGISTER_COUNT] = {
    RCX, RDX, R8, R9,
    RAX, R10, R11,
    XMM0, XMM1, XMM2, XMM3, XMM4, XMM5
};
Register NONVOLATILE_REGISTERS[NONVOLATILE_REGISTER_COUNT] = {
    RBX, RBP, RDI, RSI, RSP, R12, R13, R14, R15,
    XMM6, XMM7, XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15
};
Register GPR_INPUT_REGISTERS[INPUT_REGISTER_COUNT] = { RCX, RDX, R8, R9 };
Register XMM_INPUT_REGISTERS[INPUT_REGISTER_COUNT] = { XMM0, XMM1, XMM2, XMM3 };

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

typedef enum Move_Mode { MOVE_FROM_MEM, MOVE_TO_MEM } Move_Mode;

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
#define x64_place_address(...) (X64_Place) { .kind = PLACE_ADDRESS, .address = (__VA_ARGS__) }


//#define PRINT_GENERATED_INSTRUCTIONS

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
        case RIP_OFFSET_RDATA:   printf(" + .rdata offset"); break;
    }

    printf("]");
}

void print_x64_place(X64_Place place, u8 op_size) {
    if (place.kind == PLACE_ADDRESS) {
        switch (op_size) {
            case 1: printf("byte ptr "); break;
            case 2: printf("word ptr "); break;
            case 4: printf("dword ptr "); break;
            case 8: printf("qword ptr "); break;
        }
        print_x64_address(place.address);
    } else if (place.kind == PLACE_REGISTER) {
        printf("%s", register_name(place.reg, op_size));
    } else {
        assert(false);
    }
}

inline bool x64_address_uses_reg(X64_Address address, Register reg) {
    return address.base == reg || address.index == reg;
}

inline bool x64_address_cmp(X64_Address a, X64_Address b) {
    return a.base == b.base && a.index == b.index && a.scale == b.scale && a.immediate_offset == b.immediate_offset;
}

// Yes, the signature of these functions is really long now, but that just reflects how insane x64 is.
void encode_instruction_modrm_reg_mem(
    Context *context,
    u8 rex, u32 opcode, bool eight_bit_reg_semantics,
    X64_Address mem, Register reg,
    u64 immediate, u8 imm_bytes
) {
    u8 modrm = 0;
    u8 sib = 0;
    bool use_sib = false;
    u8 offset_bytes = 0;


    modrm |= (REGISTER_INDICES[reg] & 0x07) << 3;
    if (REGISTER_INDICES[reg] & 0x08) {
        rex |= REX_R;
    }


    bool force_i32_offset = false, rip_relative = false;

    Stack_Access_Fixup stack_access_fixup = {0};
    stack_access_fixup.kind = -1;
    Rip_Fixup data_fixup = {0};
    data_fixup.kind = -1;

    if (mem.base == RSP_OFFSET_LOCALS || mem.base == RSP_OFFSET_INPUTS) {
        switch (mem.base) {
            case RSP_OFFSET_INPUTS: stack_access_fixup.kind = STACK_ACCESS_FIXUP_INPUT_SECTION; break;
            case RSP_OFFSET_LOCALS: stack_access_fixup.kind = STACK_ACCESS_FIXUP_LOCAL_SECTION; break;
            default: assert(false);
        }

        force_i32_offset = true;
    }

    if (mem.base == RIP_OFFSET_DATA || mem.base == RIP_OFFSET_RDATA) {
        data_fixup.kind = mem.base == RIP_OFFSET_DATA? RIP_FIXUP_DATA : RIP_FIXUP_RDATA;
        data_fixup.data_offset = mem.immediate_offset;

        assert(mem.index == REGISTER_NONE);
        mem.immediate_offset = 0xdeadbeef;

        rip_relative = true;
    }

    assert(is_gpr(mem.base) || mem.base == RSP_OFFSET_INPUTS || mem.base == RSP_OFFSET_LOCALS || mem.base == RIP_OFFSET_DATA || mem.base == RIP_OFFSET_RDATA);
    assert(mem.base != REGISTER_NONE);
    assert(is_gpr(mem.index) || mem.index == REGISTER_NONE);

    if (rip_relative) {
        modrm |= MODRM_MOD_POINTER;
        offset_bytes = sizeof(i32);
    } else if (mem.immediate_offset > I8_MAX || mem.immediate_offset < I8_MIN || force_i32_offset) {
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

        assert(mem.base != RBP);
        sib |= REGISTER_INDICES[mem.base] & 0x07;
        if (REGISTER_INDICES[mem.base] & 0x08) {
            rex |= REX_B;
        }
    }

    if (eight_bit_reg_semantics && is_gpr_high(reg)) {
        // NB As per the comment in 'encode_instruction_modrm_reg_reg', we only ever use high registers (AH, CH, DH, BH)
        // in specific, hardcoded cases. None of these cases hit this path, and thus we don't have to implement it.
        // (The only place where high registers are needed are for 8-bit division/modulus)
        assert(false);
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

    data_fixup.rip_offset = buf_length(context->seg_text);
    stack_access_fixup.text_location = buf_length(context->seg_text);

    if (offset_bytes > 0) str_push_integer(&context->seg_text, offset_bytes, *((u32*) &mem.immediate_offset));
    if (imm_bytes > 0)    str_push_integer(&context->seg_text, imm_bytes, immediate);

    data_fixup.next_instruction = buf_length(context->seg_text);

    if (data_fixup.kind != -1)         buf_push(context->fixups, data_fixup);
    if (stack_access_fixup.kind != -1) buf_push(context->stack_access_fixups, stack_access_fixup);
}

// Yes, the signature of these functions is really long now, but that just reflects how insane x64 is.
void encode_instruction_modrm_reg_reg(
    Context *context,
    u8 rex, u32 opcode, bool eight_bit_reg_semantics,
    Register mem, Register reg,
    u64 immediate, u8 imm_bytes
) {
    u8 modrm = 0xc0;

    modrm |= (REGISTER_INDICES[reg] & 0x07) << 3;
    if (REGISTER_INDICES[reg] & 0x08) {
        rex |= REX_R;
    }

    modrm |= REGISTER_INDICES[mem] & 0x07;
    if (REGISTER_INDICES[mem] & 0x08) {
        rex |= REX_B;
    }

    bool force_rex = false;
    if (eight_bit_reg_semantics) {
        // NB Because we in practice only use the high registers in specific cases
        // we can avoid any of the assertions here actually triggering.
        // The only place where high registers currently are used is for
        // integer division.

        assert(!(rex & REX_W));

        bool any_high = (reg >=  AH && reg <=  BH) || (mem >=  AH && reg <=  BH);
        bool any_low  = (reg >= RSP && reg <= RDI) || (mem >= RSP && mem <= RDI);
        assert(!(any_high && any_low));

        if (any_low)  force_rex = true;
        if (any_high) assert(rex == REX_BASE);
    } else {
        assert(!is_gpr_high(reg));
        assert(!is_gpr_high(mem));
    }

    if (rex != REX_BASE || force_rex) {
        buf_push(context->seg_text, rex);
    }

    do {
        buf_push(context->seg_text, (u8) (opcode & 0xff));
        opcode >>= 8;
    } while(opcode != 0);

    buf_push(context->seg_text, modrm);

    if (imm_bytes > 0) {
        str_push_integer(&context->seg_text, imm_bytes, immediate);
    }
}

void encode_instruction_modrm(
    Context *context,
    u8 rex, u32 opcode, bool eight_bit_reg_semantics,
    X64_Place mem, Register reg
) {
    if (mem.kind == PLACE_ADDRESS) {
        encode_instruction_modrm_reg_mem(context, rex, opcode, eight_bit_reg_semantics, mem.address, reg, 0, 0);
    } else if (mem.kind == PLACE_REGISTER) {
        encode_instruction_modrm_reg_reg(context, rex, opcode, eight_bit_reg_semantics, mem.reg, reg, 0, 0);
    } else {
        assert(false);
    }
}

void encode_instruction_modrm_with_immediate(
    Context *context,
    u8 rex, u32 opcode, bool eight_bit_reg_semantics,
    X64_Place mem, Register reg,
    u64 immediate, u8 imm_bytes
) {
    if (mem.kind == PLACE_ADDRESS) {
        encode_instruction_modrm_reg_mem(context, rex, opcode, eight_bit_reg_semantics, mem.address, reg, immediate, imm_bytes);
    } else if (mem.kind == PLACE_REGISTER) {
        encode_instruction_modrm_reg_reg(context, rex, opcode, eight_bit_reg_semantics, mem.reg, reg, immediate, imm_bytes);
    } else {
        assert(false);
    }
}


void instruction_int3(Context *context) {
    buf_push(context->seg_text, 0xcc);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("int 3\n");
    #endif
}

void instruction_nop(Context *context) {
    buf_push(context->seg_text, 0x90);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("nop\n");
    #endif
}

void instruction_ret(Context *context) {
    buf_push(context->seg_text, 0xc3);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("ret\n");
    #endif
}

// Returns an index to a position where a jump offset should be written. The jump offset is a unsigned value of the size
// given in 'bytes'. This must be 1 or 4 (i.e. i8 or i32).
u64 instruction_jmp(Context *context, u8 bytes) {
    if (bytes == 4) {
        buf_push(context->seg_text, 0xe9);
        str_push_integer(&context->seg_text, 4, 0xdeadbeef);
    } else if (bytes == 1) {
        buf_push(context->seg_text, 0xeb);
        buf_push(context->seg_text, 0x00);
    } else {
        assert(false);
    }

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("jmp ??\n");
    #endif

    return buf_length(context->seg_text) - bytes;
}

// Jumps if RCX equals zero
// Returns an index to a position where a i8 jump offset should be written
u64 instruction_jrcxz(Context *context) {
    buf_push(context->seg_text, 0xe3);
    buf_push(context->seg_text, 0x00);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("jrcxz ??\n");
    #endif

    return buf_length(context->seg_text) - 1;
}

u64 instruction_jcc(Context *context, Condition condition, u8 op_size) {
    u8 opcode;
    switch (condition) {
        case COND_E:  opcode = 0x04; break;
        case COND_NE: opcode = 0x05; break;
        case COND_G:  opcode = 0x0f; break;
        case COND_GE: opcode = 0x0d; break;
        case COND_L:  opcode = 0x0c; break;
        case COND_LE: opcode = 0x0e; break;
        case COND_A:  opcode = 0x07; break;
        case COND_AE: opcode = 0x03; break;
        case COND_B:  opcode = 0x02; break;
        case COND_BE: opcode = 0x06; break;
        case COND_P:  opcode = 0x0a; break;
        case COND_NP: opcode = 0x0b; break;
        default: assert(false);
    }

    if (op_size == 4) {
        buf_push(context->seg_text, 0x0f);
        opcode |= 0x80;
    } else if (op_size == 1) {
        opcode |= 0x70;
    } else {
        assert(false);
    }

    buf_push(context->seg_text, opcode);
    str_push_integer(&context->seg_text, op_size, op_size == 4? 0xdeadbeef : 0);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("j%s ??\n", CONDITION_POSTFIXES[condition]);
    #endif

    return buf_length(context->seg_text) - op_size;
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
        case COND_P:  opcode = 0x9a0f; break;
        case COND_NP: opcode = 0x9b0f; break;
        default: assert(false);
    }

    if (place.kind == PLACE_REGISTER) assert(is_gpr(place.reg));
    encode_instruction_modrm(context, REX_BASE, opcode, true, place, REGISTER_OPCODE_0);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("set%s ", CONDITION_POSTFIXES[condition]);
    print_x64_place(place, 1);
    printf("\n");
    #endif
}

void instruction_cmp(Context *context, X64_Place left, Register right, u8 op_size) {
    assert(is_gpr(right));
    if (left.kind == PLACE_REGISTER) assert(is_gpr(left.reg));

    u8 opcode = 0x39;
    u8 rex = REX_BASE;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_modrm(context, rex, opcode, op_size == 1, left, right);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("cmp ");
    print_x64_place(left, op_size);
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

    encode_instruction_modrm_with_immediate(context, rex, opcode, op_size == 1, place, REGISTER_OPCODE_7, imm, imm_size);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
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

void instruction_call(Context *context, Fn *callee) {
    if (callee->kind == FN_KIND_IMPORTED) {
        buf_push(context->seg_text, 0xff);
        buf_push(context->seg_text, 0x15);
        str_push_integer(&context->seg_text, sizeof(i32), 0xdeadbeef);

        Rip_Fixup fixup = {0};
        fixup.rip_offset = buf_length(context->seg_text) - sizeof(i32);
        fixup.next_instruction = buf_length(context->seg_text);
        fixup.kind = RIP_FIXUP_IMPORT_CALL;
        fixup.import_index = callee->import_info.index;
        buf_push(context->fixups, fixup);
    } else {
        buf_push(context->seg_text, 0xe8);
        str_push_integer(&context->seg_text, sizeof(i32), 0xdeadbeef);

        Call_Fixup fixup = {0};
        fixup.text_location = buf_length(context->seg_text) - sizeof(i32);
        fixup.builtin = false;
        fixup.fn = callee;
        buf_push(context->call_fixups, fixup);
    }

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("call %s\n", callee->name);
    #endif
}

void instruction_call_builtin(Context *context, u32 index) {
    buf_push(context->seg_text, 0xe8);
    str_push_integer(&context->seg_text, sizeof(i32), 0xdeadbeef);

    Call_Fixup fixup = {0};
    fixup.text_location = buf_length(context->seg_text) - sizeof(i32);
    fixup.builtin = true;
    fixup.builtin_index = index;
    buf_push(context->call_fixups, fixup);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    u8 *name;
    switch (index) {
        case RUNTIME_BUILTIN_MEM_COPY:     name = "builtin_mem_copy"; break;
        case RUNTIME_BUILTIN_MEM_CLEAR:    name = "builtin_mem_clear"; break;
        default: assert(false);
    }
    printf("call %s\n", name);
    #endif
}

void instruction_call_indirect(Context *context, X64_Place place) {
    encode_instruction_modrm(context, REX_BASE, 0xff, false, place, REGISTER_OPCODE_2);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("call ");
    print_x64_place(place, POINTER_SIZE);
    printf("\n");
    #endif
}

void instruction_lea_call(Context *context, Fn *callee, Register reg) {
    assert(is_gpr(reg) && !is_gpr_high(reg));

    if (callee->kind == FN_KIND_IMPORTED) {
        // 'mov reg, [rip + ...]'               (address is in .rdata, which points to function elsewhere)

        u8 rex = REX_BASE | REX_W;
        u8 modrm = 0x05;

        modrm |= (REGISTER_INDICES[reg] & 0x07) << 3;
        if (REGISTER_INDICES[reg] & 8) {
            modrm |= REX_R;
        }

        buf_push(context->seg_text, rex);
        buf_push(context->seg_text, 0x8b);
        buf_push(context->seg_text, modrm);
        str_push_integer(&context->seg_text, sizeof(i32), 0xdeadbeef);

        Rip_Fixup fixup = {0};
        fixup.rip_offset = buf_length(context->seg_text) - sizeof(i32);
        fixup.next_instruction = buf_length(context->seg_text);
        fixup.kind = RIP_FIXUP_IMPORT_CALL;
        fixup.import_index = callee->import_info.index;
        buf_push(context->fixups, fixup);
    } else if (callee->kind == FN_KIND_NORMAL) {
        // 'lea reg, [rip + ...]'               (function is in .text)

        u8 rex = REX_BASE | REX_W;
        u8 modrm = 0x05;

        modrm |= (REGISTER_INDICES[reg] & 0x07) << 3;
        if (REGISTER_INDICES[reg] & 8) {
            modrm |= REX_R;
        }

        buf_push(context->seg_text, rex);
        buf_push(context->seg_text, 0x8d);
        buf_push(context->seg_text, modrm);
        str_push_integer(&context->seg_text, sizeof(i32), 0xdeadbeef);

        Call_Fixup fixup = {0};
        fixup.text_location = buf_length(context->seg_text) - sizeof(i32);
        fixup.builtin = false;
        fixup.fn = callee;
        buf_push(context->call_fixups, fixup);
    } else {
        assert(false);
    }

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov %s, &%s\n", register_name(reg, POINTER_SIZE), callee->name);
    #endif
}

void instruction_inc_or_dec(Context *context, bool inc, X64_Place place, u8 op_size) {
    if (place.kind == PLACE_REGISTER) assert(is_gpr(place.reg));

    u8 rex = REX_BASE;
    u8 opcode = 0xff;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_modrm(context, rex, opcode, op_size == 1, place, inc? REGISTER_OPCODE_0 : REGISTER_OPCODE_1);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("%s ", inc? "inc" : "dec");
    print_x64_place(place, op_size);
    printf("\n");
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

    encode_instruction_modrm(context, rex, opcode, op_size == 1, place, reg);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("%s ", unary? "not" : "neg");
    print_x64_place(place, op_size);
    printf("\n");
    #endif
}

void instruction_lea(Context *context, X64_Address mem, Register reg) {
    assert(is_gpr(reg));
    encode_instruction_modrm(context, REX_BASE | REX_W, 0x8d, false, x64_place_address(mem), reg);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("lea %s, ", register_name(reg, POINTER_SIZE));
    print_x64_address(mem);
    printf("\n");
    #endif
}

enum {
    INTEGER_ADD,
    INTEGER_AND,
    INTEGER_SUB,
    INTEGER_XOR,
    INTEGER_OR,

    INTEGER_INSTRUCTION_COUNT,
};

u8 *INTEGER_INSTRUCTION_NAMES[INTEGER_INSTRUCTION_COUNT] = {
    [INTEGER_ADD] = "add",
    [INTEGER_AND] = "and",
    [INTEGER_SUB] = "sub",
    [INTEGER_XOR] = "xor",
    [INTEGER_OR]  = "or",
};

void instruction_integer(Context *context, int instruction, Move_Mode mode, Register reg, X64_Place place, u8 op_size) {
    assert(is_gpr(reg));
    if (place.kind == PLACE_REGISTER) assert(is_gpr(place.reg));

    u8 opcode;
    switch (instruction) {
        case INTEGER_ADD: opcode = (mode == MOVE_FROM_MEM)? 0x03 : 0x01; break;
        case INTEGER_AND: opcode = (mode == MOVE_FROM_MEM)? 0x23 : 0x21; break;
        case INTEGER_OR:  opcode = (mode == MOVE_FROM_MEM)? 0x0b : 0x09; break;
        case INTEGER_SUB: opcode = (mode == MOVE_FROM_MEM)? 0x2b : 0x29; break;
        case INTEGER_XOR: opcode = (mode == MOVE_FROM_MEM)? 0x33 : 0x31; break;
        default: assert(false);
    }

    u8 rex = REX_BASE;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_modrm(context, rex, opcode, op_size == 1, place, reg);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("%s ", INTEGER_INSTRUCTION_NAMES[instruction]);
    if (mode == MOVE_FROM_MEM) {
        printf("%s, ", register_name(reg, op_size));
        print_x64_place(place, op_size);
        printf("\n");
    } else {
        print_x64_place(place, op_size);
        printf(", %s\n", register_name(reg, op_size));
    }
    #endif
}

void instruction_integer_imm(Context *context, int instruction, X64_Place place, u64 value, u8 op_size) {
    if (place.kind == PLACE_REGISTER) assert(is_gpr(place.reg));

    u8 rex = REX_BASE;
    u8 opcode = 0x81;
    u8 imm_size = op_size;
    Register opcode_extension;
    switch (instruction) {
        case INTEGER_ADD: opcode_extension = REGISTER_OPCODE_0; break;
        case INTEGER_OR:  opcode_extension = REGISTER_OPCODE_1; break;
        case INTEGER_AND: opcode_extension = REGISTER_OPCODE_4; break;
        case INTEGER_SUB: opcode_extension = REGISTER_OPCODE_5; break;
        case INTEGER_XOR: opcode_extension = REGISTER_OPCODE_6; break;
        default: assert(false);
    }

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: {
            rex |= REX_W;

            assert(value < I32_MAX);
            imm_size = 4; 
        } break;
        default: assert(false);
    }

    if (value < I8_MAX && op_size > 1) {
        opcode = 0x83;
        imm_size = 1;
    }

    encode_instruction_modrm_with_immediate(context, rex, opcode, op_size == 1, place, opcode_extension, value, imm_size);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("%s ", INTEGER_INSTRUCTION_NAMES[instruction]);
    print_x64_place(place, op_size);
    printf(", %u\n", value);
    #endif
}

enum {
    SHIFT_LEFT, // shifts in zeroes
    SHIFT_RIGHT, // shifts in zeroes
    SHIFT_RIGHT_ARITHMETIC, // shifts in the sign bit

    SHIFT_INSTRUCTION_COUNT,
};

u8 *SHIFT_INSTRUCTION_NAMES[SHIFT_INSTRUCTION_COUNT] = {
    [SHIFT_LEFT]             = "shl",
    [SHIFT_RIGHT]            = "shr",
    [SHIFT_RIGHT_ARITHMETIC] = "sar",
};

// Shifts the given place by the count in RCX. Only the bottom 6 bits of RCX are used!
void instruction_shift(Context *context, int instruction, X64_Place place, u8 op_size) {
    if (place.kind == PLACE_REGISTER) assert(is_gpr(place.reg));

    Register opcode_extension = REGISTER_OPCODE_0;
    switch (instruction) {
        case SHIFT_LEFT:             opcode_extension += 4; break;
        case SHIFT_RIGHT:            opcode_extension += 5; break;
        case SHIFT_RIGHT_ARITHMETIC: opcode_extension += 7; break;
        default: assert(false);
    }

    u8 opcode = 0xd3;
    u8 rex = REX_BASE;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_modrm(context, rex, opcode, op_size == 1, place, opcode_extension);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("%s ", SHIFT_INSTRUCTION_NAMES[instruction]);
    print_x64_place(place, op_size);
    printf(", cl\n");
    #endif
}

void instruction_mul_pointer_imm(Context *context, Register reg, i64 mul_by) {
    assert(is_gpr(reg));

    if (mul_by == 0) {
        assert(false); // We should never try to do this...
    } else if (mul_by == 1) {
        // Do nothing
    } else if ((mul_by & (mul_by - 1)) == 0) {
        // Optimize by using a shift
        assert(mul_by > 0);

        u8 shift_by = 0;
        u64 v = mul_by;
        while ((v >>= 1) != 0) shift_by += 1;

        encode_instruction_modrm_with_immediate(context, REX_BASE | REX_W, 0xc1, false, x64_place_reg(reg), REGISTER_OPCODE_4, shift_by, sizeof(u8));

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("shl %s, %u\n", register_name(reg, POINTER_SIZE), (u64) shift_by);
        #endif
    } else {
        // We use imul here, but it is fine because mul and imul give the same result except for beyond the 64th bit

        u64 mul_by_bits = *((u64*) &mul_by);

        if (mul_by <= I8_MAX && mul_by >= I8_MIN) {
            encode_instruction_modrm_with_immediate(context, REX_BASE | REX_W, 0x6b, false, x64_place_reg(reg), reg, mul_by_bits, sizeof(i8));
        } else if (mul_by <= I32_MAX && mul_by >= I32_MIN) {
            encode_instruction_modrm_with_immediate(context, REX_BASE | REX_W, 0x69, false, x64_place_reg(reg), reg, mul_by_bits, sizeof(i32));
        } else {
            assert(false); // NB the immediate operand to the imul instruction can at most be a i32
        }

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        u8 *reg_name = register_name(reg, POINTER_SIZE);
        printf("imul %s, %s, %i\n", reg_name, reg_name, mul_by);
        #endif
    }
}

void instruction_idiv_pointer_imm(Context *context, Register reg, i64 div_by) {
    assert(is_gpr(reg));

    if (div_by == 0) {
        panic("Atempted to generate idiv by 0\n");
    } else if (div_by == 1) {
        // Do nothing
    } else if ((div_by & (div_by - 1)) == 0) {
        // Optimize by using a shift
        assert(div_by > 0);

        u8 shift_by = 0;
        u64 v = div_by;
        while ((v >>= 1) != 0) shift_by += 1;

        encode_instruction_modrm_with_immediate(context, REX_BASE | REX_W, 0xc1, false, x64_place_reg(reg), REGISTER_OPCODE_7, shift_by, sizeof(u8));

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("sar %s, %u\n", register_name(reg, POINTER_SIZE), (u64) shift_by);
        #endif
    } else {
        unimplemented(); // TODO actually call idiv
        // We probably don't want to actually call idiv, because that is slow. Instead, we should do the same
        // trick as other compilers do (use godbolt to see it) involving a SAR and a IMUL
    }
}


enum {
    SCALING_MUL,
    SCALING_IMUL,
    SCALING_DIV,
    SCALING_IDIV,
};

void instruction_scaling(Context *context, int instruction, X64_Place rhs, u8 op_size) {
    if (rhs.kind == PLACE_REGISTER) assert(is_gpr(rhs.reg));

    u8 opcode_extension = REGISTER_OPCODE_4;
    switch (instruction) {
        case SCALING_MUL:  opcode_extension = REGISTER_OPCODE_4; break;
        case SCALING_IMUL: opcode_extension = REGISTER_OPCODE_5; break;
        case SCALING_DIV:  opcode_extension = REGISTER_OPCODE_6; break;
        case SCALING_IDIV: opcode_extension = REGISTER_OPCODE_7; break;
        default: assert(false);
    }

    u8 opcode = 0xf7;
    u8 rex = REX_BASE;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_modrm(context, rex, opcode, op_size == 1, rhs, opcode_extension);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    switch (instruction) {
        case SCALING_MUL:  printf("mul "); break;
        case SCALING_IMUL: printf("imul "); break;
        case SCALING_DIV:  printf("div "); break;
        case SCALING_IDIV: printf("idiv "); break;
        default: assert(false);
    }
    if (rhs.kind == PLACE_REGISTER) {
        printf("%s\n", register_name(rhs.reg, op_size));
    } else {
        print_x64_address(rhs.address);
        printf("\n");
    }
    #endif
}

void instruction_sign_extend_for_division(Context *context, u8 op_size) {
    switch (op_size) {
        case 1: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: buf_push(context->seg_text, REX_BASE | REX_W); break;
        default: assert(false);
    }
    buf_push(context->seg_text, op_size == 1? 0x98 : 0x99);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    switch (op_size) {
        case 1: printf("cbw\n"); break;
        case 2: printf("cwd\n"); break;
        case 4: printf("cdq\n"); break;
        case 8: printf("cqo\n"); break;
        default: assert(false);
    }
    #endif
}

void instruction_mov_reg_mem(Context *context, Move_Mode mode, X64_Address mem, Register reg, u8 op_size) {
    assert(is_gpr(reg));

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

    encode_instruction_modrm(context, rex, opcode, op_size == 1, x64_place_address(mem), reg);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
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
    assert(is_gpr(src) && is_gpr(dst));

    u8 opcode = 0x89;
    u8 rex = REX_BASE;

    switch (op_size) {
        case 1: opcode -= 1; break;
        case 2: buf_push(context->seg_text, WORD_OPERAND_PREFIX); break;
        case 4: break;
        case 8: rex |= REX_W; break;
        default: assert(false);
    }

    encode_instruction_modrm(context, rex, opcode, op_size == 1, x64_place_reg(dst), src);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov %s, %s\n", register_name(dst, op_size), register_name(src, op_size));
    #endif
}

void instruction_movzx(Context *context, X64_Place src, Register dst, u8 src_size, u8 dst_size) {
    assert(is_gpr(dst));

    u32 opcode;
    u8 rex = REX_BASE;

    if (src_size == 1 && dst_size == 2) {
        opcode = 0xb60f;
        buf_push(context->seg_text, WORD_OPERAND_PREFIX);
    } else if (src_size == 1 && dst_size == 4) {
        opcode = 0xb60f;
    } else if (src_size == 1 && dst_size == 8) {
        opcode = 0xb60f;
        rex |= REX_W;
    } else if (src_size == 2 && dst_size == 4) {
        opcode = 0xb70f;
    } else if (src_size == 2 && dst_size == 8) {
        opcode = 0xb70f;
        rex |= REX_W;
    } else {
        assert(false);
    }

    encode_instruction_modrm(context, rex, opcode, false, src, dst);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("movzx %s, ", register_name(dst, dst_size));
    print_x64_place(src, src_size);
    printf("\n");
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

    encode_instruction_modrm_with_immediate(context, rex, opcode, op_size == 1, x64_place_address(mem), REGISTER_OPCODE_0, immediate, imm_size);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov ");
    print_x64_place(x64_place_address(mem), op_size);
    printf(", %x\n", immediate);
    #endif
}

void instruction_mov_imm_reg(Context *context, Register reg, u64 immediate, u8 op_size) {
    assert(is_gpr(reg));

    if (immediate == 0) {
        instruction_integer(context, INTEGER_XOR, MOVE_FROM_MEM, reg, x64_place_reg(reg), op_size);
        return;
    }

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
        rex |= REX_B;
    }
    if (rex != REX_BASE || (op_size == 1 && reg >= RSP && reg <= RDI)) {
        buf_push(context->seg_text, rex);
    }
    buf_push(context->seg_text, opcode);
    str_push_integer(&context->seg_text, op_size, immediate);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov %s, %x\n", register_name(reg, op_size), (u64) immediate);
    #endif
}

enum {
    FLOAT_ADD,
    FLOAT_SUB,
    FLOAT_MUL,
    FLOAT_DIV,
    FLOAT_SQRT,
    FLOAT_MOV,
    FLOAT_MOV_REVERSE,
    
    FLOAT_COMI, // Compares and sets flags, similar to cmp. NB different from CMPSS, which doesn't set flags
    FLOAT_UCOMI, // Same as COMI, but doesn't raise exceptions for QNaNs.
    // NB gcc and msvc use UCOMI for equality comparasions (== !=), but not for ordered comparasions (> < >= <=),
    // meaning equality comparasions will process QNaNs (but return false), while ordered comparasions will fail
    // on any NaNs.

    FLOAT_CMPEQ,
    FLOAT_CMPNEQ,

    // NB There is no scalar version of XOR (because XOR is for integers, and non-packed integer math is not in sse)
    // As a result, there is also no single/double-precision version of this instruction.
    // TODO this XOR instruction should be generated with a separate function from the addss-style instructions!
    FLOAT_XOR_PACKED,

    FLOAT_INSTRUCTION_COUNT,
};

u32 FLOAT_SINGLE_OPCODES[FLOAT_INSTRUCTION_COUNT] = {
    [FLOAT_ADD] = 0x580ff3,
    [FLOAT_SUB] = 0x5c0ff3,
    [FLOAT_MUL] = 0x590ff3,
    [FLOAT_DIV] = 0x5e0ff3,
    [FLOAT_SQRT] = 0x510ff3,
    [FLOAT_MOV] = 0x100ff3,
    [FLOAT_MOV_REVERSE] = 0x110ff3,
    [FLOAT_COMI] = 0x2f0f,
    [FLOAT_UCOMI] = 0x2e0f,
    [FLOAT_CMPEQ] = 0xc20ff3,
    [FLOAT_CMPNEQ] = 0xc20ff3,
    [FLOAT_XOR_PACKED] = 0xef0f66,
};
u32 FLOAT_DOUBLE_OPCODES[FLOAT_INSTRUCTION_COUNT] = {
    [FLOAT_ADD] = 0x580ff2,
    [FLOAT_SUB] = 0x5c0ff2,
    [FLOAT_MUL] = 0x590ff2,
    [FLOAT_DIV] = 0x5e0ff2,
    [FLOAT_SQRT] = 0x510ff3,
    [FLOAT_MOV] = 0x100ff2,
    [FLOAT_MOV_REVERSE] = 0x110ff2,
    [FLOAT_COMI] = 0x2f0f66,
    [FLOAT_UCOMI] = 0x2e0f66,
    [FLOAT_CMPEQ] = 0xc20ff2,
    [FLOAT_CMPNEQ] = 0xc20ff2,
    [FLOAT_XOR_PACKED] = 0xef0f66,
};
u8 *FLOAT_SINGLE_NAMES[FLOAT_INSTRUCTION_COUNT] = {
    [FLOAT_ADD] = "addss",
    [FLOAT_SUB] = "subss",
    [FLOAT_MUL] = "mulss",
    [FLOAT_DIV] = "divss",
    [FLOAT_SQRT] = "sqrtss",
    [FLOAT_MOV] = "movss",
    [FLOAT_MOV_REVERSE] = "movss",
    [FLOAT_COMI] = "comiss",
    [FLOAT_UCOMI] = "ucomiss",
    [FLOAT_CMPEQ] = "cmpeqss",
    [FLOAT_CMPNEQ] = "cmpneqss",
    [FLOAT_XOR_PACKED] = "pxor",
};
u8 *FLOAT_DOUBLE_NAMES[FLOAT_INSTRUCTION_COUNT] = {
    [FLOAT_ADD] = "addsd",
    [FLOAT_SUB] = "subsd",
    [FLOAT_MUL] = "mulsd",
    [FLOAT_DIV] = "divsd",
    [FLOAT_DIV] = "sqrtsd",
    [FLOAT_MOV] = "movsd",
    [FLOAT_MOV_REVERSE] = "movsd",
    [FLOAT_COMI] = "comisd",
    [FLOAT_UCOMI] = "ucomisd",
    [FLOAT_CMPEQ] = "cmpeqsd",
    [FLOAT_CMPNEQ] = "cmpneqsd",
    [FLOAT_XOR_PACKED] = "pxor",
};
u8 FLOAT_REQUIRED_IMMEDIATE[FLOAT_INSTRUCTION_COUNT] = {
    [FLOAT_CMPEQ] = 0x08,
    [FLOAT_CMPNEQ] = 0x0c,
};

void instruction_float(Context *context, int instruction, Register dst, X64_Place src, bool single) {
    assert(is_xmm(dst));
    if (src.kind == PLACE_REGISTER) assert(is_xmm(src.reg));

    u32 opcode = single? FLOAT_SINGLE_OPCODES[instruction] : FLOAT_DOUBLE_OPCODES[instruction];

    // Ensure that the prefix is properly placed before the modrm byte
    // This is a bit of a hack
    if ((opcode & 0xff) == 0xf2 || (opcode & 0xff) == 0xf3 || (opcode & 0xff) == 0x66) {
        buf_push(context->seg_text, opcode & 0xff);
        opcode >>= 8;
    }


    u8 required_immediate = FLOAT_REQUIRED_IMMEDIATE[instruction];
    if (required_immediate != 0) {
        encode_instruction_modrm_with_immediate(context, REX_BASE, opcode, false, src, dst, required_immediate, sizeof(u8));
    } else {
        encode_instruction_modrm(context, REX_BASE, opcode, false, src, dst);
    }

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    u8 *name = single? FLOAT_SINGLE_NAMES[instruction] : FLOAT_DOUBLE_NAMES[instruction];
    u8 op_size = single? 4 : 8;
    printf("%s ", name);
    if (instruction == FLOAT_MOV_REVERSE) {
        print_x64_place(src, op_size);
        printf(", %s\n", register_name(dst, op_size));
    } else {
        printf("%s, ", register_name(dst, op_size));
        print_x64_place(src, op_size);
        printf("\n");
    }
    #endif
}

// Moves between xmm registers and gpr registers or memory
void instruction_float_movd(Context *context, Move_Mode mode, Register xmm, X64_Place gpr, bool single) {
    assert(is_xmm(xmm));
    if (gpr.kind == PLACE_REGISTER) assert(is_gpr(gpr.reg));

    buf_push(context->seg_text, WORD_OPERAND_PREFIX);

    u32 opcode = mode == MOVE_FROM_MEM? 0x6e0f : 0x7e0f;
    u8 rex = single? (REX_BASE) : (REX_BASE | REX_W);
    encode_instruction_modrm(context, rex, opcode, false, gpr, xmm);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    u8 op_size = single? 4 : 8;
    if (mode == MOVE_FROM_MEM) {
        printf("movd %s, ", register_name(xmm, op_size));
        print_x64_place(gpr, op_size);
        printf("\n");
    } else {
        printf("movd ");
        print_x64_place(gpr, op_size);
        printf(", %s\n", register_name(xmm, op_size));
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

    bool touched_registers[ALLOCATABLE_REGISTER_COUNT];

    struct {
        u64 size;
        X64_Address address;
    } *var_mem_infos;
    u64 allocated_var_mem_infos;

    X64_Address return_value_address; // only used when we return with reference semantics

    i32 max_stack_size;
    u32 max_callee_param_count;

    u64 negate_f32_data_offset, negate_f64_data_offset; // Used for negating floating point numbers
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

            if (is_gpr(reg)) {
                instruction_mov_reg_mem(context, MOVE_FROM_MEM, tmp_address, reg, POINTER_SIZE);
            } else if (is_xmm(reg)) {
                instruction_float_movd(context, MOVE_FROM_MEM, reg, x64_place_address(tmp_address), false);
            } else {
                assert(false);
            }
        }
    }

    assert(allocator->head->previous != null);
    allocator->head = allocator->head->previous;
}

X64_Address register_allocator_temp_stack_space(Reg_Allocator *allocator, u64 size, u64 align) {
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


#define RESERVE_RAX  0x01
#define RESERVE_RCX  0x02
#define RESERVE_RDX  0x04
#define RESERVE_XMM0 0x08

bool reserves_register(u32 flags, Register reg) {
    switch (reg) {
        case RAX:  return flags & RESERVE_RAX;
        case RCX:  return flags & RESERVE_RCX;
        case RDX:  return flags & RESERVE_RDX;
        case XMM0: return flags & RESERVE_XMM0;
        default:   return false;
    }
}


// Allocate a register, but don't mark it as allocated so we don' need to push/pop a frame.
// Should only be used in leaf code.
Register register_allocate_temp(Reg_Allocator *allocator, Register_Kind kind, u32 reserves) {
    Register start, end;
    switch (kind) {
        case REGISTER_KIND_GPR: { start = RAX;  end = R15;   } break;
        case REGISTER_KIND_XMM: { start = XMM0; end = XMM15; } break;
    }

    for (Register reg = start; reg < end; reg += 1) {
        if (
            reg == RSP ||
            reg == RBP ||
            reserves_register(reserves, reg)
        ) {
            continue;
        }

        if (!allocator->head->states[reg].allocated) {
            allocator->touched_registers[reg] = true;
            return reg;
        }
    }

    // TODO flush another register and allocate that
    panic("Out of registers\n");
    return REGISTER_NONE;
}

Register register_allocate(Reg_Allocator *allocator, Register_Kind kind, u32 reserves) {
    Register reg = register_allocate_temp(allocator, kind, reserves);
    allocator->head->states[reg].allocated = true;
    return reg;
}

void register_allocate_specific(Context *context, Reg_Allocator *allocator, Register reg) {
    if (allocator->head->states[reg].allocated) {
        assert(!allocator->head->states[reg].flushed);

        X64_Address tmp_address = register_allocator_temp_stack_space(allocator, POINTER_SIZE, POINTER_SIZE);
        if (is_gpr(reg)) {
            instruction_mov_reg_mem(context, MOVE_TO_MEM, tmp_address, reg, POINTER_SIZE);
        } else if (is_xmm(reg)) {
            instruction_float_movd(context, MOVE_TO_MEM, reg, x64_place_address(tmp_address), false);
        } else {
            assert(false);
        }

        allocator->head->states[reg].flushed = true;
        allocator->head->states[reg].flushed_to = tmp_address;
    }

    allocator->head->states[reg].allocated = true;

    allocator->touched_registers[reg] = true;
}

bool register_is_allocated(Reg_Allocator *allocator, Register reg) {
    return allocator->head->states[reg].allocated;
}


void machinecode_move(Context *context, Reg_Allocator *reg_allocator, X64_Place src, X64_Place dst, u64 size) {
    assert(src.kind != PLACE_NOWHERE && dst.kind != PLACE_NOWHERE);

    if (src.kind == dst.kind) {
        if (src.kind == PLACE_REGISTER && src.reg == dst.reg) return;
        if (src.kind == PLACE_ADDRESS && x64_address_cmp(src.address, dst.address)) return;
    }

    if (size == 0) {
        return;
    } else if (size == 1 || size == 2 || size == 4 || size == 8) {
        if (src.kind == PLACE_ADDRESS && dst.kind == PLACE_ADDRESS) {
            register_allocator_enter_frame(context, reg_allocator);

            Register reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, 0);
            instruction_mov_reg_mem(context, MOVE_FROM_MEM, src.address, reg, (u8) size);
            instruction_mov_reg_mem(context, MOVE_TO_MEM, dst.address, reg, (u8) size);

            register_allocator_leave_frame(context, reg_allocator);
        } else if (src.kind == PLACE_REGISTER && dst.kind == PLACE_ADDRESS) {
            if (is_gpr(src.reg)) {
                instruction_mov_reg_mem(context, MOVE_TO_MEM, dst.address, src.reg, (u8) size);
            } else {
                assert(size == 4 || size == 8);
                instruction_float(context, FLOAT_MOV_REVERSE, src.reg, dst, size == 4);
            }
        } else if (src.kind == PLACE_ADDRESS && dst.kind == PLACE_REGISTER) {
            if (is_gpr(dst.reg)) {
                instruction_mov_reg_mem(context, MOVE_FROM_MEM, src.address, dst.reg, (u8) size);
            } else {
                assert(size == 4 || size == 8);
                instruction_float(context, FLOAT_MOV, dst.reg, src, size == 4);
            }
        } else if (src.kind == PLACE_REGISTER && dst.kind == PLACE_REGISTER) {
            if (is_gpr(src.reg) && is_gpr(dst.reg)) {
                instruction_mov_reg_reg(context, src.reg, dst.reg, (u8) size);
            } else if (is_gpr(src.reg) && is_xmm(dst.reg)) {
                instruction_float_movd(context, MOVE_FROM_MEM, dst.reg, src, size == 4);
            } else if (is_xmm(src.reg) && is_gpr(dst.reg)) {
                instruction_float_movd(context, MOVE_TO_MEM, src.reg, dst, size == 4);
            } else if (is_xmm(src.reg) && is_xmm(dst.reg)) {
                instruction_float(context, FLOAT_MOV, dst.reg, src, size == 4);
            }
        } else {
            assert(false);
        }
    } else if (size <= 32) { // TODO Try tweaking this once we have a really big program, to see how it affects perf and instruction count
        assert(src.kind == PLACE_ADDRESS && dst.kind == PLACE_ADDRESS);

        register_allocator_enter_frame(context, reg_allocator);
        Register reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, 0);

        u64 bytes = size;
        while (bytes > 0) {
            u8 op_size;
            if (bytes >= 1) op_size = 1;
            if (bytes >= 2) op_size = 2;
            if (bytes >= 4) op_size = 4;
            if (bytes >= 8) op_size = 8;
            bytes -= op_size;

            instruction_mov_reg_mem(context, MOVE_FROM_MEM, src.address, reg, op_size);
            instruction_mov_reg_mem(context, MOVE_TO_MEM,   dst.address, reg, op_size);

            src.address.immediate_offset += op_size;
            dst.address.immediate_offset += op_size;
        }

        register_allocator_leave_frame(context, reg_allocator);
    } else {
        assert(src.kind == PLACE_ADDRESS && dst.kind == PLACE_ADDRESS);

        register_allocator_enter_frame(context, reg_allocator);

        if (!(x64_address_uses_reg(src.address, RAX) || x64_address_uses_reg(dst.address, RAX))) {
            register_allocate_specific(context, reg_allocator, RAX);
        }
        if (!(x64_address_uses_reg(src.address, RDX) || x64_address_uses_reg(dst.address, RDX))) {
            register_allocate_specific(context, reg_allocator, RDX);
        }
        if (!(x64_address_uses_reg(src.address, RCX) || x64_address_uses_reg(dst.address, RCX))) {
            register_allocate_specific(context, reg_allocator, RCX);
        }
        if (!(x64_address_uses_reg(src.address, RBX) || x64_address_uses_reg(dst.address, RBX))) {
            register_allocate_specific(context, reg_allocator, RBX);
        }

        if (x64_address_uses_reg(src.address, RDX) && x64_address_uses_reg(dst.address, RAX)) {
            unimplemented();
            // TODO this would essentially require us to swap rax and rax, but that is complicated by the fact that
            // the registers can be used as either the base or the index
            // NB NB Just use the XCHG instruction
        } else if (x64_address_uses_reg(dst.address, RAX)) {
            instruction_lea(context, dst.address, RDX);
            instruction_lea(context, src.address, RAX);
        } else {
            instruction_lea(context, src.address, RAX);
            instruction_lea(context, dst.address, RDX);
        }

        instruction_mov_imm_reg(context, RCX, size, POINTER_SIZE);

        instruction_call_builtin(context, RUNTIME_BUILTIN_MEM_COPY);
        register_allocator_leave_frame(context, reg_allocator);
    }
}

void machinecode_immediate_to_place(Context *context, Reg_Allocator *reg_allocator, X64_Place place, u64 immediate, u8 bytes) {
    switch (place.kind) {
        case PLACE_REGISTER: {
            if (is_gpr(place.reg)) {
                instruction_mov_imm_reg(context, place.reg, immediate, bytes);
            } else if (is_xmm(place.reg)) {
                Register temp_reg = register_allocate_temp(reg_allocator, REGISTER_KIND_GPR, 0);
                instruction_mov_imm_reg(context, temp_reg, immediate, bytes);
                machinecode_move(context, reg_allocator, x64_place_reg(temp_reg), place, bytes);
            } else {
                assert(false);
            }
        } break;

        case PLACE_ADDRESS: {
            instruction_mov_imm_mem(context, place.address, immediate, bytes);
        } break;

        case PLACE_NOWHERE: assert(false);
        default: assert(false);
    }
}

void machinecode_cast(Context *context, Register src, Register dst, Type_Kind from, Type_Kind to) {
    u8 from_size = primitive_size_of(from);
    u8 to_size = primitive_size_of(to);

    if ((from == TYPE_POINTER || from == TYPE_FN_POINTER) && (to == TYPE_POINTER || to == TYPE_FN_POINTER)) {
        // This is a no-op
    } else if (primitive_is_float(from) && primitive_is_float(to)) {
        assert(is_xmm(src) && is_xmm(dst));

        u32 opcode = 0;
        if (from == to) {
        } else if (from == TYPE_F32 && to == TYPE_F64) {
            opcode = 0x5a0ff3;
        } else if (from == TYPE_F64 && to == TYPE_F32) {
            opcode = 0x5a0ff2;
        } else {
            assert(false);
        }

        if (opcode != 0) {
            encode_instruction_modrm(context, REX_BASE, opcode, false, x64_place_reg(src), dst);

            #ifdef PRINT_GENERATED_INSTRUCTIONS
            printf("%s %s, %s\n", from == TYPE_F32? "cvtss2sd" : "cvtsd2ss", register_name(dst, to_size), register_name(src, from_size));
            #endif
        }
    } else if (primitive_is_float(from) && primitive_is_integer(to)) {
        assert(is_xmm(src));
        assert(is_gpr(dst));

        if (from == TYPE_F32) {
            buf_push(context->seg_text, 0xf3);
        } else if (from == TYPE_F64) {
            buf_push(context->seg_text, 0xf2);
        } else {
            assert(false);
        }

        u8 rex = REX_BASE;
        if (to_size == 8) rex |= REX_W;
        encode_instruction_modrm(context, rex, 0x2c0f, false, x64_place_reg(src), dst);

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("%s %s, %s\n", from == TYPE_F32? "cvttsi2ss" : "cvttsi2sd", register_name(dst, to_size), register_name(src, from_size));
        #endif

        // Although we just produce either a i32 or a i64, we don't actually have to do any casting
        // because of how twos-complement works. Downcasting of integers always just removes high bits.
    } else if (primitive_is_integer(from) && primitive_is_float(to)) {
        assert(is_gpr(src));
        assert(is_xmm(dst));

        // There only are instructions to cast from i32/i64 to floats, so we havve to
        // cast up smaller types first.
        if (from_size < 4) {
            Type_Kind extended = primitive_is_signed(from)? TYPE_I32 : TYPE_U32;
            machinecode_cast(context, src, src, from, extended);
            from_size = 4;
            from = extended;
        }

        if (to == TYPE_F32) {
            buf_push(context->seg_text, 0xf3);
        } else if (to == TYPE_F64) {
            buf_push(context->seg_text, 0xf2);
        } else {
            assert(false);
        }

        u8 rex = REX_BASE;
        if (from_size == 8) rex |= REX_W;
        encode_instruction_modrm(context, rex, 0x2a0f, false, x64_place_reg(src), dst);

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("%s %s, %s\n", to == TYPE_F32? "cvtsi2ss" : "cvtsi2sd", register_name(dst, to_size), register_name(src, from_size));
        #endif
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

            assert(!is_gpr_high(src));
            assert(!is_gpr_high(dst));
            encode_instruction_modrm(context, rex_w? (REX_BASE | REX_W) : REX_BASE, opcode, false, x64_place_reg(src), dst);

            #ifdef PRINT_GENERATED_INSTRUCTIONS
            printf("%s %s, %s\n", sign_extend? "movsx" : "movzx", register_name(dst, to_size), register_name(src, from_size));
            #endif
        }
    }
}

void machinecode_lea(Context *context, Reg_Allocator *reg_allocator, X64_Address address, X64_Place place) {
    if (place.kind == PLACE_REGISTER) {
        instruction_lea(context, address, place.reg);
    } else {
        register_allocator_enter_frame(context, reg_allocator);
        Register reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, 0);
        instruction_lea(context, address, reg);
        machinecode_move(context, reg_allocator, x64_place_reg(reg), place, POINTER_SIZE);
        register_allocator_leave_frame(context, reg_allocator);
    }
}

void machinecode_zero_out_struct(Context *context, Reg_Allocator *reg_allocator, X64_Address address, u64 size, u64 align) {
    if (!(size == 1 || size == 2 || size == 4 || size == 8)) {
        register_allocator_enter_frame(context, reg_allocator);

        register_allocate_specific(context, reg_allocator, RAX);
        register_allocate_specific(context, reg_allocator, RCX);

        instruction_lea(context, address, RAX);
        instruction_mov_imm_reg(context, RCX, size, POINTER_SIZE);
        instruction_call_builtin(context, RUNTIME_BUILTIN_MEM_CLEAR);

        register_allocator_leave_frame(context, reg_allocator);
    } else {
        machinecode_immediate_to_place(context, reg_allocator, x64_place_address(address), 0, (u8) size);
    }
}


u32 machinecode_expr_reserves(Expr *expr) {
    u32 flags = 0;

    switch (expr->kind) {
        case EXPR_VARIABLE:
        case EXPR_LITERAL:
        case EXPR_STRING_LITERAL:
        case EXPR_STATIC_MEMBER_ACCESS:
        case EXPR_TYPE_INFO_OF_TYPE:
        case EXPR_TYPE_INFO_OF_VALUE:
        case EXPR_QUERY_TYPE_INFO:
        case EXPR_ADDRESS_OF_FUNCTION:
        {} break;

        case EXPR_COMPOUND: {
            for (u32 i = 0; i < expr->compound.count; i += 1) {
                flags |= machinecode_expr_reserves(expr->compound.content[i].expr);
            }
        } break;

        case EXPR_TERNARY: {
            flags |= machinecode_expr_reserves(expr->ternary.condition);
            flags |= machinecode_expr_reserves(expr->ternary.left);
            flags |= machinecode_expr_reserves(expr->ternary.right);
        } break;

        case EXPR_BINARY: {
            if (expr->binary.op == BINARY_MUL || expr->binary.op == BINARY_DIV || expr->binary.op == BINARY_MOD) {
                if (primitive_is_integer(primitive_of(expr->type))) {
                    flags |= RESERVE_RAX;
                }
            }

            if (expr->binary.op == BINARY_SHL || expr->binary.op == BINARY_SHR) {
                flags |= RESERVE_RCX;
            }

            flags |= machinecode_expr_reserves(expr->binary.left);
            flags |= machinecode_expr_reserves(expr->binary.right);
        } break;

        case EXPR_CALL: {
            if (primitive_is_float(expr->type->kind)) {
                flags |= RESERVE_XMM0;
            } else {
                flags |= RESERVE_RAX;
            }

            if (expr->call.pointer_call) {
                flags |= machinecode_expr_reserves(expr->call.pointer_expr);
            }

            for (u32 i = 0; i < expr->call.param_count; i += 1) {
                flags |= machinecode_expr_reserves(expr->call.params[i]);
            }
        } break;

        case EXPR_UNARY: {
            flags |= machinecode_expr_reserves(expr->unary.inner);
        } break;
        case EXPR_CAST: {
            flags |= machinecode_expr_reserves(expr->cast_from);
        } break;
        case EXPR_SUBSCRIPT: {
            flags |= machinecode_expr_reserves(expr->subscript.array);
            flags |= machinecode_expr_reserves(expr->subscript.index);
        } break;
        case EXPR_MEMBER_ACCESS: {
            flags |= machinecode_expr_reserves(expr->member_access.parent);
        } break;
        case EXPR_ENUM_MEMBER_NAME: {
            flags |= machinecode_expr_reserves(expr->enum_member);
        } break;

        default: assert(false);
    }

    return flags;
}

void machinecode_for_expr(Context *context, Fn *fn, Expr *expr, Reg_Allocator *reg_allocator, X64_Place place);

X64_Address machinecode_address_for_var(Context *context, Reg_Allocator *reg_allocator, Var *var) {
    if (var->flags & VAR_FLAG_GLOBAL) {
        Global_Var *global = &context->global_vars[var->global_index];
        u32 data_offset = global->data_offset;
        Register base = global->in_rdata? RIP_OFFSET_RDATA : RIP_OFFSET_DATA;
        return (X64_Address) { .base = base, .immediate_offset = data_offset };
    } else {
        return reg_allocator->var_mem_infos[var->local_index].address;
    }
}

X64_Address machinecode_index_address(Context *context, Fn *fn, Reg_Allocator *reg_allocator, X64_Address address, Expr *index, u64 stride) {
    if (index->kind == EXPR_LITERAL) {
        u64 offset = index->literal.masked_value * stride;
        assert(((i64) address.immediate_offset) + offset <= I32_MAX);
        address.immediate_offset += offset;
    } else {
        if (address.base == RIP_OFFSET_DATA || address.base == RIP_OFFSET_RDATA) {
            u32 reserves = machinecode_expr_reserves(index);
            Register new_base = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserves);
            instruction_lea(context, address, new_base);
            address = (X64_Address) { .base = new_base };
        }

        Register index_reg = REGISTER_NONE;

        if (address.index != REGISTER_NONE) {
            Register new_base;
            if (is_gpr(address.base) && address.base != RSP && address.base != RBP) {
                new_base = address.base;
                index_reg = address.index;
            } else {
                new_base = address.index;
            }

            instruction_lea(context, address, new_base);
            address = (X64_Address) { .base = new_base };
        }
        
        if (index_reg == REGISTER_NONE) {
            u32 reserves = machinecode_expr_reserves(index);
            index_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserves);
        }
        assert(address.index == REGISTER_NONE && address.scale == 0);

        machinecode_for_expr(context, fn, index, reg_allocator, x64_place_reg(index_reg));
        machinecode_cast(context, index_reg, index_reg, primitive_of(index->type), TYPE_DEFAULT_INT);
        address.index = index_reg;

        if (stride == 1 || stride == 2 || stride == 4 || stride == 8) {
            address.scale = (u8) stride;
        } else {
            address.scale = 1;
            instruction_mul_pointer_imm(context, address.index, stride);
        }
    }

    return address;
}

X64_Place machinecode_for_addressable_expr(Context *context, Fn *fn, Expr *expr, Reg_Allocator *reg_allocator, u32 reserves) {
    assert(expr->flags & EXPR_FLAG_ADDRESSABLE);

    switch (expr->kind) {
        case EXPR_VARIABLE: {
            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));
            Var *var = expr->variable.var;

            X64_Address address = machinecode_address_for_var(context, reg_allocator, var);

            if (var->flags & VAR_FLAG_REFERENCE) {
                Register reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserves);
                instruction_mov_reg_mem(context, MOVE_FROM_MEM, address, reg, POINTER_SIZE);
                return x64_place_address((X64_Address) { .base = reg });
            } else {
                return x64_place_address(address);
            }
        } break;

        case EXPR_UNARY: {
            switch (expr->unary.op) {
                case UNARY_DEREFERENCE: {
                    Register reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserves);
                    machinecode_for_expr(context, fn, expr->unary.inner, reg_allocator, x64_place_reg(reg));
                    return x64_place_address((X64_Address) { .base = reg });
                } break;
            }
        } break;

        case EXPR_SUBSCRIPT: {
            X64_Place place = machinecode_for_addressable_expr(context, fn, expr->subscript.array, reg_allocator, reserves);
            assert(place.kind == PLACE_ADDRESS);
            X64_Address address = place.address;

            Type *array_type = expr->subscript.array->type;
            Type *child_type = expr->type;

            if (array_type->kind == TYPE_POINTER && array_type->pointer_to->kind == TYPE_ARRAY) {
                Register address_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserves);
                instruction_mov_reg_mem(context, MOVE_FROM_MEM, address, address_reg, POINTER_SIZE);
                address = (X64_Address) { .base = address_reg };
            } else if (array_type->kind == TYPE_ARRAY) {
                // No special handling required.
            } else if (array_type == context->string_type) {
                Register address_reg;
                if (is_gpr(address.base)) {
                    address_reg = address.base;
                } else if (is_gpr(address.index)) {
                    address_reg = address.base;
                } else {
                    address_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserves);
                }
                instruction_mov_reg_mem(context, MOVE_FROM_MEM, address, address_reg, POINTER_SIZE);
                address = (X64_Address) { .base = address_reg };
            } else {
                assert(false);
            }

            u64 stride = type_size_of(child_type);
            address = machinecode_index_address(context, fn, reg_allocator, address, expr->subscript.index, stride);

            return x64_place_address(address);
        } break;

        case EXPR_MEMBER_ACCESS: {
            X64_Place place = machinecode_for_addressable_expr(context, fn, expr->member_access.parent, reg_allocator, reserves);
            assert(place.kind == PLACE_ADDRESS);

            Type *parent_type = expr->member_access.parent->type;
            if (parent_type->kind == TYPE_POINTER) {
                parent_type = parent_type->pointer_to;

                Register address_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserves);
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

void machinecode_for_expr(Context *context, Fn *fn, Expr *expr, Reg_Allocator *reg_allocator, X64_Place place) {
    switch (expr->kind) {
        case EXPR_VARIABLE: {
            if (place.kind == PLACE_NOWHERE) return;

            u64 size = type_size_of(expr->type);
            X64_Place from = machinecode_for_addressable_expr(context, fn, expr, reg_allocator, 0);
            machinecode_move(context, reg_allocator, from, place, size);
        } break;

        case EXPR_LITERAL: {
            if (place.kind == PLACE_NOWHERE) return;

            u64 size = type_size_of(expr->type);
            assert(size <= 8);
            machinecode_immediate_to_place(context, reg_allocator, place, expr->literal.masked_value, (u8) size);
        } break;

        case EXPR_STRING_LITERAL: {
            if (place.kind == PLACE_NOWHERE) return;
            assert(place.kind == PLACE_ADDRESS);
            X64_Address place_address = place.address;

            u64 length = expr->string.length;
            u64 data_offset = add_exe_data(context, true, expr->string.bytes, length + 1, 1);

            assert(data_offset < I32_MAX);
            X64_Address data_address = { .base = RIP_OFFSET_RDATA, .immediate_offset = data_offset };

            machinecode_lea(context, reg_allocator, data_address, x64_place_address(place_address));
            place_address.immediate_offset += POINTER_SIZE;
            instruction_mov_imm_mem(context, place_address, length, POINTER_SIZE);
        } break;

        case EXPR_COMPOUND: {
            if (place.kind == PLACE_NOWHERE) {
                for (u32 i = 0; i < expr->compound.count; i += 1) {
                    Expr *child = expr->compound.content[i].expr;
                    machinecode_for_expr(context, fn, child, reg_allocator, place);
                }
                return;
            }

            register_allocator_enter_frame(context, reg_allocator);

            u64 size = type_size_of(expr->type);
            u64 align = type_align_of(expr->type);

            if (size == 0) return;

            X64_Place real_place = place;
            bool return_to_real_place = false;

            if (place.kind != PLACE_ADDRESS) {
                assert(size == 1 || size == 2 || size == 4 || size == 8);

                return_to_real_place = true;

                place.kind = PLACE_ADDRESS;
                place.address = register_allocator_temp_stack_space(reg_allocator, size, align);
            }

            assert(place.kind == PLACE_ADDRESS);
            switch (expr->type->kind) {
                case TYPE_ARRAY: {
                    Type* child_type = expr->type->array.of;
                    u64 child_size = type_size_of(child_type);

                    for (u32 i = 0; i < expr->compound.count; i += 1) {
                        assert(expr->compound.content[i].name_mode == EXPR_COMPOUND_NO_NAME);

                        Expr *child = expr->compound.content[i].expr;
                        machinecode_for_expr(context, fn, child, reg_allocator, place);

                        assert((((i64) place.address.immediate_offset) + ((i64) child_size)) < I32_MAX);
                        place.address.immediate_offset += child_size;
                    }
                } break;

                case TYPE_STRUCT: {
                    if (expr->compound.count != expr->type->structure.member_count) {
                        u64 size = type_size_of(expr->type);
                        u64 align = type_align_of(expr->type);
                        machinecode_zero_out_struct(context, reg_allocator, place.address, size, align);
                    }

                    for (u32 i = 0; i < expr->compound.count; i += 1) {
                        assert(expr->compound.content[i].name_mode != EXPR_COMPOUND_UNRESOLVED_NAME);

                        u32 type_member_index = expr->compound.content[i].member_index;
                        i32 member_offset = expr->type->structure.members[type_member_index].offset;

                        assert((place.address.immediate_offset + member_offset) < I32_MAX);
                        X64_Place offset_place = place;
                        offset_place.address.immediate_offset += (i32) member_offset;

                        Expr* child = expr->compound.content[i].expr;
                        machinecode_for_expr(context, fn, child, reg_allocator, offset_place);
                    }
                } break;

                default: assert(false);
            }

            if (return_to_real_place) {
                machinecode_move(context, reg_allocator, place, real_place, size);
            }

            register_allocator_leave_frame(context, reg_allocator);
        } break;

        case EXPR_TERNARY: {
            register_allocator_enter_frame(context, reg_allocator);
            Register condition_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, 0);
            machinecode_for_expr(context, fn, expr->ternary.condition, reg_allocator, x64_place_reg(condition_reg));
            instruction_cmp_imm(context, x64_place_reg(condition_reg), 0, 1);
            register_allocator_leave_frame(context, reg_allocator);

            u64 jcc_offset = instruction_jcc(context, COND_E, 1);
            machinecode_for_expr(context, fn, expr->ternary.left, reg_allocator, place);
            u64 jmp_offset = instruction_jmp(context, 1);
            u64 jcc_to = buf_length(context->seg_text);
            machinecode_for_expr(context, fn, expr->ternary.right, reg_allocator, place);
            u64 jmp_to = buf_length(context->seg_text);

            i64 jcc_by = jcc_to - (jcc_offset + sizeof(i8));
            i64 jmp_by = jmp_to - (jmp_offset + sizeof(i8));
            assert(jcc_by >= 0 && jcc_by <= I8_MAX);
            assert(jmp_by >= 0 && jmp_by <= I8_MAX); // TODO If this fails rewrite code but with a 32 bit jump
            context->seg_text[jcc_offset] = (i8) jcc_by;
            context->seg_text[jmp_offset] = (i8) jmp_by;
        } break;

        case EXPR_BINARY: {
            if (place.kind == PLACE_NOWHERE) {
                machinecode_for_expr(context, fn, expr->binary.left, reg_allocator, place);
                machinecode_for_expr(context, fn, expr->binary.right, reg_allocator, place);
                return;
            }

            // Floating point
            if (primitive_is_float(expr->binary.left->type->kind)) {
                register_allocator_enter_frame(context, reg_allocator);

                bool return_left_to_place = place.kind == PLACE_ADDRESS || (place.kind == PLACE_REGISTER && !is_xmm(place.reg));
                Register left_reg;
                if (return_left_to_place) {
                    u32 reserves_for_rhs = machinecode_expr_reserves(expr->binary.right);
                    left_reg = register_allocate(reg_allocator, REGISTER_KIND_XMM, reserves_for_rhs);
                } else {
                    left_reg = place.reg;
                }
                machinecode_for_expr(context, fn, expr->binary.left, reg_allocator, x64_place_reg(left_reg));

                register_allocator_enter_frame(context, reg_allocator);
                X64_Place right_place;
                if (expr->binary.right->flags & EXPR_FLAG_ADDRESSABLE) {
                    right_place = machinecode_for_addressable_expr(context, fn, expr->binary.right, reg_allocator, 0);
                } else {
                    Register right_reg = register_allocate(reg_allocator, REGISTER_KIND_XMM, 0);
                    right_place = x64_place_reg(right_reg);
                    machinecode_for_expr(context, fn, expr->binary.right, reg_allocator, right_place);
                }

                Type_Kind primitive = expr->binary.left->type->kind;
                bool single;
                if (primitive == TYPE_F32) {
                    single = true;
                } else if (primitive == TYPE_F64) {
                    single = false;
                } else {
                    assert(false);
                }

                if (BINARY_OP_COMPARATIVE[expr->binary.op]) {
                    // In some cases we use nonobvious sequences of instructions for floating point
                    // comparasions.
                    // We use CMPEQ and CMPNEQ for == and != because they properly handle comparasions
                    // of NaNs.
                    // We avoid setb and setbe, because they look for CF=1, and CF=1 is also set when
                    // CMOI/COMI encounters a NaN. By using seta and setae instead we always evaluate
                    // to false when we encounter a NaN (Look at the truth-tables for setcc and COMI/COMI).

                    Condition cond;
                    bool swap_operands = false;
                    int instruction;

                    switch (expr->binary.op) {
                        case BINARY_EQ:   instruction = FLOAT_CMPEQ;  break;
                        case BINARY_NEQ:  instruction = FLOAT_CMPNEQ; break;
                        case BINARY_GT:   instruction = FLOAT_COMI; cond = COND_A;  break;
                        case BINARY_GTEQ: instruction = FLOAT_COMI; cond = COND_AE; break;
                        case BINARY_LT:   instruction = FLOAT_COMI; cond = COND_A;  swap_operands = true; break;
                        case BINARY_LTEQ: instruction = FLOAT_COMI; cond = COND_AE; swap_operands = true; break;
                        default: assert(false);
                    }

                    if (swap_operands) {
                        if (right_place.kind == PLACE_REGISTER) {
                            instruction_float(context, instruction, right_place.reg, x64_place_reg(left_reg), single);
                        } else if (right_place.kind == PLACE_ADDRESS) {
                            Register temp_reg = register_allocate(reg_allocator, REGISTER_KIND_XMM, 0);
                            instruction_float(context, FLOAT_MOV, temp_reg, right_place, single);
                            instruction_float(context, instruction, temp_reg, x64_place_reg(left_reg), single);
                            left_reg = temp_reg;
                        } else {
                            assert(false);
                        }
                    } else {
                        instruction_float(context, instruction, left_reg, right_place, single);
                    }

                    if (instruction == FLOAT_COMI) {
                        instruction_setcc(context, cond, place);
                    } else {
                        instruction_float_movd(context, MOVE_TO_MEM, left_reg, place, single);
                        instruction_integer_imm(context, INTEGER_AND, place, 1, 1);
                    }

                    assert(return_left_to_place);
                    return_left_to_place = false;
                } else {
                    int instruction;
                    switch (expr->binary.op) {
                        case BINARY_ADD:  instruction = FLOAT_ADD; break;
                        case BINARY_SUB:  instruction = FLOAT_SUB; break;
                        case BINARY_MUL:  instruction = FLOAT_MUL; break;
                        case BINARY_DIV:  instruction = FLOAT_DIV; break;
                        case BINARY_MOD:  assert(false); break;
                        default: assert(false);
                    }

                    instruction_float(context, instruction, left_reg, right_place, single);
                }

                register_allocator_leave_frame(context, reg_allocator);

                if (return_left_to_place) {
                    machinecode_move(context, reg_allocator, x64_place_reg(left_reg), place, single? 4 : 8);
                }
                register_allocator_leave_frame(context, reg_allocator);

            // Short-circuiting
            } else if (expr->binary.op == BINARY_LOGICAL_AND || expr->binary.op == BINARY_LOGICAL_OR) {
                Condition cond;
                if (expr->binary.op == BINARY_LOGICAL_AND) {
                    cond = COND_E;
                } else if (expr->binary.op == BINARY_LOGICAL_OR) {
                    cond = COND_NE;
                } else {
                    assert(false);
                }

                assert(expr->type->kind == TYPE_BOOL);
                u8 op_size = 1;

                machinecode_for_expr(context, fn, expr->binary.left, reg_allocator, place);

                instruction_cmp_imm(context, place, 0, op_size);
                u64 jump_size_offset = instruction_jcc(context, cond, 1);
                u64 jump_from = buf_length(context->seg_text);

                machinecode_for_expr(context, fn, expr->binary.right, reg_allocator, place);

                i64 jump_by = buf_length(context->seg_text) - jump_from;
                assert(jump_by >= I8_MIN && jump_by <= I8_MAX); // TODO If this fails rewrite code but with a 32 bit jump
                context->seg_text[jump_size_offset] = (i8) jump_by;

            // General binary integer stuff
            } else {
                Register left_reg = REGISTER_NONE;
                if (place.kind == PLACE_ADDRESS) {
                    register_allocator_enter_frame(context, reg_allocator);
                    u32 reserves_for_rhs = machinecode_expr_reserves(expr->binary.right);
                    if (expr->binary.op == BINARY_SHL || expr->binary.op == BINARY_SHR) {
                        reserves_for_rhs |= RESERVE_RCX;
                    }
                    left_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserves_for_rhs);
                } else {
                    left_reg = place.reg;
                }

                machinecode_for_expr(context, fn, expr->binary.left, reg_allocator, x64_place_reg(left_reg));

                register_allocator_enter_frame(context, reg_allocator);

                u32 reserves_for_result = machinecode_expr_reserves(expr->binary.right);
                if (expr->binary.op == BINARY_MUL) {
                    reserves_for_result |= RESERVE_RAX;
                }
                if (expr->binary.op == BINARY_DIV || expr->binary.op == BINARY_MOD) {
                    reserves_for_result |= RESERVE_RAX;
                    reserves_for_result |= RESERVE_RDX;
                }
                Register right_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserves_for_result);

                machinecode_for_expr(context, fn, expr->binary.right, reg_allocator, x64_place_reg(right_reg));

                switch (expr->binary.op) {
                    case BINARY_ADD:
                    case BINARY_SUB:
                    case BINARY_AND:
                    case BINARY_OR:
                    case BINARY_XOR:
                    {
                        Type *type = expr->type;

                        register_allocator_enter_frame(context, reg_allocator);

                        if (expr->type->kind == TYPE_POINTER) {
                            u64 pointer_scale = type_size_of(expr->type->pointer_to);

                            if (expr->binary.left->type->kind != TYPE_POINTER) {
                                instruction_mul_pointer_imm(context, left_reg, pointer_scale);
                            }
                            
                            if (expr->binary.right->type->kind != TYPE_POINTER) {
                                instruction_mul_pointer_imm(context, right_reg, pointer_scale);
                            }
                        }

                        u8 op_size = primitive_size_of(type->kind);
                        int instruction;
                        switch (expr->binary.op) {
                            case BINARY_ADD: instruction = INTEGER_ADD; break;
                            case BINARY_SUB: instruction = INTEGER_SUB; break;
                            case BINARY_AND: instruction = INTEGER_AND; break;
                            case BINARY_OR:  instruction = INTEGER_OR;  break;
                            case BINARY_XOR: instruction = INTEGER_XOR; break;
                        }
                        instruction_integer(context, instruction, MOVE_FROM_MEM, left_reg, x64_place_reg(right_reg), op_size);

                        if (expr->binary.left->type->kind == TYPE_POINTER && expr->binary.right->type->kind == TYPE_POINTER) {
                            assert(expr->binary.op == BINARY_SUB);
                            u64 pointer_scale = type_size_of(expr->binary.left->type->pointer_to);

                            if (pointer_scale > 0) {
                                instruction_idiv_pointer_imm(context, left_reg, pointer_scale);
                            }
                        }

                        register_allocator_leave_frame(context, reg_allocator);
                    } break;

                    case BINARY_SHL:
                    case BINARY_SHR:
                    {
                        Type_Kind primitive = expr->type->kind;
                        u8 op_size = primitive_size_of(primitive);
                        int instruction;
                        if (expr->binary.op == BINARY_SHL) {
                            instruction = SHIFT_LEFT;
                        } else {
                            if (primitive_is_signed(primitive)) {
                                instruction = SHIFT_RIGHT_ARITHMETIC;
                            } else {
                                instruction = SHIFT_RIGHT;
                            }
                        }

                        register_allocator_enter_frame(context, reg_allocator);

                        assert(left_reg != RCX);
                        if (right_reg != RCX) {
                            register_allocate_specific(context, reg_allocator, RCX);
                            instruction_mov_reg_reg(context, right_reg, RCX, op_size);
                        }

                        instruction_shift(context, instruction, x64_place_reg(left_reg), op_size);

                        register_allocator_leave_frame(context, reg_allocator);
                    } break;

                    // NB remember that we need to clear RDX, there are instructions for that!
                    case BINARY_DIV:
                    case BINARY_MOD:
                    case BINARY_MUL:
                    {
                        Type_Kind primitive = expr->type->kind;
                        assert(right_reg != RAX);

                        u8 op_size = primitive_size_of(primitive);
                        bool dst_is_not_rax = left_reg != RAX;

                        register_allocator_enter_frame(context, reg_allocator);

                        if (dst_is_not_rax) {
                            register_allocate_specific(context, reg_allocator, RAX);
                            instruction_mov_reg_reg(context, left_reg, RAX, op_size);
                        }

                        if (op_size > 1 && right_reg != RDX && left_reg != RDX) {
                            register_allocate_specific(context, reg_allocator, RDX); // We will clobber RDX
                        }

                        if (expr->binary.op == BINARY_DIV || expr->binary.op == BINARY_MOD) {
                            if (primitive_is_signed(primitive)) {
                                instruction_sign_extend_for_division(context, op_size);
                            } else {
                                Register reg = op_size == 1? AH : RDX;
                                instruction_integer(context, INTEGER_XOR, MOVE_FROM_MEM, reg, x64_place_reg(reg), op_size);
                            }
                        }

                        int instruction;
                        if (expr->binary.op == BINARY_MUL) {
                            instruction = SCALING_MUL; // Signed and unsigned multiplication are equal when one discards the bits in RDX
                        } else if (expr->binary.op == BINARY_DIV || expr->binary.op == BINARY_MOD) {
                            instruction = primitive_is_signed(primitive) ? SCALING_IDIV : SCALING_DIV;
                        } else {
                            assert(false);
                        }
                        instruction_scaling(context, instruction, x64_place_reg(right_reg), op_size);

                        Register target_reg = expr->binary.op == BINARY_MOD? RDX : RAX;
                        if (op_size == 1 && target_reg == RDX) {
                            if (left_reg >= RSP) {
                                instruction_mov_reg_reg(context, AH, RAX, 1);
                                target_reg = RAX;
                            } else {
                                target_reg = AH;
                            }
                        }

                        if (left_reg != target_reg) {
                            instruction_mov_reg_reg(context, target_reg, left_reg, op_size);
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
                        Type_Kind primitive = primitive_of(expr->binary.left->type);

                        u8 inner_size = primitive_size_of(primitive);
                        Condition condition = find_condition_for_op_and_type(expr->binary.op, primitive_is_signed(primitive));

                        instruction_cmp(context, x64_place_reg(left_reg), right_reg, inner_size);
                        instruction_setcc(context, condition, x64_place_reg(left_reg));
                    } break;

                    default: assert(false);
                }

                register_allocator_leave_frame(context, reg_allocator);

                if (place.kind == PLACE_ADDRESS) {
                    u64 size = type_size_of(expr->type);
                    assert(size <= 8);
                    machinecode_move(context, reg_allocator, x64_place_reg(left_reg), place, (u8) size);
                    register_allocator_leave_frame(context, reg_allocator);
                }
            }
        } break;

        case EXPR_UNARY: {
            if (place.kind == PLACE_NOWHERE) {
                machinecode_for_expr(context, fn, expr->unary.inner, reg_allocator, place);
                return;
            }

            switch (expr->unary.op) {
                case UNARY_NOT:
                case UNARY_NEG:
                {
                    machinecode_for_expr(context, fn, expr->unary.inner, reg_allocator, place);

                    Type_Kind primitive = expr->type->kind;
                    if (primitive == TYPE_BOOL) {
                        assert(expr->unary.op == UNARY_NOT);
                        assert(primitive_size_of(primitive) == 1);

                        instruction_cmp_imm(context, place, 0, 1);
                        instruction_setcc(context, COND_E, place);
                    } else if (primitive == TYPE_F32 || primitive == TYPE_F64) {
                        assert(expr->unary.op == UNARY_NEG);
                        bool single = primitive == TYPE_F32;

                        Register reg;
                        if (place.kind == PLACE_ADDRESS) {
                            register_allocator_enter_frame(context, reg_allocator);
                            reg = register_allocate(reg_allocator, REGISTER_KIND_XMM, 0);
                            instruction_float(context, FLOAT_MOV, reg, place, single);
                        } else {
                            reg = place.reg;
                        }

                        // xor values with '-0.0', which flips the sign bit. We have to load '-0.0' from memory because
                        // sse doesn't allow immediate operands.
                        // Also, because sse only has a vector xor, no scalar xor, we have to have a bunch of negative zeros
                        // to xor with.
                        // TODO storing the negation bit patterns in seg_text, between functions, would be cleaner
                        u64 offset;
                        if (single) {
                            if (reg_allocator->negate_f32_data_offset == U64_MAX) {
                                reg_allocator->negate_f32_data_offset = add_exe_data(context, true, null, 0, 16);
                                u32 negative_zero = 0x80000000;
                                str_push_integer(&context->seg_rdata, sizeof(f32), negative_zero);
                                str_push_integer(&context->seg_rdata, sizeof(f32), negative_zero);
                                str_push_integer(&context->seg_rdata, sizeof(f32), negative_zero);
                                str_push_integer(&context->seg_rdata, sizeof(f32), negative_zero);
                            }
                            offset = reg_allocator->negate_f32_data_offset;
                        } else {
                            if (reg_allocator->negate_f64_data_offset == U64_MAX) {
                                reg_allocator->negate_f64_data_offset = add_exe_data(context, true, null, 0, 16);
                                u64 negative_zero = 0x8000000000000000;
                                str_push_integer(&context->seg_rdata, sizeof(f64), negative_zero);
                                str_push_integer(&context->seg_rdata, sizeof(f64), negative_zero);
                            }
                            offset = reg_allocator->negate_f64_data_offset;
                        }

                        X64_Address negate_address = { .base = RIP_OFFSET_RDATA, .immediate_offset = offset };
                        instruction_float(context, FLOAT_XOR_PACKED, reg, x64_place_address(negate_address), single);

                        if (place.kind == PLACE_ADDRESS) {
                            instruction_float(context, FLOAT_MOV_REVERSE, reg, place, single);
                            register_allocator_leave_frame(context, reg_allocator);
                        }
                    } else {
                        bool unary = expr->unary.op == UNARY_NOT;
                        instruction_negative(context, unary, place, primitive_size_of(primitive));
                    }
                } break;

                case UNARY_SQRT: {
                    Type_Kind primitive = expr->type->kind;
                    assert(primitive == TYPE_F32 || primitive == TYPE_F64);
                    bool single = primitive == TYPE_F32;

                    Register reg;
                    bool return_to_place = false;
                    if (place.kind == PLACE_REGISTER) {
                        reg = place.reg;
                    } else {
                        reg = register_allocate(reg_allocator, REGISTER_KIND_XMM, 0);
                        return_to_place = true;
                    }

                    machinecode_for_expr(context, fn, expr->unary.inner, reg_allocator, x64_place_reg(reg));

                    instruction_float(context, FLOAT_SQRT, reg, x64_place_reg(reg), single);

                    if (return_to_place) {
                        instruction_float_movd(context, MOVE_TO_MEM, reg, place, single);
                    }
                } break;

                case UNARY_DEREFERENCE: {
                    register_allocator_enter_frame(context, reg_allocator);
                    X64_Place inner_place = {0};
                    inner_place.kind = PLACE_REGISTER;
                    if (place.kind == PLACE_REGISTER) {
                        inner_place.reg = place.reg;
                    } else {
                        inner_place.reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, 0);
                    }

                    machinecode_for_expr(context, fn, expr->unary.inner, reg_allocator, inner_place);

                    Register inner_reg = inner_place.reg;
                    inner_place = (X64_Place) {0};
                    inner_place.kind = PLACE_ADDRESS;
                    inner_place.address.base = inner_reg;

                    u64 dereferenced_size = type_size_of(expr->type);
                    machinecode_move(context, reg_allocator, inner_place,place, dereferenced_size);

                    register_allocator_leave_frame(context, reg_allocator);
                } break;

                case UNARY_ADDRESS_OF: {
                    X64_Place inner_place = machinecode_for_addressable_expr(context, fn, expr->unary.inner, reg_allocator, 0);
                    assert(inner_place.kind == PLACE_ADDRESS);

                    switch (place.kind) {
                        case PLACE_REGISTER: {
                            instruction_lea(context, inner_place.address, place.reg);
                        } break;

                        case PLACE_ADDRESS: {
                            register_allocator_enter_frame(context, reg_allocator);
                            Register reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, 0);
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
            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));

            Fn_Signature *callee_signature;
            if (expr->call.pointer_call) {
                Type *fn_pointer_type = expr->call.pointer_expr->type;
                assert(fn_pointer_type->kind == TYPE_FN_POINTER);
                callee_signature = &fn_pointer_type->fn_signature;
            } else {
                callee_signature = expr->call.callee->signature;
            }

            reg_allocator->max_callee_param_count = max(reg_allocator->max_callee_param_count, callee_signature->param_count);


            Register return_reg;
            if (primitive_is_float(expr->type->kind)) {
                return_reg = XMM0;
            } else {
                return_reg = RAX;
            }

            // Compute parameters
            register_allocator_enter_frame(context, reg_allocator);

            bool skip_first_param_reg = false;
            Register used_volatile_registers[INPUT_REGISTER_COUNT] = {0};

            if (callee_signature->return_by_reference) {
                skip_first_param_reg = true;

                X64_Address return_into;
                if (place.kind == PLACE_NOWHERE) {
                    u64 size = type_size_of(callee_signature->return_type);
                    u64 align = type_align_of(callee_signature->return_type);
                    return_into = register_allocator_temp_stack_space(reg_allocator, size, align);
                } else {
                    assert(place.kind == PLACE_ADDRESS);
                    return_into = place.address;
                }

                Register reg = GPR_INPUT_REGISTERS[0];
                register_allocate_specific(context, reg_allocator, reg);
                used_volatile_registers[0] = reg;
                instruction_lea(context, return_into, reg);
            }

            for (u32 p = 0; p < callee_signature->param_count; p += 1) {
                Type *param_type = callee_signature->params[p].type;
                Expr *param_expr = expr->call.params[p];

                X64_Place target_place, compute_to_place;
                bool target_and_compute_differ = false;
 
                u32 r = skip_first_param_reg? (p + 1) : p;
                if (r < INPUT_REGISTER_COUNT) {
                    Register reg;
                    if (primitive_is_float(param_type->kind)) {
                        reg = XMM_INPUT_REGISTERS[r];
                    } else {
                        reg = GPR_INPUT_REGISTERS[r];
                    }

                    used_volatile_registers[r] = reg;
                    target_place = x64_place_reg(reg);

                    u32 param_reserves = machinecode_expr_reserves(param_expr);
                    if (reserves_register(param_reserves, reg)) {
                        target_and_compute_differ = true;

                        register_allocator_enter_frame(context, reg_allocator);
                        Register_Kind reg_kind = primitive_is_float(param_type->kind)? REGISTER_KIND_XMM : REGISTER_KIND_GPR;
                        Register other_reg = register_allocate(reg_allocator, reg_kind, param_reserves);
                        compute_to_place = x64_place_reg(other_reg);
                    } else {
                        compute_to_place = target_place;
                    }
                } else {
                    target_place = (X64_Place) { .kind = PLACE_ADDRESS, .address = { .base = RSP, .immediate_offset = r*POINTER_SIZE } };
                    compute_to_place = target_place;
                }


                if (callee_signature->params[p].reference_semantics) {
                    u64 size = type_size_of(param_type);
                    u64 align = type_align_of(param_type);

                    if (size > 0) {
                        X64_Address tmp_address = register_allocator_temp_stack_space(reg_allocator, size, align);
                        X64_Place tmp_place = { .kind = PLACE_ADDRESS, .address = tmp_address };

                        machinecode_for_expr(context, fn, param_expr, reg_allocator, tmp_place);
                        if (compute_to_place.kind == PLACE_REGISTER && !(place.kind == PLACE_REGISTER && compute_to_place.reg == place.reg)) {
                            register_allocate_specific(context, reg_allocator, compute_to_place.reg);
                        }

                        machinecode_lea(context, reg_allocator, tmp_address, compute_to_place);
                    }
                } else {
                    if (compute_to_place.kind == PLACE_REGISTER && !(place.kind == PLACE_REGISTER && compute_to_place.reg == place.reg)) {
                        register_allocate_specific(context, reg_allocator, compute_to_place.reg);
                    }
                    machinecode_for_expr(context, fn, param_expr, reg_allocator, compute_to_place);
                }

                if (target_and_compute_differ) {
                    machinecode_move(context, reg_allocator, compute_to_place, target_place, type_size_of(param_type));
                    register_allocator_leave_frame(context, reg_allocator);
                    if (target_place.kind == PLACE_REGISTER && !(place.kind == PLACE_REGISTER && target_place.reg == place.reg)) {
                        register_allocate_specific(context, reg_allocator, target_place.reg);
                    }
                }
            }

            Register pointer_reg = REGISTER_NONE;
            if (expr->call.pointer_call) {
                // We need to compute this before we save volatile registers for the call
                if (return_reg == RAX) {
                    pointer_reg = RAX;
                } else {
                    pointer_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, 0);
                }
                machinecode_for_expr(context, fn, expr->call.pointer_expr, reg_allocator, x64_place_reg(pointer_reg));
            }

            // Save volatile registers, unless we are using them for parameters
            for (u32 i = 0; i < VOLATILE_REGISTER_COUNT; i += 1) {
                Register reg = VOLATILE_REGISTERS[i];

                bool dont_flush =
                    (callee_signature->has_return && reg == return_reg) ||
                    (place.kind == PLACE_REGISTER && place.reg == reg);

                for (u32 j = 0; j < INPUT_REGISTER_COUNT; j += 1) {
                    if (used_volatile_registers[j] == reg) {
                        dont_flush = true;
                        break;
                    }
                }

                if (dont_flush) {
                    // we are fine overwriting this register
                } else {
                    register_allocate_specific(context, reg_allocator, reg);
                }
            }

            bool move_from_return_reg =
                !(place.kind == PLACE_REGISTER && place.reg == return_reg) &&
                place.kind != PLACE_NOWHERE &&
                callee_signature->has_return;
            if (move_from_return_reg) {
                register_allocate_specific(context, reg_allocator, return_reg);
            }

            // Call function and handle return value
            if (expr->call.pointer_call) {
                instruction_call_indirect(context, x64_place_reg(pointer_reg));
            } else {
                instruction_call(context, expr->call.callee);
            }

            X64_Address unflush_return_from;
            bool unflush_return = reg_allocator->head->states[return_reg].flushed;
            if (unflush_return) {
                unflush_return_from = reg_allocator->head->states[return_reg].flushed_to;
                reg_allocator->head->states[return_reg].flushed = false;
            }

            register_allocator_leave_frame(context, reg_allocator);

            if (move_from_return_reg) {
                assert(place.kind != PLACE_NOWHERE && callee_signature->has_return);

                Type *return_type = callee_signature->return_type;
                u64 return_size = type_size_of(callee_signature->return_type);

                if (callee_signature->return_by_reference) {
                    // The function just wrote the result into a pointer we passed it, so we don't have to
                    // do anything more here.
                    // NB The function also returns the pointer we passed (in RCX) in RAX, which we could
                    // make use of.
                } else if (place.kind == PLACE_ADDRESS && (place.address.base == RAX || place.address.index == RAX)) {
                    assert(unflush_return && return_reg == RAX);
                    register_allocator_enter_frame(context, reg_allocator);
                    Register temp_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, RESERVE_RAX);

                    instruction_mov_reg_reg(context, RAX, temp_reg, return_size);
                    instruction_mov_reg_mem(context, MOVE_FROM_MEM, unflush_return_from, RAX, POINTER_SIZE);
                    instruction_mov_reg_mem(context, MOVE_TO_MEM, place.address, temp_reg, return_size);

                    register_allocator_leave_frame(context, reg_allocator);

                    unflush_return = false;
                } else {
                    machinecode_move(context, reg_allocator, x64_place_reg(return_reg), place, return_size);
                }

            }

            if (unflush_return) {
                if (is_gpr(return_reg)) {
                    instruction_mov_reg_mem(context, MOVE_FROM_MEM, unflush_return_from, return_reg, POINTER_SIZE);
                } else if (is_xmm(return_reg)) {
                    instruction_float_movd(context, MOVE_FROM_MEM, return_reg, x64_place_address(unflush_return_from), false);
                } else {
                    assert(false);
                }
            }
        } break;

        case EXPR_CAST: {
            if (place.kind == PLACE_NOWHERE) {
                machinecode_for_expr(context, fn, expr->cast_from, reg_allocator, place);
                return;
            }

            if (expr->type->kind == expr->cast_from->type->kind) {
                machinecode_for_expr(context, fn, expr->cast_from, reg_allocator, place);
            } else {
                register_allocator_enter_frame(context, reg_allocator);

                Register_Kind inner_reg_kind = primitive_is_float(expr->cast_from->type->kind)? REGISTER_KIND_XMM : REGISTER_KIND_GPR;
                Register_Kind outer_reg_kind = primitive_is_float(expr->type->kind)?            REGISTER_KIND_XMM : REGISTER_KIND_GPR;

                Register inner_reg, outer_reg;
                bool return_to_place;

                if (place.kind == PLACE_ADDRESS) {
                    outer_reg = register_allocate(reg_allocator, outer_reg_kind, 0);
                    return_to_place = true;
                } else if (place.kind == PLACE_REGISTER) {
                    outer_reg = place.reg;
                    return_to_place = false;
                } else {
                    assert(false);
                }

                if (inner_reg_kind == outer_reg_kind) {
                    inner_reg = outer_reg;
                } else {
                    inner_reg = register_allocate(reg_allocator, inner_reg_kind, 0);
                }

                machinecode_for_expr(context, fn, expr->cast_from, reg_allocator, x64_place_reg(inner_reg));
                machinecode_cast(context, inner_reg, outer_reg, primitive_of(expr->cast_from->type), primitive_of(expr->type));
                if (return_to_place) {
                    machinecode_move(context, reg_allocator, x64_place_reg(outer_reg), place, type_size_of(expr->type));
                }

                register_allocator_leave_frame(context, reg_allocator);
            }
        } break;

        case EXPR_SUBSCRIPT: {
            if (place.kind == PLACE_NOWHERE) {
                machinecode_for_expr(context, fn, expr->subscript.array, reg_allocator, place);
                machinecode_for_expr(context, fn, expr->subscript.index, reg_allocator, place);
                return;
            }

            // NB The reason we don't allow using the subscript operator on straight pointers (e.g. *u8) is because that would create
            // confusing semantics for pointers to arrays. Should the stride an array access to a *[3]u8 should be 1 or 3?
            // Because we disallow indexing straight pointers the answer is simple: its 1.

            register_allocator_enter_frame(context, reg_allocator);

            X64_Place source;
            if (expr->flags & EXPR_FLAG_ADDRESSABLE) {
                source = machinecode_for_addressable_expr(context, fn, expr, reg_allocator, 0);
            } else {
                Type *array_type = expr->subscript.array->type;
                X64_Address array_base;

                if (array_type->kind == TYPE_POINTER && array_type->pointer_to->kind == TYPE_ARRAY) {
                    array_type = array_type->pointer_to;

                    Register pointer_reg;
                    if (place.kind == PLACE_REGISTER && is_gpr(place.reg)) {
                        pointer_reg = place.reg;
                    } else {
                        u32 reserves_for_index = machinecode_expr_reserves(expr->subscript.index);
                        pointer_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserves_for_index);
                    }

                    machinecode_for_expr(context, fn, expr->subscript.array, reg_allocator, x64_place_reg(pointer_reg));
                    array_base = (X64_Address) { .base = pointer_reg };
                } else if (array_type->kind == TYPE_ARRAY) {
                    u64 size = type_size_of(array_type);
                    u64 align = type_align_of(array_type);
                    array_base = register_allocator_temp_stack_space(reg_allocator, size, align);

                    machinecode_for_expr(context, fn, expr->subscript.array, reg_allocator, x64_place_address(array_base));
                } else if (array_type == context->string_type) {
                    u64 size = type_size_of(array_type);
                    u64 align = type_size_of(array_type);
                    X64_Address string_address = register_allocator_temp_stack_space(reg_allocator, size, align);

                    machinecode_for_expr(context, fn, expr->subscript.array, reg_allocator, x64_place_address(string_address));

                    Register pointer_reg;
                    if (place.kind == PLACE_REGISTER && is_gpr(place.reg)) {
                        pointer_reg = place.reg;
                    } else {
                        u32 reserves_for_index = machinecode_expr_reserves(expr->subscript.index);
                        pointer_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserves_for_index);
                    }

                    instruction_mov_reg_mem(context, MOVE_FROM_MEM, string_address, pointer_reg, POINTER_SIZE);

                    array_base = (X64_Address) { .base = pointer_reg };
                }

                u64 stride = type_size_of(expr->type);
                X64_Address address = machinecode_index_address(context, fn, reg_allocator, array_base, expr->subscript.index, stride);
                source = x64_place_address(address);
            }

            machinecode_move(context, reg_allocator, source, place, type_size_of(expr->type));

            register_allocator_leave_frame(context, reg_allocator);
        } break;

        case EXPR_MEMBER_ACCESS: {
            if (place.kind == PLACE_NOWHERE) {
                machinecode_for_expr(context, fn, expr->member_access.parent, reg_allocator, place);
                return;
            }

            assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));
            u64 member_size = type_size_of(expr->type);

            if (expr->flags & EXPR_FLAG_ADDRESSABLE) {
                X64_Place source = machinecode_for_addressable_expr(context, fn, expr, reg_allocator, 0);
                machinecode_move(context, reg_allocator, source, place, member_size);
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
                        pointer_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, 0);
                    }

                    machinecode_for_expr(context, fn, parent, reg_allocator, x64_place_reg(pointer_reg));

                    X64_Place member_place = { .kind = PLACE_ADDRESS };
                    member_place.address.base = pointer_reg;
                    member_place.address.immediate_offset = member_offset;

                    machinecode_move(context, reg_allocator, member_place, place, member_size);

                    register_allocator_leave_frame(context, reg_allocator);
                } else {
                    register_allocator_enter_frame(context, reg_allocator);

                    X64_Address tmp_address = register_allocator_temp_stack_space(reg_allocator, parent_type->structure.size, parent_type->structure.align);
                    machinecode_for_expr(context, fn, parent, reg_allocator, x64_place_address(tmp_address));

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

            machinecode_immediate_to_place(context, reg_allocator, place, member_value, size);
        } break;

        case EXPR_TYPE_INFO_OF_TYPE: {
            if (place.kind == PLACE_NOWHERE) return;

            Type_Kind primitive = expr->type_info_of_type->kind;
            machinecode_immediate_to_place(context, reg_allocator, place, (u64) primitive, 1);
        } break;

        case EXPR_TYPE_INFO_OF_VALUE: {
            if (place.kind == PLACE_NOWHERE) return;

            Type_Kind primitive = expr->type_info_of_value->type->kind;
            machinecode_immediate_to_place(context, reg_allocator, place, (u64) primitive, 1);
        } break;

        case EXPR_ADDRESS_OF_FUNCTION: {
            if (place.kind == PLACE_NOWHERE) return;

            if (place.kind == PLACE_REGISTER) {
                instruction_lea_call(context, expr->address_of_fn, place.reg);
            } else if (place.kind == PLACE_ADDRESS) {
                Register reg = register_allocate_temp(reg_allocator, REGISTER_KIND_GPR, 0);
                instruction_lea_call(context, expr->address_of_fn, reg);
                instruction_mov_reg_mem(context, MOVE_TO_MEM, place.address, reg, POINTER_SIZE);
            } else if (place.kind == PLACE_NOWHERE) {
                // Do nothing
            } else {
                assert(false);
            }
        } break;

        case EXPR_QUERY_TYPE_INFO: {
            if (place.kind == PLACE_NOWHERE) return;

            Type *type = expr->query_type_info.type;

            i64 result;
            switch (expr->query_type_info.query) {
                case QUERY_TYPE_INFO_ENUM_LENGTH: {
                    assert(type->kind == TYPE_ENUM);
                    result = 0;
                    for (u32 m = 0; m < type->enumeration.member_count; m += 1) {
                        u64 value = type->enumeration.members[m].value;
                        result = max(value + 1, result);
                    }
                } break;

                case QUERY_TYPE_INFO_SIZE:  result = type_size_of(type);  break;
                case QUERY_TYPE_INFO_ALIGN: result = type_align_of(type); break;

                default: assert(false);
            }

            machinecode_immediate_to_place(context, reg_allocator, place, result, primitive_size_of(TYPE_DEFAULT_INT));
        } break;

        case EXPR_ENUM_MEMBER_NAME: {
            if (place.kind == PLACE_NOWHERE) {
                machinecode_for_expr(context, fn, expr->enum_member, reg_allocator, place);
                return;
            }

            Type *enum_type = expr->enum_member->type;
            assert(enum_type->kind == TYPE_ENUM);

            u8 op_size = primitive_size_of(enum_type->enumeration.value_primitive);

            if (enum_type->enumeration.name_table_data_offset == U64_MAX) {
                build_enum_member_name_table(context, enum_type);
            }

            register_allocator_enter_frame(context, reg_allocator);

            Register member_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, 0);
            machinecode_for_expr(context, fn, expr->enum_member, reg_allocator, x64_place_reg(member_reg));

            Register pointer_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, 0);

            {
                instruction_cmp_imm(context, x64_place_reg(member_reg), enum_type->enumeration.name_table_entries, op_size);
                u64 jge_location = instruction_jcc(context, COND_GE, 1);
                u64 jge_from = buf_length(context->seg_text);
                instruction_lea(context, (X64_Address) { .base = RIP_OFFSET_RDATA, .immediate_offset = enum_type->enumeration.name_table_data_offset }, pointer_reg);
                if (op_size == 1 || op_size == 2) {
                    instruction_movzx(context, x64_place_reg(member_reg), member_reg, op_size, POINTER_SIZE);
                }
                instruction_lea(context, (X64_Address) { .base = pointer_reg, .index = member_reg, .scale = 2 }, pointer_reg);
                instruction_mov_reg_mem(context, MOVE_FROM_MEM, (X64_Address) { .base = pointer_reg }, member_reg, 2);
                machinecode_cast(context, member_reg, member_reg, TYPE_U16, TYPE_U64);
                instruction_integer(context, INTEGER_ADD, MOVE_FROM_MEM, pointer_reg, x64_place_reg(member_reg), POINTER_SIZE);
                u64 jmp_location = instruction_jmp(context, sizeof(i8));
                u64 jge_to = buf_length(context->seg_text);
                u64 jmp_from = jge_to;
                instruction_lea(context, (X64_Address) { .base = RIP_OFFSET_RDATA, .immediate_offset = enum_type->enumeration.name_table_invalid_offset }, pointer_reg);
                u64 jmp_to = buf_length(context->seg_text);
                instruction_movzx(context, x64_place_address((X64_Address) { .base = pointer_reg }), member_reg, 2, POINTER_SIZE);
                instruction_integer_imm(context, INTEGER_ADD, x64_place_reg(pointer_reg), 2, POINTER_SIZE);

                assert(place.kind == PLACE_ADDRESS);
                X64_Address address = place.address;
                instruction_mov_reg_mem(context, MOVE_TO_MEM, address, pointer_reg, POINTER_SIZE);
                address.immediate_offset += POINTER_SIZE;
                instruction_mov_reg_mem(context, MOVE_TO_MEM, address, member_reg, POINTER_SIZE);

                *((i8*) (context->seg_text + jge_location)) = jge_to - jge_from;
                *((i8*) (context->seg_text + jmp_location)) = jmp_to - jmp_from;
            }

            register_allocator_leave_frame(context, reg_allocator);
        } break;
    }
}


typedef struct Negated_Jump_Info {
    u64 first_from;
    u64 first_text_location;

    u64 second_from;
    u64 second_text_location;
} Negated_Jump_Info;

Negated_Jump_Info machinecode_for_negated_jump(Context *context, Fn *fn, Expr *expr, Reg_Allocator *reg_allocator) { 
    bool invert = true;
    while (expr->kind == EXPR_UNARY && expr->unary.op == UNARY_NOT) {
        invert = !invert;
        expr = expr->unary.inner;
    }

    Condition condition;
    bool parity_check = false;

    if (expr->kind == EXPR_BINARY && BINARY_OP_COMPARATIVE[expr->binary.op]) {
        Expr *left  = expr->binary.left;
        Expr *right = expr->binary.right;
        assert(left->type->kind == right->type->kind);
        Type_Kind primitive = primitive_of(left->type);
        u8 primitive_size = primitive_size_of(primitive);


        if (primitive_is_float(primitive)) {
            bool single;
            if (primitive == TYPE_F32) {
                single = true;
            } else if (primitive == TYPE_F64) {
                single = false;
            } else {
                assert(false);
            }

            register_allocator_enter_frame(context, reg_allocator);

            Register left_reg = register_allocate(reg_allocator, REGISTER_KIND_XMM, 0);
            machinecode_for_expr(context, fn, left, reg_allocator, x64_place_reg(left_reg));

            Register right_reg = register_allocate(reg_allocator, REGISTER_KIND_XMM, 0);
            machinecode_for_expr(context, fn, right, reg_allocator, x64_place_reg(right_reg));

            int instruction;
            bool swap_operands = false;

            switch (expr->binary.op) {
                case BINARY_EQ:   instruction = FLOAT_UCOMI; condition = COND_E;  parity_check = true; break;
                case BINARY_NEQ:  instruction = FLOAT_UCOMI; condition = COND_NE; parity_check = true; break;
                case BINARY_GT:   instruction = FLOAT_COMI;  condition = COND_B;  swap_operands = true; break;
                case BINARY_GTEQ: instruction = FLOAT_COMI;  condition = COND_BE; swap_operands = true; break;
                case BINARY_LT:   instruction = FLOAT_COMI;  condition = COND_B;  break;
                case BINARY_LTEQ: instruction = FLOAT_COMI;  condition = COND_BE; break;
                default: assert(false);
            }

            if (condition == COND_B || condition == COND_BE) {
                if (invert) {
                    invert = false;
                    condition = condition == COND_B? COND_BE : COND_B;
                    swap_operands = !swap_operands;
                }
            }

            if (swap_operands) {
                instruction_float(context, instruction, right_reg, x64_place_reg(left_reg), single);
            } else {
                instruction_float(context, instruction, left_reg, x64_place_reg(right_reg), single);
            }

            register_allocator_leave_frame(context, reg_allocator);
        } else {
            condition = find_condition_for_op_and_type(expr->binary.op, primitive_is_signed(left->type->kind));

            register_allocator_enter_frame(context, reg_allocator);

            // TODO We need to special case when either the lhs and the rhs is a simple stack load, so that we 
            // use memory operands for the compare instruction in that case. Also, do a similar check for when
            // one of the sides is a literal

            u32 reserves_for_rhs = machinecode_expr_reserves(right);

            Register left_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, reserves_for_rhs);
            machinecode_for_expr(context, fn, left, reg_allocator, x64_place_reg(left_reg));

            Register right_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, 0);
            machinecode_for_expr(context, fn, right, reg_allocator, x64_place_reg(right_reg));

            instruction_cmp(context, x64_place_reg(left_reg), right_reg, primitive_size);

            register_allocator_leave_frame(context, reg_allocator);
        }
    } else {
        Type_Kind primitive = expr->type->kind;
        u8 primitive_size = primitive_size_of(primitive);

        Register reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, 0);
        machinecode_for_expr(context, fn, expr, reg_allocator, x64_place_reg(reg));
        instruction_cmp_imm(context, x64_place_reg(reg), 0, primitive_size);
        condition = COND_NE;
    }

    if (invert) {
        condition = condition_not(condition);
    }

    Negated_Jump_Info info = {0};

    if (parity_check) {
        if (condition == COND_E) {
            // jne foo
            // jp foo
            // jmp target
            // .foo

            u64 first_text_location = instruction_jcc(context, COND_NE, sizeof(i8));
            u64 first_from = buf_length(context->seg_text);
            u64 second_text_location = instruction_jcc(context, COND_P, sizeof(i8));
            u64 second_from = buf_length(context->seg_text);

            info.first_text_location = instruction_jmp(context, sizeof(i32));
            info.first_from = buf_length(context->seg_text);

            *((i8*) &context->seg_text[first_text_location])  = (i8) (info.first_from - first_from);
            *((i8*) &context->seg_text[second_text_location]) = (i8) (info.first_from - second_from);
        } else if (condition == COND_NE) {
            // jne target
            // jp target
            info.first_text_location = instruction_jcc(context, COND_NE, sizeof(i32));
            info.first_from = buf_length(context->seg_text);
            info.second_text_location = instruction_jcc(context, COND_P, sizeof(i32));
            info.second_from = buf_length(context->seg_text);
        } else {
            assert(false);
        }
    } else {
        // jcc target
        info.first_text_location = instruction_jcc(context, condition, sizeof(i32));
        info.first_from = buf_length(context->seg_text);
    }

    return info;
}

void machinecode_for_stmt(Context *context, Fn *fn, Stmt *stmt, Reg_Allocator *reg_allocator) {
    register_allocator_enter_frame(context, reg_allocator);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("; ");
    print_stmt(context, stmt, 0);
    #endif

    switch (stmt->kind) {
        case STMT_LET: {
            assert(stmt->let.var_count >= 1);

            Type *type = stmt->let.vars[0].type;
            u64 size = type_size_of(type);
            u64 align = type_align_of(type);

            if (!primitive_is_compound(primitive_of(type)) && stmt->let.var_count > 1) {
                u32 reserves = stmt->let.right == null? 0 : machinecode_expr_reserves(stmt->let.right);
                Register_Kind reg_kind = primitive_is_float(primitive_of(type))? REGISTER_KIND_XMM : REGISTER_KIND_GPR;
                Register reg = register_allocate(reg_allocator, reg_kind, reserves & RESERVE_RCX);

                if (stmt->let.right == null) {
                    machinecode_immediate_to_place(context, reg_allocator, x64_place_reg(reg), 0, size);
                } else {
                    machinecode_for_expr(context, fn, stmt->let.right, reg_allocator, x64_place_reg(reg));
                }

                for (u32 i = 0; i < stmt->let.var_count; i += 1) {
                    Var *var = &stmt->let.vars[i];
                    assert(!(var->flags & VAR_FLAG_REFERENCE));
                    assert(var->type == type);
                    X64_Address address = machinecode_address_for_var(context, reg_allocator, var);
                    machinecode_move(context, reg_allocator, x64_place_reg(reg), x64_place_address(address), size);
                }
            } else if (stmt->let.right == null) {
                for (u32 i = 0; i < stmt->let.var_count; i += 1) {
                    Var *var = &stmt->let.vars[i];
                    assert(!(var->flags & VAR_FLAG_REFERENCE));
                    assert(var->type == type);

                    X64_Address address = machinecode_address_for_var(context, reg_allocator, var);
                    machinecode_zero_out_struct(context, reg_allocator, address, size, align);
                }
            } else {
                Var *first_var = &stmt->let.vars[0];
                X64_Address first_address = machinecode_address_for_var(context, reg_allocator, first_var);
                machinecode_for_expr(context, fn, stmt->let.right, reg_allocator, x64_place_address(first_address));

                for (u32 i = 1; i < stmt->let.var_count; i += 1) {
                    Var *next_var = &stmt->let.vars[i];
                    assert(!(next_var->flags & VAR_FLAG_REFERENCE));
                    assert(next_var->type == type);
                    X64_Address next_address = machinecode_address_for_var(context, reg_allocator, next_var);
                    machinecode_move(context, reg_allocator, x64_place_address(first_address), x64_place_address(next_address), size);
                }
            }
        } break;

        case STMT_EXPR: {
            X64_Place nowhere = { .kind = PLACE_NOWHERE };
            machinecode_for_expr(context, fn, stmt->expr, reg_allocator, nowhere);
        } break;

        case STMT_ASSIGNMENT: {
            Expr *left  = stmt->assignment.left;
            Expr *right = stmt->assignment.right;
            Type *type = right->type;

            bool needs_temporary =
                primitive_is_compound(type->kind) &&
                !(right->kind == EXPR_VARIABLE || right->kind == EXPR_STRING_LITERAL);

            if (needs_temporary) {
                u64 size = type_size_of(type);
                u64 align = type_align_of(type);

                X64_Address tmp_address = register_allocator_temp_stack_space(reg_allocator, size, align);
                X64_Place tmp_place = { .kind = PLACE_ADDRESS, .address = tmp_address };

                machinecode_for_expr(context, fn, right, reg_allocator, tmp_place);

                X64_Place left_place = machinecode_for_addressable_expr(context, fn, left, reg_allocator, 0);
                machinecode_move(context, reg_allocator, tmp_place, left_place, size);
            } else {
                u32 reserves_for_rhs = machinecode_expr_reserves(right);
                X64_Place left_place = machinecode_for_addressable_expr(context, fn, left, reg_allocator, reserves_for_rhs);
                machinecode_for_expr(context, fn, right, reg_allocator, left_place);
            }
        } break;

        case STMT_OP_ASSIGNMENT: {
            Binary_Op op = stmt->op_assignment.op;
            Expr *left  = stmt->op_assignment.left;
            Expr *right = stmt->op_assignment.right;
            Type *type = left->type; // NB this has to be left->type, bc we can do 'pointer += int', but not 'int += pointer'

            bool needs_temporary =
                primitive_is_compound(type->kind) &&
                !(right->kind == EXPR_VARIABLE || right->kind == EXPR_STRING_LITERAL);
            assert(!needs_temporary);

            Expr binary_expr = {
                .kind = EXPR_BINARY,
                .type = type,
                .binary = { op, left, right },
            };

            u32 reserves = machinecode_expr_reserves(&binary_expr);
            X64_Place left_place = machinecode_for_addressable_expr(context, fn, left, reg_allocator, reserves);
            machinecode_for_expr(context, fn, &binary_expr, reg_allocator, left_place);
        } break;

        case STMT_BLOCK: {
            for (Stmt *inner = stmt->block.stmt; inner->kind != STMT_END; inner = inner->next) {
                machinecode_for_stmt(context, fn, inner, reg_allocator);
            }
        } break;

        case STMT_IF: {
            Negated_Jump_Info jump_info = machinecode_for_negated_jump(context, fn, stmt->if_.condition, reg_allocator);

            for (Stmt *inner = stmt->if_.then; inner->kind != STMT_END; inner = inner->next) {
                machinecode_for_stmt(context, fn, inner, reg_allocator);
            }

            u64 second_jump_text_location_index, second_jump_from;
            if (stmt->if_.else_then != null) {
                second_jump_text_location_index = instruction_jmp(context, sizeof(i32));
                second_jump_from = buf_length(context->seg_text);
            }

            {
                u64 jump_to = buf_length(context->seg_text);

                if (jump_info.first_from != 0) {
                    i64 first_jump_by = jump_to - jump_info.first_from;
                    assert(first_jump_by <= I32_MAX && first_jump_by >= I32_MIN);
                    i32 *first_jump_text_location = (i32*) (&context->seg_text[jump_info.first_text_location]);
                    *first_jump_text_location = first_jump_by;
                }

                if (jump_info.second_from != 0) {
                    i64 second_jump_by = jump_to - jump_info.second_from;
                    assert(second_jump_by <= I32_MAX && second_jump_by >= I32_MIN);
                    i32 *second_jump_text_location = (i32*) (&context->seg_text[jump_info.second_text_location]);
                    *second_jump_text_location = second_jump_by;
                }
            }

            if (stmt->if_.else_then != null) {
                for (Stmt *inner = stmt->if_.else_then; inner->kind != STMT_END; inner = inner->next) {
                    machinecode_for_stmt(context, fn, inner, reg_allocator);
                }

                i64 second_jump_by = ((i64) buf_length(context->seg_text)) - ((i64) second_jump_from);
                assert(second_jump_by <= I32_MAX && second_jump_by >= I32_MIN);
                i32 *second_jump_text_location = (i32*) (&context->seg_text[second_jump_text_location_index]);
                *second_jump_text_location = second_jump_by;
            }
        } break;

        case STMT_SWITCH: {
            // TODO actually generate a jump table here, if it is appropriate

            Type *index_type = stmt->switch_.index->type;
            u8 index_size = primitive_size_of(primitive_of(index_type));

            register_allocator_enter_frame(context, reg_allocator);
            Register index_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, 0);
            machinecode_for_expr(context, fn, stmt->switch_.index, reg_allocator, x64_place_reg(index_reg));
            register_allocator_leave_frame(context, reg_allocator);

            arena_stack_push(&context->stack);
            u64 jmp_index_count = 0;
            if (stmt->switch_.case_count > 1) {
                jmp_index_count = stmt->switch_.case_count - 1;
                if (stmt->switch_.default_case != null) jmp_index_count += 1;
            }
            u64 *jmp_indices = (u64*) arena_alloc(&context->stack, jmp_index_count * sizeof(u64));
            jmp_index_count = 0;

            for (u32 i = 0; i < stmt->switch_.case_count; i += 1) {
                Switch_Case *c = &stmt->switch_.cases[i];
                assert(c->key_count >= 1);

                u64 skip_jmp_index;

                if (c->key_count == 1) {
                    u64 key_value = c->keys[0].value;
                    instruction_cmp_imm(context, x64_place_reg(index_reg), key_value, index_size);
                    skip_jmp_index = instruction_jcc(context, COND_NE, sizeof(i32));
                } else {
                    u64 *forward_jmp_indices = (u64*) arena_alloc(&context->stack, c->key_count * sizeof(u64));

                    for (u32 j = 0; j < c->key_count; j += 1) {
                        u64 key_value = c->keys[j].value;
                        instruction_cmp_imm(context, x64_place_reg(index_reg), key_value, index_size);
                        forward_jmp_indices[j] = instruction_jcc(context, COND_E, sizeof(i8));
                    }

                    skip_jmp_index = instruction_jmp(context, sizeof(i32));

                    u64 forward_jmp_to = buf_length(context->seg_text);
                    for (u32 j = 0; j < c->key_count; j += 1) {
                        u64 forward_jmp_index = forward_jmp_indices[j];
                        i8 *forward_jmp_by = (i8*) (&context->seg_text[forward_jmp_index]);
                        *forward_jmp_by = forward_jmp_to - (forward_jmp_index + sizeof(i8));
                    }
                }

                for (Stmt *inner = c->body; inner->kind != STMT_END; inner = inner->next) {
                    machinecode_for_stmt(context, fn, inner, reg_allocator);
                }

                if (!(i + 1 == stmt->switch_.case_count && stmt->switch_.default_case == null)) {
                    jmp_indices[jmp_index_count] = instruction_jmp(context, sizeof(i32)); // jmp to end
                    jmp_index_count += 1;
                }

                u64 skip_jmp_to = buf_length(context->seg_text);
                i32 *skip_jmp_by = (i32*) (&context->seg_text[skip_jmp_index]);
                *skip_jmp_by = skip_jmp_to - (skip_jmp_index + sizeof(i32));
            }

            if (stmt->switch_.default_case != null) {
                Switch_Case *c = stmt->switch_.default_case;
                for (Stmt *inner = c->body; inner->kind != STMT_END; inner = inner->next) {
                    machinecode_for_stmt(context, fn, inner, reg_allocator);
                }
            }

            u64 jmp_to = buf_length(context->seg_text);
            for (u64 i = 0; i < jmp_index_count; i += 1) {
                u64 jmp_index = jmp_indices[i];
                i32 *jmp_by = (i32*) (&context->seg_text[jmp_index]);
                *jmp_by = jmp_to - (jmp_index + sizeof(i32));
            }
            arena_stack_pop(&context->stack);
        } break;

        case STMT_FOR: {
            u32 jump_fixup_ignore = buf_length(context->jump_fixups);

            u64 loop_start;
            if (stmt->for_.kind == LOOP_CONDITIONAL) {
                loop_start = buf_length(context->seg_text);

                Negated_Jump_Info jump_info = machinecode_for_negated_jump(context, fn, stmt->for_.condition, reg_allocator);

                if (jump_info.first_from != 0) {
                    buf_push(context->jump_fixups, ((Jump_Fixup) { .text_location = jump_info.first_text_location, .jump_from = jump_info.first_from, .jump_to = JUMP_TO_END_OF_LOOP }));
                }
                if (jump_info.second_from != 0) {
                    buf_push(context->jump_fixups, ((Jump_Fixup) { .text_location = jump_info.second_text_location, .jump_from = jump_info.second_from, .jump_to = JUMP_TO_END_OF_LOOP }));
                }
            } else if (stmt->for_.kind == LOOP_RANGE) {
                Var *var = stmt->for_.range.var;
                X64_Address index_address = reg_allocator->var_mem_infos[var->local_index].address;
                machinecode_for_expr(context, fn, stmt->for_.range.start, reg_allocator, x64_place_address(index_address));

                loop_start = buf_length(context->seg_text);

                register_allocator_enter_frame(context, reg_allocator);

                Register end_reg = register_allocate(reg_allocator, REGISTER_KIND_GPR, 0xffffffff);
                machinecode_for_expr(context, fn, stmt->for_.range.end, reg_allocator, x64_place_reg(end_reg));

                instruction_cmp(context, x64_place_address(index_address), end_reg, type_size_of(var->type));
                u64 jump_text_location = instruction_jcc(context, COND_GE, sizeof(i32));

                register_allocator_leave_frame(context, reg_allocator);

                buf_push(context->jump_fixups, ((Jump_Fixup) {
                    .text_location = jump_text_location,
                    .jump_from = buf_length(context->seg_text),
                    .jump_to = JUMP_TO_END_OF_LOOP
                }));

            } else if (stmt->for_.kind == LOOP_INFINITE) {
                loop_start = buf_length(context->seg_text);
            } else {
                assert(false);
            }

            for (Stmt *inner = stmt->for_.body; inner->kind != STMT_END; inner = inner->next) {
                machinecode_for_stmt(context, fn, inner, reg_allocator);
            }

            if (stmt->for_.kind == LOOP_RANGE) {
                Var *var = stmt->for_.range.var;
                X64_Address index_address = reg_allocator->var_mem_infos[var->local_index].address;
                instruction_inc_or_dec(context, true, x64_place_address(index_address), type_size_of(var->type));
            }

            u64 backward_jump_index = instruction_jmp(context, sizeof(i32));
            u64 loop_end = buf_length(context->seg_text);

            u64 jump_by = loop_end - loop_start;
            assert(jump_by < I32_MAX);
            *((i32*) &context->seg_text[backward_jump_index]) = -((i32) jump_by);

            u32 fixup_index = 0;

            buf_foreach (Jump_Fixup, fixup, context->jump_fixups) {
                fixup_index += 1;
                if (fixup_index <= jump_fixup_ignore) continue;

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
            if (stmt->return_.value != null) {
                register_allocator_enter_frame(context, reg_allocator);

                if (fn->signature->return_by_reference) {
                    register_allocate_specific(context, reg_allocator, RAX);
                    instruction_mov_reg_mem(context, MOVE_FROM_MEM, reg_allocator->return_value_address, RAX, POINTER_SIZE);
                    X64_Place return_location = x64_place_address((X64_Address) { .base = RAX });
                    machinecode_for_expr(context, fn, stmt->return_.value, reg_allocator, return_location);
                } else {
                    Register return_reg = primitive_is_float(fn->signature->return_type->kind)? XMM0 : RAX;
                    register_allocate_specific(context, reg_allocator, return_reg);
                    machinecode_for_expr(context, fn, stmt->return_.value, reg_allocator, x64_place_reg(return_reg));
                }

                register_allocator_leave_frame(context, reg_allocator);
            }

            if (!stmt->return_.trailing) {
                Jump_Fixup fixup = {0};
                fixup.text_location = instruction_jmp(context, sizeof(i32));
                fixup.jump_from = buf_length(context->seg_text);
                fixup.jump_to = JUMP_TO_END_OF_FUNCTION;
                buf_push(context->jump_fixups, fixup);
            }
        } break;

        case STMT_BREAK: {
            Jump_Fixup fixup = {0};
            fixup.text_location = instruction_jmp(context, sizeof(i32));
            fixup.jump_from = buf_length(context->seg_text);
            fixup.jump_to = JUMP_TO_END_OF_LOOP;
            buf_push(context->jump_fixups, fixup);
        } break;

        case STMT_CONTINUE: {
            assert(false); // TODO untested code
            Jump_Fixup fixup = {0};
            fixup.text_location = instruction_jmp(context, sizeof(i32));
            fixup.jump_from = buf_length(context->seg_text);
            fixup.jump_to = JUMP_TO_START_OF_LOOP;
            buf_push(context->jump_fixups, fixup);
        } break;

        case STMT_DEBUG_BREAK: {
            instruction_int3(context);
        } break;
    }

    register_allocator_leave_frame(context, reg_allocator);
}


void build_machinecode(Context *context) {
    arena_stack_push(&context->stack);

    // Builtins
    u32 runtime_builtin_text_starts[RUNTIME_BUILTIN_COUNT] = {0};

    // TODO we can optimize builtin mem copy/clear by using a bigger mov and looping fewer times.
    // We have to consider alignment then though...
    // The amd performance guide has a section on fast memory copies.

    { // mem clear
        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("\n; --- builtin mem clear ---\n");
        #endif

        // RAX is pointer to memory, RCX is count. Both are modified in the process
        
        runtime_builtin_text_starts[RUNTIME_BUILTIN_MEM_CLEAR] = buf_length(context->seg_text);

        u64 before_loop = buf_length(context->seg_text);
        u64 forward_jump_index = instruction_jrcxz(context);
        u64 loop_start = buf_length(context->seg_text);

        instruction_mov_imm_mem(context, (X64_Address) { .base = RAX }, 0, 1);
        instruction_inc_or_dec(context, true, x64_place_reg(RAX), POINTER_SIZE);
        instruction_inc_or_dec(context, false, x64_place_reg(RCX), POINTER_SIZE);

        u64 backward_jump_index = instruction_jmp(context, sizeof(i8));
        u64 loop_end = buf_length(context->seg_text);

        i8 forward_jump_by = loop_end - loop_start;
        i8 backward_jump_by = -((i8) (loop_end - before_loop));
        context->seg_text[forward_jump_index]  = *((u8*) &forward_jump_by);
        context->seg_text[backward_jump_index] = *((u8*) &backward_jump_by);

        instruction_ret(context);
    }

    { // mem copy
        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("\n; --- builtin mem copy ---\n");
        #endif

        // RAX is src pointer, RDX is dst pointer, RCX is count, RBX is clobbered.

        runtime_builtin_text_starts[RUNTIME_BUILTIN_MEM_COPY] = buf_length(context->seg_text);

        u64 before_loop = buf_length(context->seg_text);
        u64 forward_jump_index = instruction_jrcxz(context);
        u64 loop_start = buf_length(context->seg_text);

        instruction_mov_reg_mem(context, MOVE_FROM_MEM, (X64_Address) { .base = RAX }, RBX, 1);
        instruction_mov_reg_mem(context, MOVE_TO_MEM,   (X64_Address) { .base = RDX }, RBX, 1);
        instruction_inc_or_dec(context, true, x64_place_reg(RAX), POINTER_SIZE);
        instruction_inc_or_dec(context, true, x64_place_reg(RDX), POINTER_SIZE);
        instruction_inc_or_dec(context, false, x64_place_reg(RCX), POINTER_SIZE);

        u64 backward_jump_index = instruction_jmp(context, sizeof(i8));
        u64 loop_end = buf_length(context->seg_text);
        i8 forward_jump_by = loop_end - loop_start;
        i8 backward_jump_by = -((i8) (loop_end - before_loop));

        context->seg_text[forward_jump_index]  = *((u8*) &forward_jump_by);
        context->seg_text[backward_jump_index] = *((u8*) &backward_jump_by);

        instruction_ret(context);
    }


    Reg_Allocator reg_allocator = {0};
    reg_allocator.negate_f32_data_offset = U64_MAX;
    reg_allocator.negate_f64_data_offset = U64_MAX;

    // Initializing global variables
    Fn *global_init_fn = null;
    {
        Stmt *first_stmt = null;
        Stmt *last_stmt = null;

        buf_foreach (Global_Let, global_let, context->global_lets) {
            if (global_let->compute_at_runtime) {
                Global_Var *first_global = &context->global_vars[global_let->vars[0].global_index];

                Stmt *stmt = arena_new(&context->arena, Stmt);
                stmt->kind = STMT_LET;
                stmt->let.vars = global_let->vars;
                stmt->let.var_count = global_let->var_count;
                stmt->let.right = global_let->expr;
                last_stmt = (first_stmt == null? (first_stmt = stmt) : (last_stmt->next = stmt));
            }
        }

        if (first_stmt != null) {
            last_stmt->next = arena_new(&context->arena, Stmt);
            last_stmt->next->kind = STMT_END;

            global_init_fn = arena_new(&context->arena, Fn);
            global_init_fn->name = string_intern(&context->string_table, "__init_globals__");
            global_init_fn->kind = FN_KIND_NORMAL;
            global_init_fn->body.first_stmt = first_stmt;
            global_init_fn->signature_type = context->void_fn_signature;
            global_init_fn->signature = &global_init_fn->signature_type->fn_signature;

            buf_push(context->all_fns, global_init_fn);
        }
    }

    // Normal functions
    u8 *prolog = null; // stretchy-buffer, this is a huge hack :(

    Decl *main_fn_decl = find_declaration(&context->global_scope, string_intern(&context->string_table, "main"), DECL_FN);
    if (main_fn_decl == null) panic("No main function");
    Fn *main_fn = main_fn_decl->fn;
    assert(main_fn->kind == FN_KIND_NORMAL);

    buf_foreach (Fn*, fn_ptr, context->all_fns) {
        Fn *fn = *fn_ptr;
        if (fn->kind != FN_KIND_NORMAL) continue;

        u64 previous_call_fixup_count = buf_length(context->call_fixups);
        u64 previous_fixup_count = buf_length(context->fixups);

        fn->body.text_start = buf_length(context->seg_text);

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("\n\n; --- fn %s ---\n", fn->name);
        #endif

        // Lay out stack
        if (reg_allocator.allocated_var_mem_infos < fn->body.var_count) {
            u32 alloc_count = fn->body.var_count * 2;
            reg_allocator.allocated_var_mem_infos = alloc_count;
            reg_allocator.var_mem_infos = (void*) arena_alloc(&context->stack, alloc_count * sizeof(*reg_allocator.var_mem_infos));
        }
        mem_clear((u8*) reg_allocator.var_mem_infos, sizeof(*reg_allocator.var_mem_infos) * reg_allocator.allocated_var_mem_infos);
        mem_clear((u8*) reg_allocator.touched_registers, sizeof(reg_allocator.touched_registers));

        reg_allocator.max_callee_param_count = 0;

        // Parameters
        u32 effective_param_count = fn->signature->param_count;

        u32 input_offset = 0;
        if (fn->signature->return_by_reference) {
            reg_allocator.return_value_address = (X64_Address) { .base = RSP_OFFSET_INPUTS, .immediate_offset = 0 };
            input_offset += POINTER_SIZE;
            effective_param_count += 1;
        } else {
            reg_allocator.return_value_address = (X64_Address) {0};
        }

        for (u32 p = 0; p < fn->signature->param_count; p += 1) {
            Var *var = fn->body.param_var_mappings[p];

            X64_Address address = { .base = RSP_OFFSET_INPUTS, .immediate_offset = input_offset };
            input_offset += POINTER_SIZE;

            reg_allocator.var_mem_infos[var->local_index].size = POINTER_SIZE;
            reg_allocator.var_mem_infos[var->local_index].address = address;
        }

        // Variables
        i32 next_stack_offset = 0;
        for (u32 v = 0; v < fn->body.var_count; v += 1) {
            if (reg_allocator.var_mem_infos[v].address.base != REGISTER_NONE) continue; // Ignore parameters, see previous loop
            Var *var = fn->body.local_vars[v];

            u64 size = type_size_of(var->type);
            u64 align = type_align_of(var->type);

            next_stack_offset = (i32) round_to_next(next_stack_offset, align);
            X64_Address address = { .base = RSP_OFFSET_LOCALS, .immediate_offset = next_stack_offset };
            next_stack_offset += size;

            reg_allocator.var_mem_infos[v].size = size;
            reg_allocator.var_mem_infos[v].address = address;
        }

        reg_allocator.max_stack_size = next_stack_offset;
        if (reg_allocator.head != null) reg_allocator.head->stack_size = next_stack_offset;

        u64 insert_prolog_at_index = buf_length(context->seg_text);

        // Copy parameters onto stack
        bool skip_first_param_reg = false;

        if (fn->signature->return_by_reference) {
            skip_first_param_reg = true;

            Register reg = GPR_INPUT_REGISTERS[0];
            X64_Address address = reg_allocator.return_value_address;
            instruction_mov_reg_mem(context, MOVE_TO_MEM, address, reg, POINTER_SIZE);
        }

        for (u32 p = 0; p < min(fn->signature->param_count, INPUT_REGISTER_COUNT); p += 1) {
            Var *var = fn->body.param_var_mappings[p];
            X64_Address address = reg_allocator.var_mem_infos[var->local_index].address;

            u32 r = skip_first_param_reg? (p + 1) : p;

            if (fn->signature->params[p].reference_semantics) {
                Register reg = GPR_INPUT_REGISTERS[r];
                instruction_mov_reg_mem(context, MOVE_TO_MEM, address, reg, POINTER_SIZE);
            } else {
                u64 operand_size = type_size_of(fn->signature->params[p].type);

                if (operand_size > 0) {
                    assert(operand_size == 1 || operand_size == 2 || operand_size == 4 || operand_size == 8);

                    Type_Kind operand_primitive = primitive_of(fn->signature->params[p].type);
                    if (primitive_is_float(operand_primitive)) {
                        Register reg = XMM_INPUT_REGISTERS[r];
                        instruction_float_movd(context, MOVE_TO_MEM, reg, x64_place_address(address), operand_primitive == TYPE_F32);
                    } else {
                        Register reg = GPR_INPUT_REGISTERS[r];
                        instruction_mov_reg_mem(context, MOVE_TO_MEM, address, reg, (u8) operand_size);
                    }
                }
            }
        }

        // Write out operations
        if (fn == main_fn && global_init_fn != null) {
            instruction_call(context, global_init_fn);
        }

        for (Stmt* stmt = fn->body.first_stmt; stmt->kind != STMT_END; stmt = stmt->next) {
            machinecode_for_stmt(context, fn, stmt, &reg_allocator);
        }

        buf_foreach (Jump_Fixup, fixup, context->jump_fixups) {
            assert(fixup->jump_to == JUMP_TO_END_OF_FUNCTION);

            i64 jump_by = ((i64) buf_length(context->seg_text)) - ((i64) fixup->jump_from);
            assert(jump_by <= I32_MAX && jump_by >= I32_MIN);

            i32 *jump_text_location = (i32*) (&context->seg_text[fixup->text_location]);
            *jump_text_location = jump_by;
        }
        buf_clear(context->jump_fixups);

        // Prolog, epilog, fix stack acceses
        u32 preserved_registers = 0;
        for (u32 i = 0; i < NONVOLATILE_REGISTER_COUNT; i += 1) {
            Register reg = NONVOLATILE_REGISTERS[i];
            if (reg_allocator.touched_registers[reg]) {
                preserved_registers += 1;
            }
        }

        X64_Address preserved_reg_address = {0};
        if (preserved_registers > 0) {
            preserved_reg_address = register_allocator_temp_stack_space(&reg_allocator, preserved_registers*POINTER_SIZE, POINTER_SIZE);
        }

        u64 stack_space_for_params = 0;
        if (reg_allocator.max_callee_param_count > 0) {
            stack_space_for_params = POINTER_SIZE * max(reg_allocator.max_callee_param_count, 4);
        }
        u64 total_stack_bytes = ((u64) reg_allocator.max_stack_size) + stack_space_for_params;
        total_stack_bytes = ((total_stack_bytes + 7) & (~0x0f)) + 8; // Aligns so last nibble is 8


        if (preserved_registers > 0) {
            assert(preserved_reg_address.base == RSP_OFFSET_LOCALS);
            preserved_reg_address.base = RSP;
            preserved_reg_address.immediate_offset += stack_space_for_params;
        }

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

        // Build epilog
        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("; (epilog)\n");
        #endif

        X64_Address restore_address = preserved_reg_address;
        for (u32 i = 0; i < NONVOLATILE_REGISTER_COUNT; i += 1) {
            Register reg = NONVOLATILE_REGISTERS[i];
            if (reg_allocator.touched_registers[reg]) {
                if (is_gpr(reg)) {
                    instruction_mov_reg_mem(context, MOVE_FROM_MEM, restore_address, reg, POINTER_SIZE);
                } else if (is_xmm(reg)) {
                    instruction_float_movd(context, MOVE_FROM_MEM, reg, x64_place_address(restore_address), false);
                } else {
                    assert(false);
                }
                restore_address.immediate_offset += POINTER_SIZE;
            }
        }

        if (total_stack_bytes > 0) {
            instruction_integer_imm(context, INTEGER_ADD, x64_place_reg(RSP), total_stack_bytes, POINTER_SIZE);
        }

        if (!fn->signature->has_return) {
            instruction_integer(context, INTEGER_XOR, MOVE_FROM_MEM, RAX, x64_place_reg(RAX), POINTER_SIZE);
        }

        instruction_ret(context);

        // Build and prefix prolog
        buf_clear(prolog);
        u8 *text = context->seg_text;
        context->seg_text = prolog;
        {
            #ifdef PRINT_GENERATED_INSTRUCTIONS
            printf("; (prolog, actually inserted at start of function)\n");
            #endif

            if (total_stack_bytes > 0) {
                instruction_integer_imm(context, INTEGER_SUB, x64_place_reg(RSP), total_stack_bytes, POINTER_SIZE);
            }

            X64_Address save_address = preserved_reg_address;
            for (u32 i = 0; i < NONVOLATILE_REGISTER_COUNT; i += 1) {
                Register reg = NONVOLATILE_REGISTERS[i];
                if (reg_allocator.touched_registers[reg]) {
                    if (is_gpr(reg)) {
                        instruction_mov_reg_mem(context, MOVE_TO_MEM, save_address, reg, POINTER_SIZE);
                    } else if (is_xmm(reg)) {
                        instruction_float_movd(context, MOVE_TO_MEM, reg, x64_place_address(save_address), false);
                    } else {
                        assert(false);
                    }
                    save_address.immediate_offset += POINTER_SIZE;
                }
            }
        }
        prolog = context->seg_text;
        context->seg_text = text;

        u64 prolog_length = buf_length(prolog);
        u8 *insert_prolog_here = str_make_space(&context->seg_text, insert_prolog_at_index, prolog_length);
        mem_copy(prolog, insert_prolog_here, prolog_length);

        for (u64 i = previous_call_fixup_count; i < buf_length(context->call_fixups); i += 1) {
            Call_Fixup *fixup = &context->call_fixups[i];
            fixup->text_location += prolog_length;
        }
        for (u64 i = previous_fixup_count; i < buf_length(context->fixups); i += 1) {
            Rip_Fixup *fixup = &context->fixups[i];
            fixup->rip_offset += prolog_length;
            fixup->next_instruction += prolog_length;
        }
    }

    buf_free(prolog);

    // Call fixups
    buf_foreach (Call_Fixup, fixup, context->call_fixups) {
        i32* target = (i32*) (context->seg_text + fixup->text_location);
        assert(*target == 0xdeadbeef);

        u32 jump_to;
        if (fixup->builtin) {
            jump_to = runtime_builtin_text_starts[fixup->builtin_index];
        } else {
            assert(fixup->fn->kind == FN_KIND_NORMAL);
            jump_to = fixup->fn->body.text_start;
        }

        u32 jump_from = fixup->text_location + sizeof(i32);
        i32 jump_by = ((i32) jump_to) - ((i32) jump_from);
        *target = jump_by;
    }
    buf_free(context->call_fixups);

    arena_stack_push(&context->stack);
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

    u32 checksum; // Not checked for executables
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

void parse_lib_paths_from_env_variable(Context *context) {
    assert(context->lib_paths == null);
    assert(context->lib_path_count == 0);

    arena_stack_push(&context->stack);

    u32 lib_string_length = GetEnvironmentVariableA("LIB", null, 0);
    if (lib_string_length == 0) {
        printf("%%LIB%% is not set. External libraries won't be usable\n");
        context->lib_paths = (void*) arena_alloc(&context->arena, 0); // So we know we tried parsing %LIB%
        return;
    }
    u8 *lib_string = arena_alloc(&context->stack, lib_string_length);
    u32 actual_length = GetEnvironmentVariableA("LIB", lib_string, lib_string_length);
    lib_string_length -= 1;
    assert(actual_length == lib_string_length);

    context->lib_path_count = 1;
    for (u32 i = 0; i < lib_string_length; i += 1) {
        if (lib_string[i] == ';') {
            context->lib_path_count += 1;
        }
    }

    context->lib_paths = (void*) arena_alloc(&context->arena, sizeof(u8*) * context->lib_path_count);

    u8 *substring_start = lib_string;
    u32 substring_length = 0;
    u32 substring_index = 0;
    for (u32 i = 0; /* ... */; i += 1) {
        if (i >= lib_string_length || lib_string[i] == ';') {
            u8 *string = substring_start;
            u32 length = substring_length - 1;
            while (length > 0 && (string[0] == ' ' || string[0] == '"')) {
                string += 1;
                length -= 1;
            }
            while (length > 0 && (string[length - 1] == ' ' || string[length - 1] == '"')) {
                length -= 1;
            }
            if (length > 0) {
                context->lib_paths[substring_index] = make_null_terminated(&context->arena, string, length);
                substring_index += 1;
            }

            substring_start = &lib_string[i + 1];
            substring_length = 0;

            if (i >= lib_string_length) break;
        }

        substring_length += 1;
    }

    assert(context->lib_path_count >= substring_index);
    context->lib_path_count = substring_index;

    arena_stack_pop(&context->stack);
}

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

    if (*cursor_length > 0 && (member_size&1 == 1)) {
        assert(**cursor == '\n');
        *cursor += 1;
        *cursor_length -= 1;
    }

    return true;
}

bool parse_library(Context *context, Library_Import* import) {
    arena_stack_push(&context->stack);

    u8 *raw_lib_name = import->lib_name;
    u8 *source_path = import->importing_source_file;
    u8 *source_folder = path_get_folder(&context->stack, source_path);
    u8 *path = path_join(&context->stack, source_folder, raw_lib_name);

    u8 *file;
    u32 file_length;

    IO_Result read_result;

    read_result = read_entire_file(path, &file, &file_length);

    if (read_result == IO_NOT_FOUND) {
        if (context->lib_paths == null) {
            // TODO In the future, can we figure out how to do this without checking %LIB%?
            parse_lib_paths_from_env_variable(context);
        }

        for (u32 i = 0; i < context->lib_path_count; i += 1) {
            u8 *system_lib_folder = context->lib_paths[i];
            path = path_join(&context->stack, system_lib_folder, raw_lib_name);
            read_result = read_entire_file(path, &file, &file_length);
        }
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
            u8 *specified_name = import->function_names[j];

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
                    u8 other_dll_name[17] = {0};

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
            u8 *name = import->function_names[i];
            printf("Couldn't find %s in \"%s\"\n", name, path);
            return false;
        }
    }

    sc_free(file);
    arena_stack_pop(&context->stack);
    return true;

    invalid:
    sc_free(file);
    printf("Couldn't load \"%s\": Invalid archive\n", path);
    arena_stack_pop(&context->stack);
    return false;
}

bool write_pdb(u8 *path, Context *context) {
    /*
    u32 block_size = 4096;
    u32 allocated_blocks = 1000;
    u8 *data = alloc(block_size * allocated_blocks);

    struct {
        u8 magic[32];
        u32 block_size;
        u32 fpm_block; // free page map
        u32 block_count;
        u32 directory_bytes_count;
        u32 unkown;
        u32 block_map_address;
    } *superblock = data[0];

    u8 magic_a[24] = "Microsoft C/C++ MSF 7.00";
    u8 magic_b[8]  = { 0x0d, 0x0a, 0x1a, 0x44, 0x53, 0x00, 0x00, 0x00 };
    mem_copy(magic_a, superblock->magic, sizeof(magic_a));
    mem_copy(magic_b, superblock->magic + sizeof(magic_a), sizeof(magic_b));

    superblock->block_size = block_size;
    superblock->block_count = 4; // superblock, fpm, stream directory address, stream directory
    superblock->fpm_block = 1; // I don't think we need this if we don't write anything...
    superblock->block_map_address = 2; // Block containing indices of other blocks which contain directory bytes

    u32 *block_map_address_data = (u32*) (&data[superblock->block_map_address * block_size]);
    *block_map_address_data = 3;

    u32 *stream_directory_data = (u32*) (&data[*block_map_address_data * block_size]);
    superblock->directory_bytes_count = 0;
    assert(superblock->directory_bytes_count < block_size); // We just allocated one block for the stream directory
    //struct {
    //  u32 streams;
    //  u32 stream_sizes[streams];
    //  u32 stream_blocks[streams][];
    //};
    *stream_directory_data += 1;
    *stream_directory_data[1] = 0;
    *stream_directory_data[2] = *block_map_address_data;

    IO_Result result = write_entire_file(path, data, data_size);
    sc_free(data);
    if (result != IO_OK) {
        printf("Couldn't write \"%s\": %s\n", path, io_result_message(result));
        return false;
    } else {
        return true;
    }
    */
    unimplemented();
    return false;
}

bool write_executable(u8 *path, u8 *debug_path, Context *context) {
    enum { MAX_SECTION_COUNT = 3 }; // So we can use it as an array length

    u64 text_length = buf_length(context->seg_text);
    u64 data_length = buf_length(context->seg_data);

    u32 section_count = 1; // .text
    if (data_length > 0) section_count += 1;
    if (buf_length(context->seg_rdata) > 0 || debug_path != null || !buf_empty(context->imports)) section_count += 1;

    u64 in_file_alignment = 0x200;
    // NB If this becomes lower than the page size, stuff like page protection won't work anymore. That will also
    // disable address space layout randomization.
    u64 in_memory_alignment = 0x1000;

    u64 dos_prepend_size = 200;
    u64 total_header_size = dos_prepend_size + sizeof(COFF_Header) + sizeof(Image_Header) + section_count*sizeof(Section_Header);

    // Figure out placement and final size
    // NB sections data needs to be in the same order as section headers!
    u64 header_space = round_to_next(total_header_size, in_file_alignment);

    u64 text_file_start  = header_space;
    u64 data_file_start  = text_file_start + round_to_next(text_length, in_file_alignment);
    u64 rdata_file_start = data_file_start + round_to_next(data_length, in_file_alignment);

    u64 text_memory_start  = round_to_next(total_header_size, in_memory_alignment);
    u64 data_memory_start  = text_memory_start + round_to_next(text_length, in_memory_alignment);
    u64 rdata_memory_start = data_memory_start + round_to_next(data_length, in_memory_alignment);

    u8 *rdata = context->seg_rdata; // We need to append imports and debug info into .rdata

    // Write debug info into .rdata
    u32 debug_size = 0;
    u32 rdata_debug_offset = 0;

    if (debug_path != null) {
        u8 *pdb_path = debug_path;
        u32 pdb_path_length = str_length(pdb_path);

        if (!write_pdb(pdb_path, context)) {
            return false;
        }

        // Points to a .pdb file
        u32 rsds_pointer_offset = buf_length(rdata);
        struct {
            u8 magic[4];
            u8 guid[16]; // Unique per machine, should match .pdb
            u32 age;
        } rsds_pointer = { { 'R', 'S', 'D', 'S' } };
        //rsds_pointer.guid = ; // TODO
        rsds_pointer.age = 1; // By always setting this to 1, we only check the guid
        str_push_str(&rdata, (u8*) &rsds_pointer, sizeof(rsds_pointer));
        str_push_str(&rdata, pdb_path, pdb_path_length);
        buf_push(rdata, 0);

        struct {
            u32 characteristics;
            u32 unix_timestamp;
            u16 major_version;
            u16 minor_version;
            u32 type;
            u32 size_of_data;
            u32 data_memory_pos;
            u32 data_file_pos;
        } debug_directory = {0};
        debug_directory.unix_timestamp = unix_time();
        debug_directory.type = 0x02;
        debug_directory.size_of_data = sizeof(rsds_pointer) + pdb_path_length + 1;
        debug_directory.data_memory_pos = rdata_memory_start + rsds_pointer_offset;
        debug_directory.data_file_pos = rdata_file_start + rsds_pointer_offset;
        str_push_str(&rdata, (u8*) &debug_directory, sizeof(debug_directory));

        // These go in 'image_header.data_directories[6]'
        rdata_debug_offset = buf_length(rdata);
        debug_size = sizeof(debug_directory);
    }

    // Write import data into .rdata

    u64 rdata_import_offset = buf_length(rdata);
    u64 import_header_size;

    if (!buf_empty(context->imports)) {
        typedef struct Import_Entry {
            u32 lookup_table_address;
            u32 timestamp;
            u32 forwarder_chain;
            u32 name_address;
            u32 address_table_address;
        } Import_Entry;

        import_header_size = (buf_length(context->imports) + 1) * sizeof(Import_Entry);
        str_push_zeroes(&rdata, import_header_size);
        for (u64 i = 0; i < buf_length(context->imports); i += 1) {
            Library_Import* import = &context->imports[i];
            if (!parse_library(context, import)) {
                return false;
            }

            assert(import->dll_name != null);

            u64 table_size = sizeof(u64) * (1 + buf_length(import->function_names));
            u64 address_table_start = buf_length(rdata);
            u64 lookup_table_start = address_table_start + table_size;

            str_push_zeroes(&rdata, 2*table_size); // Make space for the address & lookup table

            u64 name_table_start = buf_length(rdata);
            str_push_cstr(&rdata, import->dll_name);
            buf_push(rdata, 0);

            for (u64 j = 0; j < buf_length(import->function_names); j += 1) {
                u64 function_name_address = rdata_memory_start + buf_length(rdata);
                if ((function_name_address & 0x7fffffff) != function_name_address) {
                    panic("Import data will be invalid, because it has functions at to high rvas: %x!", function_name_address);
                }

                u8 *name = import->function_names[j];
                u16 hint = import->function_hints[j];

                buf_push(rdata, (u8) (hint & 0xff));
                buf_push(rdata, (u8) ((hint >> 8) & 0xff));
                str_push_cstr(&rdata, name);
                buf_push(rdata, 0);
                if (buf_length(rdata) & 1) { buf_push(rdata, 0); } // align

                *((u64*) (rdata + address_table_start + sizeof(u64)*j)) = function_name_address;
                *((u64*) (rdata + lookup_table_start  + sizeof(u64)*j)) = function_name_address;
            }

            // Write into the space we prefilled before the loop
            Import_Entry* entry = (void*) (rdata + rdata_import_offset + i*sizeof(Import_Entry));
            entry->address_table_address = rdata_memory_start + address_table_start;
            entry->lookup_table_address  = rdata_memory_start + lookup_table_start;
            entry->name_address          = rdata_memory_start + name_table_start;

            // Apply fixups for this library
            buf_foreach (Rip_Fixup, fixup, context->fixups) {
                if (fixup->kind != RIP_FIXUP_IMPORT_CALL || fixup->import_index.library != i) continue;
                assert(fixup->rip_offset + 4 <= fixup->next_instruction);

                u32 function = fixup->import_index.function;
                u64 function_address = rdata_memory_start + address_table_start + sizeof(u64)*function;

                i32* text_value = (i32*) (context->seg_text + fixup->rip_offset);
                assert(*text_value == 0xdeadbeef);
                *text_value = function_address - (text_memory_start + fixup->next_instruction);
            }
        }
    }

    // Knowing rdata size, we can compute final size
    u64 rdata_length = buf_length(rdata);
    u64 file_image_size   = rdata_file_start   + round_to_next(rdata_length, in_file_alignment);
    u64 memory_image_size = rdata_memory_start + round_to_next(rdata_length, in_memory_alignment);

    // Apply .data and .rdata fixups
    buf_foreach (Rip_Fixup, fixup, context->fixups) {
        u32 seg_length, seg_memory_start;
        if (fixup->kind == RIP_FIXUP_DATA) {
            seg_length = data_length;
            seg_memory_start = data_memory_start;
        } else if (fixup->kind == RIP_FIXUP_RDATA) {
            seg_length = rdata_length;
            seg_memory_start = rdata_memory_start;
        } else {
            continue;
        }

        assert(fixup->data_offset < seg_length);
        assert(fixup->rip_offset + 4 <= fixup->next_instruction);

        i32 *text_value = (u32*) (context->seg_text + fixup->rip_offset);
        assert(*text_value == 0xdeadbeef);
        *text_value = seg_memory_start + fixup->data_offset - (text_memory_start + fixup->next_instruction);
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

    if (rdata_length > 0) {
        Section_Header* rdata_header = &section_headers[section_index];
        section_index += 1;
        mem_copy(".rdata", rdata_header->name, 6);
        rdata_header->flags = SECTION_FLAGS_READ | SECTION_FLAGS_INITIALIZED_DATA;
        rdata_header->virtual_size = rdata_length;
        rdata_header->virtual_address = rdata_memory_start;
        rdata_header->size_of_raw_data = round_to_next(rdata_length, in_file_alignment);
        rdata_header->pointer_to_raw_data = rdata_file_start;
    }

    // Allocate space and fill in the image
    u8* output_file = sc_alloc(file_image_size);
    mem_clear(output_file, file_image_size);

    u8 dos_prepend[200] = {
        0x4d, 0x5a, 0x90, 0x0, 0x3, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0xff, 0xff, 0x0, 0x0, 0xb8,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, // <- dos_prepend_size goes in these four bytes
        0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
        0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e,
        0x6f, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f,
        0x53, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a, 0x24, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x00, 0x11, 0xba, 0x01, 0xc7, 0x55, 0xdb, 0x6f, 0x94, 0x55, 0xdb, 0x6f, 0x94, 0x55, 0xdb,
        0x6f, 0x94, 0x26, 0xb9, 0x6e, 0x95, 0x56, 0xdb, 0x6f, 0x94, 0x55, 0xdb, 0x6e, 0x94, 0x56,
        0xdb, 0x6f, 0x94, 0xb2, 0xbf, 0x6b, 0x95, 0x54, 0xdb, 0x6f, 0x94, 0xb2, 0xbf, 0x6d, 0x95,
        0x54, 0xdb, 0x6f, 0x94, 0x52, 0x69, 0x63, 0x68, 0x55, 0xdb, 0x6f, 0x94, 0x0, 0x0, 0x0, 0x0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
    image.size_of_initialized_data = data_length + rdata_length;
    image.size_of_uninitialized_data = 0;

    Decl *main_fn_decl = find_declaration(&context->global_scope, string_intern(&context->string_table, "main"), DECL_FN);
    if (main_fn_decl == null) panic("No main function");
    Fn *main_fn = main_fn_decl->fn;
    assert(main_fn_decl->fn->kind == FN_KIND_NORMAL);
    u32 main_text_start = main_fn_decl->fn->body.text_start;
    image.entry_point = text_memory_start + main_text_start;

    image.base_of_code = text_memory_start;
    image.size_of_image = memory_image_size;
    image.image_base = 0x00400000;

    image.stack_reserve = 0x100000;
    image.stack_commit  = 0x100000;
    image.heap_reserve  = 0x100000;
    image.heap_commit   = 0x100000;

    image.number_of_rva_and_sizes = 16;
    if (import_header_size > 0) {
        image.data_directories[1].virtual_address = rdata_memory_start + rdata_import_offset;
        image.data_directories[1].size = import_header_size;
    }
    image.data_directories[6].virtual_address = rdata_memory_start + rdata_debug_offset;
    image.data_directories[6].size = debug_size;

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
    mem_copy(rdata, output_file + rdata_file_start, rdata_length);

    IO_Result result = write_entire_file(path, output_file, file_image_size);
    if (result != IO_OK) {
        printf("Couldn't write \"%s\": %s\n", path, io_result_message(result));
        return false;
    }

    buf_free(rdata);

    return true;
}

bool run_executable(u8 *exe_path) {
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

void print_usage() {
    printf("Usage:  sea <source> <executable> [flags]\n");
    printf("Flags:\n");
    printf("    -r    Run generated executable\n");
    printf("    -d    Generate debug info\n");
}

void main() {
    Arena arena = {0};

    u8 *command_line = GetCommandLineA();
    eat_word(&command_line); // skip executable name

    u8 *source_name = command_line;
    u64 source_name_length = eat_word(&command_line);
    source_name = make_null_terminated(&arena, source_name, source_name_length);

    if (source_name_length == 0) {
        printf("No source name given\n");
        print_usage();
        return;
    }

    u8 *exe_name = command_line;
    u64 exe_name_length = eat_word(&command_line);
    exe_name = make_null_terminated(&arena, exe_name, exe_name_length);

    if (exe_name_length == 0) {
        printf("No executable name given\n");
        print_usage();
        return;
    }

    bool run_after_compile = false;
    u8 *debug_name = null;

    while (true) {
        u8* flag = command_line;
        u64 flag_length = eat_word(&command_line);
        if (flag_length == 0) break;

        bool found_match = false;
        if (flag_length == 2 && flag[0] == '-') {
            found_match = true;

            u8 c = flag[1];
            switch (c) {
                case 'r': {
                    run_after_compile = true;
                } break;

                case 'd': {
                    debug_name = str_join(&arena, exe_name, ".pdb");
                } break;

                default: {
                    found_match = false;
                } break;
            }
        }

        if (!found_match) {
            printf("Unkown flag: %z\n", flag_length, flag);
            print_usage();
            return;
        }
    }

    printf("Compiling %s to %s\n", source_name, exe_name);
    if (debug_name != null) {
        printf("Writing debug info to %s\n", debug_name);
    }

    i64 start = perf_time();

    Context context = {0};
    context.arena = arena;
    if (!build_ast(&context, source_name)) return;
    if (!typecheck(&context)) return;
    build_machinecode(&context);
    if (!write_executable(exe_name, debug_name, &context)) return;

    i64 end = perf_time();
    i64 time_in_ms = (end - start)*1000 / perf_frequency;

    printf("Generated %u bytes of machine code\n", buf_length(context.seg_text));
    printf("Compiled in %i ms\n", time_in_ms);

    if (run_after_compile) {
        run_executable(exe_name);
    }
}
