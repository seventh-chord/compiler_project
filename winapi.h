
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

typedef struct STARTUPINFO STARTUPINFO;
typedef struct PROCESSINFO PROCESSINFO;

WINAPI_PRE bool WINAPI_POST CreateProcessA(
  u8* application_name,
  u8* arguments,
  void* process_attributes,
  void* thread_attributes,
  bool inherit_handles,
  u32 creation_flags,
  void* environment,
  u8* current_directory,
  STARTUPINFO* startup_info,
  PROCESSINFO* process_info
);

struct STARTUPINFO {
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

struct PROCESSINFO {
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
