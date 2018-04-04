
// This is the program we try to dissasemble

typedef void* Handle;

#define WINAPI_PRE  __declspec(dllimport)
#define WINAPI_POST __stdcall

WINAPI_PRE void WINAPI_POST ExitProcess(unsigned __int32 exit_code);
WINAPI_PRE Handle WINAPI_POST GetStdHandle(unsigned __int32 key);
WINAPI_PRE int WINAPI_POST WriteFile(
    Handle file,
    void* buffer,
    unsigned __int32 bytes_to_write,
    unsigned __int32* bytes_written,
    void* overlapped // We don't use this, let it be nil
);

void main() {
    unsigned __int8* text = "Gh\n"; 
    text[0] += 1;
    text[1] += 1;

    Handle handle = GetStdHandle((unsigned __int32) -11);
    unsigned __int32 written = 0;
    WriteFile(handle, text, 3, &written, 0);
    ExitProcess(0);
}
