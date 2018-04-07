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

#define max(a, b)  ((a) > (b)? (a) : (b))

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
#define assert(x)        ((x)? (null) : (printf("assert(%s) failed, %s:%u\n", #x, __FILE__, __LINE__), ExitProcess(-1), null))
#define panic(x, ...)    (printf(x, __VA_ARGS__), ExitThread(-1))
#define unimplemented()  (printf("Reached unimplemented code at %s:%u\n", __FILE__, __LINE__), ExitProcess(-1), null)


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

// Stretchy buffers

typedef struct Buf_Header {
    u64 length;
    u64 capacity;
    u8 buffer[0];
} Buf_Header;

#define BUF_HEADER_SIZE 16

#define _buf_header(b)     ((Buf_Header*) ((u8*) b - BUF_HEADER_SIZE))
#define buf_length(b)      ((b)? _buf_header(b)->length : 0)
#define buf_capacity(b)    ((b)? _buf_header(b)->capacity : 0)
#define _buf_fits(b, n)    (buf_length(b) + (n) <= buf_capacity(b))
#define _buf_fit(b, n)     (_buf_fits(b, n)? 0 : ((b) = _buf_grow(b, buf_length(b) + (n), sizeof(*b))))
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

// Arenas
// Pointers remain valid throughout entire lifetime, but you can't remove individual
// elements, only append to the end.

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

void arena_push(Arena* arena) {
    Arena_Stack_Frame new_frame = {0};
    new_frame.head = arena->current_page;
    new_frame.head_used = arena->current_page? arena->current_page->used : 0;
    new_frame.parent = arena_insert_with_size(arena, &arena->frame, sizeof(Arena_Stack_Frame));
    arena->frame = new_frame;
}

void arena_pop(Arena* arena) {
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

// String interning

const u32 STRING_TABLE_NO_MATCH = 0xffffffff;

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

    va_list args;
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


#define BRACKET_CURLY  0
#define BRACKET_ROUND  1
#define BRACKET_SQUARE 2

typedef struct Token {
    enum {
        token_end_of_stream = 0,

        token_identifier,
        token_literal,

        token_operator,
        token_line_end,
        token_bracket,

        token_keyword_var,
        token_keyword_fn,
    } kind;

    union {
        u32 identifier_string_table_index;
        u32 literal_value;
        u8 operator_symbol;
        struct { u8 kind; u8 open; } bracket;
    };

    File_Pos pos;
} Token;


#define BINARY_ADD 0
#define BINARY_SUB 1
#define BINARY_MUL 2
#define BINARY_DIV 3

#define EXPR_FLAG_UNRESOLVED 0x01
#define EXPR_FLAG_UNRESOLVED_CHILDREN 0x02
#define EXPR_FLAG_ANY_UNRESOLVED (EXPR_FLAG_UNRESOLVED | EXPR_FLAG_UNRESOLVED_CHILDREN)

typedef struct Expr Expr;
struct Expr {
    // TODO use a u8 instead of a full enum here, which saves us a bunch of space
    enum {
        expr_variable,
        expr_literal,
        expr_binary,
        expr_call,
    } kind;

    u8 flags;

    union {
        u32 variable;
        u32 literal;

        struct { u8 op; Expr* left; Expr* right; } binary;

        // Discriminated by EXPR_FLAG_UNRESOLVED
        union { u32 unresolved_name; u32 func_index; } call;
    };
};

typedef struct Stmt {
    enum {
        stmt_end_of_stream = 0,
        stmt_assignment,
    } kind;

    union {
        struct { u32 var; Expr* expr; } assignment;
    };
} Stmt;


typedef struct Var {
    u32 name;
    File_Pos declaration_pos;
} Var;


typedef struct Func {
    u32 name;

    // NB 'last_*' is not inclusive (invalid or points to sentinel), if 'first_* == last_*' there are no elements
    u32 first_var, last_var;
    u32 first_stmt, last_stmt;
    u32 first_op, last_op;

    u32 bytecode_start;
} Func;


typedef struct Local {
    enum { local_temporary, local_variable } kind;
    u32 index; // either variable index of temporary nubmer
} Local;

inline bool local_cmp(Local a, Local b) {
    return a.kind == b.kind && a.index == b.index;
}

typedef struct Op_Binary_Operands {
    // NB (Morten, 07.04.18) 
    // There are some restrictions on which operators can have literal operands. We have assertions
    // to ensure this holds at runtime.
    // Currently, mul & div can't have a literal source, due to x64 restrictions.

    enum { op_source_literal, op_source_local } source_kind;
    union { u32 literal; Local local; } source;
    Local target;
} Op_Binary_Operands;

#define OP_KIND_BINARY_FLAG 0x80

typedef struct Op {
    enum {
        op_end_of_stream = 0,
        op_end_of_function = 1,
        op_reset_temporaries = 2,

        op_call = 3,
 
        // 'binary'
        op_set = 0 | OP_KIND_BINARY_FLAG,
        op_add = 1 | OP_KIND_BINARY_FLAG,
        op_sub = 2 | OP_KIND_BINARY_FLAG,
        op_mul = 3 | OP_KIND_BINARY_FLAG,
        op_div = 4 | OP_KIND_BINARY_FLAG,
    } kind;

    union {
        Op_Binary_Operands binary;

        struct {
            u32 func_index;
            Local target;
        } call;
    };
} Op;



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
    u32 stack_offset;
    u32 element_size;
} Stack_Fixup;

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
u8* reg_names[REG_COUNT] = { "eax", "ecx", "edx", "ebx" };

typedef struct Reg {
    bool used;
    u32 alloc_time;
    Local local;
} Reg;


//#define PRINT_GENERATED_INSTRUCTIONS
#define NO_STACK_SPACE_ALLOCATED U32_MAX

// NB regarding memory allocation.
// For short-lived objects, we allocate in the 'stack' arena, which we push/pop.
// For permanent objects, we stick them in the 'arena' arena, which we should never really push/pop
// We also use a bunch of stretchy-buffers, though some of those we might be able to replace with arena allocations
typedef struct Context {
    Arena arena, stack; // arena is for permanent storage, stack for temporary

    enum {
        context_state_ast,
        context_state_typechecked,
        context_state_intermediate,
        context_state_bytecode,
    } state;

    u8* string_table; // stretchy-buffer string table

    // AST
    // NB that we store all local variables & statements in the same buffer, with members in each 'Func'
    // designating which variables belong to a given function. Iterating over the whole 'vars'/'stmts'
    // buffers rarely (if ever) makes sense. Usually you just want to iterate over current functions part.
    Stmt* stmts; // stretchy-buffer
    Var* vars; // stretchy-buffer
    Func* funcs; // stretchy-buffer


    // Intermediate representation
    Op* ops; // stretchy-buffer, linearized for of stmts
    u32 max_temporaries;


    // Low level representation
    u8* bytecode;
    u8* bytecode_data;
    Fixup* fixups;
    DynlibImport* dlls;

    // Used during codegen
    Reg regs[REG_COUNT];

    u32* var_stack_offsets; // one per variable, arena allocated
    u32* tmp_stack_offsets; // also arena allocated
    u32 next_stack_offset;

    Stack_Fixup* stack_fixups; // stretchy-buffer
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
            printf("identifier (\"%s\")", name);
        } break;
        case token_literal: {
            u32 value = t->literal_value;
            printf("literal (%u)", value);
        } break;

        case token_operator: {
            u8 operator = t->operator_symbol;
            printf("operator %c", operator);
        } break;
        case token_line_end: {
            printf("end of line");
        } break;
        case token_bracket: {
            u8 brackets[6] = { '{', '(', '[', '}', ')', ']' };
            u8 i = t->bracket.kind + (t->bracket.open ? 0 : 3);
            assert(i < 6);
            printf("%c", brackets[i]);
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

void expr_print(Context* context, Expr* expr) {
    switch (expr->kind) {
        case expr_variable: {
            Var* var = &context->vars[expr->variable];
            u8* name = string_table_access(context->string_table, var->name);
            printf("%s", name);
        } break;

        case expr_literal: {
            printf("%u", expr->literal);
        } break;

        case expr_binary: {
            printf("(");
            expr_print(context, expr->binary.left);
            switch (expr->binary.op) {
                case BINARY_ADD: printf(" + "); break;
                case BINARY_SUB: printf(" - "); break;
                case BINARY_MUL: printf(" * "); break;
                case BINARY_DIV: printf(" / "); break;
                default: assert(false);
            }
            expr_print(context, expr->binary.right);
            printf(")");
        } break;

        case expr_call: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u8* name = string_table_access(context->string_table, expr->call.unresolved_name);
                printf("(<unresolved> %s)", name);
            } else {
                Func* func = &context->funcs[expr->call.func_index];
                u8* name = string_table_access(context->string_table, func->name);
                printf("(%s)", name);
            }
        } break;

        default: assert(false);
    }
}

void stmt_print(Context* context, Stmt* stmt) {
    switch (stmt->kind) {
        case stmt_assignment: {
            Var* var = &context->vars[stmt->assignment.var];
            u8* name = string_table_access(context->string_table, var->name);
            printf("%s = ", name);
            expr_print(context, stmt->assignment.expr);
        } break;

        case stmt_end_of_stream: {
            printf("end of stream");
        } break;

        default: assert(false);
    }
}

void print_local(Context* context, Local local) {
    switch (local.kind) {
        case local_variable: {
            Var* var = &context->vars[local.index];
            u8* name = string_table_access(context->string_table, var->name);
            printf("%s", name);
        } break;

        case local_temporary: {
            printf("$%u", local.index);
        } break;

        default: assert(false);
    }
}

void op_print(Context* context, Op* op) {
    if (op->kind & OP_KIND_BINARY_FLAG) {
        switch (op->kind) {
            case op_set: printf("set "); break;
            case op_add: printf("add "); break;
            case op_sub: printf("sub "); break;
            case op_mul: printf("mul "); break;
            case op_div: printf("div "); break;
            default: assert(false);
        }

        print_local(context, op->binary.target);
        printf(", ");
        switch (op->binary.source_kind) {
            case op_source_literal: printf("%u", op->binary.source.literal);  break;
            case op_source_local:   print_local(context, op->binary.source.local); break;
            default: assert(false);
        }
    } else switch (op->kind) {
        case op_reset_temporaries: {
            printf("reset temporaries");
        } break;

        case op_call: {
            Func* func = context->funcs + op->call.func_index;
            u8* name = string_table_access(context->string_table, func->name);
            printf("set ");
            print_local(context, op->call.target);
            printf(", (call %s)", name);
        } break;

        default: assert(false);
    }
}

u32 find_var(Context* context, Func* func, u32 name) {
    for (u32 i = func->first_var; i < func->last_var; i += 1) {
        if (context->vars[i].name == name) {
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

Expr* expr_parse_with_length(Context* context, Func* func, Token* t, u32 length) {
    if (length == 0) {
        printf("Expected expression but found nothing (Line %u)\n", t->pos.line);
        return null;
    }

    if (length == 1) {
        switch (t->kind) {
            case token_literal: {
                Expr* expr = arena_insert(&context->arena, ((Expr) {0}));
                expr->kind = expr_literal;
                expr->literal = t->literal_value;
                return expr;
            } break;

            case token_identifier: {
                u32 name_index = t->identifier_string_table_index;
                u32 var_index = find_var(context, func, name_index);
                if (var_index == U32_MAX) {
                    u8* name = string_table_access(context->string_table, name_index);
                    printf("Found undeclared variable '%s' in expression (Line %u)\n", name, t->pos.line);
                    return null;
                }

                Expr* expr = arena_insert(&context->arena, ((Expr) {0}));
                expr->kind = expr_variable;
                expr->variable = var_index;
                return expr;
            } break;
        }

        printf("Expected literal or variable, but got ");
        token_print(context->string_table, t);
        printf(" (Line %u)\n", t->pos.line);
        return null;
    }

    u32 op_pos = U32_MAX;
    u8 op_precedence = U8_MAX;
    u32 open_brackets = 0;
    u32 close_brackets = 0;

    for (u32 i = 0; i < length; i += 1) {
        if (t[i].kind == token_bracket) {
            switch (t[i].bracket.kind) {
                case BRACKET_CURLY:  printf("Can't have curly brackets {} in expressions (Line %u)\n",  t->pos.line); break;
                case BRACKET_SQUARE: printf("Can't have square brackets [] in expressions (Line %u)\n", t->pos.line); break;

                case BRACKET_ROUND: {
                    if (t[i].bracket.open) {
                        open_brackets += 1;
                    } else {
                        close_brackets += 1;
                    }
                } break;

                default: assert(false);
            }
        }

        if (open_brackets == close_brackets && t[i].kind == token_operator) {
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

    if (open_brackets != close_brackets) {
        printf("Unbalanced brackets in expression (Line %u)\n", t->pos.line);
        return null;
    }

    if (open_brackets == 1 && close_brackets == 1 && t[0].kind == token_bracket && t[0].bracket.open && t[length - 1].kind == token_bracket && !t[length - 1].bracket.open) {
        if (length != 3) {
            printf("We don't support parameters in function calls, for now (Line %u)\n", t[0].pos.line);
            return null;
        }

        if (t[1].kind != token_identifier) {
            printf("Expected function name, but got ");
            token_print(context->string_table, &t[1]);
            printf(" (Line %u)\n", t[1].pos.line);
            return null;
        }

        Expr* expr = arena_insert(&context->arena, ((Expr) {0}));
        expr->kind = expr_call;
        expr->call.unresolved_name = t[1].identifier_string_table_index;
        expr->flags |= EXPR_FLAG_UNRESOLVED;
        return expr;
    }

    if (op_pos == U32_MAX) {
        printf("Found no operator in expression (Starting on line %u)\n", t->pos.line);
        return null;
    }


    u8 binary_op;
    Token* op_token = t + op_pos;
    switch (op_token->operator_symbol) {
        case '+': binary_op = BINARY_ADD; break;
        case '-': binary_op = BINARY_SUB; break;
        case '*': binary_op = BINARY_MUL; break;
        case '/': binary_op = BINARY_DIV; break;
        default: {
            printf("Expected binary operator, but got %c (Line %u)\n", op_token->operator_symbol, op_token->pos.line);
            return null;
        } break;
    }

    Expr* left  = expr_parse_with_length(context, func, t, op_pos);
    Expr* right = expr_parse_with_length(context, func, t + op_pos + 1, length - op_pos - 1);

    if (left == null || right == null) { return null; }

    Expr* expr = arena_insert(&context->arena, ((Expr) {0}));
    expr->kind = expr_binary;
    expr->binary.op = binary_op;
    expr->binary.left = left;
    expr->binary.right = right;

    if ((left->flags | right->flags) & EXPR_FLAG_ANY_UNRESOLVED) {
        expr->flags |= EXPR_FLAG_UNRESOLVED_CHILDREN;
    }
    return expr;
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

    // Lex
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
            u32 lcontext = i;

            for (; i < file_length; i += 1) {
                switch (file[i]) {
                LOWERCASE UPPERCASE DIGIT case '_': { lcontext = i; } break;
                default: goto done_with_identifier;
                }
            }
            done_with_identifier:

            u32 length = lcontext - first + 1;
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
            u32 lcontext = i;
            bool overflow = false;
            
            u32 value = 0;

            for (; i < file_length; i += 1) {
                switch (file[i]) {
                DIGIT {
                    lcontext = i;

                    u32 previous_value = value;

                    u32 digit = file[i] - '0';
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
                    lcontext - first + 1, &file[first], value, file_pos.line
                );
            }

            buf_push(tokens, ((Token) { token_literal, .literal_value = value, .pos = file_pos }));
        } break;

        case '+': case '-':
        case '*': case '/':
        case '=':
        {
            u8 symbol = file[i];
            buf_push(tokens, ((Token) { token_operator, .operator_symbol = symbol, .pos = file_pos }));
            i += 1;
        } break;

        case '{': {
            buf_push(tokens, ((Token) {
                token_bracket,
                .bracket = { .open = true, .kind = BRACKET_CURLY },
                .pos = file_pos
            }));
            i += 1;
        } break;
        case '}': {
            buf_push(tokens, ((Token) {
                token_bracket,
                .bracket = { .open = false, .kind = BRACKET_CURLY },
                .pos = file_pos
            }));
            i += 1;
        } break;
        case '[': {
            buf_push(tokens, ((Token) {
                token_bracket,
                .bracket = { .open = true, .kind = BRACKET_SQUARE },
                .pos = file_pos
            }));
            i += 1;
        } break;
        case ']': {
            buf_push(tokens, ((Token) {
                token_bracket,
                .bracket = { .open = false, .kind = BRACKET_SQUARE },
                .pos = file_pos
            }));
            i += 1;
        } break;
        case '(': {
            buf_push(tokens, ((Token) {
                token_bracket,
                .bracket = { .open = true, .kind = BRACKET_ROUND },
                .pos = file_pos
            }));
            i += 1;
        } break;
        case ')': {
            buf_push(tokens, ((Token) {
                token_bracket,
                .bracket = { .open = false, .kind = BRACKET_ROUND },
                .pos = file_pos
            }));
            i += 1;
        } break;

        case '#': {
            // Eat the rest of the line as a comment
            for (; i < file_length; i += 1) {
                if (file[i] == '\n' || file[i] == '\r') { break; }
            }
        } break;

        case '\n': {
            i += 1;
            for (; i < file_length; i += 1) { if (file[i] != '\r') break; }
            buf_push(tokens, ((Token) { token_line_end, .pos = file_pos }));
            file_pos.line += 1;
        } break;
        case '\r': {
            i += 1;
            for (; i < file_length; i += 1) { if (file[i] != '\n') break; }
            buf_push(tokens, ((Token) { token_line_end, .pos = file_pos }));
            file_pos.line += 1;
        } break;

        SPACE {
            i += 1;
        } break;

        default: {
            printf("Unexpected character: %c (Line %u)\n", file[i], file_pos.line);
            valid = false;
            i += 1;
        } break;
    }
    buf_push(tokens, ((Token) { token_end_of_stream }));

    free(file);

    /*
    printf("%u tokens:\n", buf_length(tokens));
    for (Token* t = tokens; t->kind != token_end_of_stream; t += 1) {
        printf("  ");
        token_print(string_table, t);
        printf(" (Line %u)\n", t->pos.line);
    }
    */

    // Parse
    Func* current_func = null; // pointer into context->funcs

    #define EAT_TOKENS_TO_NEWLINE \
    while (t->kind != token_line_end && t->kind != token_end_of_stream) { t += 1; }
    #define EAT_WHITESPACE \
    while (t->kind == token_line_end) { t += 1; }

    for (Token* t = tokens; t->kind != token_end_of_stream; t += 1) switch (t->kind) {
        case token_keyword_fn: {
            File_Pos declaration_pos = t->pos;

            t += 1;
            if (t->kind != token_identifier) {
                printf("Expected identifier after 'fn', but found ");
                token_print(context->string_table, t);
                printf(" (Line %u)\n", t->pos.line);
                EAT_TOKENS_TO_NEWLINE
                valid = false;
                
                // TODO we probably want to try synchronizing to the next closing bracket or next
                // statement at equal indentation instead of to the end of the line.
                break;
            }

            u32 name_index = t->identifier_string_table_index;
            u8* name = string_table_access(context->string_table, name_index);

            t += 1;
            if (t->kind != token_bracket && t->bracket.kind != BRACKET_CURLY && t->bracket.open) {
                printf("Expected { after 'fn %s', but got ", name);
                token_print(context->string_table, t);
                printf(" (Line %u)\n", declaration_pos.line);
                valid = false;
                EAT_TOKENS_TO_NEWLINE
                break;
            }

            t += 1;
            if (t->kind != token_line_end) {
                printf("Expected end of line after 'fn %s {', but got ", name);
                token_print(context->string_table, t);
                printf(" (Line %u)\n", declaration_pos.line);
                valid = false;
                EAT_TOKENS_TO_NEWLINE
                break;
            }

            if (current_func != null) {
                u8* current_name = string_table_access(context->string_table, current_func->name);
                printf("Can't have start of function %s before end of function %s (Line %u)\n", name, current_name, declaration_pos.line);
                valid = false;
                break;
            }

            Func func = {0};
            func.name = name_index;
            func.first_var = buf_length(context->vars);
            func.last_var = buf_length(context->vars);
            func.first_stmt = buf_length(context->stmts);
            func.last_stmt = buf_length(context->stmts);

            buf_push(context->funcs, func);
            current_func = context->funcs + (buf_length(context->funcs) - 1);

            Var output_var = {0};
            output_var.name = string_table_canonicalize(&context->string_table, "output", 6);
            buf_push(context->vars, output_var);
            current_func->last_var += 1;
        } break;

        case token_bracket: {
            if (t->bracket.kind == BRACKET_CURLY && !t->bracket.open) {
                if (current_func == null) {
                    valid = false;
                    break;
                }
                current_func = null;
            } else {
                goto invalid_line_start;
            }
        } break;

        case token_keyword_var: {
            File_Pos declaration_pos = t->pos;

            t += 1;
            if (t->kind != token_identifier) {
                printf("Expected identifier after 'var', but found ");
                token_print(context->string_table, t);
                printf(" (Line %u)\n", t->pos.line);
                EAT_TOKENS_TO_NEWLINE
                valid = false;
                break;
            }

            u32 name_index = t->identifier_string_table_index;
            u8* name = string_table_access(context->string_table, name_index);

            if (current_func == null) {
                printf(
                    "Tried declaring 'var %s' outside of a function (Line %u)\n",
                    name, declaration_pos.line
                );
                EAT_TOKENS_TO_NEWLINE
                valid = false;
                break;
            }

            bool redeclaration = false;
            for (u32 i = current_func->first_var; i < current_func->last_var; i += 1) {
                Var* v = &context->vars[i];
                if (v->name == name_index) {
                    printf(
                        "Redeclaration of %s on line %u. First declaration on line %u.\n",
                        name, declaration_pos.line, v->declaration_pos.line
                    );
                    redeclaration = true;
                    valid = false;
                    break;
                }
            }
            if (redeclaration) {
                break;
            }

            u32 var_index = buf_length(context->vars);
            Var var = {0};
            var.name = name_index;
            var.declaration_pos = declaration_pos;
            buf_push(context->vars, var);
            current_func->last_var += 1;

            // Figure out what to assign to the value
            Expr* initial_value = null;

            t += 1;
            if (t->kind == token_line_end || t->kind == token_end_of_stream) {
                initial_value = arena_insert(&context->arena, ((Expr) {0}));
                initial_value->kind = expr_literal;
                initial_value->literal = 0;
            } else if (t->kind == token_operator && t->operator_symbol == '=') {
                t += 1;

                Token* start = t;
                u32 length = 0;
                while (t->kind != token_line_end && t->kind != token_end_of_stream) {
                    length += 1;
                    t += 1;
                }
                initial_value = expr_parse_with_length(context, current_func, start, length);
                if (initial_value == null) {
                    valid = false;
                    break;
                }
            } else {
                printf("Expected operator = or end of line after 'var %s', but found ", name);
                token_print(context->string_table, t);
                printf(" (Line %u)\n", t->pos.line);
                EAT_TOKENS_TO_NEWLINE
                valid = false;
                break;
            }

            Stmt stmt = {0};
            stmt.kind = stmt_assignment;
            stmt.assignment.var = var_index;
            stmt.assignment.expr = initial_value;
            buf_push(context->stmts, stmt);
            current_func->last_stmt += 1;
        } break;

        case token_identifier: {
            File_Pos assignment_pos = t->pos;

            u32 name_index = t->identifier_string_table_index;
            u8* name = string_table_access(context->string_table, name_index);

            Expr* expr = null;

            t += 1;
            if (t->kind == token_operator && t->operator_symbol == '=') {
                t += 1;

                Token* start = t;
                u32 length = 0;
                while (t->kind != token_line_end && t->kind != token_end_of_stream) {
                    length += 1;
                    t += 1;
                }
                expr = expr_parse_with_length(context, current_func, start, length);
                if (expr == null) {
                    valid = false;
                    break;
                }
            } else {
                printf("Expected operator = after '%s', but found ", name);
                token_print(context->string_table, t);
                printf(" (Line %u)\n", t->pos.line);
                EAT_TOKENS_TO_NEWLINE
                valid = false;
                break;
            }

            if (current_func == null) {
                printf(
                    "Assignments are not allowed outside of functions, but found '%s = ...' (Line %u)\n",
                    name, assignment_pos.line
                );
                EAT_TOKENS_TO_NEWLINE
                valid = false;
                break;
            }

            u32 var_index = find_var(context, current_func, name_index);
            if (var_index == -1) {
                printf(
                    "Assignment to undeclared variable '%s' (Line %u)\n",
                    name, assignment_pos.line
                );
                break;
            }

            Stmt stmt = {0};
            stmt.kind = stmt_assignment;
            stmt.assignment.var = var_index;
            stmt.assignment.expr = expr;
            buf_push(context->stmts, stmt);
            current_func->last_stmt += 1;
        } break;

        case token_line_end: break;

        invalid_line_start:
        case token_literal:
        case token_operator:
        {
            printf("Found ");
            token_print(context->string_table, t);
            printf(", which is an invalid start to a line (Line %u)\n", t->pos.line);
            valid = false;
        } break;

        default: assert(false);
    }
    buf_push(context->stmts, ((Stmt) { stmt_end_of_stream }));

    if (!valid) {
        printf("Encountered errors while lexing / parsing, exiting compiler!\n");
        return false;
    }

    context->state = context_state_ast;

    return true;
}

bool expr_resolve(Context* context, Expr* expr) {
    if (!(expr->flags & EXPR_FLAG_ANY_UNRESOLVED)) {
        return true;
    }

    switch (expr->kind) {
        case expr_variable: {
            printf("Variables can't be unresolved\n");
            assert(false);
        } break;
        case expr_literal: {
            printf("Literals really can't be unresolved\n");
            assert(false);
        } break;

        case expr_binary: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED_CHILDREN) {
                if (!expr_resolve(context, expr->binary.left))  return false;
                if (!expr_resolve(context, expr->binary.right)) return false;
            }
        } break;

        case expr_call: {
            if (expr->flags & EXPR_FLAG_UNRESOLVED) {
                u32 func_index = find_func(context, expr->call.unresolved_name);
                if (func_index == U32_MAX) {
                    printf("Can't find function '%s' (Line idk, TODO)\n");
                    return false;
                }

                expr->call.func_index = func_index;
                expr->flags &= ~EXPR_FLAG_UNRESOLVED;
            }

            if (expr->flags & EXPR_FLAG_UNRESOLVED_CHILDREN) {
                // Here we want to handle unresolved parameters
                unimplemented();
            }
        } break;

        default: assert(false);
    }

    return true;
}

void expr_linearize_recursive(Context* context, Expr* expr, u32 tmp) {
    assert(!(expr->flags & EXPR_FLAG_UNRESOLVED));

    switch (expr->kind) {
        case expr_variable: {
            Op op = {0};
            op.kind = op_set;

            op.binary.target.kind = local_temporary;
            op.binary.target.index = tmp;

            op.binary.source_kind = op_source_local;
            op.binary.source.local.kind = local_variable;
            op.binary.source.local.index = expr->variable;

            buf_push(context->ops, op);
        } break;

        case expr_literal: {
            Op op = {0};
            op.kind = op_set;

            op.binary.target.kind = local_temporary;
            op.binary.target.index = tmp;

            op.binary.source_kind = op_source_literal;
            op.binary.source.literal = expr->literal;

            buf_push(context->ops, op);
        } break;

        case expr_binary: {
            expr_linearize_recursive(context, expr->binary.left, tmp);

            Op op = {0};
            op.binary.target.kind = local_temporary;
            op.binary.target.index = tmp;

            bool right_may_be_literal = expr->binary.op == BINARY_ADD || expr->binary.op == BINARY_SUB;

            switch (expr->binary.op) {
                case BINARY_ADD: op.kind = op_add; break;
                case BINARY_SUB: op.kind = op_sub; break;
                case BINARY_MUL: op.kind = op_mul; break;
                case BINARY_DIV: op.kind = op_div; break;
                default: assert(false);
            }

            // The `expr_binary` case is the fallthrough case. This case works for all kinds of
            // expressions. We handle some expressions differently though, which results in
            // less temporaries allocated.
            switch (expr->binary.right->kind) {
                case expr_literal: {
                    op.binary.source_kind = op_source_literal;
                    op.binary.source.literal = expr->binary.right->literal;
                } break;

                case expr_variable: {
                    op.binary.source_kind = op_source_local;
                    op.binary.source.local.kind = local_variable;
                    op.binary.source.local.index = expr->binary.right->variable;
                } break;

                // for more complex expression kinds
                case expr_binary:
                case expr_call:
                {
                    right_may_be_literal = false; // oof, messy control flow
                } break;

                default: assert(false);
            }

            if (!right_may_be_literal) {
                expr_linearize_recursive(context, expr->binary.right, tmp + 1);

                op.binary.source_kind = op_source_local;
                op.binary.source.local.kind = local_temporary;
                op.binary.source.local.index = tmp + 1;
            }

            buf_push(context->ops, op);
        } break;

        case expr_call: {
            Op op = {0};

            op.kind = op_call;
            op.call.func_index = expr->call.func_index;
            op.call.target.kind = local_temporary;
            op.call.target.index = tmp;
            buf_push(context->ops, op);
        } break;

        default: assert(false);
    }
}

// Get local used as source for operator, if operator has source and source is local
Local* op_get_source_local(Op* op) {
    if (op->kind & OP_KIND_BINARY_FLAG) {
        if (op->binary.source_kind == op_source_local) {
            return &op->binary.source.local;
        }
    } else switch (op->kind) {
        case op_call: break;
        default: assert(false);
    }

    return null;
}

// Get local used to store operator result, if operator produces result
Local* op_get_target(Op* op) {
    if (op->kind & OP_KIND_BINARY_FLAG) {
        return &op->binary.target;
    } else switch (op->kind) {
        case op_call: return &op->call.target;
        default: assert(false);
    }

    return null;
}

void linearize_assignment(Context* context, u32 var, Expr* root) {
    u32 initial_op_count = buf_length(context->ops);

    expr_linearize_recursive(context, root, 0);

    // Try replacing temporary $0 with our variable.
    // If we write to $0 after reading from 'var' we need $0
    bool need_temporary_0 = false;
    bool has_assigned_to_0 = false;
    for (u32 i = initial_op_count; i < buf_length(context->ops); i += 1) {
        Op* op = context->ops + i;

        Local* target = op_get_target(op);
        Local* source = op_get_source_local(op);

        if (source != null && source->kind == local_variable && source->index == var) {
            if (has_assigned_to_0) {
                need_temporary_0 = true;
                break;
            }
        }

        if (target != null) {
            assert(target->kind == local_temporary);
            if (target->index == 0) {
                has_assigned_to_0 = true;
            }
        }
    }

    if (need_temporary_0) {
        // Move the temporary $0 into our variable
        buf_push(context->ops, ((Op) {
            .kind = op_set,
            .binary = {
                .source_kind = op_source_local,
                .source = { .local = { .kind = local_temporary, .index = 0 } },
                .target = { .kind = local_variable, .index = var }
            },
        }));
    } else {
        for (u32 i = initial_op_count; i < buf_length(context->ops); i += 1) {
            Op* op = context->ops + i;

            Local* source = op_get_source_local(op);
            Local* target = op_get_target(op);

            if (target != null && target->kind == local_temporary) {
                if (target->index == 0) {
                    target->kind = local_variable;
                    target->index = var; 
                } else {
                    target->index -= 1;
                }
            }

            if (source != null && source->kind == local_temporary) {
                if (source->index == 0) {
                    source->kind = local_variable;
                    source->index = var; 
                } else {
                    source->index -= 1;
                }
            }
        }

        // By removing temporary $0 we might convert 'set $0, x' to 'set x, x' as the first instruction
        Op* first = context->ops + initial_op_count;
        if (first->kind == op_set && first->binary.source_kind == op_source_local && local_cmp(first->binary.source.local, first->binary.target)) {
            for (u32 i = initial_op_count; i < buf_length(context->ops) - 1; i += 1) {
                context->ops[i] = context->ops[i + 1];
            }
            buf_pop(context->ops);
        }
    }

    // TODO Optimize
    // * Summing constants
    // * Reorganizing trees so as many right branches are leaves. We only need temporaries if we
    //   have non-leaf expressions on right branches (Draw it up, it makes sense!).
    
    // Figure out how many temporaries we ended up using
    bool used_temporaries = false;

    for (u32 i = initial_op_count; i < buf_length(context->ops); i += 1) {
        Op* op = &context->ops[i];
        if (!(op->kind & OP_KIND_BINARY_FLAG)) continue;

        if (op->binary.source_kind == op_source_local && op->binary.source.local.kind == local_temporary) {
            used_temporaries = true;
            context->max_temporaries = max(op->binary.source.local.index + 1, context->max_temporaries);
        }
        if (op->binary.target.kind == local_temporary) {
            used_temporaries = true;
            context->max_temporaries = max(op->binary.target.index + 1, context->max_temporaries);
        }
    }

    if (used_temporaries) {
        buf_push(context->ops, ((Op) { op_reset_temporaries }));
    }
}

bool typecheck(Context* context) {
    assert(context->state == context_state_ast);

    bool success = true;

    for (u32 f = 0; f < buf_length(context->funcs); f += 1) {
        Func* func = context->funcs + f;

        Stmt* end = context->stmts + func->last_stmt;
        for (Stmt* stmt = context->stmts + func->first_stmt; stmt != end; stmt += 1) {
            switch (stmt->kind) {
                case stmt_assignment: {
                    expr_resolve(context, stmt->assignment.expr);
                } break;

                default: assert(false);
            }
        }
    }

    if (success) {
        context->state = context_state_typechecked;
        return true;
    } else {
        return false;
    }
}

void build_intermediate(Context* context) {
    assert(context->state == context_state_typechecked);

    // Linearize statements
    Func* func_end = buf_end(context->funcs);
    for (Func* func = context->funcs; func != buf_end(context->funcs); func += 1) {
        func->first_op = buf_length(context->ops);

        Stmt* first_stmt = context->stmts + func->first_stmt;
        Stmt* last_stmt = context->stmts + func->last_stmt;
        for (Stmt* stmt = first_stmt; stmt != last_stmt; stmt += 1) switch (stmt->kind) {
            case stmt_assignment: {
                linearize_assignment(context, stmt->assignment.var, stmt->assignment.expr);
            } break;

            default: assert(false);
        }

        func->last_op = buf_length(context->ops);
        buf_push(context->ops, ((Op) { op_end_of_function }));

        u8* name = string_table_access(context->string_table, func->name);
        printf("%s has %u operations:\n", name, func->last_op - func->first_op);
        for (Op* op = context->ops + func->first_op; op->kind != op_end_of_function; op += 1) {
            printf("  ");
            op_print(context, op);
            printf("\n");
        }
    }
    buf_push(context->ops, ((Op) { op_end_of_stream }));

    context->state = context_state_intermediate;
}

void eval_ops(Context* context) {
    arena_push(&context->stack);

    assert(context->state == context_state_intermediate);

    u32 output_value = 0;

    typedef struct Stack_Frame Stack_Frame;
    struct Stack_Frame {
        Func* func;
        Op* current_op;
        Stack_Frame* parent;
        Local call_result_into;
    };

    u32* var_values = (u32*) arena_alloc(&context->stack, sizeof(u32) * buf_length(context->vars));
    u32* tmp_values = (u32*) arena_alloc(&context->stack, sizeof(u32) * context->max_temporaries);

    u32 main_func_index = find_func(context, string_table_search(context->string_table, "main")); 
    if (main_func_index == STRING_TABLE_NO_MATCH) {
        panic("No main function");
    }
    Func* main_func = context->funcs + main_func_index;

    Stack_Frame* frame = arena_insert(&context->stack, ((Stack_Frame) { main_func }));

    while (frame != null) {
        u8* name = string_table_access(context->string_table, frame->func->name);

        if (frame->current_op == null) {
            frame->current_op = context->ops + frame->func->first_op;
        }

        bool break_into_call = false;

        Op* last_op = context->ops + frame->func->last_op;
        while (frame->current_op != last_op && !break_into_call) {
            Op* op = frame->current_op;
            frame->current_op += 1;

            if (op->kind & OP_KIND_BINARY_FLAG) {
                Op_Binary_Operands* bin = &op->binary;

                u32* left_value;
                switch (bin->target.kind) {
                    case local_temporary: left_value = tmp_values + bin->target.index; break;
                    case local_variable:  left_value = var_values + bin->target.index; break;
                    default: assert(false);
                }

                u32 right_literal;
                u32* right_value;
                switch (bin->source_kind) {
                    case op_source_literal: {
                        right_literal = bin->source.literal;
                        right_value = &right_literal;
                    } break;
                    case op_source_local: {
                        switch (bin->source.local.kind) {
                            case local_temporary: right_value = tmp_values + bin->source.local.index; break;
                            case local_variable:  right_value = var_values + bin->source.local.index; break;
                            default: assert(false);
                        }
                    } break;
                    default: assert(false);
                }

                switch (op->kind) {
                    case op_set: *left_value = *right_value; break;
                    case op_add: *left_value = *left_value + *right_value; break;
                    case op_sub: *left_value = *left_value - *right_value; break;
                    case op_mul: *left_value = *left_value * *right_value; break;
                    case op_div: *left_value = *left_value / *right_value; break;

                    default: assert(false);
                }

            // Other operators
            } else switch (op->kind) {
                case op_reset_temporaries: break;

                case op_call: {
                    Func* func = context->funcs + op->call.func_index;
                    Stack_Frame* next_frame = arena_insert(&context->stack, ((Stack_Frame) {
                        .func = func,
                        .parent = frame,
                        .call_result_into = op->call.target,
                    }));
                    frame = next_frame;

                    break_into_call = true;
                } break;

                default: assert(false);
            }
        }

        if (!break_into_call) {
            if (frame->parent != null) {
                u32 output_value = var_values[frame->func->first_var];

                u32* target_value;
                Local target = frame->call_result_into;
                switch (target.kind) {
                    case local_temporary: target_value = tmp_values + target.index; break;
                    case local_variable:  target_value = var_values + target.index; break;
                    default: assert(false);
                }
                *target_value = output_value;
            }

            frame = frame->parent;
        }
    }

    printf("Evaluated intermediate bytecode:\n");
    for (Func* func = context->funcs; func != buf_end(context->funcs); func += 1) {
        u8* name = string_table_access(context->string_table, func->name);
        printf("  fn %s:\n", name);

        for (u32 i = func->first_var; i < func->last_var; i += 1) {
            Var* var = &context->vars[i];
            u8* name = string_table_access(context->string_table, var->name);
            u32 value = var_values[i];

            printf("    %s = %u\n", name, value);
        }
    }

    arena_pop(&context->stack);
}

u32 local_stack_offset(Context* context, Local local, bool allocate) {
    u32 stack_offset;

    switch (local.kind) {
        case local_temporary: {
            stack_offset = context->tmp_stack_offsets[local.index];
            if (stack_offset == NO_STACK_SPACE_ALLOCATED && allocate) {
                stack_offset = context->next_stack_offset;
                context->next_stack_offset += sizeof(u32);
                context->tmp_stack_offsets[local.index] = stack_offset;
            }
        } break;

        case local_variable: {
            stack_offset = context->var_stack_offsets[local.index];
            if (stack_offset == NO_STACK_SPACE_ALLOCATED && allocate) {
                stack_offset = context->next_stack_offset;
                context->next_stack_offset += sizeof(u32);
                context->var_stack_offsets[local.index] = stack_offset;
            }
        } break;

        default: assert(false);
    }

    return stack_offset;
}

void reg_deallocate(Context* context, u8 reg) {
    if (!context->regs[reg].used) return;
    context->regs[reg].used = false;

    Local old_local = context->regs[reg].local;
    u32 stack_offset = local_stack_offset(context, old_local, true);

    // TODO check if we need to deallocate the register at all, or if we can get away
    // with just overwriting it!
    // To do this, we need info about the lcontext use of a certain variable/temporary.
    // To do this, we can just read ahead in the current ops list. Might not be terribly fcontext though...

    // Eventually, this assertion will trip. We then need to encode disp32 instead of always encoding disp8
    // The assert checks for signed values, not sure if that is needed...
    // We also have to fix the code for loading values of the stack below once we get here!
    assert((stack_offset & 0x7f) == stack_offset);

    buf_push(context->bytecode, 0x89); // mov r/m32 r32     (MR)
    buf_push(context->bytecode, 0x44 | (reg << 3));
    buf_push(context->bytecode, 0x24);
    buf_push(context->bytecode, 0x00);
    context->time += 1;

    Stack_Fixup stack_fixup = {0};
    stack_fixup.text_location = buf_length(context->bytecode) - sizeof(u8);
    stack_fixup.stack_offset = stack_offset;
    stack_fixup.element_size = sizeof(u32);
    buf_push(context->stack_fixups, stack_fixup);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov [stack %u], %s\n", stack_offset, reg_names[reg]);
    #endif
}

void reg_allocate_into(Context* context, Local local, u8 reg) {
    if (context->regs[reg].used && local_cmp(context->regs[reg].local, local)) {
        return;
    }

    reg_deallocate(context, reg);

    u8 old_reg = REG_BAD;
    for (u32 r = 0; r < REG_COUNT; r += 1) {
        if (context->regs[r].used && local_cmp(context->regs[r].local, local)) {
            old_reg = r;
            break;
        }
    }

    if (old_reg == REG_BAD) {
        u32 stack_offset = local_stack_offset(context, local, false);
        if (stack_offset == NO_STACK_SPACE_ALLOCATED) {
            // Zero out the register?
            // Is this case even legal? Doesn't it imply we are using an uninitialized variable
            unimplemented();
        } else {
            // Move down from stack
            unimplemented();
        }

    // Local already is in a register, but in the wrong one!
    } else {
        buf_push(context->bytecode, 0x89);
        buf_push(context->bytecode, 0xc0 | reg | (old_reg << 3));

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("mov %s, %s\n", reg_names[reg], reg_names[old_reg]);
        #endif

        context->regs[old_reg].used = false;
    }

    context->regs[reg].used = true;
    context->regs[reg].local = local;
    context->regs[reg].alloc_time = context->time;
}

u8 reg_allocate(Context* context, Local local) {
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
        if (context->regs[r].used && local_cmp(context->regs[r].local, local)) {
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
        context->regs[reg].local = local;
        context->regs[reg].alloc_time = context->time;

        u32 stack_offset = local_stack_offset(context, local, false);
        if (stack_offset != NO_STACK_SPACE_ALLOCATED) {
            // mov r32 r/m32
            buf_push(context->bytecode, 0x8b);
            buf_push(context->bytecode, 0x44 | (reg << 3));
            buf_push(context->bytecode, 0x24);
            buf_push(context->bytecode, 0x00); // disp8 goes here
            context->time += 1;

            Stack_Fixup stack_fixup = {0};
            stack_fixup.text_location = buf_length(context->bytecode) - sizeof(u8);
            stack_fixup.stack_offset = stack_offset;
            stack_fixup.element_size = sizeof(u32);
            buf_push(context->stack_fixups, stack_fixup);

            #ifdef PRINT_GENERATED_INSTRUCTIONS
            printf("mov %s, [stack %u] ", reg_names[reg], stack_offset);
            #endif
        }

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        switch (local.kind) {
            case local_temporary: {
                printf("; alloc %s for $%u\n", reg_names[reg], local.index);
            } break;
            case local_variable: {
                Var* var = &context->vars[local.index];
                u8* name = string_table_access(context->string_table, var->name);
                printf("; alloc %s for %s\n", reg_names[reg], name);
            } break;
            default: assert(false);
        }
        #endif
    }

    return reg;
}

void op_bytecode(Context* context, Func* func, Op* op) {
    // Binary operators
    if (op->kind & OP_KIND_BINARY_FLAG) {
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
                assert(op->binary.source_kind != op_source_literal);
            } break;

            case op_div: {
                // Probably can be same as op_mul though, need to verify once we implement division properly
                unimplemented();
            } break;

            default: assert(false);
        }

        // Allocate registers based on requirements
        u8 left_reg, right_reg;
        u32 right_literal;
        bool use_right_literal;

        if (left_must_be_eax) {
            left_reg = 0;
            reg_allocate_into(context, op->binary.target, left_reg);
        } else {
            left_reg = reg_allocate(context, op->binary.target);
        }

        if (op->binary.source_kind == op_source_literal) {
            use_right_literal = true;
            right_literal = op->binary.source.literal;
        } else {
            use_right_literal = false;
            right_reg = reg_allocate(context, op->binary.source.local);
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
                    buf_push(context->bytecode, 0xb8 | left_reg);
                    buf_push(context->bytecode, (right_literal >> 0x00) & 0xff);
                    buf_push(context->bytecode, (right_literal >> 0x08) & 0xff);
                    buf_push(context->bytecode, (right_literal >> 0x10) & 0xff);
                    buf_push(context->bytecode, (right_literal >> 0x18) & 0xff);

                    #ifdef PRINT_GENERATED_INSTRUCTIONS
                    printf("mov %s, %u\n", reg_names[left_reg], right_literal);
                    #endif
                } else {
                    buf_push(context->bytecode, 0x89);
                    buf_push(context->bytecode, 0xc0 | left_reg | (right_reg << 3));

                    #ifdef PRINT_GENERATED_INSTRUCTIONS
                    printf("mov %s, %s\n", reg_names[left_reg], reg_names[right_reg]);
                    #endif
                }
            } break;

            case op_add: {
                if (use_right_literal) {
                    buf_push(context->bytecode, 0x81);
                    buf_push(context->bytecode, 0xc0 | left_reg);
                    buf_push(context->bytecode, (right_literal >> 0x00) & 0xff);
                    buf_push(context->bytecode, (right_literal >> 0x08) & 0xff);
                    buf_push(context->bytecode, (right_literal >> 0x10) & 0xff);
                    buf_push(context->bytecode, (right_literal >> 0x18) & 0xff);

                    #ifdef PRINT_GENERATED_INSTRUCTIONS
                    printf("add %s, %u\n", reg_names[left_reg], right_literal);
                    #endif
                } else {
                    buf_push(context->bytecode, 0x01);
                    buf_push(context->bytecode, 0xc0 | left_reg | (right_reg << 3));

                    #ifdef PRINT_GENERATED_INSTRUCTIONS
                    printf("add %s, %s\n", reg_names[left_reg], reg_names[right_reg]);
                    #endif
                }
            } break;

            case op_sub: {
                if (use_right_literal) {
                    buf_push(context->bytecode, 0x81);
                    buf_push(context->bytecode, 0xe8 | left_reg);
                    buf_push(context->bytecode, (right_literal >> 0x00) & 0xff);
                    buf_push(context->bytecode, (right_literal >> 0x08) & 0xff);
                    buf_push(context->bytecode, (right_literal >> 0x10) & 0xff);
                    buf_push(context->bytecode, (right_literal >> 0x18) & 0xff);

                    #ifdef PRINT_GENERATED_INSTRUCTIONS
                    printf("sub %s, %u\n", reg_names[left_reg], right_literal);
                    #endif
                } else {
                    buf_push(context->bytecode, 0x29);
                    buf_push(context->bytecode, 0xc0 | left_reg | (right_reg << 3));

                    #ifdef PRINT_GENERATED_INSTRUCTIONS
                    printf("sub %s, %s\n", reg_names[left_reg], reg_names[right_reg]);
                    #endif
                }
            } break;

            case op_mul: {
                // Assert that the required preconditions were met
                assert(left_reg == 0); // left must be eax
                assert(!use_right_literal); // literals in reg
                assert(!context->regs[2].used); // edx unused

                buf_push(context->bytecode, 0xf7);
                buf_push(context->bytecode, 0xe0 | right_reg);

                #ifdef PRINT_GENERATED_INSTRUCTIONS
                printf("mul %s, %s\n", reg_names[left_reg], reg_names[right_reg]);
                #endif

                /*
                if (use_right_literal) {

                    // mov edx, right_literal
                    buf_push(context->bytecode, 0xba);
                    buf_push(context->bytecode, (right_literal >> 0x00) & 0xff);
                    buf_push(context->bytecode, (right_literal >> 0x08) & 0xff);
                    buf_push(context->bytecode, (right_literal >> 0x10) & 0xff);
                    buf_push(context->bytecode, (right_literal >> 0x18) & 0xff);
                    // mul eax, edx
                    buf_push(context->bytecode, 0xf7);
                    buf_push(context->bytecode, 0xe2);

                    #ifdef PRINT_GENERATED_INSTRUCTIONS
                    printf("mov edx, %u\n", right_literal);
                    printf("mul eax, edx\n");
                    #endif
                } else {
                    // If we previously allocated eax for right_reg, that won't work because left_reg must be eax (see above).
                    // right_reg CAN be edx, because even though we deallocate it we can still use it until it is overwritten
                    // by our mul instruction!
                    assert(right_reg != 0);

                }
                */
            } break;

            case op_div: {
                if (use_right_literal) {
                    unimplemented();

                    #ifdef PRINT_GENERATED_INSTRUCTIONS
                    printf("div %s, %u\n", reg_names[left_reg], right_literal);
                    #endif
                } else {
                    unimplemented();

                    #ifdef PRINT_GENERATED_INSTRUCTIONS
                    printf("div %s, %s\n", reg_names[left_reg], reg_names[right_reg]);
                    #endif
                }
            } break;

            default: assert(false);
        }

    // Other operators
    } else switch (op->kind) {
        case op_reset_temporaries: {
            for (u32 r = 0; r < REG_COUNT; r += 1) {
                if (context->regs[r].used && context->regs[r].local.kind == local_temporary) {
                    context->regs[r] = (Reg) {0};
                }
            }
        } break;

        case op_call: {
            // TODO calling convention
            // Which registers do we need to deallocate
            // How do we pass parameters?
           
            for (u32 r = 0; r < REG_COUNT; r += 1) {
                reg_deallocate(context, r);
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

            // TODO calling convention
            // Which register is for return value? eax for now...
            // We need to do return-via-stack later too...

            u8 left_reg = reg_allocate(context, op->call.target);
            if (left_reg != 0 /* eax */) {
                u8 right_reg = 0; // eax

                buf_push(context->bytecode, 0x89);
                buf_push(context->bytecode, 0xc0 | left_reg | (right_reg << 3));

                #ifdef PRINT_GENERATED_INSTRUCTIONS
                printf("mov %s, %s\n", reg_names[left_reg], reg_names[right_reg]);
                #endif
            }
        } break;

        default: assert(false);
    }
}

void build_bytecode(Context* context) {
    arena_push(&context->stack);
    context->var_stack_offsets = (u32*) arena_alloc(&context->stack, sizeof(u32) * buf_length(context->vars));
    context->tmp_stack_offsets = (u32*) arena_alloc(&context->stack, sizeof(u32) * context->max_temporaries);
    for (u32 i = 0; i < buf_length(context->vars); i += 1) { context->var_stack_offsets[i] = NO_STACK_SPACE_ALLOCATED; }
    for (u32 i = 0; i < context->max_temporaries; i += 1)  { context->tmp_stack_offsets[i] = NO_STACK_SPACE_ALLOCATED; }


    u32 main_func_index = find_func(context, string_table_search(context->string_table, "main")); 
    if (main_func_index == STRING_TABLE_NO_MATCH) {
        panic("No main function");
    }
    Func* main_func = context->funcs + main_func_index;


    buf_foreach (Func, func, context->funcs) {
        // TODO calling convention
        // We need preserve non-volatile registers!

        func->bytecode_start = buf_length(context->bytecode);

        buf_clear(context->stack_fixups);
        mem_clear((u8*) context->regs, sizeof(Reg) * REG_COUNT);

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        u8* name = string_table_access(context->string_table, func->name);
        printf("; --- fn %s ---\n", name);
        #endif

        // sub rsp, stack frame size
        buf_push(context->bytecode, 0x48);
        buf_push(context->bytecode, 0x83);
        buf_push(context->bytecode, 0xec);
        buf_push(context->bytecode, 0x00);
        u64 stack_frame_size_text_location = buf_length(context->bytecode) - sizeof(u8);
        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("sub rsp, stack_frame_size\n");
        #endif

        Op* op_start = context->ops + func->first_op;
        Op* op_end   = context->ops + func->last_op;
        for (Op* op = op_start; op != op_end; op += 1) {
            context->time += 1;
            op_bytecode(context, func, op);
        }

        // Fix up stack
        u32 stack_size = context->next_stack_offset; // TODO + stack space for function parameters
        stack_size = ((stack_size + 0x0f) & (~0x0f)); // Round up to 16-byte align

        // If this assertion trips, we have to encode stack size as a imm32 in the add/sub
        // instructions setting up the stack frame.
        // While we are at it, me might want to figure out a way of removing the add/sub
        // instructions completely when we do not use the stack at all!
        assert((stack_size & 0x7f) == stack_size);

        // TODO calling convention
        // How do we pass return values?
        // This needs to be the same as how we do return value reading in 'op_call' bytecode
        if (func != main_func) {
            Local output_var = {
                .kind = local_variable,
                .index = func->first_var,
            };

            u8 right_reg = reg_allocate(context, output_var);
            u8 left_reg = 0; // eax

            if (right_reg == left_reg) {
                // output already is in correct register
            } else {
                reg_deallocate(context, left_reg);

                buf_push(context->bytecode, 0x89);
                buf_push(context->bytecode, 0xc0 | left_reg | (right_reg << 3));

                #ifdef PRINT_GENERATED_INSTRUCTIONS
                printf("mov %s, %s\n", reg_names[left_reg], reg_names[right_reg]);
                #endif
            }
        }

        // add rsp, stack frame size
        buf_push(context->bytecode, 0x48);
        buf_push(context->bytecode, 0x83);
        buf_push(context->bytecode, 0xc4);
        buf_push(context->bytecode, stack_size);
        context->bytecode[stack_frame_size_text_location] = stack_size; // fixes up initial 'sub rsp, ...'

        #ifdef PRINT_GENERATED_INSTRUCTIONS
        printf("add rsp, stack_frame_size (stack_frame_size is %u)\n", stack_size);
        #endif

        for (u32 i = 0; i < buf_length(context->stack_fixups); i += 1) {
            Stack_Fixup* f = &context->stack_fixups[i];

            u8 old_value = context->bytecode[f->text_location];
            assert(old_value == 0x00);

            u8 adjusted_offset = stack_size - f->stack_offset - f->element_size;
            context->bytecode[f->text_location] = (u8) adjusted_offset;
        }

        // TODO this is only for testing purposes!!
        if (func != main_func) {
            buf_push(context->bytecode, 0xc3);
            #ifdef PRINT_GENERATED_INSTRUCTIONS
            printf("ret\n");
            #endif
        }
    }

    // Move output into .data+0
    {
        u32 output_var = context->funcs[main_func_index].first_var;

        u8 output_reg = reg_allocate(context, (Local) { .kind = local_variable, .index = output_var });

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

    arena_pop(&context->stack);
}



u64 round_to_next(u64 value, u64 step) {
    value += step - 1;
    value /= step;
    value *= step;
    return value;
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
            panic("ERROR: Can't apply fixup at %x which is beyond end of text section at %x\n", fixup->text_location, text_length);
        }

        i32 text_value = *((u32*) (context->bytecode + fixup->text_location));
        if (text_value != 0xefbeadde) {
            panic("ERROR: All fixup override locations should be set to {0xde 0xad 0xbe 0xef} as a sentinel. Found %x instead\n", text_value);
        }

        switch (fixup->kind) {
            case fixup_imported_function: {
                u32 l = fixup->imported.dll;
                u32 f = fixup->imported.function;

                if (l > buf_length(context->dlls)) {
                    panic(
                        "ERROR: Function fixup refers to invalid library %u. There are only %u dlls.\n",
                        l, buf_length(context->dlls)
                    );
                } else if (f > buf_length(context->dlls[l].functions)) {
                    panic(
                        "ERROR: Function fixup refers to invalid function %u in library %u. There are only %u functions.\n",
                        f, l, buf_length(context->dlls[l].functions)
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
                panic("ERROR: Import data will be invalid, because it has functions at to high rvas: %x!", function_name_address);
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

    printf("  %s file size: %u\n", path, file_length);
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

    printf("  Section count: %u\n", coff_header->section_count);
    printf("  Header size: %u\n", coff_header->size_of_optional_header);

    Image_Header* image_header = (void*) (coff_header + 1);

    printf("  Linker version: %u %u\n", image_header->major_linker_version, image_header->minor_linker_version);
    printf("  .text is %u, .data is %u, .bss is %u\n", image_header->size_of_code, image_header->size_of_initialized_data, image_header->size_of_uninitialized_data);
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
    printf("%u functions:\n", buf_length(context->funcs));
    for (u32 f = 0; f < buf_length(context->funcs); f += 1) {
        Func* func = context->funcs + f;

        u8* name = string_table_access(context->string_table, func->name);
        printf("  fn %s\n", name);

        printf("    %u variables: ", func->last_var - func->first_var);
        for (u32 v = func->first_var; v < func->last_var; v += 1) {
            Var* var = context->vars + v;
            u8* name = string_table_access(context->string_table, var->name);

            if (v == func->first_var) {
                printf("%s", name);
            } else {
                printf(", %s", name);
            }
        }
        printf("\n");

        printf("    %u statements:\n", func->last_stmt - func->first_stmt);
        for (u32 s = func->first_stmt; s < func->last_stmt; s += 1) {
            printf("      ");
            stmt_print(context, context->stmts + s);
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
    build_bytecode(&context);
    write_executable("out.exe", &context);

    //free_context(context);

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
