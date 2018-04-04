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
/*
#define assert(x) do { \
    if (!(x)) { \
        printf("assert(%s) failed, %s:%u\n", #x, __FILE__, __LINE__); \
        ExitProcess(-1); \
    } \
} while (0)
*/
#define assert(x) ((x)? (null) : (printf("assert(%s) failed, %s:%u\n", #x, __FILE__, __LINE__), ExitProcess(-1), null))


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

enum { ARENA_PAGE_SIZE = 4096 };

typedef struct Arena Arena;
typedef struct Arena_Page Arena_Page;

struct Arena {
    u64 pages;
    Arena_Page* current_page;
};

struct Arena_Page {
    Arena_Page* previous_page;
    u64 used, capacity;
    u8 data[0];
};

#define arena_insert(a, e)   (arena_insert_with_size((a), &(e), sizeof((e)), 16))
// NB (Morten, 30.03.18) Because msvc provides no alignof macro we just align everything to 16 bits. Might not be the best solution, but heyo, it works!

void arena_make_space(Arena* arena, u64 size, u64 align) {
    if (arena->current_page == null) {
        Arena_Page* page = (Arena_Page*) alloc(sizeof(Arena_Page) + ARENA_PAGE_SIZE);
        page->used = 0;
        page->capacity = ARENA_PAGE_SIZE;
        page->previous_page = null;
        arena->current_page = page;
    }

    u64 free_space = arena->current_page->capacity - arena->current_page->used;

    u8* start = ((u8*) arena->current_page) + sizeof(Arena_Page) + arena->current_page->used;

    u64 align_offset = ((u64) start) % align;
    if (align_offset != 0) {
        align_offset = align - align_offset;
    }

    if (size + align_offset > free_space) {
        Arena_Page* page = (Arena_Page*) alloc(sizeof(Arena_Page) + ARENA_PAGE_SIZE);
        page->used = 0;
        page->capacity = ARENA_PAGE_SIZE;
        page->previous_page = arena->current_page;
        arena->current_page = page;
    }
}

u8* arena_alloc(Arena* arena, u64 size, u64 align) {
    assert(size < ARENA_PAGE_SIZE);

    arena_make_space(arena, size, align);

    u8* ptr = ((u8*) arena->current_page) + sizeof(Arena_Page) + arena->current_page->used;
    u64 align_offset = ((u64) ptr) % align;
    if (align_offset != 0) {
        align_offset = align - align_offset;
        ptr += align_offset;
    }

    arena->current_page->used += size + align_offset;

    return ptr;
}

void* arena_insert_with_size(Arena* arena, void* element, u64 size, u64 align) {
    u8* ptr = arena_alloc(arena, size, align); 
    mem_copy((u8*) element, ptr, size);
    return (void*) ptr;
}

void arena_free(Arena* arena) {
    arena->pages = 0;

    Arena_Page* page = arena->current_page;
    while (page != null) {
        Arena_Page* previous_page = page->previous_page;
        free(page);
        page = previous_page;
    }
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

u32 string_table_search(u8* table, u8* string, u32 length) {
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

u32 string_table_canonicalize(u8** table, u8* string, u32 length) {
    u32 index;

    index = string_table_search(*table, string, length);
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


// AST

typedef struct File_Pos {
    u32 line;
} File_Pos;

typedef struct Token {
    enum {
        token_end_of_stream = 0,
        token_identifier,
        token_literal,
        token_operator,
        token_line_end,
        token_keyword_var,
    } kind;

    union {
        u32 identifier_string_table_index;
        u32 literal_value;
        u8 operator_symbol;
    };

    File_Pos pos;
} Token;

typedef struct Expr Expr;
struct Expr {
    enum {
        expr_variable,
        expr_literal,
    } kind;
    union {
        u32 variable;
        u32 literal;
    };

    enum {
        chain_none = 0,
        chain_add,
        chain_sub,
    } chain_op;
    Expr* chain; // or null if `chain_op = chain_none`
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


/*
#define OP_KIND_SET 0
#define OP_KIND_ADD 1
#define OP_KIND_SUB 2

#define OP_SOURCE_VAR 0
#define OP_SOURCE_LIT 1

typedef struct Op {
    u8 kind;
    u8 source_kind;
    u32 var;
    union { u32 var; u32 lit; } source;
} Op;
*/


typedef struct Var {
    u32 name;
    File_Pos declaration_pos;
} Var;

typedef struct AST {
    u8* string_table; // stretchy-buffer string table
    Stmt* stmts; // stretchy-buffer
    Var* vars;
} AST;

void free_ast(AST ast) {
    buf_free(ast.string_table);
    buf_free(ast.stmts);
    buf_free(ast.vars);
}

void token_print(u8* string_table, Token* t) {
    switch (t->kind) {

    case token_identifier: {
        u32 index = t->identifier_string_table_index;
        u8* name = string_table_access(string_table, index);
        printf("identifier \"%s\"", name);
    } break;

    case token_literal: {
        u32 value = t->literal_value;
        printf("%u", value);
    } break;

    case token_operator: {
        u8 operator = t->operator_symbol;
        printf("operator %c", operator);
    } break;

    case token_keyword_var: {
        printf("keyword var");
    } break;

    case token_line_end: {
        printf("end of line");
    } break;

    case token_end_of_stream: {
        printf("end of file");
    } break;

    default: {
        printf("<unkown token %x>", t->kind);
    } break;

    }
}

void expr_print(AST* ast, Expr* expr) {
    while (1) {
        switch (expr->kind) {
            case expr_variable: {
                Var* var = &ast->vars[expr->variable];
                u8* name = string_table_access(ast->string_table, var->name);
                printf("%s", name);
            } break;

            case expr_literal: {
                printf("%u", expr->literal);
            } break;

            default: {
                printf("<unkown expression %x>", expr->kind);
            } break;
        }

        if (expr->chain_op == chain_none) {
            break;
        }

        switch (expr->chain_op) {
            case chain_add: printf(" + "); break;
            case chain_sub: printf(" - "); break;
            default:        printf(" <unkown operator> "); break;
        }

        expr = expr->chain;
    }
}

void stmt_print(AST* ast, Stmt* stmt) {
    switch (stmt->kind) {
        case stmt_assignment: {
            Var* var = &ast->vars[stmt->assignment.var];
            u8* name = string_table_access(ast->string_table, var->name);
            printf("%s = ", name);
            expr_print(ast, stmt->assignment.expr);
        } break;

        case stmt_end_of_stream: {
            printf("end of stream");
        } break;

        default: {
            printf("<unkown statement %x>", stmt->kind);
        } break;
    }
}

u32 ast_find_var(AST* ast, u32 name) {
    u32 length = buf_length(ast->vars);
    for (u32 i = 0; i < length; i += 1) {
        if (ast->vars[i].name == name) {
            return i;
        }
    }
    return U32_MAX;
}

Expr* expr_parse_with_length(Arena* arena, AST* ast, Token* t, u32 length) {
    if (length == 0) {
        printf("Expected expression but found nothing (Line %u)\n", t->pos.line);
        return null;
    }

    Expr* start_expr = arena_insert(arena, ((Expr) {0}));
    Expr* expr = start_expr;

    Token* end = (t + length);
    while (t != end) {
        // Parse a identifier or literal
        switch (t->kind) {
            case token_literal: {
                expr->kind = expr_literal;
                expr->literal = t->literal_value;
            } break;

            case token_identifier: {
                u32 name_index = t->identifier_string_table_index;
                u32 var_index = ast_find_var(ast, name_index);

                if (var_index == U32_MAX) {
                    u8* name = string_table_access(ast->string_table, name_index);
                    printf("Found undeclared variable '%s' in expression (Line %u)\n", name, t->pos.line);
                    return null;
                }

                expr->kind = expr_variable;
                expr->variable = var_index;
            } break;

            default: {
                printf("Expected identifier or literal after ");
                token_print(ast->string_table, t - 1);
                printf(", but found ");
                token_print(ast->string_table, t);
                printf(" (Line %u)\n", t->pos.line);
                return null;
            } break;
        }

        t += 1;
        if (t == end) { break; }

        // Maybe parse a chaining operator
        if (t->kind == token_operator) {
            int chain_op;
            switch (t->operator_symbol) {
            case '+': chain_op = chain_add; break;
            case '-': chain_op = chain_sub; break;
            default: {
                printf("Expected binary operator, but got '%c' (Line %u)\n", t->operator_symbol, t->pos.line);
                return null;
            } break;
            }

            expr->chain_op = chain_op;
            expr->chain = arena_insert(arena, ((Expr) {0}));
            expr = expr->chain;

            t += 1;
        } else {
            printf("Expected end of expression or operator after ");
            token_print(ast->string_table, t - 1);
            printf(", but found ");
            token_print(ast->string_table, t);
            printf(" (Line %u)\n");
            return null;
        }
    }

    return start_expr;
}

void expr_collapse(Expr* first) {
    u32 literal_count = 0;
    u32 literal_positive = 0;
    u32 literal_negative = 0;
    Expr* e;

    int chain_op = chain_add;
    e = first;
    while (1) {
        if (e->kind == expr_literal) {
            literal_count += 1;
            switch (chain_op) {
                case chain_add: literal_positive += e->literal; break;
                case chain_sub: literal_negative += e->literal; break;
                default: assert(false);
            }
        }

        chain_op = e->chain_op;
        if (chain_op == chain_none) {
            break;
        } else {
            e = e->chain;
        }
    }

    if (literal_count <= 1) {
        return;
    }

    e = first;
    Expr* unused_expr = null;
    Expr* prev = null;
    while (1) {
        if (e->chain_op == chain_none) break;
        if (e->kind == expr_literal) {
            unused_expr = e->chain;
            mem_copy((u8*) e->chain, (u8*) e, sizeof(Expr));
        } else {
            prev = e;
            e = e->chain;
        }
    }

    if (e->kind != expr_literal) {
        if (literal_positive == literal_negative) return;

        assert(unused_expr != null);
        e->chain = unused_expr;
        prev = e;
        e = e->chain;
    }

    mem_clear((u8*) e, sizeof(Expr));
    e->kind = expr_literal;

    if (prev == null) {
        e->literal = literal_positive - literal_negative; // We have no choise but to encode a wrapped literal
    } else {
        if (literal_negative > literal_positive) {
            prev->chain_op = chain_sub;
            e->literal = literal_negative - literal_positive;
        } else {
            prev->chain_op = chain_add;
            e->literal = literal_positive - literal_negative;
        }
    }
}

u32 expr_eval(Expr* expr, u32* var_values) {
    int chain_op = chain_add;
    u32 value = 0;

    while (1) {
        u32 sub_value = 0;
        switch (expr->kind) {
            case expr_variable: sub_value = var_values[expr->variable]; break;
            case expr_literal:  sub_value = expr->literal; break;
            default: assert(false);
        }

        switch (chain_op) {
            case chain_add: value += sub_value; break;
            case chain_sub: value -= sub_value; break;
            default: assert(false);
        }

        if (expr->chain_op == chain_none) {
            break;
        } else {
            chain_op = expr->chain_op;
            expr = expr->chain;
        }
    }

    return value;
}

AST* build_ast(Arena* arena, u8* path) {
    u8* file;
    u32 file_length;
    if (!read_entire_file(path, &file, &file_length)) {
        printf("Couldn't load %s\n", path);
        return null;
    }

    u8* string_table = null;
    bool valid = true;

    u32 keyword_var = string_table_canonicalize(&string_table, "var", 3);

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

    for (u32 i = 0; i < file_length;) {
        switch (file[i]) {

        LOWERCASE UPPERCASE case '_': {
            u32 first = i;
            u32 last = i;

            for (; i < file_length; i += 1) {
                switch (file[i]) {
                LOWERCASE UPPERCASE DIGIT case '_': { last = i; } break;
                default: goto done_with_identifier;
                }
            }
            done_with_identifier:

            u32 length = last - first + 1;
            u8* identifier = &file[first];

            u32 string_table_index = string_table_canonicalize(&string_table, identifier, length);

            if (string_table_index == keyword_var) {
                buf_push(tokens, ((Token) { token_keyword_var, .pos = file_pos }));
            } else {
                buf_push(tokens, ((Token) { token_identifier, .identifier_string_table_index = string_table_index, .pos = file_pos }));
            }
        } break;

        DIGIT {
            u32 first = i;
            u32 last = i;
            bool overflow = false;
            
            u32 value = 0;

            for (; i < file_length; i += 1) {
                switch (file[i]) {
                DIGIT {
                    last = i;

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
                    last - first + 1, &file[first], value, file_pos.line
                );
            }

            buf_push(tokens, ((Token) { token_literal, .literal_value = value, .pos = file_pos }));
        } break;

        case '+': case '-': case '=': {
            u8 symbol = file[i];
            buf_push(tokens, ((Token) { token_operator, .operator_symbol = symbol, .pos = file_pos }));
            i += 1;
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

        case '#': {
            // Eat the rest of the line as a comment
            for (; i < file_length; i += 1) {
                if (file[i] == '\n' || file[i] == '\r') { break; }
            }
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
    AST* ast = arena_insert(arena, ((AST) {0}));
    ast->string_table = string_table;

    Var output_var = {0};
    output_var.name = string_table_canonicalize(&ast->string_table, "output", 6);
    buf_push(ast->vars, output_var);

    #define EAT_TOKENS_TO_NEWLINE \
    while (t->kind != token_line_end && t->kind != token_end_of_stream) { t += 1; }

    for (Token* t = tokens; t->kind != token_end_of_stream; t += 1) {
        switch (t->kind) {

        case token_keyword_var: {
            File_Pos declaration_pos = t->pos;

            t += 1;
            if (t->kind != token_identifier) {
                printf("Expected identifier after 'var', but found ");
                token_print(ast->string_table, t);
                printf(" (Line %u)\n", t->pos.line);
                EAT_TOKENS_TO_NEWLINE
                valid = false;
                break;
            }
            u32 name_index = t->identifier_string_table_index;
            u8* name = string_table_access(ast->string_table, name_index);

            Expr* initial_value = null;

            t += 1;
            if (t->kind == token_line_end || t->kind == token_end_of_stream) {
                initial_value = arena_insert(arena, ((Expr) {0}));
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
                initial_value = expr_parse_with_length(arena, ast, start, length);
                if (initial_value == null) {
                    break;
                }
            } else {
                printf("Expected operator = or end of line after 'var %s', but found ", name);
                token_print(ast->string_table, t);
                printf(" (Line %u)\n", t->pos.line);
                EAT_TOKENS_TO_NEWLINE
                valid = false;
                break;
            }

            bool redeclaration = false;
            for (u32 i = 0; i < buf_length(ast->vars); i += 1) {
                Var* v = &ast->vars[i];
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

            u32 var_index = buf_length(ast->vars);
            Var var = {0};
            var.name = name_index;
            var.declaration_pos = declaration_pos;
            buf_push(ast->vars, var);

            Stmt stmt = {0};
            stmt.kind = stmt_assignment;
            stmt.assignment.var = var_index;
            stmt.assignment.expr = initial_value;
            buf_push(ast->stmts, stmt);
        } break;

        case token_identifier: {
            File_Pos assignment_pos = t->pos;

            u32 name_index = t->identifier_string_table_index;
            u8* name = string_table_access(ast->string_table, name_index);

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
                expr = expr_parse_with_length(arena, ast, start, length);
                if (expr == null) {
                    break;
                }
            } else {
                printf("Expected operator = after '%s', but found ", name);
                token_print(ast->string_table, t);
                printf(" (Line %u)\n", t->pos.line);
                EAT_TOKENS_TO_NEWLINE
                valid = false;
                break;
            }

            u32 var_index = ast_find_var(ast, name_index);
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
            buf_push(ast->stmts, stmt);
        } break;

        case token_literal: {
            printf(
                "Found %u, but lines can't start with a literal (Line %u)\n",
                t->literal_value, t->pos.line
            );
            valid = false;
        } break;
        case token_operator: {
            printf(
                "Found %c, but lines can't start with operators (Line %u)\n",
                t->operator_symbol, t->pos.line
            );
            valid = false;
        } break;

        case token_line_end: {} break;

        default: case token_end_of_stream: {
            printf("Invalid token, we should have broken out of the loop earlier!\n");
            assert(false);
        } break;

        }
    }
    buf_push(ast->stmts, ((Stmt) { stmt_end_of_stream }));

    for (Stmt* stmt = ast->stmts; stmt->kind != stmt_end_of_stream; stmt += 1) {
        if (stmt->kind == stmt_assignment) {
            expr_collapse(stmt->assignment.expr);
        }
    }

    printf("%u variables:\n", buf_length(ast->vars));
    for (Var* var = ast->vars; var != buf_end(ast->vars); var += 1) {
        u8* name = string_table_access(ast->string_table, var->name);
        printf("  var %s\n", name);
    }
    printf("%u statements:\n", buf_length(ast->stmts) - 1);
    for (Stmt* stmt = ast->stmts; stmt->kind != stmt_end_of_stream; stmt += 1) {
        printf("  ");
        stmt_print(ast, stmt);
        printf("\n");
    }

    if (!valid) {
        printf("Encountered errors while lexing / parsing, exiting compiler!\n");
        free_ast(*ast);
        // TODO rewind arena to before we started inserting stuff into it!
        // probably doesn't matter for now, we just exit out anyways
        return null;
    }

    // Try evaluating the ast
    printf("Evaluating...\n");

    u32* var_values = (u32*) arena_alloc(arena, sizeof(u32) * buf_length(ast->vars), 4);
    mem_clear((u8*) var_values, sizeof(u32) * buf_length(ast->vars));

    for (Stmt* stmt = ast->stmts; stmt->kind != stmt_end_of_stream; stmt += 1) {
        switch (stmt->kind) {

        case stmt_assignment: {
            u32 value = expr_eval(stmt->assignment.expr, var_values);
            var_values[stmt->assignment.var] = value;
        } break;

        default: case stmt_end_of_stream: {
            printf("Invalid statement, we should have broken out of the loop earlier!\n");
            assert(false);
        } break;

        }
    }
    for (u32 i = 0; i < buf_length(ast->vars); i += 1) {
        u32 name_index = ast->vars[i].name;
        u8* name = string_table_access(ast->string_table, name_index);
        u32 value = var_values[i];
        printf("  %s = %u\n", name, value);
    }

    return ast;
}

// Codegen

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

const u16 COFF_FLAGS_EXECUTABLE_IMAGE           = 0x0002;
const u16 COFF_FLAGS_LARGE_ADDRESS_AWARE        = 0x0020;
// the rest are not used...
const u16 COFF_FLAGS_RELOCS_STRIPPED            = 0x0001;
const u16 COFF_FLAGS_LINE_NUMS_STRIPPED         = 0x0004;
const u16 COFF_FLAGS_LOCAL_SYMS_STRIPPED        = 0x0008;
const u16 COFF_FLAGS_AGGRESSIVE_WS_TRIM         = 0x0010;
const u16 COFF_FLAGS_BYTES_REVERSED_LO          = 0x0080;
const u16 COFF_FLAGS_32BIT_MACHINE              = 0x0100;
const u16 COFF_FLAGS_DEBUG_STRIPPED             = 0x0200;
const u16 COFF_FLAGS_REMOVABLE_RUN_FROM_SWAP    = 0x0400;
const u16 COFF_FLAGS_NET_RUN_FROM_SWAP          = 0x0800;
const u16 COFF_FLAGS_SYSTEM                     = 0x1000;
const u16 COFF_FLAGS_DLL                        = 0x2000;
const u16 COFF_FLAGS_UP_SYSTEM_ONLY             = 0x4000;
const u16 COFF_FLAGS_BYTES_REVERSED_HI          = 0x8000;

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

    u32 checksum; // Not checked for exes
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


typedef struct Fixup {
    u64 text_location;

    enum {
        rel_to_idata,
        rel_to_data
    } section;

    union {
        struct {
            u32 offset;
        } data;
        struct {
            u32 function;
            u32 dll;
        } idata;
    };
} Fixup;

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

#define PRINT_CODEGEN
u8* reg_names[REG_COUNT] = { "eax", "ecx", "edx", "ebx" };

#define NO_STACK_SPACE_ALLOCATED U32_MAX

typedef struct Stack_Fixup {
    u64 text_location;
    u32 stack_offset;
    u32 element_size;
} Stack_Fixup;



typedef struct Exe {
    // For full executable
    u8* text;
    u8* data;
    Fixup* fixups;
    DynlibImport* dlls;

    // Per function
    struct {
        enum {
            reg_unused = 0,
            reg_local,
        } usage;
        u32 var;
        u32 alloc_time;
    } regs[REG_COUNT];

    u32 var_count;
    u32* stack_offsets; // one per variable, arena allocated
    u32 next_stack_offset;

    Stack_Fixup* stack_fixups; // stretchy-buffer

    u32 time; // incremented with each emitted instruction
} Exe;

void free_win64exe(Exe exe) {
    buf_free(exe.text);
    buf_free(exe.data);
    buf_free(exe.fixups);
    for (DynlibImport* library = exe.dlls; library != buf_end(exe.dlls); library += 1) {
        buf_free(library->functions);
    }
    buf_free(exe.dlls);
    buf_free(exe.stack_fixups);
}


u8 reg_allocate(Exe* exe, AST* ast, u32 var) {
    bool deallocate = true;
    bool reallocate = true;

    u8 reg = REG_BAD;
    u32 oldest_time = exe->time;
    for (u32 r = 0; r < REG_COUNT; r += 1) {
        // Reallocate a old register
        if (exe->regs[r].alloc_time < oldest_time) {
            oldest_time = exe->regs[r].alloc_time;
            reg = r;

            reallocate = true;
            deallocate = true;
        }

        // Or better, use a unused register
        if (exe->regs[r].usage == reg_unused) {
            oldest_time = 0;
            reg = r;

            reallocate = true;
            deallocate = false;
        }

        // Or even better, find a previously allocated regsiter
        if (exe->regs[r].usage == reg_local && exe->regs[r].var == var) {
            reg = r;

            reallocate = false;
            deallocate = false;

            break;
        }
    }
    assert(reg != REG_BAD);

    // Deallocate old contents of register if needed
    if (deallocate) {
        u32 old_var = exe->regs[reg].var;
        u32 stack_offset = exe->stack_offsets[old_var];
        if (stack_offset == NO_STACK_SPACE_ALLOCATED) {
            stack_offset = exe->next_stack_offset;
            exe->next_stack_offset += sizeof(u32);
            exe->stack_offsets[old_var] = stack_offset;
        }

        #ifdef PRINT_CODEGEN
        u8* var_name = string_table_access(ast->string_table, ast->vars[old_var].name);
        printf("  ; de-alloc %s for %s\n", reg_names[reg], var_name);
        #endif

        // TODO check if we need to deallocate the register at all, or if we can get away
        // with just overwriting it!
        // To do this, we need info about the last use of a certain variable.

        // Eventually, this assertion will trip. We then need to encode disp32 instead of always encoding disp8
        // The assert checks for signed values, not sure if that is needed...
        assert((stack_offset & 0x7f) == stack_offset);

        buf_push(exe->text, 0x89); // mov r/m32 r32     (MR)
        buf_push(exe->text, 0x44 | (reg << 3));
        buf_push(exe->text, 0x24);
        buf_push(exe->text, 0x00);
        exe->time += 1;

        Stack_Fixup stack_fixup = {0};
        stack_fixup.text_location = buf_length(exe->text) - sizeof(u8);
        stack_fixup.stack_offset = stack_offset;
        stack_fixup.element_size = sizeof(u32);
        buf_push(exe->stack_fixups, stack_fixup);

        #ifdef PRINT_CODEGEN
        printf("  mov [stack %u], %s\n", stack_offset, reg_names[reg]);
        #endif
    }

    // Reallocate regsiter
    if (reallocate) {
        #ifdef PRINT_CODEGEN
        u8* var_name = string_table_access(ast->string_table, ast->vars[var].name);
        printf("  ; alloc %s for %s\n", reg_names[reg], var_name);
        #endif

        exe->regs[reg].usage = reg_local;
        exe->regs[reg].var = var;
        exe->regs[reg].alloc_time = exe->time;

        u32 stack_offset = exe->stack_offsets[var];
        if (stack_offset != NO_STACK_SPACE_ALLOCATED) {
            // mov r32 r/m32
            buf_push(exe->text, 0x8b);
            buf_push(exe->text, 0x44 | (reg << 3));
            buf_push(exe->text, 0x24);
            buf_push(exe->text, 0x00);
            exe->time += 1;

            Stack_Fixup stack_fixup = {0};
            stack_fixup.text_location = buf_length(exe->text) - sizeof(u8);
            stack_fixup.stack_offset = stack_offset;
            stack_fixup.element_size = sizeof(u32);
            buf_push(exe->stack_fixups, stack_fixup);

            #ifdef PRINT_CODEGEN
            printf("  mov %s, [stack %u]\n", reg_names[reg], stack_offset);
            #endif
        }
    }

    return reg;
}

Exe* gen_win64exe(Arena* arena, AST* ast) {
    Exe* exe = arena_insert(arena, ((Exe) {0}));

    exe->var_count = buf_length(ast->vars);
    exe->stack_offsets = (u32*) arena_alloc(arena, sizeof(u32) * exe->var_count, sizeof(u32));
    for (u32 i = 0; i < exe->var_count; i += 1) { exe->stack_offsets[i] = NO_STACK_SPACE_ALLOCATED; }

    #ifdef PRINT_CODEGEN
    printf("Codegen:\n");
    #endif

    // sub rsp, stack frame size
    buf_push(exe->text, 0x48);
    buf_push(exe->text, 0x83);
    buf_push(exe->text, 0xec);
    buf_push(exe->text, 0x00);
    u64 stack_frame_size_text_location = buf_length(exe->text) - sizeof(u8);
    #ifdef PRINT_CODEGEN
    printf("  ; enter function\n  sub rsp, stack_size\n");
    #endif

    for (Stmt* stmt = ast->stmts; stmt->kind != stmt_end_of_stream; stmt += 1) {
        #ifdef PRINT_CODEGEN
        printf("  ; ");
        stmt_print(ast, stmt);
        printf("\n");
        #endif

        switch (stmt->kind) {
            case stmt_assignment: {
                u8 reg = reg_allocate(exe, ast, stmt->assignment.var);

                Expr* prev = null;
                Expr* expr = stmt->assignment.expr;

                while (1) {
                    switch(expr->kind) {
                        case expr_literal: {
                            u32 value = expr->literal;

                            if (prev == null) {
                                // mov reg, literal
                                buf_push(exe->text, 0xb8 | reg);
                                exe->time += 1;
                                    
                                #ifdef PRINT_CODEGEN
                                printf("  mov %s, %u\n", reg_names[reg], value);
                                #endif
                            } else {
                                // add/sub reg, literal
                                u8 modrm;
                                switch (prev->chain_op) {
                                    case chain_add: modrm = 0xc0; break;
                                    case chain_sub: modrm = 0xe8; break;
                                    default: assert(false);
                                }
                                modrm |= reg;

                                buf_push(exe->text, 0x81);
                                buf_push(exe->text, modrm);

                                #ifdef PRINT_CODEGEN
                                if (prev->chain_op == chain_add) {
                                    printf("  add %s, %u\n", reg_names[reg], value);
                                } else {
                                    printf("  sub %s, %u\n", reg_names[reg], value);
                                }
                                #endif
                            }

                            // the literal for the above instructions
                            buf_push(exe->text, value & 0xff);
                            buf_push(exe->text, (value >> 8) & 0xff);
                            buf_push(exe->text, (value >> 16) & 0xff);
                            buf_push(exe->text, (value >> 24) & 0xff);
                            exe->time += 1;
                        } break;

                        case expr_variable: {
                            // TODO optimization:
                            // If we don't have a register allocated, we can use 'mov r32 r/m32' to
                            // add without pulling the second operand into a separate register.

                            u8 source_reg = reg_allocate(exe, ast, expr->variable);

                            if (prev == null) {
                                // mov reg, source_reg
                                if (reg != source_reg) {
                                    buf_push(exe->text, 0x8b);
                                    buf_push(exe->text, 0xc0 | source_reg | (reg << 3));
                                    exe->time += 1;

                                    #ifdef PRINT_CODEGEN
                                    printf("  mov %s, %s\n", reg_names[reg], reg_names[source_reg]);
                                    #endif
                                }
                            } else {
                                // add/sub reg, source_reg
                                u8 instruction;
                                switch (prev->chain_op) {
                                    case chain_add: instruction = 0x03; break;
                                    case chain_sub: instruction = 0x2b; break;
                                    default: assert(false);
                                }

                                buf_push(exe->text, instruction);
                                buf_push(exe->text, 0xc0 | source_reg | (reg << 3));
                                exe->time += 1;

                                #ifdef PRINT_CODEGEN
                                if (prev->chain_op == chain_add) {
                                    printf("  add %s, %s\n", reg_names[reg], reg_names[source_reg]);
                                } else {
                                    printf("  sub %s, %s\n", reg_names[reg], reg_names[source_reg]);
                                }
                                #endif
                            }
                        } break;

                        default: assert(false);
                    }

                    if (expr->chain_op == chain_none) {
                        break;
                    } else {
                        prev = expr;
                        expr = expr->chain;
                    }
                }
            } break;

            default: assert(false);
        }
    }

    // Fix up stack

    u32 stack_size = exe->next_stack_offset; // TODO + stack space for function parameters
    stack_size = ((stack_size + 0x0f) & (~0x0f)); // Round up to 16-byte align
    // If this assertion trips, we have to encode stack size as a imm32 in the add/sub
    // instructions setting up the stack frame.
    // While we are at it, me might want to figure out a way of removing the add/sub
    // instructions completely when we do not use the stack at all!
    assert((stack_size & 0x7f) == stack_size);

    // add rsp, stack frame size
    buf_push(exe->text, 0x48);
    buf_push(exe->text, 0x83);
    buf_push(exe->text, 0xc4);
    buf_push(exe->text, stack_size);
    #ifdef PRINT_CODEGEN
    printf("  ; leave function (stack_size = %u)\n  add rsp, stack_size\n", stack_size);
    #endif

    exe->text[stack_frame_size_text_location] = stack_size; // fixes up initial sub

    for (u32 i = 0; i < buf_length(exe->stack_fixups); i += 1) {
        Stack_Fixup* f = &exe->stack_fixups[i];

        u8 old_value = exe->text[f->text_location];
        assert(old_value == 0x00);

        u8 adjusted_offset = stack_size - f->stack_offset - f->element_size;
        exe->text[f->text_location] = (u8) adjusted_offset;
    }

    // TODO we need preserve non-volatile registers!

    // Move output into .data+0
    {
        u8 output_reg = reg_allocate(exe, ast, 0);

        buf_push(exe->text, 0x88);
        buf_push(exe->text, 0x05 | (output_reg << 3));
        buf_push(exe->text, 0xde);
        buf_push(exe->text, 0xad);
        buf_push(exe->text, 0xbe);
        buf_push(exe->text, 0xef);

        Fixup fixup = {0};
        fixup.text_location = buf_length(exe->text) - sizeof(i32);
        fixup.section = rel_to_data;
        fixup.data.offset = 0;
        buf_push(exe->fixups, fixup);
    }

    DynlibImport kernel32 = {0};
    kernel32.name = "KERNEL32.DLL";
    buf_push(kernel32.functions, ((Import_Function){"GetStdHandle", 0x2d5}));
    buf_push(kernel32.functions, ((Import_Function){"WriteFile", 0x619}));
    buf_push(kernel32.functions, ((Import_Function){"ExitProcess", 0x162}));
    buf_push(exe->dlls, kernel32);

    str_push_str(&exe->data, "_i\n\0", 4);

    Fixup fixup = {0};

    // sub rsp,58h  
    buf_push(exe->text, 0x48);
    buf_push(exe->text, 0x83);
    buf_push(exe->text, 0xec);
    buf_push(exe->text, 0x58);

    //lea rax,[0cc3000h]  
    buf_push(exe->text, 0x48);
    buf_push(exe->text, 0x8d);
    buf_push(exe->text, 0x05);
    buf_push(exe->text, 0xde);
    buf_push(exe->text, 0xad);
    buf_push(exe->text, 0xbe);
    buf_push(exe->text, 0xef);
    fixup.text_location = buf_length(exe->text) - sizeof(i32);
    fixup.section = rel_to_data;
    fixup.data.offset = 0;
    buf_push(exe->fixups, fixup);
    // mov qword ptr [rsp+38h],rax  
    buf_push(exe->text, 0x48);
    buf_push(exe->text, 0x89);
    buf_push(exe->text, 0x44);
    buf_push(exe->text, 0x24);
    buf_push(exe->text, 0x38);

    // GetStdHandle()
    // mov ecx, 0xfffffff5   (param)
    buf_push(exe->text, 0xb9);
    buf_push(exe->text, 0xf5);
    buf_push(exe->text, 0xff);
    buf_push(exe->text, 0xff);
    buf_push(exe->text, 0xff);
    // call qword ptr [rip + 0x0f9b]  
    buf_push(exe->text, 0xff);
    buf_push(exe->text, 0x15);
    buf_push(exe->text, 0xde);
    buf_push(exe->text, 0xad);
    buf_push(exe->text, 0xbe);
    buf_push(exe->text, 0xef);

    fixup.text_location = buf_length(exe->text) - sizeof(i32);
    fixup.section = rel_to_idata;
    fixup.idata.dll = 0;
    fixup.idata.function = 0;
    buf_push(exe->fixups, fixup);

    // mov qword ptr [rsp+40h],rax  
    buf_push(exe->text, 0x48);
    buf_push(exe->text, 0x89);
    buf_push(exe->text, 0x44);
    buf_push(exe->text, 0x24);
    buf_push(exe->text, 0x40);
    
    // This is space for the `bytes_written` pointer which is returned
    // mov dword ptr [rsp+30h],0  
    buf_push(exe->text, 0xc7);
    buf_push(exe->text, 0x44);
    buf_push(exe->text, 0x24);
    buf_push(exe->text, 0x30);
    buf_push(exe->text, 0x00);
    buf_push(exe->text, 0x00);
    buf_push(exe->text, 0x00);
    buf_push(exe->text, 0x00);
    
    // WriteFile()
    // mov qword ptr [rsp+20h],0  
    buf_push(exe->text, 0x48);
    buf_push(exe->text, 0xc7);
    buf_push(exe->text, 0x44);
    buf_push(exe->text, 0x24);
    buf_push(exe->text, 0x20);
    buf_push(exe->text, 0x00);
    buf_push(exe->text, 0x00);
    buf_push(exe->text, 0x00);
    buf_push(exe->text, 0x00);
    // lea r9,[rsp+30h]  
    buf_push(exe->text, 0x4c);
    buf_push(exe->text, 0x8d);
    buf_push(exe->text, 0x4c);
    buf_push(exe->text, 0x24);
    buf_push(exe->text, 0x30);
    // mov r8d,3  
    buf_push(exe->text, 0x41);
    buf_push(exe->text, 0xb8);
    buf_push(exe->text, 0x03);
    buf_push(exe->text, 0x00);
    buf_push(exe->text, 0x00);
    buf_push(exe->text, 0x00);
    // mov rdx,qword ptr [rsp+38h]  
    buf_push(exe->text, 0x48);
    buf_push(exe->text, 0x8b);
    buf_push(exe->text, 0x54);
    buf_push(exe->text, 0x24);
    buf_push(exe->text, 0x38);
    // mov rcx,qword ptr [rsp+40h]  
    buf_push(exe->text, 0x48);
    buf_push(exe->text, 0x8b);
    buf_push(exe->text, 0x4c);
    buf_push(exe->text, 0x24);
    buf_push(exe->text, 0x40);
    // call        qword ptr [rip + buf_push(exe->text, 0x0f72]  
    buf_push(exe->text, 0xff);
    buf_push(exe->text, 0x15);
    buf_push(exe->text, 0xde);
    buf_push(exe->text, 0xad);
    buf_push(exe->text, 0xbe);
    buf_push(exe->text, 0xef);

    fixup.text_location = buf_length(exe->text) - sizeof(i32);
    fixup.section = rel_to_idata;
    fixup.idata.dll = 0;
    fixup.idata.function = 1;
    buf_push(exe->fixups, fixup);

    // ExitProcess()
    // xor ecx,ecx  
    buf_push(exe->text, 0x33);
    buf_push(exe->text, 0xc9);
    // call qword ptr [rip + 0x0f72]  
    buf_push(exe->text, 0xff);
    buf_push(exe->text, 0x15);
    buf_push(exe->text, 0xde);
    buf_push(exe->text, 0xad);
    buf_push(exe->text, 0xbe);
    buf_push(exe->text, 0xef);

    fixup.text_location = buf_length(exe->text) - sizeof(i32);
    fixup.section = rel_to_idata;
    fixup.idata.dll = 0;
    fixup.idata.function = 2;
    buf_push(exe->fixups, fixup);

    // xor eax,eax  
    buf_push(exe->text, 0x33);
    buf_push(exe->text, 0xc0);

    // Reset stack
    // add rsp,58h  
    buf_push(exe->text, 0x48);
    buf_push(exe->text, 0x83);
    buf_push(exe->text, 0xc4);
    buf_push(exe->text, 0x58);
    // ret
    buf_push(exe->text, 0xc3);

    return exe;
}

void write_executable(u8* path, Exe* exe) {
    enum { section_count = 4 }; // So we can use it as an array length
    u64 in_file_alignment = 0x200;
    u64 in_memory_alignment = 0x1000;
    u64 dos_prepend_size = 200;
    u64 total_header_size = dos_prepend_size + sizeof(COFF_Header) + sizeof(Image_Header) + section_count*sizeof(Section_Header);

    u64 text_length = buf_length(exe->text);
    u64 data_length = buf_length(exe->data);

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
    bool bad_fixups = false;
    for (u64 i = 0; i < buf_length(exe->fixups); i += 1) {
        Fixup* fixup = &exe->fixups[i];

        if (fixup->text_location >= text_length) {
            printf("ERROR: Can't apply fixup at %x which is beyond end of text section at %x\n", fixup->text_location, text_length);
            bad_fixups = true;
            continue;
        }

        i32 text_value = *((u32*) (exe->text + fixup->text_location));
        if (text_value != 0xefbeadde) {
            printf("ERROR: All fixup override locations should be set to {0xde 0xad 0xbe 0xef} as a sentinel. Found %x instead\n", text_value);
            bad_fixups = true;
        }

        if (fixup->section == rel_to_idata) {
            u32 l = fixup->idata.dll;
            u32 f = fixup->idata.function;

            if (l > buf_length(exe->dlls)) {
                printf(
                    "ERROR: Function fixup refers to invalid library %u. There are only %u dlls.\n",
                    fixup->idata.dll, buf_length(exe->dlls)
                );
                bad_fixups = true;
            } else if (f > buf_length(exe->dlls[l].functions)) {
                printf(
                    "ERROR: Function fixup refers to invalid function %u in library %u. There are only %u functions.\n",
                    f, l, buf_length(exe->dlls[l].functions)
                );
                bad_fixups = true;
            }
        }
    }
    assert(!bad_fixups);

    // Build idata
    u8* idata = null;

    typedef struct Import_Entry {
        u32 lookup_table_address;
        u32 timestamp;
        u32 forwarder_chain;
        u32 name_address;
        u32 address_table_address;
    } Import_Entry;

    str_push_zeroes(&idata, (buf_length(exe->dlls) + 1) * sizeof(Import_Entry));
    for (u64 i = 0; i < buf_length(exe->dlls); i += 1) {
        DynlibImport* library = &exe->dlls[i];

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
                printf("WARN: .idata will be invalid, because it has functions at to high rvas: %x!", function_name_address);
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
        Import_Entry* entry = (void*) (idata + i*sizeof(Import_Entry));
        entry->address_table_address = idata_memory_start + address_table_start;
        entry->lookup_table_address  = idata_memory_start + lookup_table_start;
        entry->name_address          = idata_memory_start + name_table_start;

        // Apply fixups for this library
        for (u64 k = 0; k < buf_length(exe->fixups); k += 1) {
            Fixup* fixup = &exe->fixups[k];
            if (fixup->section != rel_to_idata || fixup->idata.dll != i) { continue; }

            u32 function = fixup->idata.function;
            u64 function_address = idata_memory_start + address_table_start + sizeof(u64)*function;

            i32* text_value = (u32*) (exe->text + fixup->text_location);
            *text_value = function_address;
            *text_value -= (text_memory_start + fixup->text_location + sizeof(i32)); // make relative
        }
    }
    u64 idata_length = buf_length(idata);

    // Knowing idata size, we can compute final size
    u64 file_image_size   = idata_file_start   + round_to_next(idata_length, in_file_alignment);
    u64 memory_image_size = idata_memory_start + round_to_next(idata_length, in_memory_alignment);

    // Apply data fixups
    for (u64 i = 0; i < buf_length(exe->fixups); i += 1) {
        Fixup* fixup = &exe->fixups[i];
        if (fixup->section != rel_to_data) { continue; }

        i32* text_value = (u32*) (exe->text + fixup->text_location);
        *text_value = data_memory_start + fixup->data.offset;
        *text_value -= (text_memory_start + fixup->text_location + sizeof(i32)); // make relative
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
    image.entry_point = text_memory_start;
    image.base_of_code = text_memory_start;
    image.size_of_image = memory_image_size;
    image.image_base = 0x00400000;

    image.stack_reserve = 0x100000;
    image.stack_commit  = 0x100000;
    image.heap_reserve  = 0x100000;
    image.heap_commit   = 0x100000;

    image.number_of_rva_and_sizes = 16;
    image.data_directories[1].virtual_address = idata_memory_start;
    image.data_directories[1].size = (buf_length(exe->dlls) + 1)*sizeof(Import_Entry);
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
    mem_copy(exe->text, output_file + text_file_start,  text_length);
    mem_copy(exe->data, output_file + data_file_start,  data_length);
    mem_copy(pdata,    output_file + pdata_file_start, pdata_length);
    mem_copy(idata,    output_file + idata_file_start, idata_length);

    write_entire_file(path, output_file, file_image_size);

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



void main() {
    //print_executable_info("build/tiny.exe");

    Arena arena = {0};

    AST* ast = build_ast(&arena, "W:/small/asm2/code.txt");
    if (ast == null) {
        printf("Failed building ast\n");
        return;
    }

    Exe* exe = gen_win64exe(&arena, ast);
    if (exe == null) {
        printf("Failed generating executable\n");
        return;
    }

    write_executable("out.exe", exe);

    printf("Running generated executable\n");
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
