
// TODO How do we get rid of this in the user facing part of the library?
// We currently, as far as I know, depend on the user giving us two arenas
// (though we could just create our own), and on our custom integer types.
#include "common.c"

enum { POINTER_SIZE = 8 };

typedef struct Code_Builder Code_Builder;
Code_Builder *new_code_builder(Arena *arena, Arena *stack);

typedef struct Key Key;
typedef enum Key_Kind {
    KEY_INTEGER  = 0,
    KEY_FLOAT    = 1,
    KEY_COMPOUND = 2,
} Key_Kind;

Key *new_key(Code_Builder *builder, Key_Kind kind, u32 size, u32 alignment);

#define GEN_NEW_INT_FUNCTION(name, type) \
Key *name(Code_Builder *builder, type value);
GEN_NEW_INT_FUNCTION(new_i8,  i8)
GEN_NEW_INT_FUNCTION(new_i16, i16)
GEN_NEW_INT_FUNCTION(new_i32, i32)
GEN_NEW_INT_FUNCTION(new_i64, i64)
GEN_NEW_INT_FUNCTION(new_u8,  u8)
GEN_NEW_INT_FUNCTION(new_u16, u16)
GEN_NEW_INT_FUNCTION(new_u32, u32)
GEN_NEW_INT_FUNCTION(new_u64, u64)
GEN_NEW_INT_FUNCTION(new_pointer, u64)
#undef GEN_NEW_INT_FUNCTION

typedef struct Place Place;
Place key_direct(Key *key);
Place key_deref(Key *key, u32 size);

Key *address_of(Code_Builder *builder, Key *value);

typedef enum Binary_Kind {
    BINARY_MOV,
    BINARY_ADD,
    BINARY_SUB,
    BINARY_MUL,
    BINARY_DIV,
    BINARY_IMUL,
    BINARY_IDIV,
    BINARY_AND,
    BINARY_OR,
    BINARY_XOR,
    BINARY_CMP,
    BINARY_SHL,
    BINARY_SHR,
    BINARY_SAR,
} Binary_Kind;
void binary(Code_Builder *builder, Key_Kind kind, Binary_Kind binary, Place left, Place right);

typedef enum Unary_Kind {
    UNARY_NEG,
    UNARY_NOT,
    UNARY_INC,
    UNARY_DEC,
} Unary_Kind;
void unary(Code_Builder *builder, Key_Kind kind, Unary_Kind unary, Place place);

void clear(Code_Builder *builder, Place place);
void copy(Code_Builder *builder, Place source, Place destination);

typedef struct Jump_From Jump_From;
typedef struct Jump_To Jump_To;
typedef enum Condition {
    CONDITION_NONE = 0,

    CONDITION_E,
    CONDITION_NE,
    CONDITION_P,
    CONDITION_NP,
    CONDITION_A,
    CONDITION_AE,
    CONDITION_B,
    CONDITION_BE,
    CONDITION_L,
    CONDITION_LE,
    CONDITION_G,
    CONDITION_GE,

    CONDITION_COUNT,
} Condition;
void link_jump(Code_Builder *builder, Jump_From *from, Jump_To *to);
Jump_From *add_jump(Code_Builder *builder, Condition condition);
Jump_To *add_label(Code_Builder *builder, u8 *debug_name);

void set_return(Code_Builder *builder, Key_Kind kind, Place place);
void end_function(Code_Builder *builder);

typedef struct Encoded_Insts {
    u8 *bytes;
    u64 length;
} Encoded_Insts;
Encoded_Insts encode_insts(Code_Builder *builder);

void print_all_insts(Code_Builder *builder, bool show_bytecode);
