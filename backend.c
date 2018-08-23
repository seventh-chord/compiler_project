
#include "common.c"

#define IMM_SIZE_USE_POINTER 0xff

typedef struct Big_Imm {
    u32 size;
    u8 data[];
} Big_Imm;

typedef struct Imm {
    u8 size;
    union {
        u64 value; // only used when size is 1, 2, 4 or 8
        Big_Imm *pointer;
    };
} Imm;

typedef enum Reg {
    REG_NONE = 0,

    RAX, RCX, RDX, RBX,
    RSP, RBP, RSI, RDI,
    R8,  R9,  R10, R11,
    R12, R13, R14, R15,

    RIP, // Only used for addresses

    XMM0,  XMM1,  XMM2,  XMM3, 
    XMM4,  XMM5,  XMM6,  XMM7, 
    XMM8,  XMM9,  XMM10, XMM11,
    XMM12, XMM13, XMM14, XMM15,

    REG_COUNT
} Reg;

typedef enum Reg_Kind {
    REG_KIND_INVALID = 0,
    REG_KIND_GPR,
    REG_KIND_XMM,
} Reg_Kind;

Reg_Kind reg_kind(Reg reg) {
    if (reg >= RAX && reg <= R15) return REG_KIND_GPR;
    if (reg >= XMM0 && reg <= XMM15) return REG_KIND_GPR;
    assert(false);
    return 0;
}

typedef struct Address {
    u8 base, index; // Reg
    u8 scale; // Must be 1, 2, 4 or 8
    i32 offset;
} Address;


enum Key_Flags {
    KEY_FLAG_ONLY_SET_ONCE = 1 << 0,
};

typedef struct Key {
    u64 index;
    u32 flags;

    u32 size;
    enum { KEY_INTEGER, KEY_FLOAT, KEY_COMPOUND } kind;

    u16 lifetime_start, lifetime_end; // inst indices

    Imm constant_value; // Used when 'KEY_FLAG_ONLY_SET_ONCE'
} Key;


typedef struct Place {
    enum {
        PLACE_NONE,
        PLACE_KEY,
        PLACE_REG,
        PLACE_MEM,
    } kind;
    u32 size;

    union {
        Key *key;
        Reg reg;
        Address address;
    };
} Place;

typedef enum Inst_Kind {
    INST_INVALID = 0,

    INST_CALL,
    INST_JMP,
    INST_RET,
    INST_INT3,
    INST_NOP,
    
    INST_MOV,
    INST_XCHG,
    INST_ADD,
    INST_SUB,
    INST_AND,
    INST_OR,
    INST_XOR,
    INST_CMP,
    INST_SHL,
    INST_SHR,
    INST_SAR,
    INST_INC,
    INST_DEC,
    INST_MUL,
    INST_IMUL,
    INST_DIV,
    INST_IDIV,
    INST_NEG,
    INST_NOT,

    INST_JE,  // ZF = 1
    INST_JNE, // ZF = 0
    INST_JP,  // PF = 1
    INST_JNP, // PF = 0
    INST_JA,  // CF = 0 && ZF = 0
    INST_JAE, // CF = 0
    INST_JB,  // CF = 1
    INST_JBE, // CF = 0 || ZF = 0
    INST_JL,  // SF != OF
    INST_JLE, // ZF = 1 || ZF != OF
    INST_JG,  // ZF = 0 && ZF == OF
    INST_JGE, // SF == OF
    #define INST_JCC_FIRST INST_JE
    #define INST_JCC_LAST  INST_JGE

    INST_SETE,  // ZF = 1
    INST_SETNE, // ZF = 0
    INST_SETP,  // PF = 1
    INST_SETNP, // PF = 0
    INST_SETA,  // CF = 0 && ZF = 0
    INST_SETAE, // CF = 0
    INST_SETB,  // CF = 1
    INST_SETBE, // CF = 0 || ZF = 0
    INST_SETL,  // SF != OF
    INST_SETLE, // ZF = 1 || ZF != OF
    INST_SETG,  // ZF = 0 && ZF == OF
    INST_SETGE, // SF == OF
    
    // TODO SSE

    INST_COUNT,
} Inst_Kind;

u8 *INST_NAMES[INST_COUNT] = {
    [INST_CALL] = "call",
    [INST_JMP]  = "jmp",
    [INST_RET]  = "ret",
    [INST_INT3] = "int 3",
    [INST_NOP]  = "nop",

    [INST_JE]   = "je",
    [INST_JNE]  = "jne",
    [INST_JP]   = "jp",
    [INST_JNP]  = "jnp",
    [INST_JA]   = "ja",
    [INST_JAE]  = "jae",
    [INST_JB]   = "jb",
    [INST_JBE]  = "jbe",
    [INST_JL]   = "jl",
    [INST_JLE]  = "jle",
    [INST_JG]   = "jg",
    [INST_JGE]  = "jge",

    [INST_SETE]   = "sete",
    [INST_SETNE]  = "setne",
    [INST_SETP]   = "setp",
    [INST_SETNP]  = "setnp",
    [INST_SETA]   = "seta",
    [INST_SETAE]  = "setae",
    [INST_SETB]   = "setb",
    [INST_SETBE]  = "setbe",
    [INST_SETL]   = "setl",
    [INST_SETLE]  = "setle",
    [INST_SETG]   = "setg",
    [INST_SETGE]  = "setge",

    [INST_MOV]  = "mov",
    [INST_XCHG] = "xchg",
    [INST_ADD]  = "add",
    [INST_SUB]  = "sub",
    [INST_AND]  = "and",
    [INST_OR]   = "or",
    [INST_XOR]  = "xor",
    [INST_CMP]  = "cmp",
    [INST_SHL]  = "shl",
    [INST_SHR]  = "shr",
    [INST_SAR]  = "sar",
    [INST_INC]  = "inc",
    [INST_DEC]  = "dec",
    [INST_MUL]  = "mul",
    [INST_IMUL] = "imul",
    [INST_DIV]  = "div",
    [INST_IDIV] = "idiv",
    [INST_NEG]  = "neg",
    [INST_NOT]  = "not",
};


typedef struct Inst {
    Inst_Kind kind;
    Place places[2];
    Imm imm;

    u16 index;
} Inst;


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

Inst_Kind JMP_FOR_CONDITION[CONDITION_COUNT] = {
    [CONDITION_NONE] = INST_JMP,
    [CONDITION_E]    = INST_JE,
    [CONDITION_NE]   = INST_JNE,
    [CONDITION_P]    = INST_JP,
    [CONDITION_NP]   = INST_JNP,
    [CONDITION_A]    = INST_JA,
    [CONDITION_AE]   = INST_JAE,
    [CONDITION_B]    = INST_JB,
    [CONDITION_BE]   = INST_JBE,
    [CONDITION_L]    = INST_JL,
    [CONDITION_LE]   = INST_JLE,
    [CONDITION_G]    = INST_JG,
    [CONDITION_GE]   = INST_JGE,
};


typedef struct Inst_Block Inst_Block;

typedef struct Jump_To {
    u8 *debug_name;
    Inst_Block *block;

    u64 relative_bytecode_pos;
} Jump_To;

typedef struct Jump_From {
    Jump_To *jump_to;
    Inst_Block *block;
} Jump_From;


enum { DEFAULT_INST_BLOCK_CAPACITY = 16 };
struct Inst_Block {
    u16 length, capacity;
    Inst_Block *next;

    Jump_To *jump_to; // refers to label at start of block, if any
    Jump_From *jump_from; // refers to INST_JMP at end of block, if any

    Inst insts[];
};

enum { LINK_LIST_BLOCK_CAPACITY = 16 };
typedef struct Link_List Link_List; // A linked list of jump links
struct Link_List {
    u32 length;
    Link_List *next;
    struct {
        Jump_From *from;
        Jump_To *to;
    } links[LINK_LIST_BLOCK_CAPACITY];
};


typedef struct Code_Builder {
    Arena *arena;
    u64 next_key_index;
    u16 next_inst_index;
    Inst_Block *insts_start, *insts_head;
    Link_List *link_list_start, *link_list_head;
} Code_Builder;

Code_Builder *code_builder_new(Arena *arena) {
    Code_Builder *builder = arena_new(arena, Code_Builder);
    builder->arena = arena;
    return builder;
}

void code_builder_start_new_inst_block(Code_Builder *builder, u16 capacity) {
    Inst_Block *new = (Inst_Block*) arena_alloc(builder->arena, sizeof(Inst_Block) + capacity*sizeof(Inst));
    new->capacity = capacity;
    builder->insts_head = builder->insts_start == null? (builder->insts_start = new) : (builder->insts_head->next = new);
}

void code_builder_add_inst(Code_Builder *builder, Inst inst) {
    if (
        builder->insts_head == null ||
        builder->insts_head->length >= builder->insts_head->capacity ||
        builder->insts_head->jump_from != null
    ) {
        code_builder_start_new_inst_block(builder, DEFAULT_INST_BLOCK_CAPACITY);
    }

    assert(builder->next_inst_index + 1 > builder->next_inst_index);
    builder->next_inst_index += 1;
    inst.index = builder->next_inst_index;

    builder->insts_head->insts[builder->insts_head->length] = inst;
    builder->insts_head->length += 1;
}

void code_builder_insert_inst(Code_Builder *builder, Inst_Block *block, u16 index, bool after, Inst inst) {
    assert(index < block->length);
    inst.index = block->insts[index].index;

    bool spill_into_next = false;
    if (block->length >= block->capacity) {
        u16 capacity = DEFAULT_INST_BLOCK_CAPACITY;
        Inst_Block *new = (Inst_Block*) arena_alloc(builder->arena, sizeof(Inst_Block) + capacity*sizeof(Inst));
        new->capacity = capacity;
        new->next = block->next;
        block->next = new;

        spill_into_next = true;
    }

    u16 slot = after? index + 1 : index;

    if (spill_into_next) {
        block->next->length += 1;
        assert(block->next->length == 1);
        block->next->insts[0] = block->insts[block->length - 1];
    } else {
        block->length += 1;
    }
    for (u16 i = block->length - 1; i > slot; i -= 1) {
        block->insts[i] = block->insts[i - 1];
    }
    block->insts[slot] = inst;
}


Key *new_key(Code_Builder *builder, int kind, u32 size) {
    if (kind == KEY_INTEGER) {
        assert(size == 1 || size == 2 || size == 4 || size == 8);
    } else if (kind == KEY_FLOAT) {
        assert(size == 4 || size == 8);
    }

    Key *key = arena_new(builder->arena, Key);
    key->index = builder->next_key_index;
    builder->next_key_index += 1;
    key->size = size;
    key->kind = kind;
    builder->next_key_index;
    return key;
}

Key *new_key_with_value(Code_Builder *builder, int kind, u32 size, void *value) {
    Imm imm = {0};
    imm.size = (u8) size;
    switch (size) {
        case 1: imm.value = (u64) *((u8*)  value); break;
        case 2: imm.value = (u64) *((u16*) value); break;
        case 4: imm.value = (u64) *((u32*) value); break;
        case 8: imm.value = (u64) *((u64*) value); break;
        default: {
            imm.size = IMM_SIZE_USE_POINTER;
            imm.pointer = (Big_Imm*) arena_alloc(builder->arena, sizeof(u32) + size);
            imm.pointer->size = size;
            mem_copy(value, imm.pointer->data, size);
        } break;
    }

    Key *key = new_key(builder, kind, size);
    key->flags |= KEY_FLAG_ONLY_SET_ONCE;
    key->constant_value = imm;

    Inst inst = { INST_MOV, { { PLACE_KEY, .size = size, .key = key } }, imm };
    code_builder_add_inst(builder, inst);

    return key;
}


#define GEN_NEW_INT_FUNCTION(name, type) \
Key *name(Code_Builder *builder, type value) { \
    return new_key_with_value(builder, KEY_INTEGER, sizeof(type), &value); \
}
GEN_NEW_INT_FUNCTION(new_i8,  i8)
GEN_NEW_INT_FUNCTION(new_i16, i16)
GEN_NEW_INT_FUNCTION(new_i32, i32)
GEN_NEW_INT_FUNCTION(new_i64, i64)
GEN_NEW_INT_FUNCTION(new_u8,  u8)
GEN_NEW_INT_FUNCTION(new_u16, u16)
GEN_NEW_INT_FUNCTION(new_u32, u32)
GEN_NEW_INT_FUNCTION(new_u64, u64)
#undef GEN_NEW_INT_FUNCTION

Jump_To *add_label(Code_Builder *builder, u8 *debug_name) {
    Jump_To *result = arena_new(builder->arena, Jump_To);
    result->relative_bytecode_pos = U64_MAX;
    result->debug_name = debug_name;

    if (builder->insts_head == null || builder->insts_head->length > 0 || builder->insts_head->jump_to != null) {
        code_builder_start_new_inst_block(builder, DEFAULT_INST_BLOCK_CAPACITY);
    }
    assert(builder->insts_head->jump_to == null);
    builder->insts_head->jump_to = result;
    result->block = builder->insts_head;

    return result;
}

Jump_From *add_jump(Code_Builder *builder, Condition condition) {
    Jump_From *result = arena_new(builder->arena, Jump_From);

    if (builder->insts_head == null || builder->insts_head->jump_from != null) {
        code_builder_start_new_inst_block(builder, 1); // We have to start a new block after the jump we insert!
    }

    Inst inst = { JMP_FOR_CONDITION[condition] };
    code_builder_add_inst(builder, inst);

    assert(builder->insts_head->jump_from == null);
    builder->insts_head->jump_from = result;
    result->block = builder->insts_head;
    
    return result;
}

void link_jump(Code_Builder *builder, Jump_From *from, Jump_To *to) {
    assert(from->jump_to == null);
    from->jump_to = to;

    if (builder->link_list_start == null) {
        builder->link_list_start = arena_new(builder->arena, Link_List);
        builder->link_list_head = builder->link_list_start;
    }

    if (builder->link_list_head->length >= LINK_LIST_BLOCK_CAPACITY) {
        Link_List *new = arena_new(builder->arena, Link_List);
        builder->link_list_head->next = new;
        builder->link_list_head = new;
    }

    builder->link_list_head->links[builder->link_list_head->length].from = from;
    builder->link_list_head->links[builder->link_list_head->length].to = to;
    builder->link_list_head->length += 1;
}


enum {
    BINARY_MOV,
    BINARY_ADD,
    BINARY_SUB,
    BINARY_MUL,
    BINARY_DIV,
    BINARY_AND,
    BINARY_OR,
    BINARY_XOR,
    BINARY_CMP,
    BINARY_SHL,
    BINARY_SHR,
    BINARY_SAR,
};

void binary(Code_Builder *builder, int binary, Key *left, Key *right) {
    left->flags &= ~KEY_FLAG_ONLY_SET_ONCE;

    assert(left->size == right->size);
    assert(left->kind == right->kind);
    int key_kind = left->kind;
    u32 size = left->size;

    Inst_Kind inst_kind;

    if (key_kind == KEY_INTEGER) {
        switch (binary) {
            case BINARY_MOV: inst_kind = INST_MOV; break;
            case BINARY_ADD: inst_kind = INST_ADD; break;
            case BINARY_SUB: inst_kind = INST_SUB; break;
            case BINARY_MUL: inst_kind = INST_MUL; break;
            case BINARY_DIV: inst_kind = INST_DIV; break;
            case BINARY_AND: inst_kind = INST_AND; break;
            case BINARY_OR:  inst_kind = INST_OR;  break;
            case BINARY_XOR: inst_kind = INST_XOR; break;
            case BINARY_CMP: inst_kind = INST_CMP; break;
            case BINARY_SHL: inst_kind = INST_SHL; break;
            case BINARY_SHR: inst_kind = INST_SHR; break;
            case BINARY_SAR: inst_kind = INST_SAR; break;
            default: assert(false);
        }
    } else if (key_kind == KEY_FLOAT) {
        unimplemented();
    } else {
        assert(false);
    }

    Inst inst = { inst_kind, { { PLACE_KEY, size, .key = left }, { PLACE_KEY, size, .key = right } } };
    code_builder_add_inst(builder, inst);
}

enum {
    UNARY_NEG,
    UNARY_NOT,
    UNARY_INC,
    UNARY_DEC,
};

void unary(Code_Builder *builder, int unary, Key *key) {
    key->flags &= ~KEY_FLAG_ONLY_SET_ONCE;

    Inst_Kind inst_kind;

    if (key->kind == KEY_INTEGER) {
        switch (unary) {
            case UNARY_NEG: inst_kind = INST_NEG; break;
            case UNARY_NOT: inst_kind = INST_NOT; break;
            case UNARY_INC: inst_kind = INST_INC; break;
            case UNARY_DEC: inst_kind = INST_DEC; break;
            default: assert(false);
        }
    } else if (key->kind == KEY_FLOAT) {
        unimplemented();
    } else {
        assert(false);
    }

    Inst inst = { inst_kind, { { PLACE_KEY, key->size, .key = key } } };
    code_builder_add_inst(builder, inst);
}


typedef Key *Register_Map[REG_COUNT];

Reg find_free_reg(Register_Map *map, Reg_Kind reg_kind) {
    Reg range_start, range_end;
    switch (reg_kind) {
        case REG_KIND_GPR: range_start = RAX; range_end = R15; break;
        case REG_KIND_XMM: range_start = XMM0; range_end = XMM15; break;
        default: assert(false);
    }

    for (Reg reg = range_start; reg <= range_end; reg += 1) {
        if ((*map)[reg] == null) return reg;
    }

    unimplemented(); // TODO We have do flush some registers
    return REG_NONE;
}

Reg find_reg_for_key(Register_Map *map, Key *key) {
    Reg_Kind reg_kind = REG_KIND_GPR; // TODO

    Reg range_start, range_end;
    switch (reg_kind) {
        case REG_KIND_GPR: range_start = RAX; range_end = R15; break;
        case REG_KIND_XMM: range_start = XMM0; range_end = XMM15; break;
        default: assert(false);
    }

    Reg first_free = REG_NONE;
    for (Reg reg = range_start; reg <= range_end; reg += 1) {
        if ((*map)[reg] == key) return reg;
        if (first_free == REG_NONE && (*map)[reg] == null) first_free = reg;
    }

    if (first_free == REG_NONE) {
        unimplemented(); // TODO We have do flush some registers
        return REG_NONE;
    } else {
        (*map)[first_free] = key;
        return first_free;
    }
}

void assign_registers(Code_Builder *builder) {
    Register_Map usage_map = {0};

    for (Inst_Block *block = builder->insts_start; block != null; block = block->next) {
        for (u16 i = 0; i < block->length; i += 1) {
            Inst *inst = &block->insts[i];

            for (u8 j = 0; j < 2; j += 1) {
                if (inst->places[j].kind == PLACE_KEY) {
                    Key *key = inst->places[j].key;
                    if (inst->index < key->lifetime_start) key->lifetime_start = inst->index;
                    if (inst->index > key->lifetime_end)   key->lifetime_end   = inst->index;
                }
            }
        }
    }

    u32 skip_insts = 0;

    for (Inst_Block *block = builder->insts_start; block != null; block = block->next) {
        for (u16 i = 0; i < block->length; i += 1) {
            if (skip_insts > 0) {
                skip_insts -= 1;
                continue;
            }

            Inst *inst = &block->insts[i];
            bool remove_inst = false;

            for (Reg reg = 0; reg < REG_COUNT; reg += 1) {
                Key *key = usage_map[reg];
                if (key != null) {
                    assert(key->lifetime_start <= inst->index);
                    if (key->lifetime_end < inst->index) usage_map[reg] = null;
                }
            }

            if (inst->places[0].kind == PLACE_KEY) {
                Key *key = inst->places[0].key;

                if (key->flags & KEY_FLAG_ONLY_SET_ONCE) {
                    assert(inst->places[1].kind == PLACE_NONE);
                    assert(inst->kind == INST_MOV);
                    remove_inst = true;
                } else {
                    Reg reg = find_reg_for_key(&usage_map, key);
                    inst->places[0].kind = PLACE_REG;
                    inst->places[0].reg = reg;
                }
            }

            if (inst->places[1].kind == PLACE_KEY) {
                Key *key = inst->places[1].key;

                if (key->flags & KEY_FLAG_ONLY_SET_ONCE) {
                    assert(inst->imm.size == 0);
                    inst->places[1].kind = PLACE_NONE;
                    inst->imm = key->constant_value;
                } else {
                    Reg reg = find_reg_for_key(&usage_map, key);
                    inst->places[1].kind = PLACE_REG;
                    inst->places[1].reg = reg;
                }
            }

            if (remove_inst) {
                for (u16 j = i; j < block->length; j += 1) {
                    block->insts[j] = block->insts[j + 1];
                }
                i -= 1;
                block->length -= 1;
                continue;
            }


            Reg force_into_reg = REG_NONE;
            u8 force_place;

            if (inst->kind == INST_MUL || inst->kind == INST_DIV || inst->kind == INST_IMUL || inst->kind == INST_IDIV) {
                force_into_reg = RAX;
                force_place = 0;
            } else if (inst->kind == INST_SHL || inst->kind == INST_SHR || inst->kind == INST_SAR) {
                force_into_reg = RCX;
                force_place = 1;
            }

            if (force_into_reg != REG_NONE) {
                Place current_place = inst->places[force_place];
                Place other_place = inst->places[force_place == 0? 1 : 0];
                
                // Remove the other register, because it is implied in the instruction
                if (force_place == 0) inst->places[0] = inst->places[1];
                inst->places[1].kind = PLACE_NONE;

                // Add instructions to get things into the right place
                if (current_place.kind == PLACE_REG && current_place.reg == force_into_reg) {
                    // Don't do anything
                } else if (other_place.kind == PLACE_REG && other_place.reg == force_into_reg) {
                    Reg temp_reg = find_free_reg(&usage_map, reg_kind(force_into_reg));
                    Place temp_place = { PLACE_REG, current_place.size, .reg = temp_reg };
                    inst->places[0] = temp_place;

                    Inst extra[4] = {
                        { INST_MOV, { temp_place, other_place } },
                        { INST_MOV, { other_place, current_place } },
                        { INST_MOV, { current_place, other_place } },
                        { INST_MOV, { other_place, temp_place } },
                    };

                    code_builder_insert_inst(builder, block, i, true, extra[3]);
                    code_builder_insert_inst(builder, block, i, true, extra[2]);
                    code_builder_insert_inst(builder, block, i, false, extra[1]);
                    code_builder_insert_inst(builder, block, i, false, extra[0]);
                    skip_insts += 4;
                } else if (usage_map[force_into_reg] != null) {
                    assert(false); // TODO Test!

                    Reg temp_reg = find_free_reg(&usage_map, reg_kind(force_into_reg));

                    Inst extra[4] = {
                        { INST_MOV, { { PLACE_REG, 8, .reg = temp_reg }, { PLACE_REG, 8, .reg = force_into_reg } } },
                        { INST_MOV, { { PLACE_REG, current_place.size, .reg = force_into_reg },  current_place } },
                        { INST_MOV, { current_place, { PLACE_REG, current_place.size, .reg = force_into_reg } } },
                        { INST_MOV, { { PLACE_REG, 8, .reg = force_into_reg },  { PLACE_REG, 8, .reg = temp_reg } } },
                    };

                    code_builder_insert_inst(builder, block, i, true, extra[3]);
                    code_builder_insert_inst(builder, block, i, true, extra[2]);
                    code_builder_insert_inst(builder, block, i, false, extra[1]);
                    code_builder_insert_inst(builder, block, i, false, extra[0]);
                    skip_insts += 4;
                } else {
                    assert(false); // TODO Test!
                    unimplemented(); // TODO some crazy move mess
                }
            }
        }

        if (block->length == 0) {
            assert(block->jump_from == null);
            unimplemented(); // TODO Unlink this block, if we can stick our label onto the next block
        }
    }
}



typedef enum Encoding_Mode {
    // R means register, M means register or memory, I means immediate
    // The number indicates the number of bytes of the operand
    // We are going pretty close to full combinatorics explosion mode here.
    // This allows us to circumnavigate a lot of the non-uniformity in x64 by just
    // omitting certain entries from the table below.

    ENCODING_MODE_INVALID = 0,

    ENCODE_NO_PARAMS,

    ENCODE_I1, ENCODE_I4,
    ENCODE_R1, ENCODE_R2, ENCODE_R4, ENCODE_R8,
    ENCODE_M1, ENCODE_M2, ENCODE_M4, ENCODE_M8,

    ENCODE_R1_I1, ENCODE_R2_I1, ENCODE_R4_I1, ENCODE_R8_I1,
    ENCODE_R2_I2, ENCODE_R4_I4, ENCODE_R8_I4, ENCODE_R8_I8,

    ENCODE_M1_I1, ENCODE_M2_I1, ENCODE_M4_I1, ENCODE_M8_I1,
    ENCODE_M2_I2, ENCODE_M4_I4, ENCODE_M8_I4,

    ENCODE_R1_R1, ENCODE_R2_R2, ENCODE_R4_R4, ENCODE_R8_R8,
    ENCODE_R1_M1, ENCODE_R2_M2, ENCODE_R4_M4, ENCODE_R8_M8,
    ENCODE_M1_R1, ENCODE_M2_R2, ENCODE_M4_R4, ENCODE_M8_R8,

    ENCODING_MODE_COUNT,
} Encoding_Mode;

u8 *ENCODING_MODE_NAMES[ENCODING_MODE_COUNT] = {
    [ENCODE_NO_PARAMS] = "",
    [ENCODE_I1]     = " imm8",
    [ENCODE_I4]     = " imm32",
    [ENCODE_R1]     = " reg8",
    [ENCODE_R2]     = " reg16",
    [ENCODE_R4]     = " reg32",
    [ENCODE_R8]     = " reg64",
    [ENCODE_M1]     = " mem8",
    [ENCODE_M2]     = " mem16",
    [ENCODE_M4]     = " mem32",
    [ENCODE_M8]     = " mem64",
    [ENCODE_R1_I1]  = " reg8, imm8",
    [ENCODE_R2_I1]  = " reg16, imm8",
    [ENCODE_R4_I1]  = " reg32, imm8",
    [ENCODE_R8_I1]  = " reg64, imm8",
    [ENCODE_R2_I2]  = " reg16, imm16",
    [ENCODE_R4_I4]  = " reg32, imm32",
    [ENCODE_R8_I4]  = " reg64, imm32",
    [ENCODE_R8_I8]  = " reg64, imm64",
    [ENCODE_M1_I1]  = " mem8, imm8",
    [ENCODE_M2_I1]  = " reg16, imm8",
    [ENCODE_M4_I1]  = " reg32, imm8",
    [ENCODE_M8_I1]  = " reg64, imm8",
    [ENCODE_M2_I2]  = " reg16, imm16",
    [ENCODE_M4_I4]  = " reg32, imm32",
    [ENCODE_M8_I4]  = " reg64, imm32",
    [ENCODE_R1_R1]  = " reg8, reg8",
    [ENCODE_R2_R2]  = " reg16, reg16",
    [ENCODE_R4_R4]  = " reg32, reg32",
    [ENCODE_R8_R8]  = " reg64, reg64",
    [ENCODE_R1_M1]  = " reg8, mem8",
    [ENCODE_R2_M2]  = " reg16, mem16",
    [ENCODE_R4_M4]  = " reg32, mem32",
    [ENCODE_R8_M8]  = " reg64, mem64",
    [ENCODE_M1_R1]  = " mem8, reg8",
    [ENCODE_M2_R2]  = " mem16, reg16",
    [ENCODE_M4_R4]  = " mem32, reg32",
    [ENCODE_M8_R8]  = " mem64, reg64",
};


#define ENCODING_WORD_OPERANDS    0x01 // prefixes 0x66
#define ENCODING_REX_W            0x02
#define ENCODING_MODRM_FLAG       0x04 // sets modrm.reg to Encoding.modrm_flag
#define ENCODING_REG_IN_OPCODE    0x08
#define ENCODING_SECONDARY        0x10 // prefixes 0x0f

typedef struct Encoding {
    u8 exists;
    u8 opcode;
    u8 flags;
    u8 modrm_flag;
} Encoding;

typedef struct Encoded_Inst {
    u8 length;
    u8 bytes[15]; // NB x64 instructions can be at most 15 bytes long
} Encoded_Inst;


enum {
    // These are the absolute maxima for x64. Min length is for a jump to an immediate 8-bit offset,
    // max length is for an indirect jump to a modrm+sib+32-bit offset memory address, which requires
    // a rex prefix to encode.
    ENCODING_JMP_MAX_LENGTH = 8,
    ENCODING_JMP_MIN_LENGTH = 2,
};

Encoding ENCODING_TABLE[INST_COUNT][ENCODING_MODE_COUNT] = {
    [INST_CALL] = {
        // There are I2, R2 and M2 encodings, but those don't seem to work on x64. Also, they are 
        // mostly useless anyways
        [ENCODE_I4] = { 1, 0xe8 },
        [ENCODE_R8] = { 1, 0xff, ENCODING_MODRM_FLAG, .modrm_flag = 2 },
        [ENCODE_R8] = { 1, 0xff, ENCODING_MODRM_FLAG, .modrm_flag = 2 },
    },
    [INST_JMP] = {
        [ENCODE_I1] = { 1, 0xeb },
        [ENCODE_I4] = { 1, 0xe9 },
        // There are M and R variants too, we just need to add them to the table
    },

    [INST_INT3] = { [ENCODE_NO_PARAMS] = { 1, 0xcc } },
    [INST_RET]  = { [ENCODE_NO_PARAMS] = { 1, 0xc3 } },
    [INST_NOP]  = { [ENCODE_NO_PARAMS] = { 1, 0x90 } },

    [INST_JE]  = { [ENCODE_I1] = { 1, 0x74 }, [ENCODE_I4] = { 1, 0x84, ENCODING_SECONDARY } },
    [INST_JNE] = { [ENCODE_I1] = { 1, 0x75 }, [ENCODE_I4] = { 1, 0x85, ENCODING_SECONDARY } },
    [INST_JP]  = { [ENCODE_I1] = { 1, 0x7a }, [ENCODE_I4] = { 1, 0x8a, ENCODING_SECONDARY } },
    [INST_JNP] = { [ENCODE_I1] = { 1, 0x7b }, [ENCODE_I4] = { 1, 0x8b, ENCODING_SECONDARY } },
    [INST_JA]  = { [ENCODE_I1] = { 1, 0x77 }, [ENCODE_I4] = { 1, 0x87, ENCODING_SECONDARY } },
    [INST_JAE] = { [ENCODE_I1] = { 1, 0x73 }, [ENCODE_I4] = { 1, 0x83, ENCODING_SECONDARY } },
    [INST_JB]  = { [ENCODE_I1] = { 1, 0x72 }, [ENCODE_I4] = { 1, 0x82, ENCODING_SECONDARY } },
    [INST_JBE] = { [ENCODE_I1] = { 1, 0x76 }, [ENCODE_I4] = { 1, 0x86, ENCODING_SECONDARY } },
    [INST_JG]  = { [ENCODE_I1] = { 1, 0x7f }, [ENCODE_I4] = { 1, 0x8f, ENCODING_SECONDARY } },
    [INST_JGE] = { [ENCODE_I1] = { 1, 0x7d }, [ENCODE_I4] = { 1, 0x8d, ENCODING_SECONDARY } },
    [INST_JL]  = { [ENCODE_I1] = { 1, 0x7c }, [ENCODE_I4] = { 1, 0x8c, ENCODING_SECONDARY } },
    [INST_JLE] = { [ENCODE_I1] = { 1, 0x7e }, [ENCODE_I4] = { 1, 0x8e, ENCODING_SECONDARY } },

    [INST_SETE]  = { [ENCODE_R1] = { 1, 0x94, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 }, [ENCODE_M1] = { 1, 0x94, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 } },
    [INST_SETNE] = { [ENCODE_R1] = { 1, 0x95, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 }, [ENCODE_M1] = { 1, 0x95, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 } },
    [INST_SETP]  = { [ENCODE_R1] = { 1, 0x9a, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 }, [ENCODE_M1] = { 1, 0x9a, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 } },
    [INST_SETNP] = { [ENCODE_R1] = { 1, 0x9b, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 }, [ENCODE_M1] = { 1, 0x9b, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 } },
    [INST_SETA]  = { [ENCODE_R1] = { 1, 0x97, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 }, [ENCODE_M1] = { 1, 0x97, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 } },
    [INST_SETAE] = { [ENCODE_R1] = { 1, 0x93, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 }, [ENCODE_M1] = { 1, 0x93, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 } },
    [INST_SETB]  = { [ENCODE_R1] = { 1, 0x92, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 }, [ENCODE_M1] = { 1, 0x92, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 } },
    [INST_SETBE] = { [ENCODE_R1] = { 1, 0x96, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 }, [ENCODE_M1] = { 1, 0x96, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 } },
    [INST_SETG]  = { [ENCODE_R1] = { 1, 0x9f, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 }, [ENCODE_M1] = { 1, 0x9f, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 } },
    [INST_SETGE] = { [ENCODE_R1] = { 1, 0x9d, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 }, [ENCODE_M1] = { 1, 0x9d, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 } },
    [INST_SETL]  = { [ENCODE_R1] = { 1, 0x9c, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 }, [ENCODE_M1] = { 1, 0x9c, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 } },
    [INST_SETLE] = { [ENCODE_R1] = { 1, 0x9e, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 }, [ENCODE_M1] = { 1, 0x9e, ENCODING_SECONDARY | ENCODING_MODRM_FLAG, .modrm_flag = 0 } },

    [INST_MOV] = {
        [ENCODE_R1_I1] = { 1, 0xb0, ENCODING_REG_IN_OPCODE },
        [ENCODE_R2_I2] = { 1, 0xb8, ENCODING_WORD_OPERANDS | ENCODING_REG_IN_OPCODE },
        [ENCODE_R4_I4] = { 1, 0xb8, ENCODING_REG_IN_OPCODE },
        [ENCODE_R8_I8] = { 1, 0xb8, ENCODING_REX_W | ENCODING_REG_IN_OPCODE },

        [ENCODE_M1_I1] = { 1, 0xc6, ENCODING_MODRM_FLAG, .modrm_flag = 0 },
        [ENCODE_M2_I2] = { 1, 0xc7, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 0 },
        [ENCODE_M4_I4] = { 1, 0xc7, ENCODING_MODRM_FLAG,                          .modrm_flag = 0 },
        [ENCODE_M8_I4] = { 1, 0xc7, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 0 },

        [ENCODE_R1_R1] = { 1, 0x88 },
        [ENCODE_R2_R2] = { 1, 0x89, ENCODING_WORD_OPERANDS },
        [ENCODE_R4_R4] = { 1, 0x89 },
        [ENCODE_R8_R8] = { 1, 0x89, ENCODING_REX_W },

        [ENCODE_M1_R1] = { 1, 0x88 },
        [ENCODE_M2_R2] = { 1, 0x89, ENCODING_WORD_OPERANDS },
        [ENCODE_M4_R4] = { 1, 0x89 },
        [ENCODE_M8_R8] = { 1, 0x89, ENCODING_REX_W },

        [ENCODE_R1_M1] = { 1, 0x8a },
        [ENCODE_R2_M2] = { 1, 0x8b, ENCODING_WORD_OPERANDS },
        [ENCODE_R4_M4] = { 1, 0x8b },
        [ENCODE_R8_M8] = { 1, 0x8b, ENCODING_REX_W },
    },

    [INST_XCHG] = {
        [ENCODE_R1_R1] = { 1, 0x86 },
        [ENCODE_R2_R2] = { 1, 0x87, ENCODING_WORD_OPERANDS },
        [ENCODE_R4_R4] = { 1, 0x87 },
        [ENCODE_R8_R8] = { 1, 0x87, ENCODING_REX_W },
    },

    #define INST_INTEGER(inst, imm_flag, op_a, op_b, op_c, op_d) \
    [inst] = { \
        [ENCODE_R1_I1] = { 1, 0x80, ENCODING_MODRM_FLAG,                          .modrm_flag = imm_flag }, \
        [ENCODE_R2_I1] = { 1, 0x83, ENCODING_WORD_OPERANDS | ENCODING_MODRM_FLAG, .modrm_flag = imm_flag }, \
        [ENCODE_R4_I1] = { 1, 0x83, ENCODING_MODRM_FLAG,                          .modrm_flag = imm_flag }, \
        [ENCODE_R8_I1] = { 1, 0x83, ENCODING_REX_W | ENCODING_MODRM_FLAG,         .modrm_flag = imm_flag }, \
        [ENCODE_R2_I2] = { 1, 0x81, ENCODING_WORD_OPERANDS | ENCODING_MODRM_FLAG, .modrm_flag = imm_flag }, \
        [ENCODE_R4_I4] = { 1, 0x81, ENCODING_MODRM_FLAG,                          .modrm_flag = imm_flag }, \
        [ENCODE_R8_I4] = { 1, 0x81, ENCODING_REX_W | ENCODING_MODRM_FLAG,         .modrm_flag = imm_flag }, \
        [ENCODE_M1_I1] = { 1, 0x80, ENCODING_MODRM_FLAG,                          .modrm_flag = imm_flag }, \
        [ENCODE_M2_I1] = { 1, 0x83, ENCODING_WORD_OPERANDS | ENCODING_MODRM_FLAG, .modrm_flag = imm_flag }, \
        [ENCODE_M4_I1] = { 1, 0x83, ENCODING_MODRM_FLAG,                          .modrm_flag = imm_flag }, \
        [ENCODE_M8_I1] = { 1, 0x83, ENCODING_REX_W | ENCODING_MODRM_FLAG,         .modrm_flag = imm_flag }, \
        [ENCODE_M2_I2] = { 1, 0x81, ENCODING_WORD_OPERANDS | ENCODING_MODRM_FLAG, .modrm_flag = imm_flag }, \
        [ENCODE_M4_I4] = { 1, 0x81, ENCODING_MODRM_FLAG,                          .modrm_flag = imm_flag }, \
        [ENCODE_M8_I4] = { 1, 0x81, ENCODING_REX_W | ENCODING_MODRM_FLAG,         .modrm_flag = imm_flag }, \
 \
        [ENCODE_R1_M1] = { 1, op_c }, \
        [ENCODE_R2_M2] = { 1, op_d, ENCODING_WORD_OPERANDS }, \
        [ENCODE_R4_M4] = { 1, op_d }, \
        [ENCODE_R8_M8] = { 1, op_d, ENCODING_REX_W }, \
 \
        [ENCODE_M1_R1] = { 1, op_a }, \
        [ENCODE_M2_R2] = { 1, op_b, ENCODING_WORD_OPERANDS }, \
        [ENCODE_M4_R4] = { 1, op_b }, \
        [ENCODE_M8_R8] = { 1, op_b, ENCODING_REX_W }, \
 \
        [ENCODE_R1_R1] = { 1, op_c }, \
        [ENCODE_R2_R2] = { 1, op_d, ENCODING_WORD_OPERANDS }, \
        [ENCODE_R4_R4] = { 1, op_d }, \
        [ENCODE_R8_R8] = { 1, op_d, ENCODING_REX_W }, \
    },

    INST_INTEGER(INST_ADD, 0, 0x00, 0x01, 0x02, 0x03)
    INST_INTEGER(INST_OR,  1, 0x08, 0x09, 0x0a, 0x0b)
    // ADC and SBB slot in here
    INST_INTEGER(INST_AND, 4, 0x20, 0x21, 0x22, 0x23)
    INST_INTEGER(INST_SUB, 5, 0x28, 0x29, 0x2a, 0x2b)
    INST_INTEGER(INST_XOR, 6, 0x30, 0x31, 0x32, 0x33)
    INST_INTEGER(INST_CMP, 7, 0x38, 0x39, 0x3a, 0x3b)
    #undef INST_INTEGER

    [INST_SHR] = {
        [ENCODE_R1]    = { 1, 0xd2, ENCODING_MODRM_FLAG,                          .modrm_flag = 5},
        [ENCODE_R2]    = { 1, 0xd3, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 5},
        [ENCODE_R4]    = { 1, 0xd3, ENCODING_MODRM_FLAG,                          .modrm_flag = 5},
        [ENCODE_R8]    = { 1, 0xd3, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 5},
        [ENCODE_M1]    = { 1, 0xd2, ENCODING_MODRM_FLAG,                          .modrm_flag = 5},
        [ENCODE_M2]    = { 1, 0xd3, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 5},
        [ENCODE_M4]    = { 1, 0xd3, ENCODING_MODRM_FLAG,                          .modrm_flag = 5},
        [ENCODE_M8]    = { 1, 0xd3, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 5},

        [ENCODE_R1_I1] = { 1, 0xc0, ENCODING_MODRM_FLAG,                          .modrm_flag = 5},
        [ENCODE_R2_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 5},
        [ENCODE_R4_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG,                          .modrm_flag = 5},
        [ENCODE_M1_I1] = { 1, 0xc0, ENCODING_MODRM_FLAG,                          .modrm_flag = 5},
        [ENCODE_M2_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 5},
        [ENCODE_M4_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG,                          .modrm_flag = 5},
        [ENCODE_M8_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 5},
    },
    [INST_SAR] = {
        [ENCODE_R1]    = { 1, 0xd2, ENCODING_MODRM_FLAG,                          .modrm_flag = 7},
        [ENCODE_R2]    = { 1, 0xd3, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 7},
        [ENCODE_R4]    = { 1, 0xd3, ENCODING_MODRM_FLAG,                          .modrm_flag = 7},
        [ENCODE_R8]    = { 1, 0xd3, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 7},
        [ENCODE_M1]    = { 1, 0xd2, ENCODING_MODRM_FLAG,                          .modrm_flag = 7},
        [ENCODE_M2]    = { 1, 0xd3, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 7},
        [ENCODE_M4]    = { 1, 0xd3, ENCODING_MODRM_FLAG,                          .modrm_flag = 7},
        [ENCODE_M8]    = { 1, 0xd3, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 7},

        [ENCODE_R1_I1] = { 1, 0xc0, ENCODING_MODRM_FLAG,                          .modrm_flag = 7},
        [ENCODE_R2_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 7},
        [ENCODE_R4_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG,                          .modrm_flag = 7},
        [ENCODE_R8_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 7},
        [ENCODE_M1_I1] = { 1, 0xc0, ENCODING_MODRM_FLAG,                          .modrm_flag = 7},
        [ENCODE_M2_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 7},
        [ENCODE_M4_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG,                          .modrm_flag = 7},
        [ENCODE_M8_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 7},
    },
    [INST_SHL] = {
        [ENCODE_R1]    = { 1, 0xd2, ENCODING_MODRM_FLAG,                          .modrm_flag = 4},
        [ENCODE_R2]    = { 1, 0xd3, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 4},
        [ENCODE_R4]    = { 1, 0xd3, ENCODING_MODRM_FLAG,                          .modrm_flag = 4},
        [ENCODE_R8]    = { 1, 0xd3, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 4},
        [ENCODE_M1]    = { 1, 0xd2, ENCODING_MODRM_FLAG,                          .modrm_flag = 4},
        [ENCODE_M2]    = { 1, 0xd3, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 4},
        [ENCODE_M4]    = { 1, 0xd3, ENCODING_MODRM_FLAG,                          .modrm_flag = 4},
        [ENCODE_M8]    = { 1, 0xd3, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 4},

        [ENCODE_R1_I1] = { 1, 0xc0, ENCODING_MODRM_FLAG,                          .modrm_flag = 4},
        [ENCODE_R2_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 4},
        [ENCODE_R4_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG,                          .modrm_flag = 4},
        [ENCODE_R8_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 4},
        [ENCODE_M1_I1] = { 1, 0xc0, ENCODING_MODRM_FLAG,                          .modrm_flag = 4},
        [ENCODE_M2_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 4},
        [ENCODE_M4_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG,                          .modrm_flag = 4},
        [ENCODE_M8_I1] = { 1, 0xc1, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 4},
    },

    [INST_INC] = {
        [ENCODE_R1] = { 1, 0xfe, ENCODING_MODRM_FLAG,                          .modrm_flag = 0 },
        [ENCODE_R2] = { 1, 0xff, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 0 },
        [ENCODE_R4] = { 1, 0xff, ENCODING_MODRM_FLAG,                          .modrm_flag = 0 },
        [ENCODE_R8] = { 1, 0xff, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 0 },

        [ENCODE_M1] = { 1, 0xfe, ENCODING_MODRM_FLAG,                          .modrm_flag = 0 },
        [ENCODE_M2] = { 1, 0xff, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 0 },
        [ENCODE_M4] = { 1, 0xff, ENCODING_MODRM_FLAG,                          .modrm_flag = 0 },
        [ENCODE_M8] = { 1, 0xff, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 0 },
    },
    [INST_DEC] = {
        [ENCODE_R1] = { 1, 0xfe, ENCODING_MODRM_FLAG,                          .modrm_flag = 1 },
        [ENCODE_R2] = { 1, 0xff, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 1 },
        [ENCODE_R4] = { 1, 0xff, ENCODING_MODRM_FLAG,                          .modrm_flag = 1 },
        [ENCODE_R8] = { 1, 0xff, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 1 },

        [ENCODE_M1] = { 1, 0xfe, ENCODING_MODRM_FLAG,                          .modrm_flag = 1 },
        [ENCODE_M2] = { 1, 0xff, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 1 },
        [ENCODE_M4] = { 1, 0xff, ENCODING_MODRM_FLAG,                          .modrm_flag = 1 },
        [ENCODE_M8] = { 1, 0xff, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 1 },
    },

    [INST_MUL] = {
        [ENCODE_R1] = { 1, 0xf6, ENCODING_MODRM_FLAG,                          .modrm_flag = 4 },
        [ENCODE_R2] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 4 },
        [ENCODE_R4] = { 1, 0xf7, ENCODING_MODRM_FLAG,                          .modrm_flag = 4 },
        [ENCODE_R8] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 4 },
        [ENCODE_M1] = { 1, 0xf6, ENCODING_MODRM_FLAG,                          .modrm_flag = 4 },
        [ENCODE_M2] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 4 },
        [ENCODE_M4] = { 1, 0xf7, ENCODING_MODRM_FLAG,                          .modrm_flag = 4 },
        [ENCODE_M8] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 4 },
    },
    [INST_DIV] = {
        [ENCODE_R1] = { 1, 0xf6, ENCODING_MODRM_FLAG,                          .modrm_flag = 6 },
        [ENCODE_R2] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 6 },
        [ENCODE_R4] = { 1, 0xf7, ENCODING_MODRM_FLAG,                          .modrm_flag = 6 },
        [ENCODE_R8] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 6 },
        [ENCODE_M1] = { 1, 0xf6, ENCODING_MODRM_FLAG,                          .modrm_flag = 6 },
        [ENCODE_M2] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 6 },
        [ENCODE_M4] = { 1, 0xf7, ENCODING_MODRM_FLAG,                          .modrm_flag = 6 },
        [ENCODE_M8] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 6 },
    },
    [INST_IMUL] = {
        [ENCODE_R1] = { 1, 0xf6, ENCODING_MODRM_FLAG,                          .modrm_flag = 5 },
        [ENCODE_R2] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 5 },
        [ENCODE_R4] = { 1, 0xf7, ENCODING_MODRM_FLAG,                          .modrm_flag = 5 },
        [ENCODE_R8] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 5 },
        [ENCODE_M1] = { 1, 0xf6, ENCODING_MODRM_FLAG,                          .modrm_flag = 5 },
        [ENCODE_M2] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 5 },
        [ENCODE_M4] = { 1, 0xf7, ENCODING_MODRM_FLAG,                          .modrm_flag = 5 },
        [ENCODE_M8] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 5 },

        [ENCODE_R2_R2] = { 1, 0xaf, ENCODING_SECONDARY | ENCODING_WORD_OPERANDS },
        [ENCODE_R4_R4] = { 1, 0xaf, ENCODING_SECONDARY },
        [ENCODE_R8_R8] = { 1, 0xaf, ENCODING_SECONDARY | ENCODING_REX_W },
        [ENCODE_R2_M2] = { 1, 0xaf, ENCODING_SECONDARY | ENCODING_WORD_OPERANDS },
        [ENCODE_R4_M4] = { 1, 0xaf, ENCODING_SECONDARY },
        [ENCODE_R8_M8] = { 1, 0xaf, ENCODING_SECONDARY | ENCODING_REX_W },

        // We don't have the ENCODE_R*_R*_I* and ENCODE_R*_M*_I* variants of imul at the moment
    },
    [INST_IDIV] = {
        [ENCODE_R1] = { 1, 0xf6, ENCODING_MODRM_FLAG,                          .modrm_flag = 7 },
        [ENCODE_R2] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 7 },
        [ENCODE_R4] = { 1, 0xf7, ENCODING_MODRM_FLAG,                          .modrm_flag = 7 },
        [ENCODE_R8] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 7 },
        [ENCODE_M1] = { 1, 0xf6, ENCODING_MODRM_FLAG,                          .modrm_flag = 7 },
        [ENCODE_M2] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 7 },
        [ENCODE_M4] = { 1, 0xf7, ENCODING_MODRM_FLAG,                          .modrm_flag = 7 },
        [ENCODE_M8] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 7 },
    },
    [INST_NEG] = {
        [ENCODE_R1] = { 1, 0xf6, ENCODING_MODRM_FLAG,                          .modrm_flag = 3 },
        [ENCODE_R2] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 3 },
        [ENCODE_R4] = { 1, 0xf7, ENCODING_MODRM_FLAG,                          .modrm_flag = 3 },
        [ENCODE_R8] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 3 },
        [ENCODE_M1] = { 1, 0xf6, ENCODING_MODRM_FLAG,                          .modrm_flag = 3 },
        [ENCODE_M2] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 3 },
        [ENCODE_M4] = { 1, 0xf7, ENCODING_MODRM_FLAG,                          .modrm_flag = 3 },
        [ENCODE_M8] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 3 },
    },
    [INST_NOT] = {
        [ENCODE_R1] = { 1, 0xf6, ENCODING_MODRM_FLAG,                          .modrm_flag = 2 },
        [ENCODE_R2] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 2 },
        [ENCODE_R4] = { 1, 0xf7, ENCODING_MODRM_FLAG,                          .modrm_flag = 2 },
        [ENCODE_R8] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 2 },
        [ENCODE_M1] = { 1, 0xf6, ENCODING_MODRM_FLAG,                          .modrm_flag = 2 },
        [ENCODE_M2] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_WORD_OPERANDS, .modrm_flag = 2 },
        [ENCODE_M4] = { 1, 0xf7, ENCODING_MODRM_FLAG,                          .modrm_flag = 2 },
        [ENCODE_M8] = { 1, 0xf7, ENCODING_MODRM_FLAG | ENCODING_REX_W,         .modrm_flag = 2 },
    },
};

u8 REG_INDEX_MAP[REG_COUNT] = {
    [RAX] = 0,
    [RCX] = 1,
    [RDX] = 2,
    [RBX] = 3,
    [RSP] = 4,
    [RBP] = 5,
    [RSI] = 6,
    [RDI] = 7,
    [R8]  = 8,
    [R9]  = 9,
    [R10] = 10,
    [R11] = 11,
    [R12] = 12,
    [R13] = 13,
    [R14] = 14,
    [R15] = 15,
};

Encoded_Inst encode_inst(Inst *inst) {
    Encoding encoding;
    {
        enum {
            NONE = 0,
            R1, R2, R4, R8,
            X4, X8,
            M1, M2, M4, M8,
            MODE_COUNT,
        } place_modes[2];

        u8 *MODE_NAMES[MODE_COUNT] = {
            [R1] = "reg8", [R2] = "reg16", [R4] = "reg32", [R8] = "reg64",
            [X4] = "xmm32", [X8] = "xmm64",
            [M1] = "mem8", [M2] = "mem16", [M4] = "mem32", [M8] = "mem64",
        };

        int size_offset;

        for (u8 i = 0; i < 2; i += 1) {
            switch (inst->places[i].size) {
                case 0: assert(inst->places[i].kind == PLACE_NONE);
                case 1: size_offset = 0; break;
                case 2: size_offset = 1; break;
                case 4: size_offset = 2; break;
                case 8: size_offset = 3; break;
                default: assert(false);
            }

            switch (inst->places[i].kind) {
                case PLACE_NONE: place_modes[i] = NONE; break;
                case PLACE_REG: switch (reg_kind(inst->places[i].reg)) {
                    case REG_KIND_GPR: place_modes[i] = R1 + size_offset; break;
                    case REG_KIND_XMM: place_modes[i] = X4 + (size_offset - 2); assert(size_offset >= 2); break;
                    default: assert(false);
                } break;
                case PLACE_MEM:  place_modes[i] = M1 + size_offset; break;
                default: assert(inst->places[i].kind == PLACE_NONE);
            }
        }

        Encoding_Mode encoding_mode = ENCODING_MODE_INVALID;

        #define ENC(x, y, s) ((x << 0) | (y << 4) | (s << 8))
        switch (ENC(place_modes[0], place_modes[1], inst->imm.size)) {
            case ENC(0,  0,  0): encoding_mode = ENCODE_NO_PARAMS; break;

            case ENC(0,  0,  1): encoding_mode = ENCODE_I1; break;
            case ENC(0,  0,  4): encoding_mode = ENCODE_I4; break;

            case ENC(R1, 0,  1): encoding_mode = ENCODE_R1_I1; break;
            case ENC(R2, 0,  1): encoding_mode = ENCODE_R2_I1; break;
            case ENC(R4, 0,  1): encoding_mode = ENCODE_R4_I1; break;
            case ENC(R8, 0,  1): encoding_mode = ENCODE_R8_I1; break;
            case ENC(R2, 0,  2): encoding_mode = ENCODE_R2_I2; break;
            case ENC(R4, 0,  4): encoding_mode = ENCODE_R4_I4; break;
            case ENC(R8, 0,  4): encoding_mode = ENCODE_R8_I4; break;
            case ENC(R8, 0,  8): encoding_mode = ENCODE_R8_I8; break;

            case ENC(M1, 0,  1): encoding_mode = ENCODE_M1_I1; break;
            case ENC(M2, 0,  1): encoding_mode = ENCODE_M2_I1; break;
            case ENC(M4, 0,  1): encoding_mode = ENCODE_M4_I1; break;
            case ENC(M8, 0,  1): encoding_mode = ENCODE_M8_I1; break;
            case ENC(M2, 0,  2): encoding_mode = ENCODE_M2_I2; break;
            case ENC(M4, 0,  4): encoding_mode = ENCODE_M4_I4; break;
            case ENC(M8, 0,  4): encoding_mode = ENCODE_M8_I4; break;

            case ENC(R1, 0,  0): encoding_mode = ENCODE_R1; break;
            case ENC(R2, 0,  0): encoding_mode = ENCODE_R2; break;
            case ENC(R4, 0,  0): encoding_mode = ENCODE_R4; break;
            case ENC(R8, 0,  0): encoding_mode = ENCODE_R8; break;
            case ENC(M1, 0,  0): encoding_mode = ENCODE_M1; break;
            case ENC(M2, 0,  0): encoding_mode = ENCODE_M2; break;
            case ENC(M4, 0,  0): encoding_mode = ENCODE_M4; break;
            case ENC(M8, 0,  0): encoding_mode = ENCODE_M8; break;

            case ENC(R1, R1, 0): encoding_mode = ENCODE_R1_R1; break;
            case ENC(R2, R2, 0): encoding_mode = ENCODE_R2_R2; break;
            case ENC(R4, R4, 0): encoding_mode = ENCODE_R4_R4; break;
            case ENC(R8, R8, 0): encoding_mode = ENCODE_R8_R8; break;
            case ENC(R1, M1, 0): encoding_mode = ENCODE_R1_M1; break;
            case ENC(R2, M2, 0): encoding_mode = ENCODE_R2_M2; break;
            case ENC(R4, M4, 0): encoding_mode = ENCODE_R4_M4; break;
            case ENC(R8, M8, 0): encoding_mode = ENCODE_R8_M8; break;
            case ENC(M1, R1, 0): encoding_mode = ENCODE_M1_R1; break;
            case ENC(M2, R2, 0): encoding_mode = ENCODE_M2_R2; break;
            case ENC(M4, R4, 0): encoding_mode = ENCODE_M4_R4; break;
            case ENC(M8, R8, 0): encoding_mode = ENCODE_M8_R8; break;
            default: assert(false);
        }
        #undef ENC

        encoding = ENCODING_TABLE[inst->kind][encoding_mode];
        if (encoding_mode == ENCODING_MODE_INVALID || encoding.exists != 1) {
            printf("No encoding for '%s", INST_NAMES[inst->kind]);
            if (MODE_NAMES[place_modes[0]] != null) {
                printf(" %s", MODE_NAMES[place_modes[0]]);
                if (MODE_NAMES[place_modes[1]] != null) {
                    printf(", %s", MODE_NAMES[place_modes[1]]);
                }
                if (inst->imm.size > 0) printf(", imm%u", (u64) inst->imm.size);
            } else {
                if (inst->imm.size > 0) printf(" imm%u", (u64) inst->imm.size);
            }
            printf("'\n");

            printf("Available encodings:\n");
            for (int i = 0; i < ENCODING_MODE_COUNT; i += 1) {
                if (ENCODING_TABLE[inst->kind][i].exists) {
                    printf("    '%s%s'\n", INST_NAMES[inst->kind], ENCODING_MODE_NAMES[i]);
                }
            }

            panic("Attempted to encode invalid x64 instruction\n");
        }
    }

    enum {
        REX_BASE = 0x40,
        REX_W    = 0x08, // selects 64-bit operands over 32-bit operands
        REX_R    = 0x04, // Most significant, fourth, bit of modrm/reg
        REX_X    = 0x02, // Most significant, fourth, bit of SIB/index
        REX_B    = 0x01, // Most significant, fourth, bit of modrm/rm, SIB base or opcode reg

        WORD_OPERAND_PREFIX = 0x66, // selects 16-bit operands over 32-bit operands
        SECONDARY_OPCODE_MAP_PREFIX = 0x0f,

        // Keep in mind that when modrm/rm is RSP or RBP, R12 or R13 using MODRM_RM_POINTER_* has special semantics
        MODRM_MOD_MEM          = 0x00,
        MODRM_MOD_MEM_PLUS_I8  = 0x40,
        MODRM_MOD_MEM_PLUS_I32 = 0x80,
        MODRM_MOD_REG          = 0xc0,
        MODRM_RM_USE_SIB = 0x04,

        SIB_SCALE_1 = 0x00,
        SIB_SCALE_2 = 0x40,
        SIB_SCALE_4 = 0x80,
        SIB_SCALE_8 = 0xc0,
        SIB_NO_INDEX = 0x20,
    };

    u8 rex = 0, modrm = 0, sib = 0;
    bool use_modrm = false, use_sib = false;
    u8 opcode = encoding.opcode;

    u8 extra_imm_size = 0;
    u32 extra_imm = 0;

    {
        if (encoding.flags & ENCODING_REX_W) {
            rex |= REX_BASE | REX_W;
        }

        enum { ENCODE_NEITHER, ENCODE_FIRST, ENCODE_SECOND }
        encode_in_reg = ENCODE_NEITHER,
        encode_in_rm  = ENCODE_NEITHER;

        switch (inst->places[0].kind) {
            case PLACE_NONE: {
                assert(inst->places[1].kind == PLACE_NONE);
            } break;

            case PLACE_REG: {
                encode_in_reg = ENCODE_FIRST;
                encode_in_rm  = inst->places[1].kind == PLACE_NONE? ENCODE_NEITHER : ENCODE_SECOND;
            } break;

            case PLACE_MEM: {
                encode_in_rm  = ENCODE_FIRST;
                assert(inst->places[1].kind != PLACE_MEM);
                encode_in_reg = inst->places[1].kind == PLACE_NONE? ENCODE_NEITHER : ENCODE_SECOND;
            } break;

            default: assert(false);
        }

        if (encoding.flags & ENCODING_MODRM_FLAG) {
            assert(!(encoding.flags & ENCODING_REG_IN_OPCODE));
            assert(inst->places[0].kind != PLACE_NONE && inst->places[1].kind == PLACE_NONE);
            assert((encoding.modrm_flag & 7) == encoding.modrm_flag);
            modrm |= (encoding.modrm_flag & 7) << 3;

            encode_in_reg = ENCODE_NEITHER;
            encode_in_rm = inst->places[0].kind == PLACE_NONE? ENCODE_NEITHER : ENCODE_FIRST;
            use_modrm = true;
        }

        if (encoding.flags & ENCODING_REG_IN_OPCODE) {
            assert(inst->places[0].kind == PLACE_REG && inst->places[1].kind == PLACE_NONE);

            encode_in_reg = ENCODE_NEITHER;
            encode_in_rm  = ENCODE_NEITHER;

            u8 index = REG_INDEX_MAP[inst->places[0].reg];
            opcode |= index & 7;
            if (index & 8) rex |= REX_B;
        }

        if (encode_in_reg != ENCODE_NEITHER) {
            use_modrm = true;
            Place *place = &inst->places[encode_in_reg == ENCODE_FIRST? 0 : 1];
            assert(place->kind == PLACE_REG);

            u8 index = REG_INDEX_MAP[place->reg];
            modrm |= (index & 7) << 3;
            if (index & 8) rex |= REX_BASE | REX_R;
        }

        if (encode_in_rm != ENCODE_NEITHER) {
            use_modrm = true;
            Place *place = &inst->places[encode_in_rm == ENCODE_FIRST? 0 : 1];

            if (place->kind == PLACE_REG) {
                modrm |= MODRM_MOD_REG;
                u8 index = REG_INDEX_MAP[place->reg];
                modrm |= index & 7;
                if (index & 8) rex |= REX_BASE | REX_B;
            } else if (place->kind == PLACE_MEM) {
                Address address = place->address;
                assert(address.base == RIP || reg_kind(address.base) == REG_KIND_GPR);
                assert(address.index == REG_NONE || reg_kind(address.index) == REG_KIND_GPR);
                assert(address.index != RSP && address.index != RSP && address.base != RBP);

                extra_imm = address.offset;

                if (address.base == RIP) {
                    assert(address.index == REG_NONE);
                    use_sib = false;
                    extra_imm_size = 4;
                    modrm |= 0x05;
                } else {
                    use_sib = address.base == RSP || address.index != REG_NONE;

                    if (use_sib) {
                        modrm |= MODRM_RM_USE_SIB;

                        u8 base_index  = REG_INDEX_MAP[address.base];
                        sib |= base_index & 7;
                        if (base_index  & 8) rex |= REX_BASE | REX_B;

                        if (address.index == REG_NONE) {
                            sib |= 0x20;
                        } else {
                            u8 index_index = REG_INDEX_MAP[address.index];
                            sib |= (index_index & 7) << 3;
                            if (index_index & 8) rex |= REX_BASE | REX_X;

                            switch (address.scale) {
                                case 1: sib |= SIB_SCALE_1; break;
                                case 2: sib |= SIB_SCALE_2; break;
                                case 4: sib |= SIB_SCALE_4; break;
                                case 8: sib |= SIB_SCALE_8; break;
                                default: assert(false);
                            }
                        }
                    } else {
                        u8 base_index = REG_INDEX_MAP[address.base];
                        modrm |= base_index & 7;
                        if (base_index & 8) rex |= REX_BASE | REX_B;
                    }

                    if (address.offset == 0) {
                        extra_imm_size = 0;
                        modrm |= MODRM_MOD_MEM;
                    } else if (address.offset >= I8_MIN && address.offset <= I8_MAX) {
                        extra_imm_size = 1;
                        modrm |= MODRM_MOD_MEM_PLUS_I8;
                    } else {
                        extra_imm_size = 4;
                        modrm |= MODRM_MOD_MEM_PLUS_I32;
                    }
                }
            } else {
                assert(false);
            }
        }

        // Avoid encoding AH, CH, DH and BH
        if ((inst->places[0].kind == PLACE_REG && inst->places[0].size == 1 && inst->places[0].reg >= RSP && inst->places[0].reg <= RDI) ||
            (inst->places[1].kind == PLACE_REG && inst->places[1].size == 1 && inst->places[1].reg >= RSP && inst->places[1].reg <= RDI)) {
            rex |= REX_BASE;
        }
    }

    Encoded_Inst result = {0};

    if (encoding.flags & ENCODING_WORD_OPERANDS) {
        result.bytes[result.length++] = WORD_OPERAND_PREFIX;
    }

    if (rex != 0) {
        result.bytes[result.length++] = rex;
    }

    if (encoding.flags & ENCODING_SECONDARY) {
        result.bytes[result.length++] = SECONDARY_OPCODE_MAP_PREFIX;
    }

    result.bytes[result.length++] = opcode;

    if (use_modrm) {
        result.bytes[result.length++] = modrm;
        if (use_sib) {
            result.bytes[result.length++] = sib;
        }
    }

    if (extra_imm_size > 0) {
        u64 imm_bytes = extra_imm;
        for (u8 i = 0; i < extra_imm_size; i += 1) {
            result.bytes[result.length++] = imm_bytes & 0xff;
            imm_bytes >>= 8;
        }
    }

    if (inst->imm.size > 0) {
        u64 imm_bytes = inst->imm.value;
        for (u8 i = 0; i < inst->imm.size; i += 1) {
            result.bytes[result.length++] = imm_bytes & 0xff;
            imm_bytes >>= 8;
        }
    }

    assert(result.length <= 15);
    return result;
}

void encode_insts(Code_Builder *builder) {
    u64 bytecode_length = 0;

    for (Inst_Block *block = builder->insts_start; block != null; block = block->next) {
        if (block->jump_to != null) block->jump_to->relative_bytecode_pos = bytecode_length;

        u16 l = block->jump_from == null? block->length : block->length - 1;
        for (u16 i = 0; i < l; i += 1) {
            Encoded_Inst encoded = encode_inst(&block->insts[i]);
            bytecode_length += (u64) encoded.length;
        }

        if (block->jump_from != null) {
            assert(block->jump_from->jump_to != null);
            u64 target_pos = block->jump_from->jump_to->relative_bytecode_pos;

            Inst *inst = &block->insts[block->length - 1];

            if (target_pos == U64_MAX) {
                unimplemented(); // TODO backwards jumps require us to iterate with a speculative encoded size range
            } else {
                i64 offset = target_pos - bytecode_length;
                if (offset - 2 >= I8_MIN && offset - 2 <= I8_MAX && false) {
                    inst->imm = (Imm) { .size = 1, .value = offset };
                } else {
                    assert(offset - 4 >= I32_MIN && offset - 4 <= I32_MAX);
                    inst->imm = (Imm) { .size = 4, .value = offset };
                }

                Encoded_Inst encoded = encode_inst(inst);
                bytecode_length += (u64) encoded.length;
            }
        }
    }

    printf("Encoded %u bytes of machinecode\n", bytecode_length);
}

u8 *REG_NAMES[REG_COUNT][4] = {
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

    [RIP] = { null, null, null, "rip" },

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
};

void print_reg(Reg reg, u8 size) {
    u8 name_index;
    switch (size) {
        case 1:   name_index = 0; break;
        case 2:   name_index = 1; break;
        case 4:   name_index = 2; break;
        case 8:   name_index = 3; break;
        case 16:  name_index = 4; break;
        case 32:  name_index = 6; break;
        case 64:  name_index = 7; break;
        case 128: name_index = 8; break;
        default: assert(false);
    }
    printf(REG_NAMES[reg][name_index]);
}

void print_place(Place *place) {
    if (place->kind == PLACE_NONE) {
        
    } else if (place->kind == PLACE_KEY) {
        if (place->key->flags & KEY_FLAG_ONLY_SET_ONCE) {
            printf("$$%u", place->key->index);
        } else {
            printf("$%u", place->key->index);
        }
    } else if (place->kind == PLACE_REG) {
        print_reg(place->reg, place->size);
    } else if (place->kind == PLACE_MEM) {
        switch (place->size) {
            case 1: printf("byte ptr [");  break;
            case 2: printf("word ptr [");  break;
            case 4: printf("dword ptr ["); break;
            case 8: printf("qword ptr ["); break;
            default: assert(false);
        }

        print_reg(place->address.base, 8);

        if (place->address.index != REG_NONE) {
            printf(" + ");
            print_reg(place->address.index, 8);
            switch (place->address.scale) {
                case 1: break;
                case 2: printf("*2"); break;
                case 4: printf("*4"); break;
                case 8: printf("*8"); break;
                default: assert(false);
            }
        }

        if (place->address.offset != 0) {
            printf(" + %x", (u64) place->address.offset);
        }

        printf("]");
    }
}

void print_inst(Inst *inst) {
    printf("%s", INST_NAMES[inst->kind]);

    if (inst->places[0].kind != PLACE_NONE) {
        printf(" ");
        print_place(&inst->places[0]);
        if (inst->places[1].kind != PLACE_NONE) {
            printf(", ");
            print_place(&inst->places[1]);
        }
    }

    if (inst->imm.size == 0) {
        // Do nothing
        printf("\n");
    } else if (inst->imm.size == IMM_SIZE_USE_POINTER) {
        printf("{ %u bytes }\n", (u64) inst->imm.pointer->size);
    } else if (inst->imm.size == 1 || inst->imm.size == 2 || inst->imm.size == 4 || inst->imm.size == 8) {
        printf(inst->places[0].kind == PLACE_NONE? " " : ", ");
        u64 size_mask = 0xffffffffffffffff >> ((8-inst->imm.size)*8);
        printf("%i\n", inst->imm.value & size_mask);
    } else {
        printf("\n");
        assert(false);
    }
}

void print_encoded_inst(Encoded_Inst encoded) {
    for (u8 i = 0; i < encoded.length; i += 1) {
        printf("%x ", encoded.bytes[i]);
    }
    printf("\n");
}

void dump_instructions(Code_Builder *builder) {
    for (Inst_Block *block = builder->insts_start; block != null; block = block->next) {
        if (block->jump_to != null) {
            printf("%s:\n", block->jump_to->debug_name);
        }

        u16 print_length = block->length;
        if (block->jump_from != null) {
            print_length -= 1;
        }

        for (u16 i = 0; i < print_length; i += 1) {
            printf("    ");
            print_inst(&block->insts[i]);
        }

        if (block->jump_from != null) {
            Inst *jmp_inst = &block->insts[block->length - 1];
            assert(jmp_inst->kind == INST_JMP || (jmp_inst->kind >= INST_JCC_FIRST && jmp_inst->kind <= INST_JCC_LAST));
            printf("    %s ", INST_NAMES[jmp_inst->kind]);
            if (block->jump_from->jump_to != null) {
                printf(block->jump_from->jump_to->debug_name);
            } else {
                printf("<no target given>");
            }
            printf("\n");
        }
    }
}



void fibonachi(Code_Builder *code_builder, i32 iterations) {
    Key *m = new_i32(code_builder, 1);
    Key *n = new_i32(code_builder, 1);

    Key *counter = new_i32(code_builder, 0);
    Jump_To *loop_start = add_label(code_builder, "start");

    Key *old_m = new_i32(code_builder, 0);
    binary(code_builder, BINARY_MOV, old_m, m);
    binary(code_builder, BINARY_ADD, m, n);
    binary(code_builder, BINARY_MOV, n, old_m);

    unary(code_builder, UNARY_INC, counter);
    binary(code_builder, BINARY_CMP, counter, new_i32(code_builder, iterations));
    Jump_From *loop_end = add_jump(code_builder, CONDITION_L);
    link_jump(code_builder, loop_end, loop_start);
}

void not_fibonachi(Code_Builder *code_builder, i32 iterations) {
    Key *a = new_i32(code_builder, 2);
    Key *b = new_i32(code_builder, 2);

    Key *counter = new_i32(code_builder, 0);
    Jump_To *loop_start = add_label(code_builder, "start");

    binary(code_builder, BINARY_MUL, a, b);
    binary(code_builder, BINARY_MUL, b, a);

    unary(code_builder, UNARY_INC, counter);
    binary(code_builder, BINARY_CMP, counter, new_i32(code_builder, iterations));
    Jump_From *loop_end = add_jump(code_builder, CONDITION_L);
    link_jump(code_builder, loop_end, loop_start);
}


void main() {
    Arena arena = {0};
    Code_Builder *code_builder = code_builder_new(&arena);

    //fibonachi(code_builder, 10);
    not_fibonachi(code_builder, 4);

    printf("\n; input\n");
    dump_instructions(code_builder);

    assign_registers(code_builder);

    printf("\n; output\n");
    dump_instructions(code_builder);

    encode_insts(code_builder);
}
