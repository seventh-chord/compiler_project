
// TODO sse instructions, which get somewhat funky

#include "common.c"


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


typedef enum Place_Kind {
    PLACE_NONE,
    PLACE_REG,
    PLACE_MEM,
} Place_Kind;

typedef struct Place {
    u8 kind;
    u8 size;

    union {
        Reg reg;
        Address address;
    };
} Place;


typedef enum Inst_Kind {
    INST_ADD,

    INST_MUL,
    INST_IMUL,
    INST_DIV,
    INST_IDIV,

    INST_COUNT,
} Inst_Kind;

typedef struct Inst {
    Inst_Kind kind;
    Place a, b;

    u8 immediate_size;
    u64 immediate;
} Inst;


typedef enum Encoding_Mode {
    // R means register, M means register or memory, I means immediate
    // The number indicates the number of bytes of the operand
    // We are going pretty close to full combinatorics explosion mode here.
    // This allows us to circumnavigate a lot of the non-uniformity in x64 by just
    // omitting certain entries from the table below.

    ENCODING_MODE_INVALID = 0,

    ENCODE_R1_I1, ENCODE_R2_I1, ENCODE_R4_I1, ENCODE_R8_I1,
    ENCODE_R2_I2,
    ENCODE_R4_I4, ENCODE_R8_I4,
    ENCODE_R8_I8,

    ENCODE_R1_R1, ENCODE_R2_R2, ENCODE_R4_R4, ENCODE_R8_R8,
    ENCODE_R1_M1, ENCODE_R2_M2, ENCODE_R4_M4, ENCODE_R8_M8,
    ENCODE_M1_R1, ENCODE_M2_R2, ENCODE_M4_R4, ENCODE_M8_R8,

    ENCODE_R1, ENCODE_R2, ENCODE_R4, ENCODE_R8,
    ENCODE_M1, ENCODE_M2, ENCODE_M4, ENCODE_M8,

    ENCODING_MODE_COUNT,
} Encoding_Mode;


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


Encoding ENCODING_TABLE[INST_COUNT][ENCODING_MODE_COUNT] = {
    [INST_ADD] = {
        [ENCODE_R1_I1] = { 1, 0x80, ENCODING_MODRM_FLAG,                          .modrm_flag = 0 },
        [ENCODE_R2_I1] = { 1, 0x83, ENCODING_WORD_OPERANDS | ENCODING_MODRM_FLAG, .modrm_flag = 0 },
        [ENCODE_R4_I1] = { 1, 0x83, ENCODING_MODRM_FLAG,                          .modrm_flag = 0 },
        [ENCODE_R8_I1] = { 1, 0x83, ENCODING_REX_W | ENCODING_MODRM_FLAG,         .modrm_flag = 0 },
        [ENCODE_R2_I2] = { 1, 0x81, ENCODING_WORD_OPERANDS | ENCODING_MODRM_FLAG, .modrm_flag = 0 },
        [ENCODE_R4_I4] = { 1, 0x81, ENCODING_MODRM_FLAG,                          .modrm_flag = 0 },
        [ENCODE_R8_I4] = { 1, 0x81, ENCODING_REX_W | ENCODING_MODRM_FLAG,         .modrm_flag = 0 },

        [ENCODE_R1_M1] = { 1, 0x02 },
        [ENCODE_R2_M2] = { 1, 0x03, ENCODING_WORD_OPERANDS },
        [ENCODE_R4_M4] = { 1, 0x03 },
        [ENCODE_R8_M8] = { 1, 0x03, ENCODING_REX_W },

        [ENCODE_M1_R1] = { 1, 0x00 },
        [ENCODE_M2_R2] = { 1, 0x01, ENCODING_WORD_OPERANDS },
        [ENCODE_M4_R4] = { 1, 0x01 },
        [ENCODE_M8_R8] = { 1, 0x01, ENCODING_REX_W },

        [ENCODE_R1_R1] = { 1, 0x02 },
        [ENCODE_R2_R2] = { 1, 0x03, ENCODING_WORD_OPERANDS },
        [ENCODE_R4_R4] = { 1, 0x03 },
        [ENCODE_R8_R8] = { 1, 0x03, ENCODING_REX_W },
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

Encoded_Inst encode(Inst inst) {
    Encoding_Mode encoding_mode = ENCODING_MODE_INVALID;
    {
        enum {
            NONE = 0,
            R1, R2, R4, R8,
            X1, X2, X4, X8,
            M1, M2, M4, M8,
        } a_mode, b_mode;

        int size_offset;

        switch (inst.a.size) {
            case 1: size_offset = 0; break;
            case 2: size_offset = 1; break;
            case 4: size_offset = 2; break;
            case 8: size_offset = 3; break;
            default: assert(false);
        }
        switch (inst.a.kind) {
            case PLACE_NONE: a_mode = NONE; break;
            case PLACE_REG: switch (reg_kind(inst.a.reg)) {
                case REG_KIND_GPR: a_mode = R1 + size_offset; break;
                case REG_KIND_XMM: a_mode = X1 + size_offset; break;
                default: assert(false);
            } break;
            case PLACE_MEM:  a_mode = M1 + size_offset; break;
            default: assert(inst.a.kind == PLACE_NONE);
        }

        switch (inst.b.size) {
            case 1: size_offset = 0; break;
            case 2: size_offset = 1; break;
            case 4: size_offset = 2; break;
            case 8: size_offset = 3; break;
            default: assert(inst.b.kind == PLACE_NONE);
        }
        switch (inst.b.kind) {
            case PLACE_NONE: b_mode = NONE; break;
            case PLACE_REG: switch (reg_kind(inst.b.reg)) {
                case REG_KIND_GPR: b_mode = R1 + size_offset; break;
                case REG_KIND_XMM: b_mode = X1 + size_offset; break;
                default: assert(false);
            } break;
            case PLACE_MEM:  b_mode = M1 + size_offset; break;
            default: assert(false);
        }

        #define ENC(x, y, s) ((x << 0) | (y << 4) | (s << 8))
        switch (ENC(a_mode, b_mode, inst.immediate_size)) {
            case ENC(R1, 0,  1): encoding_mode = ENCODE_R1_I1; break;
            case ENC(R2, 0,  1): encoding_mode = ENCODE_R2_I1; break;
            case ENC(R4, 0,  1): encoding_mode = ENCODE_R4_I1; break;
            case ENC(R8, 0,  1): encoding_mode = ENCODE_R8_I1; break;
            case ENC(R2, 0,  2): encoding_mode = ENCODE_R2_I2; break;
            case ENC(R4, 0,  4): encoding_mode = ENCODE_R4_I4; break;
            case ENC(R8, 0,  4): encoding_mode = ENCODE_R8_I4; break;
            case ENC(R8, 0,  8): encoding_mode = ENCODE_R8_I8; break;

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
    }

    Encoding encoding = ENCODING_TABLE[inst.kind][encoding_mode];
    assert(encoding.exists == 1);

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

    u8 extra_immediate_size = 0;
    u32 extra_immediate = 0;

    {
        if (encoding.flags & ENCODING_REX_W) {
            rex |= REX_BASE | REX_W;
        }

        enum { ENCODE_NEITHER, ENCODE_A, ENCODE_B }
        encode_in_reg = ENCODE_NEITHER,
        encode_in_rm  = ENCODE_NEITHER;

        switch (inst.a.kind) {
            case PLACE_NONE: assert(false);
            case PLACE_REG: {
                encode_in_reg = ENCODE_A;
                encode_in_rm  = inst.b.kind == PLACE_NONE? ENCODE_NEITHER : ENCODE_B;
            } break;
            case PLACE_MEM: {
                encode_in_rm  = ENCODE_A;
                assert(inst.b.kind != PLACE_MEM);
                encode_in_reg = inst.b.kind == PLACE_NONE? ENCODE_NEITHER : ENCODE_B;
            } break;
        }

        if (encoding.flags & ENCODING_MODRM_FLAG) {
            assert(!(encoding.flags & ENCODING_REG_IN_OPCODE));
            assert(inst.a.kind != PLACE_NONE && inst.b.kind == PLACE_NONE);
            assert((encoding.modrm_flag & 7) == encoding.modrm_flag);
            modrm |= (encoding.modrm_flag & 7) << 3;

            encode_in_reg = ENCODE_NEITHER;
            encode_in_rm = inst.a.kind == PLACE_NONE? ENCODE_NEITHER : ENCODE_A;
            use_modrm = true;
        }

        if (encoding.flags & ENCODING_REG_IN_OPCODE) {
            assert(inst.a.kind == PLACE_REG && inst.b.kind == PLACE_NONE);

            u8 index = REG_INDEX_MAP[inst.a.reg];
            opcode |= index & 7;
            if (index & 8) rex |= REX_B;
        }

        if (encode_in_reg != ENCODE_NEITHER) {
            use_modrm = true;
            Place *place = encode_in_reg == ENCODE_A? &inst.a : &inst.b;
            assert(place->kind == PLACE_REG);

            u8 index = REG_INDEX_MAP[place->reg];
            modrm |= (index & 7) << 3;
            if (index & 8) rex |= REX_BASE | REX_R;
        }

        if (encode_in_rm != ENCODE_NEITHER) {
            use_modrm = true;
            Place *place = encode_in_rm == ENCODE_A? &inst.a : &inst.b;

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

                extra_immediate = address.offset;

                if (address.base == RIP) {
                    assert(address.index == REG_NONE);
                    use_sib = false;
                    extra_immediate_size = 4;
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
                        extra_immediate_size = 0;
                        modrm |= MODRM_MOD_MEM;
                    } else if (address.offset >= I8_MIN && address.offset <= I8_MAX) {
                        extra_immediate_size = 1;
                        modrm |= MODRM_MOD_MEM_PLUS_I8;
                    } else {
                        extra_immediate_size = 4;
                        modrm |= MODRM_MOD_MEM_PLUS_I32;
                    }
                }
            } else {
                assert(false);
            }
        }

        // Avoid encoding AH, CH, DH and BH
        if ((inst.a.kind == PLACE_REG && inst.a.size == 1 && inst.a.reg >= RSP && inst.a.reg <= RDI) ||
            (inst.b.kind == PLACE_REG && inst.b.size == 1 && inst.b.reg >= RSP && inst.b.reg <= RDI)) {
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

    if (extra_immediate_size > 0) {
        u64 imm_bytes = extra_immediate;
        for (u8 i = 0; i < extra_immediate_size; i += 1) {
            result.bytes[result.length++] = imm_bytes & 0xff;
            imm_bytes >>= 8;
        }
    }

    if (inst.immediate_size > 0) {
        u64 imm_bytes = inst.immediate;
        for (u8 i = 0; i < inst.immediate_size; i += 1) {
            result.bytes[result.length++] = imm_bytes & 0xff;
            imm_bytes >>= 8;
        }
    }

    assert(result.length <= 15);
    return result;
}


u8 *INST_NAMES[INST_COUNT] = {
    [INST_ADD] = "add",

    [INST_MUL]  = "mul",
    [INST_IMUL] = "imul",
    [INST_DIV]  = "div",
    [INST_IDIV] = "idiv",
};

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
    if (inst->a.kind != PLACE_NONE) {
        printf(" ");
        print_place(&inst->a);
        if (inst->b.kind != PLACE_NONE) {
            printf(", ");
            print_place(&inst->b);
        }
    }
    if (inst->immediate_size != 0) {
        if (inst->a.kind != PLACE_NONE) printf(", ");
        u64 size_mask = 0xffffffffffffffff >> ((8-inst->immediate_size)*8);
        printf("%x", inst->immediate & size_mask);
    }
    printf("\n");
}

void print_encoded_inst(Encoded_Inst encoded) {
    for (u8 i = 0; i < encoded.length; i += 1) {
        printf("%x ", encoded.bytes[i]);
    }
    printf("\n");
}



void main() {
    Inst i = { INST_IMUL, { PLACE_REG, 2, .reg = R12 }, { PLACE_MEM, 2, .address = { RCX, R13, 4, 9 } } };

    //print_inst(&i);
    print_encoded_inst(encode(i));
}
