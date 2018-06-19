
typedef enum Register {
    // Symbolic values
    REGISTER_NONE = 0,
    REGISTER_ANY = 1,

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

    REGISTER_COUNT,
} Register;

u8 REGISTER_INDEX[REGISTER_COUNT] = {
    [RAX] = 0,  [RCX] = 1,  [RDX] = 2,  [RBX] = 3,
    [RSP] = 4,  [RBP] = 5,  [RSI] = 6,  [RDI] = 7,
    [R8]  = 8,  [R9]  = 9,  [R10] = 10, [R11] = 11,
    [R12] = 12, [R13] = 13, [R14] = 14, [R15] = 15,
    [AH] = 4 [CH] = 5, [DH] = 6, [BH] = 7,
    [XMM0] = 0,   [XMM1] = 1,   [XMM2] = 2,   [XMM3] = 3,
    [XMM4] = 4,   [XMM5] = 5,   [XMM6] = 6,   [XMM7] = 7,
    [XMM8] = 8,   [XMM9] = 9,   [XMM10] = 10, [XMM11] = 11,
    [XMM12] = 12, [XMM13] = 13, [XMM14] = 14, [XMM15] = 15,
};

enum {
    REX_BASE = 0x40,
    REX_W    = 0x08, // selects 64-bit operands over 32-bit operands
    REX_R    = 0x04, // Most significant, fourth, bit of modrm/reg
    REX_X    = 0x02, // Most significant, fourth, bit of SIB/index
    REX_B    = 0x01, // Most significant, fourth, bit of modrm/rm, SIB base or opcode reg

    WORD_OPERAND_PREFIX = 0x66, // selects 16-bit operands over 32-bit operands

    // Keep in mind that when modrm/rm is RSP or RBP, R12 or R13 using MODRM_RM_POINTER_* has special semantics
    MODRM_RM_VALUE            = 0xc0,
    MODRM_RM_POINTER          = 0xc0,
    MODRM_RM_POINTER_PLUS_I8  = 0xc0,
    MODRM_RM_POINTER_PLUS_I32 = 0xc0,

    SIB_SCALE_1 = 0x00,
    SIB_SCALE_2 = 0x40,
    SIB_SCALE_4 = 0x80,
    SIB_SCALE_8 = 0xc0,
}


inline void encode_modrm_reg(Register reg, u8 *modrm, u8 *rex) {
    u8 index = REGISTER_INDEX[reg];

    *modrm |= (index & 0x07) << 3;
    if (index & 0x08) {
        *rex |= REX_R;
    }
}

inline void encode_modrm_rm(Register reg, u8 *modrm, u8* rex) {
    u8 index = REGISTER_INDEX[reg];

    *modrm |= index & 0x07;
    if (index & 0x08) {
        *rex |= REX_B;
    }
}


typedef struct Item {
    enum {
        ITEM_STACK,
        ITEM_STACK_UNALLOCATED, // Goes on the stack only if we need to temporarily deallocate it
        ITEM_DATA_SEGMENT,
    } kind;

    u8 size;
    u64 offset; // Offset into stack or .data

    enum {
        REGISTER_KIND_GPR,
        REGISTER_KIND_XMM,
    } needed_register_kind;
} Item;

typedef struct Register_State {
    bool alllocated;
    Item *item; // used if allocated
} Register_State;

typedef struct Register_Allocator {
    Register_State states[REGISTER_COUNT];
} Register_Allocator;


Register allocate_register(Register_Allocator* allocator, Register into_reg, Item *item) {
    Register start_reg, end_reg;
    switch (item->needed_register_kind) {
        case REGISTER_KIND_GPR: { start_reg = RAX;  end_reg   = R15;   } break;
        case REGISTER_KIND_XMM: { start_reg = XMM0; end_reg   = XMM15; } break;
        default: assert(false);
    }

    if (into_reg == REGISTER_ANY) {
        for (Register reg = start_reg; reg != end_reg; reg += 1) {
            if (!allocator->states[reg].allocated) {
                into_reg = reg;
                break;
            }
        }

        if (into_reg == REGISTER_ANY) {
            // TODO some good heuristic for which register to force-flush here
            flush_register(start_reg);
            into_reg = start_reg;
        }
    }

    assert(into_reg != REGISTER_ANY && into_reg != REGISTER_NONE);
    assert(!allocator->states[into_reg].allocated);

    Register swap_with_reg = REGISTER_NONE;
    for (Register reg = start_reg; reg != end_reg; reg += 1) {
        if (allocator->states[reg].allocated && allocator->states[reg].item == item) {
            swap_with_reg = reg;
            break;
        }
    }
    
    if (swap_with_reg == REGISTER_NONE) {
        if (allocator->states[into_reg.allocated]) {
            flush_register(into_reg);
        }

        allocator->states[into_reg].allocated = true;
        allocator->states[into_reg].item = item;
    } else {
        switch (item->needed_register_kind) {
            case REGISTER_KIND_GPR: {
                // insert appropriate mov
                unimplemented();
            } break;

            case REGISTER_KIND_XMM: {
                // insert appropriate movss
                unimplemented();
            } break;

            default: assert(false);
        }

        Register_State tmp = allocator->states[swap_with_reg]
        allocator->states[swap_with_reg] = allocator->states[into_reg];
        allocator->states[into_reg] = tmp;
    }
}

void forget_register(Register_Allocator *allocator, u64 item_index) {
    if (allocator->states[reg].allocated) {
        allocator->states[reg].allocated = false;
        allocator->states[reg].item = null;
    }
}

void flush_register(Register_Allocator *allocator, Register reg) {
    if (!allocator->states[reg].allocated) return;

    Item *item = allocator->states[reg].item;
    switch (item->needed_register_kind) {
        case REGISTER_KIND_GPR: {
            // insert appropriate mov
            unimplemented();
        } break;

        case REGISTER_KIND_XMM: {
            // insert appropriate movss
            unimplemented();
        } break;

        default: assert(false);
    }

    forget_register(reg);
}
