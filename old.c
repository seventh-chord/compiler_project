void write_lit(Context* context, u8 size, u64 lit) {
    switch (size) {
        default: assert(false);

        #define CASE_N(n)\
        case n:\
            buf_push(context->bytecode, lit & 0xff);\
            lit = lit >> 8;\
            // fallthrough!

        CASE_N(8)
        CASE_N(7)
        CASE_N(6)
        CASE_N(5)
        CASE_N(4)
        CASE_N(3)
        CASE_N(2)
        CASE_N(1)

        #undef CASE_N
    }
}

void write_xor_reg(Context* context, u8 size, u8 reg) {
    switch (size) {
        case 1: {
            buf_push(context->bytecode, 0x32);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, 0x33);
        } break;
        case 4: {
            buf_push(context->bytecode, 0x33);
        } break;
        case 8: {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0x33);
        } break;
        default: assert(false);
    }

    buf_push(context->bytecode, 0xc0 | (reg << 3) | reg);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("xor%u %s, %s\n", (u64) (size*8), reg_names[reg], reg_names[reg]);
    #endif
}

void write_mov_reg_to_reg(Context* context, u8 size, u8 from_reg, u8 to_reg) {
    assert(to_reg < 8 && from_reg < 8); // otherwise we need to encode registers using rex.{r, x, b}

    switch (size) {
        case 1: {
            buf_push(context->bytecode, 0x88);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, 0x89);
        } break;
        case 4: {
            buf_push(context->bytecode, 0x89);
        } break;
        case 8: {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0x89);
        } break;
        default: assert(false);
    }

    buf_push(context->bytecode, 0xc0 | (from_reg << 3) | to_reg);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov%u %s, %s\n", (u64) (size*8), reg_names[to_reg], reg_names[from_reg]);
    #endif
}

void write_mov_lit_to_reg(Context* context, u8 size, u64 lit, u8 to_reg) {
    assert(to_reg < 8); // otherwise we need to encode registers using rex.{r, x, b}

    switch (size) {
        case 1: {
            buf_push(context->bytecode, 0xb0 | to_reg);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, 0xb8 | to_reg);
        } break;
        case 4: {
            buf_push(context->bytecode, 0xb8 | to_reg);
        } break;
        case 8: {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0xb8 | to_reg);
        } break;
        default: assert(false);
    }

    write_lit(context, size, lit);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov%u %s, %u\n", (u64) (size*8), reg_names[to_reg], size_mask(size) & lit);
    #endif
}

void write_zero_extend(Context* context, u8 from_size, u8 to_size, u8 reg) {
    // From the intel manual, 3.4.1.1 (./reference/intel_introduction.pdf):
    // • 64-bit operands generate a 64-bit result in the destination
    //   general-purpose register.
    // • 32-bit operands generate a 32-bit result, zero-extended to a 64-bit
    //   result in the destination general-purpose register.
    // • 8-bit and 16-bit operands generate an 8-bit or 16-bit result. The
    //   upper 56 bits or 48 bits (respectively) of the destination
    //   general-purpose register are not modified by the operation. If the
    //   result of an 8-bit or 16-bit operation is intended for 64-bit address
    //   calculation, explicitly sign-extend the register to the full 64-bits.

    bool invalid = false;

    switch (from_size) {
        case 1: {
            switch (to_size) {
                case 1: invalid = true; break;

                case 2: {
                    buf_push(context->bytecode, 0x66);
                    buf_push(context->bytecode, 0x0f);
                    buf_push(context->bytecode, 0xb6);
                    buf_push(context->bytecode, 0xc0 | (reg << 3) | reg);
                } break;

                case 4: {
                    buf_push(context->bytecode, 0x0f);
                    buf_push(context->bytecode, 0xb6);
                    buf_push(context->bytecode, 0xc0 | (reg << 3) | reg);
                } break;

                case 8: {
                    buf_push(context->bytecode, 0x48);
                    buf_push(context->bytecode, 0x0f);
                    buf_push(context->bytecode, 0xb6);
                    buf_push(context->bytecode, 0xc0 | (reg << 3) | reg);
                } break;

                default: assert(false);
            }
        } break;

        case 2: {
            switch (to_size) {
                case 1: invalid = true; break;
                case 2: invalid = true; break;

                case 4: {
                    buf_push(context->bytecode, 0x0f);
                    buf_push(context->bytecode, 0xb7);
                    buf_push(context->bytecode, 0xc0 | (reg << 3) | reg);
                } break;

                case 8: {
                    buf_push(context->bytecode, 0x48);
                    buf_push(context->bytecode, 0x0f);
                    buf_push(context->bytecode, 0xb7);
                    buf_push(context->bytecode, 0xc0 | (reg << 3) | reg);
                } break;

                default: assert(false);
            }
        } break;

        case 4: {
            // This should be a nop probably, read the notes from the manual above just to verify, then remove the 'unimplemented' if appropriate
            unimplemented();
        } break;

        case 8: invalid = true; break;

        default: assert(false);
    }

    if (invalid) {
        panic("Can't movzx from %u bytes to %u bytes\n", from_size, to_size);
    }

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("movzx %s, %s (%u to %u)\n", reg_names[reg], reg_names[reg], (u64) (from_size*8), (u64) (to_size*8));
    #endif
}

void write_mov_reg_to_stack(Context* context, u8 size, u32 stack_item_index, u8 from_reg) {
    assert(from_reg < 8); // otherwise we need to encode registers using rex.{r, x, b}

    switch (size) {
        case 1: {
            buf_push(context->bytecode, 0x88);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, 0x89);
        } break;
        case 4: {
            buf_push(context->bytecode, 0x89);
        } break;
        case 8: {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0x89);
        } break;
        default: assert(false);
    }

    buf_push(context->bytecode, 0x44 | (from_reg << 3)); // 0x44 is x+imm8, 0x84 is x+imm32
    buf_push(context->bytecode, 0x24); // x is rsp

    buf_push(context->bytecode, 0x00);
    unimplemented(); // TODO TODO TODO TODO put in proper stack offset

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov%u [stack %u], %s\n", (u64) (size*8), (u64) stack_item_index, reg_names[from_reg]);
    #endif
}

void write_mov_stack_to_reg(Context* context, u8 size, u32 stack_item_index, u8 to_reg) {
    assert(to_reg < 8); // otherwise we need to encode registers using rex.{r, x, b}

    switch (size) {
        case 1: {
            buf_push(context->bytecode, 0x8a);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, 0x8b);
        } break;
        case 4: {
            buf_push(context->bytecode, 0x8b);
        } break;
        case 8: {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0x8b);
        } break;
        default: assert(false);
    }

    buf_push(context->bytecode, 0x44 | (to_reg << 3)); // 0x44 is x+imm8, 0x84 is x+imm32
    buf_push(context->bytecode, 0x24); // x is rsp

    buf_push(context->bytecode, 0x00);
    unimplemented(); // TODO TODO TODO TODO put in proper stack offset

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov%u %s, [stack %u]\n", (u64) (size*8), reg_names[to_reg], (u64) stack_item_index);
    #endif
}

void write_lea_stack_to_reg(Context* context, u32 stack_item_index, u8 to_reg) {
    assert(to_reg < 8); // otherwise we need to encode registers using rex.{r, x, b}

    buf_push(context->bytecode, 0x48);
    buf_push(context->bytecode, 0x8d);
    buf_push(context->bytecode, 0x44 | (to_reg << 3)); // 0x44 is x+imm8, 0x84 is x+imm32
    buf_push(context->bytecode, 0x24); // x is rsp

    buf_push(context->bytecode, 0x00);
    unimplemented(); // TODO TODO TODO TODO put in proper stack offset

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("lea %s, [stack %u]\n", reg_names[to_reg], (u64) stack_item_index);
    #endif
}

void write_mov_reg_to_mem(Context* context, u8 size, u8 value_reg, u8 address_reg) {
    assert(value_reg < 8 && address_reg < 4); // otherwise we need to encode registers using rex.{r, x, b}

    switch (size) {
        case 1: {
            buf_push(context->bytecode, 0x88);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, 0x89);
        } break;
        case 4: {
            buf_push(context->bytecode, 0x89);
        } break;
        case 8: {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0x89);
        } break;
        default: assert(false);
    }

    buf_push(context->bytecode, (value_reg << 3) | (address_reg));

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov%u [%s], %s\n", (u64) (size*8), reg_names[address_reg], reg_names[value_reg]);
    #endif
}

void write_mov_mem_to_reg(Context* context, u8 size, u8 value_reg, u8 address_reg) {
    assert(value_reg < 8 && address_reg < 4); // otherwise we need to encode registers using rex.{r, x, b}

    switch (size) {
        case 1: {
            buf_push(context->bytecode, 0x8a);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, 0x8b);
        } break;
        case 4: {
            buf_push(context->bytecode, 0x8b);
        } break;
        case 8: {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0x8b);
        } break;
        default: assert(false);
    }

    buf_push(context->bytecode, (value_reg << 3) | (address_reg));

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mov%u %s, [%s]\n", (u64) (size*8), reg_names[value_reg], reg_names[address_reg]);
    #endif
}

void write_add_or_sub_lit_to_reg(Context* context, u8 size, bool add, u64 lit, u8 to_reg) {
    assert(to_reg < 8);

    switch (size) {
        case 1: {
            buf_push(context->bytecode, 0x80);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, 0x81);
        } break;
        case 4: {
            buf_push(context->bytecode, 0x81);
        } break;
        case 8: {
            panic("Can't add/sub a 64-bit literal on x64!\n");
        } break;
        default: assert(false);
    }
    buf_push(context->bytecode, (add? 0xc0 : 0xe8) | to_reg);
    write_lit(context, size, lit);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("%s%u %s, %u\n", add? "add" : "sub", (u64) (size*8), reg_names[to_reg], size_mask(size) & lit);
    #endif
}

void write_add_or_sub_reg_to_reg(Context* context, u8 size, bool add, u8 from_reg, u8 to_reg) {
    assert(from_reg < 8 && to_reg < 8);

    switch (size) {
        case 1: {
            buf_push(context->bytecode, add? 0x00 : 0x28);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, add? 0x01 : 0x29);
        } break;
        case 4: {
            buf_push(context->bytecode, add? 0x01 : 0x29);
        } break;
        case 8: {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, add? 0x01 : 0x29);
        } break;
        default: assert(false);
    }

    buf_push(context->bytecode, 0xc0 | (from_reg << 3) | to_reg);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("%s%u %s, %s\n", add? "add" : "sub", (u64) (size*8), reg_names[to_reg], reg_names[from_reg]);
    #endif
}

void write_unsigned_mul(Context* context, u8 size, u8 by_reg) {
    // remainder goes in rdx, multiplies rax by the value in the given register

    assert(by_reg < 8);
    assert(!context->regs[reg_rdx].used);

    switch (size) {
        case 1: {
            buf_push(context->bytecode, 0xf6);
        } break;
        case 2: {
            buf_push(context->bytecode, 0x66);
            buf_push(context->bytecode, 0xf7);
        } break;
        case 4: {
            buf_push(context->bytecode, 0xf7);
        } break;
        case 8: {
            buf_push(context->bytecode, 0x48);
            buf_push(context->bytecode, 0xf7);
        } break;
        default: assert(false);
    }
    buf_push(context->bytecode, 0xe0 | by_reg);

    #ifdef PRINT_GENERATED_INSTRUCTIONS
    printf("mul%u %s\n", (u64) (size*8), reg_names[by_reg]);
    #endif
}


u32 local_stack_item_index(Context* context, u8 size, Local local, bool allocate) {
    assert(local.kind != local_literal);

    u32 index = NO_STACK_SPACE_ALLOCATED;

    for (u32 i = 0; i < buf_length(context->stack_items); i += 1) {
        Stack_Item* stack_item = &context->stack_items[i];
        if (local_cmp(&stack_item->local, &local)) {
            switch (local.kind) {
                case local_temporary: {
                    stack_item->size = max(stack_item->size, size);
                } break;
                case local_variable: {
                    assert(stack_item->size == size);
                } break;
                case local_literal: assert(false);
                default: assert(false);
            }

            index = i;
            break;
        }
    }

    if (index == NO_STACK_SPACE_ALLOCATED && allocate) {
        index = buf_length(context->stack_items);
        buf_push(context->stack_items, ((Stack_Item) { .local = local, .size = size }));
    }

    return index;
}

void reg_deallocate(Context* context, u8 reg) {
    // TODO check if we need to deallocate the register at all, or if we can get away
    // with just overwriting it!
    // To do this, we need info about the last use of a certain variable/temporary.
    // To do this, we can just read ahead in the current ops list. Might not be terribly fast though...

    if (!context->regs[reg].used) return;
    context->regs[reg].used = false;

    Local local = context->regs[reg].local;
    u8 size = context->regs[reg].size;
    u32 stack_item_index = local_stack_item_index(context, size, local, true);
    write_mov_reg_to_stack(context, size, stack_item_index, reg);
}

void reg_allocate_into(Context* context, u8 size, Local local, u8 reg) {
    if (context->regs[reg].used && local_cmp(&context->regs[reg].local, &local)) {
        return;
    }

    reg_deallocate(context, reg);

    u8 old_reg = REG_BAD;
    for (u32 r = 0; r < REG_COUNT; r += 1) {
        if (context->regs[r].used && local_cmp(&context->regs[r].local, &local)) {
            old_reg = r;
            break;
        }
    }

    if (old_reg == REG_BAD) {
        u32 stack_item_index = local_stack_item_index(context, size, local, false);
        if (stack_item_index == NO_STACK_SPACE_ALLOCATED) {
            unimplemented(); // Is this case even legal? Doesn't it imply we are using an uninitialized variable
        } else {
            write_mov_stack_to_reg(context, size, stack_item_index, reg);
        }
    } else {
        write_mov_reg_to_reg(context, size, old_reg, reg);
        context->regs[old_reg].used = false;
    }

    context->regs[reg].used = true;
    context->regs[reg].alloc_time = context->time;
    context->regs[reg].local = local;
    context->regs[reg].size = size;
}

u8 reg_allocate(Context* context, u8 size, Local local) {
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
        if (context->regs[r].used && local_cmp(&context->regs[r].local, &local)) {
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
        context->regs[reg].alloc_time = context->time;
        context->regs[reg].local = local;
        context->regs[reg].size = size;

        u32 stack_item_index = local_stack_item_index(context, size, local, false);
        if (stack_item_index != NO_STACK_SPACE_ALLOCATED) {
            write_mov_stack_to_reg(context, size, stack_item_index, reg);
        }
    }

    return reg;
}

void op_write_machinecode(Context* context, Func* func, Op* op) {
    u8 flush = REG_BAD;

    // Binary operators
    switch (op->kind) {
        case op_set:
        case op_add:
        case op_sub:
        case op_mul:
        case op_div:
        {
            /*
            case op_read_pointer: {
                assert(op->binary.source.kind != local_literal);
                assert(op->binary.target.kind != local_literal);

                u8 operand_size = primitive_size_of(op->primitive);
                u8 value_reg = reg_allocate(context, operand_size, op->binary.target);
                u8 address_reg = reg_allocate(context, operand_size, op->binary.source);
                write_mov_mem_to_reg(context, operand_size, value_reg, address_reg);

                flush = value_reg;
            } break;

            case op_write_pointer: {
                assert(local_kind(op->binary.source) != local_literal);
                assert(local_kind(op->binary.target) != local_literal);

                u8 operand_size = primitive_size_of(op->primitive);
                u8 value_reg = reg_allocate(context, operand_size, op->binary.source);
                u8 address_reg = reg_allocate(context, operand_size, op->binary.target);
                write_mov_reg_to_mem(context, operand_size, value_reg, address_reg);
            } break;
            */

            unimplemented();

            u8 operand_size = primitive_size_of(op->primitive);

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
                    assert(op->binary.source.kind != local_literal);
                } break;

                case op_div: {
                    // Probably can be same as op_mul though, need to verify once we implement division properly
                    unimplemented();
                } break;

                default: assert(false);
            }

            // Allocate registers based on requirements
            u8 left_reg, right_reg;
            u64 right_literal;
            bool use_right_literal;

            if (left_must_be_eax) {
                left_reg = reg_rax;
                reg_allocate_into(context, operand_size, op->binary.target, left_reg);
            } else {
                left_reg = reg_allocate(context, operand_size, op->binary.target);
            }

            if (op->binary.source.kind == local_literal) {
                assert(!op->binary.source.as_reference);
                use_right_literal = true;
                right_literal = op->binary.source.value;
            } else {
                use_right_literal = false;
                right_reg = reg_allocate(context, operand_size, op->binary.source);
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
                        write_mov_lit_to_reg(context, operand_size, right_literal, left_reg);
                    } else {
                        write_mov_reg_to_reg(context, operand_size, right_reg, left_reg);
                    }
                } break;

                case op_add: {
                    if (use_right_literal) {
                        write_add_or_sub_lit_to_reg(context, operand_size, true, right_literal, left_reg);
                    } else {
                        write_add_or_sub_reg_to_reg(context, operand_size, true, right_reg, left_reg);
                    }
                } break;

                case op_sub: {
                    if (use_right_literal) {
                        write_add_or_sub_lit_to_reg(context, operand_size, false, right_literal, left_reg);
                    } else {
                        write_add_or_sub_reg_to_reg(context, operand_size, false, right_reg, left_reg);
                    }
                } break;

                case op_mul: {
                    assert(left_reg == reg_rax);
                    assert(!use_right_literal);
                    write_unsigned_mul(context, operand_size, right_reg);
                } break;

                case op_div: {
                    assert(left_reg == reg_rax);
                    assert(!use_right_literal);
                    unimplemented();
                } break;

                default: assert(false);
            }

            flush = left_reg;
        } break;

        case op_address_of: {
            unimplemented();

            u8 pointer_size = 8;
            u8 target_reg = reg_allocate(context, pointer_size, op->binary.target);

            Local source = op->binary.source;
            assert(source.kind == local_variable);
            Primitive operand_primitive = context->type_buf[func->vars[source.value].type_index];
            u8 operand_size = primitive_size_of(operand_primitive);
            u32 stack_item_index = local_stack_item_index(context, operand_size, source, false);

            // Implies we are taking the address of a uninitialized variable
            assert(stack_item_index != NO_STACK_SPACE_ALLOCATED);

            write_lea_stack_to_reg(context, stack_item_index, target_reg);

            flush = target_reg;
        } break;

        case op_call: {
            unimplemented();

            // TODO calling convention: Which registers do we need to deallocate

            // TODO we can avoid deallocating and reallocating here, if we deallocate
            // after punching in parameters
            for (u32 r = 0; r < REG_COUNT; r += 1) {
                reg_deallocate(context, r);
            }

            Func* callee = &context->funcs[op->call.func_index];
            for (u32 p = 0; p < callee->param_count; p += 1) {
                Local param_local = op->call.params[p].local;
                u8 param_size = op->call.params[p].size;

                if (p < 4) {
                    u8 param_reg;
                    switch (p) {
                        case 0: param_reg = reg_rcx; break;
                        case 1: param_reg = reg_rdx; break;
                        case 2: unimplemented(); break; // r8
                        case 3: unimplemented(); break; // r9
                        default: assert(false);
                    }

                    if (param_local.kind == local_literal) {
                        assert(!param_local.as_reference);
                        u64 literal = param_local.value;
                        write_mov_lit_to_reg(context, param_size, literal, param_reg);
                    } else {
                        reg_allocate_into(context, param_size, param_local, param_reg);
                        context->regs[param_reg].used = false;
                    }
                } else {
                    // TODO Parameters go on the stack
                
                    // TODO we need to reserve stack space for parameters, even if we only
                    // pass parameters via registers.
                    unimplemented();
                }
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

            assert(!context->regs[reg_rax].used);
            context->regs[reg_rax] = (Reg) {
                .used = true,
                .alloc_time = context->time,
                .local = op->call.target,
                .size = primitive_size_of(op->primitive)
            };
            flush = reg_rax;
        } break;

        case op_cast: {
            unimplemented();

            u8 new_size = primitive_size_of(op->primitive);
            u8 old_size = primitive_size_of(op->cast.old_primitive);

            if (new_size > old_size) {
                u8 reg = reg_allocate(context, old_size, op->cast.local);
                write_zero_extend(context, old_size, new_size, reg);
                context->regs[reg].size = new_size;
                flush = reg;
            }
        } break;

        case op_reset_temporary: {
            for (u32 r = 0; r < REG_COUNT; r += 1) {
                Local local = context->regs[r].local;
                if (context->regs[r].used && local.kind == local_temporary && local.value == op->temporary) {
                    context->regs[r] = (Reg) {0};
                }
            }
        } break;


        default: assert(false);
    }

    if (flush != REG_BAD && context->regs[flush].local.kind == local_variable) {
        reg_deallocate(context, flush);
    }
}
