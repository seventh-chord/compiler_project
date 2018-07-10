
Notes on x64 (not x86). Mostly based on intel manuals.

# Memory layout
Little endian
A memory address points to the least significant bytes.
The rest of a value lies at higher memory addresses.

# Registers

     |  0   1   2   3
  ---+----------------
   0 | RAX RCX RDX RBX
   4 | RSP RBP RSI RDI
   8 | R8  R9  R10 R11
   c | R12 R13 R14 R15

The eight higher registers can only be encoded using the REX byte.

# Operand size prefix
Instructions have 32-bit and 8-bit variants.
Prefixes can be used on the 32-bit variants:
0x66    16-bit mode instead of 32-bit mode
REX.W   64-bit mode instead of 32-bit mode

# ModRM and SIB
Bitwise layout:
  ModRM:
    mod     7, 6,
    reg           5, 4, 3,
    r/m                    2, 1, 0
  SIB:
    scale   7, 6,
    index         5, 4, 3,
    base                   2, 1, 0

'reg' can only specify a register
Based on the value of 'mod', 'r/m' can either reference a register or a memory location.
When a displacement (8-bit or 32-bit) is given, this appears after the SIB and the ModRM
byte, but _before_ any immediate byte.

 'mod'
  00   
        Access memory pointed to by register 'r/m', except when:
        'r/m' is 100 (rsp), then a SIB byte alone decides the memory location.
        'r/m' is 101 (rbp), then rip + 32-bit signed displacement is used.
  01   
        Same as 00, but an 8-bit signed displacement is added to the address, except when:
        'r/m' is 101, then rbp plus the displacement is used.
  10   
        Same as 01, but with a 32-bit displacement.
  11   
        Use the value in the register given by 'r/m'

A SIB byte is used when ('mod' != 11, 'r/m' == 100).
It is used for more complex addressing calculations.
It is encoded as follows.
    'index' selects a register (except when it's 100, then the literal 0 is used).
    'scale' is a literal value.
    'base' selects a second register (except when it's 101 (rbp), then special rules apply).
The memory location is then computed as:
    index * 2^scale + base
Remember that a 8/32-bit displacement is added if 'mod' is 01 or 10.

# REX
After any prefixes, just before the opcode
You can only have one REX prefix

Single byte:    0 1 0 0 W R X B
W   Use 64-bit operands
R   Extends ModRM reg
X   Extends SIB index
B   Extends ModRM rm, SIB base or opcode reg

R, X and B extend 3-bit fields, adding a MSB. Used (only?) to encode 8 extra registers

Use cases: (ignoring REX.W, it can be used independently)
Just ModRM:             R and B used. B used for ModRM rm.
ModRM and SIB:          R, X and B used. B used for SIB base.
Extendable opcode:      B used. Opcode tables show when this is relevant.

# Flags
CF  Carry flag
PF  Parity flag
ZF  Zero flag
SF  Sign flag
OF  Overflow flag

# Stack
'rsp' points to the stack
No segment selectors are used in x64, the manual mentions them because it was written for x86

The stack grows towards lower addresses.
=> 'sub rsp, ...' when entering a function, 'add rsp, ...' when leaving.

'call' pushes return 'rip' (64-bits) onto the stack, then branches.
'ret' pops return 'rip' and branches back.
Relative offsets are sign-extended and added to 'rip'.

# Calling convention
(Somewhat sketchy old notes, probably revise these...)
win32 functions are __stdcall, but that is ignored in x64

First four parameters go in registers, depending on type:
     rcx  xmm0
     rdx  xmm1
     r8   xmm2
     r9   xmm3
Larger types are passed as pointers to caller-allocated memory
Caller-allocated memory must be 16-byte alligned
Values are returned in rax or xmm0 if they fit

## Return values
Compound types can be squished into RAX or returned by reference.
Only structures which are 1, 2, 4 or 8 bytes large can be returned in RAX (A lot of other rules
apply to this in the windows spec, but those rules all pertain to c++ nonsense which we don't have
to care about in a c-like language).
When we can't return in RAX, we return "by reference" (what I refer to as reference semantics in code).
When returning by reference, the following change of function signature effectively happens:
    fn f(a, b: u32) -> Foo
    fn f(_: *Foo, a, b: u32) -> *Foo
Here, the caller allocates space for the return value and passes it as the first parameter (in RCX)
and the callee returns the same pointer in RAX.

Voltatile registers can be overwritten by the callee, invalidating their previous
values. Nonvolatile registers must remain constant across function calls.
Volatile         rax rcx rdx  r8  r9 r10 r11
Nonvoltatile     rbx rbp rdi rsi rsp r12 r13 r14 r15

Caller must allocate stack space for all passed parameters, even though the first
four parameters always go in registers rather than on the stack. Space for at least
four parameters must be allocated!

The stack grows downwards
rsp points to the bottom of the stack
rsp must be 16 byte aligned after 'call' is executed
'call' pushes return rip (8 bytes)

# General purpose instructions
Not comprehensive!!

MOV         Move
MOVSX       Move and sign extend.
MOVZX       Move and zero extend.
CMOV        Conditional move, lots of variants
CWD/CDQ     Convert word to doubleword/Convert doubleword to quadword.
CBW/CWDE    Convert byte to word/Convert word to doubleword in EAX register.
PUSH        Push onto stack.
POP         Pop off of stack.

LEA         Do address computation, but return address rather than value at address.
NOP         No operation.
CPUID       Gets processor info.

JMP         Jump. Also, see conditional variants.
LOOP        Loop, uses 'ecx' as counter.
CALL, RET   See calling convention.
INT         Softwarre interrupt.
INTO        Interrupt on overflow.
BOUND       Detect value out of range.

ADCX        Unsigned integer add with carry.
ADOX        Unsigned integer add with overflow.
ADD         Integer add.
ADC         Add with carry.
SUB         Subtract.
SBB         Subtract with borrow.
IMUL        Signed multiply.
MUL         Unsigned multiply.
IDIV        Signed divide.
DIV         Unsigned divide.
INC         Increment.
DEC         Decrement.
NEG         Negate.
CMP         Compare.

AND         Bitwise AND.
OR          Bitwise OR.
XOR         Bitwise XOR.
NOT         Bitwise NOT.
More bitwise instructions in intel_introduction.pdf, 5.1.16 and 5.1.6

SAR         Shift arithmetic right.
SHR         Shift logical right.
SAL/SHL     Shift arithmetic left/Shift logical left.
SHRD        Shift right double.
SHLD        Shift left double.
ROR         Rotate right.
ROL         Rotate left.
RCR         Rotate through carry right.
RCL         Rotate through carry left.

PREFETCHW   Prefetches data into cache, when we anticipate a write.
CLFLUSH     Flushes and invalidates cache.
