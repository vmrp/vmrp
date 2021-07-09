
#ifndef mr_opcodes_h
#define mr_opcodes_h

#include "mr_limits.h"

/*===========================================================================
  We assume that instructions are unsigned numbers.
  All instructions have an opcode in the first 6 bits.
  Instructions can have the following fields:
	`A' : 8 bits
	`B' : 9 bits
	`C' : 9 bits
	`Bx' : 18 bits (`B' and `C' together)
	`sBx' : signed Bx

  A signed argument is represented in excess K; that is, the number
  value is the unsigned value minus K. K is exactly the maximum value
  for that argument (so that -max is represented by 0, and +max is
  represented by 2*max), which is half the maximum for the corresponding
  unsigned argument.
===========================================================================*/

/* basic instruction format */
enum OpMode {
    iABC,
    iABx,
    iAsBx
};

/*
** size and position of opcode arguments.
*/
#define SIZE_C 9
#define SIZE_B 9
#define SIZE_Bx (SIZE_C + SIZE_B)
#define SIZE_A 8

#define SIZE_OP 6

#define POS_C SIZE_OP
#define POS_B (POS_C + SIZE_C)
#define POS_Bx POS_C
#define POS_A (POS_B + SIZE_B)

/*
** limits for opcode arguments.
** we use (signed) int to manipulate most arguments,
** so they must fit in BITS_INT-1 bits (-1 for sign)
*/
#if SIZE_Bx < BITS_INT - 1
#define MAXARG_Bx ((1 << SIZE_Bx) - 1)
#define MAXARG_sBx (MAXARG_Bx >> 1) /* `sBx' is signed */
#else
#define MAXARG_Bx MAX_INT
#define MAXARG_sBx MAX_INT
#endif

#define MAXARG_A ((1 << SIZE_A) - 1)
#define MAXARG_B ((1 << SIZE_B) - 1)
#define MAXARG_C ((1 << SIZE_C) - 1)

/* creates a mask with `n' 1 bits at position `p' */
#define MASK1(n, p) ((~((~(Instruction)0) << n)) << p)

/* creates a mask with `n' 0 bits at position `p' */
#define MASK0(n, p) (~MASK1(n, p))

/*
** the following macros help to manipulate instructions
*/

// 因为MASK1会在编译阶段出现警告，所以采用预先计算出来的值

// #define GET_OPCODE(i)	(cast(OpCode, (i)&MASK1(SIZE_OP,0)))
#define GET_OPCODE(i) (cast(OpCode, (i)&0x3F))  // MASK1(SIZE_OP,0):0x3F

// #define SET_OPCODE(i,o)	((i) = (((i)&MASK0(SIZE_OP,0)) | cast(Instruction, o)))
#define SET_OPCODE(i, o) ((i) = (((i)&0xFFFFFFC0) | cast(Instruction, o)))  // MASK0(SIZE_OP,0):0xFFFFFFC0

#define GETARG_A(i) (cast(int, (i) >> POS_A))

// #define SETARG_A(i,u)	((i) = (((i)&MASK0(SIZE_A,POS_A)) | ((cast(Instruction, u)<<POS_A)&MASK1(SIZE_A,POS_A))))
#define SETARG_A(i, u) ((i) = (((i)&0xFFFFFF) | ((cast(Instruction, u) << POS_A) & 0xFF000000)))  // MASK0(SIZE_A,POS_A):0xFFFFFF  MASK1(SIZE_A,POS_A):0xFF000000

// #define GETARG_B(i)	(cast(int, ((i)>>POS_B) & MASK1(SIZE_B,0)))
#define GETARG_B(i) (cast(int, ((i) >> POS_B) & 0x1FF))  // MASK1(SIZE_B,0):0x1FF

// #define SETARG_B(i,b)	((i) = (((i)&MASK0(SIZE_B,POS_B)) | ((cast(Instruction, b)<<POS_B)&MASK1(SIZE_B,POS_B))))
#define SETARG_B(i, b) ((i) = (((i)&0xFF007FFF) | ((cast(Instruction, b) << POS_B) & 0xFF8000)))  // MASK0(SIZE_B,POS_B):0xFF007FFF   MASK1(SIZE_B,POS_B):0xFF8000

// #define GETARG_C(i)	(cast(int, ((i)>>POS_C) & MASK1(SIZE_C,0)))
#define GETARG_C(i) (cast(int, ((i) >> POS_C) & 0x1FF))  // MASK1(SIZE_C,0):0x1FF

// #define SETARG_C(i,b)	((i) = (((i)&MASK0(SIZE_C,POS_C)) | ((cast(Instruction, b)<<POS_C)&MASK1(SIZE_C,POS_C))))
#define SETARG_C(i, b) ((i) = (((i)&0xFFFF803F) | ((cast(Instruction, b) << POS_C) & 0x7FC0)))  // MASK0(SIZE_C,POS_C):0xFFFF803F   MASK1(SIZE_C,POS_C):0x7FC0

// #define GETARG_Bx(i)	(cast(int, ((i)>>POS_Bx) & MASK1(SIZE_Bx,0)))
#define GETARG_Bx(i) (cast(int, ((i) >> POS_Bx) & 0x3FFFF))  // MASK1(SIZE_Bx,0):0x3FFFF

// #define SETARG_Bx(i,b)	((i) = (((i)&MASK0(SIZE_Bx,POS_Bx)) | ((cast(Instruction, b)<<POS_Bx)&MASK1(SIZE_Bx,POS_Bx))))
#define SETARG_Bx(i, b) ((i) = (((i)&0xFF00003F) | ((cast(Instruction, b) << POS_Bx) & 0xFFFFC0)))  // MASK0(SIZE_Bx,POS_Bx):0xFF00003F   MASK1(SIZE_Bx,POS_Bx):0xFFFFC0

#define GETARG_sBx(i) (GETARG_Bx(i) - MAXARG_sBx)
#define SETARG_sBx(i, b) SETARG_Bx((i), cast(unsigned int, (b) + MAXARG_sBx))

#define CREATE_ABC(o, a, b, c) (cast(Instruction, o) | (cast(Instruction, a) << POS_A) | (cast(Instruction, b) << POS_B) | (cast(Instruction, c) << POS_C))

#define CREATE_ABx(o, a, bc) (cast(Instruction, o) | (cast(Instruction, a) << POS_A) | (cast(Instruction, bc) << POS_Bx))

/*
** invalid register that fits in 8 bits
*/
#define NO_REG MAXARG_A

/*
** R(x) - register
** Kst(x) - constant (in constant table)
** RK(x) == if x < MAXSTACK then R(x) else Kst(x-MAXSTACK)
*/

/*
** grep "ORDER OP" if you change these enums
*/

typedef enum {
    /*----------------------------------------------------------------------
name		args	description
------------------------------------------------------------------------*/
    OP_MOVE,     /*	A B	R(A) := R(B)					*/
    OP_LOADK,    /*	A Bx	R(A) := Kst(Bx)					*/
    OP_LOADBOOL, /*	A B C	R(A) := (Bool)B; if (C) PC++			*/
    OP_LOADNIL,  /*	A B	R(A) := ... := R(B) := nil			*/
    OP_GETUPVAL, /*	A B	R(A) := UpValue[B]				*/

    OP_GETGLOBAL, /*	A Bx	R(A) := Gbl[Kst(Bx)]				*/
    OP_GETTABLE,  /*	A B C	R(A) := R(B)[RK(C)]				*/

    OP_SETGLOBAL, /*	A Bx	Gbl[Kst(Bx)] := R(A)				*/
    OP_SETUPVAL,  /*	A B	UpValue[B] := R(A)				*/
    OP_SETTABLE,  /*	A B C	R(A)[RK(B)] := RK(C)				*/

    OP_NEWTABLE, /*	A B C	R(A) := {} (size = B,C)				*/

    OP_SELF, /*	A B C	R(A+1) := R(B); R(A) := R(B)[RK(C)]		*/

    OP_ADD, /*	A B C	R(A) := RK(B) + RK(C)				*/
    OP_SUB, /*	A B C	R(A) := RK(B) - RK(C)				*/
    OP_MUL, /*	A B C	R(A) := RK(B) * RK(C)				*/
    OP_DIV, /*	A B C	R(A) := RK(B) / RK(C)				*/
    OP_POW, /*	A B C	R(A) := RK(B) ^ RK(C)				*/
    OP_UNM, /*	A B	R(A) := -R(B)					*/
    OP_NOT, /*	A B	R(A) := not R(B)				*/

    OP_CONCAT, /*	A B C	R(A) := R(B).. ... ..R(C)			*/

    OP_JMP, /*	sBx	PC += sBx					*/

    OP_EQ, /*	A B C	if ((RK(B) == RK(C)) ~= A) then pc++		*/
    OP_LT, /*	A B C	if ((RK(B) <  RK(C)) ~= A) then pc++  		*/
    OP_LE, /*	A B C	if ((RK(B) <= RK(C)) ~= A) then pc++  		*/

    OP_TEST, /*	A B C	if (R(B) <=> C) then R(A) := R(B) else pc++	*/

    OP_CALL,     /*	A B C	R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
    OP_TAILCALL, /*	A B C	return R(A)(R(A+1), ... ,R(A+B-1))		*/
    OP_RETURN,   /*	A B	return R(A), ... ,R(A+B-2)	(see note)	*/

    OP_FORLOOP, /*	A sBx	R(A)+=R(A+2); if R(A) <?= R(A+1) then PC+= sBx	*/

    OP_TFORLOOP, /*	A C	R(A+2), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2)); 
                        if R(A+2) ~= nil then pc++			*/
    OP_TFORPREP, /*	A sBx	if type(R(A)) == table then R(A+1):=R(A), R(A):=next;
			PC += sBx					*/

    OP_SETLIST,  /*	A Bx	R(A)[Bx-Bx%FPF+i] := R(A+i), 1 <= i <= Bx%FPF+1	*/
    OP_SETLISTO, /*	A Bx							*/

    OP_CLOSE, /*	A 	close all variables in the stack up to (>=) R(A)*/
#if 0
OP_CLOSURE/*	A Bx	R(A) := closure(KPROTO[Bx], R(A), ... ,R(A+n))	*/
#else
    OP_CLOSURE, /* A Bx  R(A) := closure(KPROTO[Bx], R(A), ... ,R(A+n))  */
    OP_BNOT,    /* A B     R(A) := bitwise-complement R(B) */
    OP_BAND,    /* A B C   R(A) := R(B) bitwise-and R(C) */
    OP_BOR,     /* A B C   R(A) := R(B) bitwise-or  R(C) */
    OP_BXOR     /* A B C   R(A) := R(B) bitwise-xor R(C) */
#endif

} OpCode;

#if 0
#define NUM_OPCODES (cast(int, OP_CLOSURE + 1))
#else
#define NUM_OPCODES (cast(int, OP_BXOR + 1))
#endif

/*===========================================================================
  Notes:
  (1) In OP_CALL, if (B == 0) then B = top. C is the number of returns - 1,
      and can be 0: OP_CALL then sets `top' to last_result+1, so
      next open instruction (OP_CALL, OP_RETURN, OP_SETLIST) may use `top'.

  (2) In OP_RETURN, if (B == 0) then return up to `top'

  (3) For comparisons, B specifies what conditions the test should accept.

  (4) All `skips' (pc++) assume that next instruction is a jump
===========================================================================*/

/*
** masks for instruction properties
*/
enum OpModeMask {
    OpModeBreg = 2, /* B is a register */
    OpModeBrk,      /* B is a register/constant */
    OpModeCrk,      /* C is a register/constant */
    OpModesetA,     /* instruction set register A */
    OpModeK,        /* Bx is a constant */
    OpModeT         /* operator is a test */

};

extern const lu_byte mr_P_opmodes[NUM_OPCODES];

#define getOpMode(m) (cast(enum OpMode, mr_P_opmodes[m] & 3))
#define testOpMode(m, b) (mr_P_opmodes[m] & (1 << (b)))

#ifdef MRP_OPNAMES
extern const char *mr_P_opnames[]; /* opcode names */
void init_mr_opcodes(void);
#endif

/* number of list items to accumulate before a SETLIST instruction */
/* (must be a power of 2) */
#define LFIELDS_PER_FLUSH 32

#endif
