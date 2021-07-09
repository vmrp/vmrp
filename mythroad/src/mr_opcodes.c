

//#define lopcodes_c


#include "./h/mr_object.h"
#include "./h/mr_opcodes.h"

#ifdef MRP_OPNAMES

const char *mr_P_opnames[39];

void init_mr_opcodes(void) {
  mr_P_opnames[0] = "MOVE";
  mr_P_opnames[1] = "LOADK";
  mr_P_opnames[2] = "LOADBOOL";
  mr_P_opnames[3] = "LOADNIL";
  mr_P_opnames[4] = "GETUPVAL";
  mr_P_opnames[5] = "GETGLOBAL";
  mr_P_opnames[6] = "GETTABLE";
  mr_P_opnames[7] = "SETGLOBAL";
  mr_P_opnames[8] = "SETUPVAL";
  mr_P_opnames[9] = "SETTABLE";
  mr_P_opnames[10] = "NEWTABLE";
  mr_P_opnames[11] = "SELF";
  mr_P_opnames[12] = "ADD";
  mr_P_opnames[13] = "SUB";
  mr_P_opnames[14] = "MUL";
  mr_P_opnames[15] = "DIV";
  mr_P_opnames[16] = "POW";
  mr_P_opnames[17] = "UNM";
  mr_P_opnames[18] = "NOT";
  mr_P_opnames[19] = "CONCAT";
  mr_P_opnames[20] = "JMP";
  mr_P_opnames[21] = "EQ";
  mr_P_opnames[22] = "LT";
  mr_P_opnames[23] = "LE";
  mr_P_opnames[24] = "TEST";
  mr_P_opnames[25] = "CALL";
  mr_P_opnames[26] = "TAILCALL";
  mr_P_opnames[27] = "RETURN";
  mr_P_opnames[28] = "FORLOOP";
  mr_P_opnames[29] = "TFORLOOP";
  mr_P_opnames[30] = "TFORPREP";
  mr_P_opnames[31] = "SETLIST";
  mr_P_opnames[32] = "SETLISTO";
  mr_P_opnames[33] = "CLOSE";
#if 0
  mr_P_opnames[34] = "CLOSURE";
#else
  mr_P_opnames[34] = "CLOSURE";
  mr_P_opnames[35] = "BITNOT";
  mr_P_opnames[36] = "BITAND";
  mr_P_opnames[37] = "BITOR";
  mr_P_opnames[38] = "BITXOR";
#endif
}

#endif

#define opmode(t,b,bk,ck,sa,k,m) (((t)<<OpModeT) | \
   ((b)<<OpModeBreg) | ((bk)<<OpModeBrk) | ((ck)<<OpModeCrk) | \
   ((sa)<<OpModesetA) | ((k)<<OpModeK) | (m))


const lu_byte mr_P_opmodes[NUM_OPCODES] = {
/*       T  B Bk Ck sA  K  mode			   opcode    */
  opmode(0, 1, 0, 0, 1, 0, iABC)		/* OP_MOVE */
 ,opmode(0, 0, 0, 0, 1, 1, iABx)		/* OP_LOADK */
 ,opmode(0, 0, 0, 0, 1, 0, iABC)		/* OP_LOADBOOL */
 ,opmode(0, 1, 0, 0, 1, 0, iABC)		/* OP_LOADNIL */
 ,opmode(0, 0, 0, 0, 1, 0, iABC)		/* OP_GETUPVAL */
 ,opmode(0, 0, 0, 0, 1, 1, iABx)		/* OP_GETGLOBAL */
 ,opmode(0, 1, 0, 1, 1, 0, iABC)		/* OP_GETTABLE */
 ,opmode(0, 0, 0, 0, 0, 1, iABx)		/* OP_SETGLOBAL */
 ,opmode(0, 0, 0, 0, 0, 0, iABC)		/* OP_SETUPVAL */
 ,opmode(0, 0, 1, 1, 0, 0, iABC)		/* OP_SETTABLE */
 ,opmode(0, 0, 0, 0, 1, 0, iABC)		/* OP_NEWTABLE */
 ,opmode(0, 1, 0, 1, 1, 0, iABC)		/* OP_SELF */
 ,opmode(0, 0, 1, 1, 1, 0, iABC)		/* OP_ADD */
 ,opmode(0, 0, 1, 1, 1, 0, iABC)		/* OP_SUB */
 ,opmode(0, 0, 1, 1, 1, 0, iABC)		/* OP_MUL */
 ,opmode(0, 0, 1, 1, 1, 0, iABC)		/* OP_DIV */
 ,opmode(0, 0, 1, 1, 1, 0, iABC)		/* OP_POW */
 ,opmode(0, 1, 0, 0, 1, 0, iABC)		/* OP_UNM */
 ,opmode(0, 1, 0, 0, 1, 0, iABC)		/* OP_NOT */
 ,opmode(0, 1, 0, 1, 1, 0, iABC)		/* OP_CONCAT */
 ,opmode(0, 0, 0, 0, 0, 0, iAsBx)		/* OP_JMP */
 ,opmode(1, 0, 1, 1, 0, 0, iABC)		/* OP_EQ */
 ,opmode(1, 0, 1, 1, 0, 0, iABC)		/* OP_LT */
 ,opmode(1, 0, 1, 1, 0, 0, iABC)		/* OP_LE */
 ,opmode(1, 1, 0, 0, 1, 0, iABC)		/* OP_TEST */
 ,opmode(0, 0, 0, 0, 0, 0, iABC)		/* OP_CALL */
 ,opmode(0, 0, 0, 0, 0, 0, iABC)		/* OP_TAILCALL */
 ,opmode(0, 0, 0, 0, 0, 0, iABC)		/* OP_RETURN */
 ,opmode(0, 0, 0, 0, 0, 0, iAsBx)		/* OP_FORLOOP */
 ,opmode(1, 0, 0, 0, 0, 0, iABC)		/* OP_TFORLOOP */
 ,opmode(0, 0, 0, 0, 0, 0, iAsBx)		/* OP_TFORPREP */
 ,opmode(0, 0, 0, 0, 0, 0, iABx)		/* OP_SETLIST */
 ,opmode(0, 0, 0, 0, 0, 0, iABx)		/* OP_SETLISTO */
 ,opmode(0, 0, 0, 0, 0, 0, iABC)		/* OP_CLOSE */
 ,opmode(0, 0, 0, 0, 1, 0, iABx)		/* OP_CLOSURE */
#if 1
 ,opmode(0, 1, 0, 0, 1, 0, iABC)      /* OP_BNOT */
 ,opmode(0, 0, 1, 1, 1, 0, iABC)      /* OP_BAND */
 ,opmode(0, 0, 1, 1, 1, 0, iABC)      /* OP_BOR */
 ,opmode(0, 0, 1, 1, 1, 0, iABC)      /* OP_BXOR */
#endif
};

