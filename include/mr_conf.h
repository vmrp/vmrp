
#ifndef mr_config_h
#define mr_config_h

#include "../src/mr_limits.h"


/*
** {======================================================
** Index (search for keyword to find corresponding entry)
** =======================================================
*/


/* }====================================================== */




/*
** {======================================================
** Generic configuration
** =======================================================
*/

/* default path */
#define MRP_PATH_DEFAULT	"?;?.mr"


/* type of numbers in Lua */
#define MRP_NUMBER	double

/* formats for Lua numbers */
#define MRP_NUMBER_SCAN		"%lf"
#define MRP_NUMBER_FMT		"%.14g"


/* type for integer functions */
#define MRP_INTEGER	long


/* mark for all API functions */
#define MRP_API		extern

/* mark for auxlib functions */
#define MRPLIB_API      extern

/* buffer size used by lauxlib buffer system */
#define MRP_L_BUFFERSIZE   BUFSIZ


/* first index for arrays */
#define MRP_FIRSTINDEX		1

/* assertions in Lua (mainly for internal debugging) */
#define mrp_assert(c)		((void)0)

/* }====================================================== */



/*
** {======================================================
** Stand-alone configuration
** =======================================================
*/

#ifdef mrp_c

/* definition of `isatty' */
#ifdef _POSIX_C_SOURCE
#define stdin_is_tty()		isatty(0)
#else
#define stdin_is_tty()		1  /* assume stdin is a tty */
#endif


#define PROMPT		"> "
#define PROMPT2		">> "
#define PROGNAME	"mr"


/*
** this macro allows you to open other libraries when starting the
** stand-alone interpreter
*/
#define mrp_userinit(L)		mrp_open_stdlibs(L)
/*
** #define mrp_userinit(L)  { int mrp_open_mylibs(mrp_State *L); \
**				mrp_open_stdlibs(L); mrp_open_mylibs(L); }
*/



/*
** this macro can be used by some `history' system to save lines
** read in manual input
*/
#define mrp_saveline(L,line)	/* empty */



#endif

/* }====================================================== */



/*
** {======================================================
** Core configuration
** =======================================================
*/

#ifdef MRP_CORE

/* LUA-C API assertions */
#define api_check(L, o)		mrp_assert(o)


/* an unsigned integer with at least 32 bits */
#define MRP_UINT32	unsigned long

/* a signed integer with at least 32 bits */
#define MRP_INT32	long
#define MRP_MAXINT32	LONG_MAX


/* maximum depth for calls (unsigned short) */
#define MRP_MAXCALLS	2048

/*
** maximum depth for C calls (unsigned short): Not too big, or may
** overflow the C stack...
*/
#define MRP_MAXCCALLS	100


/* maximum size for the virtual stack of a C function */
#define MAXCSTACK	2048


/*
** maximum number of syntactical nested non-terminals: Not too big,
** or may overflow the C stack...
*/
#define MRP_MAXPARSERLEVEL	200


/* maximum number of variables declared in a function */
#define MAXVARS	200		/* <MAXSTACK */


/* maximum number of upvalues per function */
#define MAXUPVALUES		32	/* <MAXSTACK */


/* maximum size of expressions for optimizing `while' code */
#define MAXEXPWHILE		100


/* function to convert a mrp_Number to int (with any rounding method) */
#if defined(__GNUC__) && defined(__i386)
#define mrp_number2int(i,d)	__asm__ ("fistpl %0":"=m"(i):"t"(d):"st")
#elif 0
/* on machines compliant with C99, you can try `lrint' */
#define mrp_number2int(i,d)	((i)=lrint(d))
#else
#define mrp_number2int(i,d)	((i)=(int)(d))
#endif

/* function to convert a mrp_Number to mrp_Integer (with any rounding method) */
#define mrp_number2integer(i,n)		mrp_number2int(i,n)


/* function to convert a mrp_Number to a string */
#define mrp_number2str(s,n)	sprintf((s), MRP_NUMBER_FMT, (n))

/* function to convert a string to a mrp_Number */
#define mrp_str2number(s,p)	strtod((s), (p))



/* result of a `usual argument conversion' over mrp_Number */
#define MRP_UACNUMBER	double


/* number of bits in an `int' */
/* avoid overflows in comparison */
#if INT_MAX-20 < 32760
#define MRP_BITSINT	16
#elif INT_MAX > 2147483640L
/* machine has at least 32 bits */
#define MRP_BITSINT	32
#else
#error "you must define MRP_BITSINT with number of bits in an integer"
#endif


/* type to ensure maximum alignment */
#define LUSER_ALIGNMENT_T	union { double u; void *s; long l; }


/* exception handling */
#ifndef __cplusplus
/* default handling with long jumps */
#define L_THROW(c)	longjmp((c)->b, 1)
#define L_TRY(c,a)	if (setjmp((c)->b) == 0) { a }
#define l_jmpbuf	jmp_buf

#else
/* C++ exceptions */
#define L_THROW(c)	throw(c)
#define L_TRY(c,a)	try { a } catch(...) \
	{ if ((c)->status == 0) (c)->status = -1; }
#define l_jmpbuf	int  /* dummy variable */
#endif



/*
** macros for thread synchronization inside Lua core machine:
** all accesses to the global state and to global objects are synchronized.
** Because threads can read the stack of other threads
** (when running garbage collection),
** a thread must also synchronize any write-access to its own stack.
** Unsynchronized accesses are allowed only when reading its own stack,
** or when reading immutable fields from global objects
** (such as string values and udata values).
*/
#define mrp_lock(L)     ((void) 0)
#define mrp_unlock(L)   ((void) 0)

/*
** this macro allows a thread switch in appropriate places in the Lua
** core
*/
#define mrp_threadyield(L)	{mrp_unlock(L); mrp_lock(L);}



/* allows user-specific initialization on new threads */
#define mrp_userstateopen(l)	/* empty */


#endif

/* }====================================================== */



/*
** {======================================================
** Library configuration
** =======================================================
*/

#ifdef MRP_LIB



/* `assert' options */

/* environment variable that holds the search path for packages */
#define MRP_PATH	"MR_PATH"

/* separator of templates in a path */
#define MRP_PATH_SEP	';'

/* wild char in each template */
#define MRP_PATH_MARK	"?"


/* maximum number of captures in pattern-matching */
#define MAX_CAPTURES	32  /* arbitrary limit */


/*
** by default, gcc does not get `tmpname'
*/ 
#ifdef __GNUC__
#define USE_TMPNAME	0
#else
#define USE_TMPNAME	1 
#endif



#endif

/* }====================================================== */




/* Local configuration */

#undef USE_TMPNAME
#define USE_TMPNAME	1

#endif
