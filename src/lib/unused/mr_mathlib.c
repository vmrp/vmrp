


//#define lmathlib_c

#include "mr.h"

#include "mr_auxlib.h"
#include "mr_lib.h"


#undef PI
#define PI (3.14159265358979323846)
#define RADIANS_PER_DEGREE (PI/180.0)



/*
** If you want Lua to operate in degrees (instead of radians),
** define USE_DEGREES
*/
#ifdef USE_DEGREES
#define FROMRAD(a)	((a)/RADIANS_PER_DEGREE)
#define TORAD(a)	((a)*RADIANS_PER_DEGREE)
#else
#define FROMRAD(a)	(a)
#define TORAD(a)	(a)
#endif


static int math_abs (mrp_State *L) {
  mrp_pushnumber(L, fabs(mr_L_checknumber(L, 1)));
  return 1;
}

static int math_sin (mrp_State *L) {
  mrp_pushnumber(L, sin(TORAD(mr_L_checknumber(L, 1))));
  return 1;
}

static int math_cos (mrp_State *L) {
  mrp_pushnumber(L, cos(TORAD(mr_L_checknumber(L, 1))));
  return 1;
}

static int math_tan (mrp_State *L) {
  mrp_pushnumber(L, tan(TORAD(mr_L_checknumber(L, 1))));
  return 1;
}

static int math_asin (mrp_State *L) {
  mrp_pushnumber(L, FROMRAD(asin(mr_L_checknumber(L, 1))));
  return 1;
}

static int math_acos (mrp_State *L) {
  mrp_pushnumber(L, FROMRAD(acos(mr_L_checknumber(L, 1))));
  return 1;
}

static int math_atan (mrp_State *L) {
  mrp_pushnumber(L, FROMRAD(atan(mr_L_checknumber(L, 1))));
  return 1;
}

static int math_atan2 (mrp_State *L) {
  mrp_pushnumber(L, FROMRAD(atan2(mr_L_checknumber(L, 1), mr_L_checknumber(L, 2))));
  return 1;
}

static int math_ceil (mrp_State *L) {
  mrp_pushnumber(L, ceil(mr_L_checknumber(L, 1)));
  return 1;
}

static int math_floor (mrp_State *L) {
  mrp_pushnumber(L, floor(mr_L_checknumber(L, 1)));
  return 1;
}

static int math_mod (mrp_State *L) {
  mrp_pushnumber(L, fmod(mr_L_checknumber(L, 1), mr_L_checknumber(L, 2)));
  return 1;
}

static int math_sqrt (mrp_State *L) {
  mrp_pushnumber(L, sqrt(mr_L_checknumber(L, 1)));
  return 1;
}

static int math_pow (mrp_State *L) {
  mrp_pushnumber(L, pow(mr_L_checknumber(L, 1), mr_L_checknumber(L, 2)));
  return 1;
}

static int math_log (mrp_State *L) {
  mrp_pushnumber(L, log(mr_L_checknumber(L, 1)));
  return 1;
}

static int math_log10 (mrp_State *L) {
  mrp_pushnumber(L, log10(mr_L_checknumber(L, 1)));
  return 1;
}

static int math_exp (mrp_State *L) {
  mrp_pushnumber(L, exp(mr_L_checknumber(L, 1)));
  return 1;
}

static int math_deg (mrp_State *L) {
  mrp_pushnumber(L, mr_L_checknumber(L, 1)/RADIANS_PER_DEGREE);
  return 1;
}

static int math_rad (mrp_State *L) {
  mrp_pushnumber(L, mr_L_checknumber(L, 1)*RADIANS_PER_DEGREE);
  return 1;
}

static int math_frexp (mrp_State *L) {
  int e;
  mrp_pushnumber(L, frexp(mr_L_checknumber(L, 1), &e));
  mrp_pushnumber(L, e);
  return 2;
}

static int math_ldexp (mrp_State *L) {
  mrp_pushnumber(L, ldexp(mr_L_checknumber(L, 1), mr_L_checkint(L, 2)));
  return 1;
}



static int math_min (mrp_State *L) {
  int n = mrp_gettop(L);  /* number of arguments */
  mrp_Number dmin = mr_L_checknumber(L, 1);
  int i;
  for (i=2; i<=n; i++) {
    mrp_Number d = mr_L_checknumber(L, i);
    if (d < dmin)
      dmin = d;
  }
  mrp_pushnumber(L, dmin);
  return 1;
}


static int math_max (mrp_State *L) {
  int n = mrp_gettop(L);  /* number of arguments */
  mrp_Number dmax = mr_L_checknumber(L, 1);
  int i;
  for (i=2; i<=n; i++) {
    mrp_Number d = mr_L_checknumber(L, i);
    if (d > dmax)
      dmax = d;
  }
  mrp_pushnumber(L, dmax);
  return 1;
}


static int math_random (mrp_State *L) {
  /* the `%' avoids the (rare) case of r==1, and is needed also because on
     some systems (SunOS!) `rand()' may return a value larger than RAND_MAX */
  mrp_Number r = (mrp_Number)(rand()%RAND_MAX) / (mrp_Number)RAND_MAX;
  switch (mrp_gettop(L)) {  /* check number of arguments */
    case 0: {  /* no arguments */
      mrp_pushnumber(L, r);  /* Number between 0 and 1 */
      break;
    }
    case 1: {  /* only upper limit */
      int u = mr_L_checkint(L, 1);
      mr_L_argcheck(L, 1<=u, 1, "interval is empty");
      mrp_pushnumber(L, (int)floor(r*u)+1);  /* int between 1 and `u' */
      break;
    }
    case 2: {  /* lower and upper limits */
      int l = mr_L_checkint(L, 1);
      int u = mr_L_checkint(L, 2);
      mr_L_argcheck(L, l<=u, 2, "interval is empty");
      mrp_pushnumber(L, (int)floor(r*(u-l+1))+l);  /* int between `l' and `u' */
      break;
    }
    default: return mr_L_error(L, "wrong number of arguments");
  }
  return 1;
}


static int math_randomseed (mrp_State *L) {
  srand(mr_L_checkint(L, 1));
  return 0;
}


static const mr_L_reg mathlib[] = {
  {"abs",   math_abs},
  {"sin",   math_sin},
  {"cos",   math_cos},
  {"tan",   math_tan},
  {"asin",  math_asin},
  {"acos",  math_acos},
  {"atan",  math_atan},
  {"atan2", math_atan2},
  {"ceil",  math_ceil},
  {"floor", math_floor},
  {"mod",   math_mod},
  {"frexp", math_frexp},
  {"ldexp", math_ldexp},
  {"sqrt",  math_sqrt},
  {"min",   math_min},
  {"max",   math_max},
  {"log",   math_log},
  {"log10", math_log10},
  {"exp",   math_exp},
  {"deg",   math_deg},
  {"pow",   math_pow},
  {"rad",   math_rad},
  {"random",     math_random},
  {"randomseed", math_randomseed},
  {NULL, NULL}
};


/*
** Open math library
*/
MRPLIB_API int mrp_open_math (mrp_State *L) {
  mr_L_openlib(L, MRP_MATHLIBNAME, mathlib, 0);
  mrp_pushliteral(L, "pi");
  mrp_pushnumber(L, PI);
  mrp_settable(L, -3);
  mrp_pushliteral(L, "__pow");
  mrp_pushcfunction(L, math_pow);
  mrp_settable(L, MRP_GLOBALSINDEX);
  return 1;
}

