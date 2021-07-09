

#ifndef TOMR_H
#define TOMR_H

#ifndef TO_MR_API
#define TO_MR_API extern
#endif

#define TO_MR_VERSION "tomr"

#ifdef __cplusplus
extern "C" {
#endif

#include "../include/mem.h"
#include "../include/mr.h"
#include "../include/mr_auxlib.h"
#include "../include/mr_helper.h"

struct to_mr_Error
{
	int index;
	int array;
	const char* type;
};
typedef struct to_mr_Error to_mr_Error;


TO_MR_API const char* to_mr_typename (mrp_State* L, int lo);
TO_MR_API void to_mr_error (mrp_State* L, char* msg, to_mr_Error* err);
TO_MR_API int to_mr_isnoobj (mrp_State* L, int lo, to_mr_Error* err);
TO_MR_API int to_mr_isvalue (mrp_State* L, int lo, int def, to_mr_Error* err);
TO_MR_API int to_mr_isboolean (mrp_State* L, int lo, int def, to_mr_Error* err);
TO_MR_API int to_mr_isnumber (mrp_State* L, int lo, int def, to_mr_Error* err);
TO_MR_API int to_mr_isstring (mrp_State* L, int lo, int def, to_mr_Error* err);
TO_MR_API int to_mr_istable (mrp_State* L, int lo, int def, to_mr_Error* err);
TO_MR_API int to_mr_isusertable (mrp_State* L, int lo, const char* type, int def, to_mr_Error* err);
TO_MR_API int to_mr_isfunction (mrp_State* L, int lo, int def, to_mr_Error* err); 
TO_MR_API int to_mr_isuserdata (mrp_State* L, int lo, int def, to_mr_Error* err);
TO_MR_API int to_mr_isusertype (mrp_State* L, int lo, const char* type, int def, to_mr_Error* err);
TO_MR_API int to_mr_isvaluearray 
 (mrp_State* L, int lo, int dim, int def, to_mr_Error* err);
TO_MR_API int to_mr_isbooleanarray 
 (mrp_State* L, int lo, int dim, int def, to_mr_Error* err);
TO_MR_API int to_mr_isnumberarray 
 (mrp_State* L, int lo, int dim, int def, to_mr_Error* err);
TO_MR_API int to_mr_isstringarray 
 (mrp_State* L, int lo, int dim, int def, to_mr_Error* err);
TO_MR_API int to_mr_istablearray 
 (mrp_State* L, int lo, int dim, int def, to_mr_Error* err);
TO_MR_API int to_mr_isuserdataarray 
 (mrp_State* L, int lo, int dim, int def, to_mr_Error* err);
TO_MR_API int to_mr_isusertypearray 
 (mrp_State* L, int lo, const char* type, int dim, int def, to_mr_Error* err);

TO_MR_API void to_mr_open (mrp_State* L);

TO_MR_API void* to_mr_copy (mrp_State* L, void* value, unsigned int size);
TO_MR_API void* to_mr_clone (mrp_State* L, void* value, mrp_CFunction func);

TO_MR_API void to_mr_usertype (mrp_State* L, char* type);
TO_MR_API void to_mr_beginmodule (mrp_State* L, char* name);
TO_MR_API void to_mr_endmodule (mrp_State* L);
TO_MR_API void to_mr_module (mrp_State* L, char* name, int hasvar);
TO_MR_API void to_mr_class (mrp_State* L, char* name, char* base);
TO_MR_API void to_mr_cclass (mrp_State* L, char* lname, char* name, char* base, mrp_CFunction col);
TO_MR_API void to_mr_function (mrp_State* L, char* name, mrp_CFunction func);
TO_MR_API void to_mr_constant (mrp_State* L, char* name, int value);
TO_MR_API void to_mr_variable (mrp_State* L, char* name, mrp_CFunction get, mrp_CFunction set);
TO_MR_API void to_mr_array (mrp_State* L,char* name, mrp_CFunction get, mrp_CFunction set);


TO_MR_API void to_mr_pushvalue (mrp_State* L, int lo);
TO_MR_API void to_mr_pushboolean (mrp_State* L, int value);
TO_MR_API void to_mr_pushnumber (mrp_State* L, int value);
TO_MR_API void to_mr_pushstring (mrp_State* L, const char* value);
TO_MR_API void to_mr_pushuserdata (mrp_State* L, void* value);
TO_MR_API void to_mr_pushusertype (mrp_State* L, void* value, const char* type);
TO_MR_API void to_mr_pushfieldvalue (mrp_State* L, int lo, int index, int v);
TO_MR_API void to_mr_pushfieldboolean (mrp_State* L, int lo, int index, int v);
TO_MR_API void to_mr_pushfieldnumber (mrp_State* L, int lo, int index, int v);
TO_MR_API void to_mr_pushfieldstring (mrp_State* L, int lo, int index, const char* v);
TO_MR_API void to_mr_pushfielduserdata (mrp_State* L, int lo, int index, void* v);
TO_MR_API void to_mr_pushfieldusertype (mrp_State* L, int lo, int index, void* v, const char* type);

TO_MR_API int to_mr_tonumber (mrp_State* L, int narg, int def);
TO_MR_API const char* to_mr_tostring (mrp_State* L, int narg, const char* def);
TO_MR_API void* to_mr_touserdata (mrp_State* L, int narg, void* def);
TO_MR_API void* to_mr_tousertype (mrp_State* L, int narg, void* def);
TO_MR_API int to_mr_tovalue (mrp_State* L, int narg, int def);
TO_MR_API int to_mr_toboolean (mrp_State* L, int narg, int def);
TO_MR_API double to_mr_tofieldnumber (mrp_State* L, int lo, int index, double def);
TO_MR_API const char* to_mr_tofieldstring (mrp_State* L, int lo, int index, const char* def);
TO_MR_API void* to_mr_tofielduserdata (mrp_State* L, int lo, int index, void* def);
TO_MR_API void* to_mr_tofieldusertype (mrp_State* L, int lo, int index, void* def);
TO_MR_API int to_mr_tofieldvalue (mrp_State* L, int lo, int index, int def);
TO_MR_API int to_mr_getfieldboolean (mrp_State* L, int lo, int index, int def);

#ifdef __cplusplus
}
#endif

#endif
