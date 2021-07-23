/* tolua: event functions
** Support code for Lua bindings.
** Written by Waldemar Celes
** TeCGraf/PUC-Rio
** Apr 2003
** $Id: $
*/

/* This code is free software; you can redistribute it and/or modify it. 
** The software provided hereunder is on an "as is" basis, and 
** the author has no obligation to provide maintenance, support, updates,
** enhancements, or modifications. 
*/

#ifndef TO_MR_EVENT_H
#define TO_MR_EVENT_H

#include "tomr.h"

TO_MR_API void to_mr_moduleevents (mrp_State* L);
TO_MR_API int to_mr_ismodulemetatable (mrp_State* L);
TO_MR_API void to_mr_classevents (mrp_State* L);

#endif
