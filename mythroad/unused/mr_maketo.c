/*
** Lua binding: mythroad
** Generated automatically by tolua 5.0a on 12/14/05 15:55:02.
*/

#ifndef __cplusplus
#include "stdlib.h"
#endif
#include "string.h"

#include "tomr.h"

/* Exported function */
TO_MR_API int to_mr_mythroad_open (mrp_State* to_mr_S);

#include "mr_formaketo.h"

/* function to register type */
static void to_mr_reg_types (mrp_State* to_mr_S)
{
}

/* function: MRF_DispUpEx */
static int to_mr_mythroad_MRF_DispUpEx00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,4,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,5,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  int16 x = ((int16)  to_mr_tonumber(to_mr_S,1,0));
  int16 y = ((int16)  to_mr_tonumber(to_mr_S,2,0));
  uint16 w = ((uint16)  to_mr_tonumber(to_mr_S,3,0));
  uint16 h = ((uint16)  to_mr_tonumber(to_mr_S,4,0));
 {
  MRF_DispUpEx(x,y,w,h);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_DispUpEx'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_TimerStart */
static int to_mr_mythroad_MRF_TimerStart00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isstring(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,4,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  int n = ((int)  to_mr_tonumber(to_mr_S,1,0));
  uint16 thistime = ((uint16)  to_mr_tonumber(to_mr_S,2,0));
  char* pcFunction = ((char*)  to_mr_tostring(to_mr_S,3,0));
 {
  MRF_TimerStart(n,thistime,pcFunction);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_TimerStart'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_TimerStop */
static int to_mr_mythroad_MRF_TimerStop00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,2,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  int n = ((int)  to_mr_tonumber(to_mr_S,1,0));
 {
  MRF_TimerStop(n);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_TimerStop'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_SpriteSet */
static int to_mr_mythroad_MRF_SpriteSet00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,3,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
  uint16 h = ((uint16)  to_mr_tonumber(to_mr_S,2,0));
 {
  MRF_SpriteSet(i,h);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_SpriteSet'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_SpriteDraw */
static int to_mr_mythroad_MRF_SpriteDraw00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,4,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,5,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
  uint16 spriteindex = ((uint16)  to_mr_tonumber(to_mr_S,2,0));
  int16 x = ((int16)  to_mr_tonumber(to_mr_S,3,0));
  int16 y = ((int16)  to_mr_tonumber(to_mr_S,4,0));
 {
  MRF_SpriteDraw(i,spriteindex,x,y);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_SpriteDraw'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_SpriteDrawEx */
static int to_mr_mythroad_MRF_SpriteDrawEx00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,4,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,5,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,6,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,7,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,8,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,9,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
  uint16 spriteindex = ((uint16)  to_mr_tonumber(to_mr_S,2,0));
  int16 x = ((int16)  to_mr_tonumber(to_mr_S,3,0));
  int16 y = ((int16)  to_mr_tonumber(to_mr_S,4,0));
  int16 A = ((int16)  to_mr_tonumber(to_mr_S,5,0));
  int16 B = ((int16)  to_mr_tonumber(to_mr_S,6,0));
  int16 C = ((int16)  to_mr_tonumber(to_mr_S,7,0));
  int16 D = ((int16)  to_mr_tonumber(to_mr_S,8,0));
 {
  MRF_SpriteDrawEx(i,spriteindex,x,y,A,B,C,D);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_SpriteDrawEx'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_SpriteCheck */
static int to_mr_mythroad_MRF_SpriteCheck00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,4,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,5,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,6,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
  uint16 spriteindex = ((uint16)  to_mr_tonumber(to_mr_S,2,0));
  int16 x = ((int16)  to_mr_tonumber(to_mr_S,3,0));
  int16 y = ((int16)  to_mr_tonumber(to_mr_S,4,0));
  uint32 color_check = ((uint32)  to_mr_tonumber(to_mr_S,5,0));
 {
  int to_mr_ret = (int)  MRF_SpriteCheck(i,spriteindex,x,y,color_check);
 to_mr_pushnumber(to_mr_S,(mrp_Number)to_mr_ret);
 }
 }
 return 1;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_SpriteCheck'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_ClearScreen */
static int to_mr_mythroad_MRF_ClearScreen00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,4,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  int r = ((int)  to_mr_tonumber(to_mr_S,1,0));
  int g = ((int)  to_mr_tonumber(to_mr_S,2,0));
  int b = ((int)  to_mr_tonumber(to_mr_S,3,0));
 {
  MRF_ClearScreen(r,g,b);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_ClearScreen'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_TileSet */
static int to_mr_mythroad_MRF_TileSet00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,4,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,5,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,6,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,7,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
  int16 x = ((int16)  to_mr_tonumber(to_mr_S,2,0));
  int16 y = ((int16)  to_mr_tonumber(to_mr_S,3,0));
  uint16 w = ((uint16)  to_mr_tonumber(to_mr_S,4,0));
  uint16 h = ((uint16)  to_mr_tonumber(to_mr_S,5,0));
  uint16 tileh = ((uint16)  to_mr_tonumber(to_mr_S,6,0));
 {
  MRF_TileSet(i,x,y,w,h,tileh);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_TileSet'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_TileSetRect */
static int to_mr_mythroad_MRF_TileSetRect00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,4,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,5,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,6,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
  int16 x1 = ((int16)  to_mr_tonumber(to_mr_S,2,0));
  int16 y1 = ((int16)  to_mr_tonumber(to_mr_S,3,0));
  int16 x2 = ((int16)  to_mr_tonumber(to_mr_S,4,0));
  int16 y2 = ((int16)  to_mr_tonumber(to_mr_S,5,0));
 {
  MRF_TileSetRect(i,x1,y1,x2,y2);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_TileSetRect'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_TileDraw */
static int to_mr_mythroad_MRF_TileDraw00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,2,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
 {
  MRF_TileDraw(i);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_TileDraw'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_GetTile */
static int to_mr_mythroad_MRF_GetTile00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,4,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
  uint16 x = ((uint16)  to_mr_tonumber(to_mr_S,2,0));
  uint16 y = ((uint16)  to_mr_tonumber(to_mr_S,3,0));
 {
  int16 to_mr_ret = (int16)  MRF_GetTile(i,x,y);
 to_mr_pushnumber(to_mr_S,(mrp_Number)to_mr_ret);
 }
 }
 return 1;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_GetTile'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_SetTile */
static int to_mr_mythroad_MRF_SetTile00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,4,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,5,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
  uint16 x = ((uint16)  to_mr_tonumber(to_mr_S,2,0));
  uint16 y = ((uint16)  to_mr_tonumber(to_mr_S,3,0));
  uint16 v = ((uint16)  to_mr_tonumber(to_mr_S,4,0));
 {
  MRF_SetTile(i,x,y,v);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_SetTile'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_TileShift */
static int to_mr_mythroad_MRF_TileShift00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,3,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
  uint16 mode = ((uint16)  to_mr_tonumber(to_mr_S,2,0));
 {
  MRF_TileShift(i,mode);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_TileShift'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_TileLoad */
static int to_mr_mythroad_MRF_TileLoad00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isstring(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,3,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
  char* filename = ((char*)  to_mr_tostring(to_mr_S,2,0));
 {
  MRF_TileLoad(i,filename);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_TileLoad'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_GetRand */
static int to_mr_mythroad_MRF_GetRand00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,2,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  int32 n = ((int32)  to_mr_tonumber(to_mr_S,1,0));
 {
  int32 to_mr_ret = (int32)  MRF_GetRand(n);
 to_mr_pushnumber(to_mr_S,(mrp_Number)to_mr_ret);
 }
 }
 return 1;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_GetRand'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_mod */
static int to_mr_mythroad_MRF_mod00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,3,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  int n = ((int)  to_mr_tonumber(to_mr_S,1,0));
  int m = ((int)  to_mr_tonumber(to_mr_S,2,0));
 {
  int to_mr_ret = (int)  MRF_mod(n,m);
 to_mr_pushnumber(to_mr_S,(mrp_Number)to_mr_ret);
 }
 }
 return 1;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_mod'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_DrawText */
static int to_mr_mythroad_MRF_DrawText00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isstring(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,4,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,5,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,6,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,7,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  char* pcText = ((char*)  to_mr_tostring(to_mr_S,1,0));
  int16 x = ((int16)  to_mr_tonumber(to_mr_S,2,0));
  int16 y = ((int16)  to_mr_tonumber(to_mr_S,3,0));
  uint8 r = ((uint8)  to_mr_tonumber(to_mr_S,4,0));
  uint8 g = ((uint8)  to_mr_tonumber(to_mr_S,5,0));
  uint8 b = ((uint8)  to_mr_tonumber(to_mr_S,6,0));
 {
  MRF_DrawText(pcText,x,y,r,g,b);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_DrawText'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_DrawRect */
static int to_mr_mythroad_MRF_DrawRect00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,4,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,5,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,6,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,7,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,8,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  int16 x = ((int16)  to_mr_tonumber(to_mr_S,1,0));
  int16 y = ((int16)  to_mr_tonumber(to_mr_S,2,0));
  int16 w = ((int16)  to_mr_tonumber(to_mr_S,3,0));
  int16 h = ((int16)  to_mr_tonumber(to_mr_S,4,0));
  uint8 r = ((uint8)  to_mr_tonumber(to_mr_S,5,0));
  uint8 g = ((uint8)  to_mr_tonumber(to_mr_S,6,0));
  uint8 b = ((uint8)  to_mr_tonumber(to_mr_S,7,0));
 {
  MRF_DrawRect(x,y,w,h,r,g,b);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_DrawRect'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_DrawLine */
static int to_mr_mythroad_MRF_DrawLine00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,4,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,5,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,6,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,7,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,8,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  int16 x1 = ((int16)  to_mr_tonumber(to_mr_S,1,0));
  int16 y1 = ((int16)  to_mr_tonumber(to_mr_S,2,0));
  int16 x2 = ((int16)  to_mr_tonumber(to_mr_S,3,0));
  int16 y2 = ((int16)  to_mr_tonumber(to_mr_S,4,0));
  uint8 r = ((uint8)  to_mr_tonumber(to_mr_S,5,0));
  uint8 g = ((uint8)  to_mr_tonumber(to_mr_S,6,0));
  uint8 b = ((uint8)  to_mr_tonumber(to_mr_S,7,0));
 {
  MRF_DrawLine(x1,y1,x2,y2,r,g,b);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_DrawLine'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_DrawPoint */
static int to_mr_mythroad_MRF_DrawPoint00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,4,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,5,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,6,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  int16 x = ((int16)  to_mr_tonumber(to_mr_S,1,0));
  int16 y = ((int16)  to_mr_tonumber(to_mr_S,2,0));
  uint8 r = ((uint8)  to_mr_tonumber(to_mr_S,3,0));
  uint8 g = ((uint8)  to_mr_tonumber(to_mr_S,4,0));
  uint8 b = ((uint8)  to_mr_tonumber(to_mr_S,5,0));
 {
  MRF_DrawPoint(x,y,r,g,b);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_DrawPoint'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_BgMusicSet */
static int to_mr_mythroad_MRF_BgMusicSet00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isstring(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,2,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  char* filename = ((char*)  to_mr_tostring(to_mr_S,1,0));
 {
  MRF_BgMusicSet(filename);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_BgMusicSet'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_BgMusicStart */
static int to_mr_mythroad_MRF_BgMusicStart00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isstring(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,2,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  char* filename = ((char*)  to_mr_tostring(to_mr_S,1,0));
 {
  MRF_BgMusicStart(filename);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_BgMusicStart'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_BgMusicStop */
static int to_mr_mythroad_MRF_BgMusicStop00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnoobj(to_mr_S,1,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
 {
  MRF_BgMusicStop();
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_BgMusicStop'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_SoundSet */
static int to_mr_mythroad_MRF_SoundSet00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isstring(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,3,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
  char* filename = ((char*)  to_mr_tostring(to_mr_S,2,0));
 {
  MRF_SoundSet(i,filename);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_SoundSet'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_SoundPlay */
static int to_mr_mythroad_MRF_SoundPlay00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,2,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
 {
  MRF_SoundPlay(i);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_SoundPlay'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_BitmapLoad */
static int to_mr_mythroad_MRF_BitmapLoad00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isstring(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,4,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,5,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,6,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,7,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,8,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
  char* filename = ((char*)  to_mr_tostring(to_mr_S,2,0));
  int16 x = ((int16)  to_mr_tonumber(to_mr_S,3,0));
  int16 y = ((int16)  to_mr_tonumber(to_mr_S,4,0));
  uint16 w = ((uint16)  to_mr_tonumber(to_mr_S,5,0));
  uint16 h = ((uint16)  to_mr_tonumber(to_mr_S,6,0));
  uint16 max_w = ((uint16)  to_mr_tonumber(to_mr_S,7,0));
 {
  MRF_BitmapLoad(i,filename,x,y,w,h,max_w);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_BitmapLoad'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_BitmapShow */
static int to_mr_mythroad_MRF_BitmapShow00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,4,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,5,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
  int16 x = ((int16)  to_mr_tonumber(to_mr_S,2,0));
  int16 y = ((int16)  to_mr_tonumber(to_mr_S,3,0));
  uint16 rop = ((uint16)  to_mr_tonumber(to_mr_S,4,0));
 {
  MRF_BitmapShow(i,x,y,rop);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_BitmapShow'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_BitmapNew */
static int to_mr_mythroad_MRF_BitmapNew00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,4,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
  uint16 w = ((uint16)  to_mr_tonumber(to_mr_S,2,0));
  uint16 h = ((uint16)  to_mr_tonumber(to_mr_S,3,0));
 {
  MRF_BitmapNew(i,w,h);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_BitmapNew'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_BitmapDraw */
static int to_mr_mythroad_MRF_BitmapDraw00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,4,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,5,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,6,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,7,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,8,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,9,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 di = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,2,0));
  int16 x = ((int16)  to_mr_tonumber(to_mr_S,3,0));
  int16 y = ((int16)  to_mr_tonumber(to_mr_S,4,0));
  int16 A = ((int16)  to_mr_tonumber(to_mr_S,5,0));
  int16 B = ((int16)  to_mr_tonumber(to_mr_S,6,0));
  int16 C = ((int16)  to_mr_tonumber(to_mr_S,7,0));
  int16 D = ((int16)  to_mr_tonumber(to_mr_S,8,0));
 {
  MRF_BitmapDraw(di,i,x,y,A,B,C,D);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_BitmapDraw'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_BmGetScr */
static int to_mr_mythroad_MRF_BmGetScr00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,2,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  uint16 i = ((uint16)  to_mr_tonumber(to_mr_S,1,0));
 {
  MRF_BmGetScr(i);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_BmGetScr'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_Exit */
static int to_mr_mythroad_MRF_Exit00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnoobj(to_mr_S,1,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
 {
  MRF_Exit();
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_Exit'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_EffSetCon */
static int to_mr_mythroad_MRF_EffSetCon00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,3,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,4,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,5,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,6,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,7,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,8,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  int16 x = ((int16)  to_mr_tonumber(to_mr_S,1,0));
  int16 y = ((int16)  to_mr_tonumber(to_mr_S,2,0));
  int16 w = ((int16)  to_mr_tonumber(to_mr_S,3,0));
  int16 h = ((int16)  to_mr_tonumber(to_mr_S,4,0));
  int16 perr = ((int16)  to_mr_tonumber(to_mr_S,5,0));
  int16 perg = ((int16)  to_mr_tonumber(to_mr_S,6,0));
  int16 perb = ((int16)  to_mr_tonumber(to_mr_S,7,0));
 {
  MRF_EffSetCon(x,y,w,h,perr,perg,perb);
 }
 }
 return 0;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_EffSetCon'.",&to_mr_err);
 return 0;
#endif
}

/* function: MRF_TestCom */
static int to_mr_mythroad_MRF_TestCom00(mrp_State* to_mr_S)
{
#ifndef TO_MR_RELEASE
 to_mr_Error to_mr_err;
 if (
 !to_mr_isnumber(to_mr_S,1,0,&to_mr_err) ||
 !to_mr_isnumber(to_mr_S,2,0,&to_mr_err) ||
 !to_mr_isnoobj(to_mr_S,3,&to_mr_err)
 )
 goto to_mr_lerror;
 else
#endif
 {
  int input0 = ((int)  to_mr_tonumber(to_mr_S,1,0));
  int input1 = ((int)  to_mr_tonumber(to_mr_S,2,0));
 {
  int to_mr_ret = (int)  MRF_TestCom(input0,input1);
 to_mr_pushnumber(to_mr_S,(mrp_Number)to_mr_ret);
 }
 }
 return 1;
#ifndef TO_MR_RELEASE
 to_mr_lerror:
 to_mr_error(to_mr_S,"#ferror in function 'MRF_TestCom'.",&to_mr_err);
 return 0;
#endif
}

/* Open function */
TO_MR_API int to_mr_mythroad_open (mrp_State* to_mr_S)
{
 to_mr_open(to_mr_S);
 to_mr_reg_types(to_mr_S);
 to_mr_module(to_mr_S,NULL,0);
 to_mr_beginmodule(to_mr_S,NULL);
/*
#define TIMERMAX  10
enum {
   K_0,               //按键 0
   K_1,               //按键 1
   K_2,               //按键 2
   K_3,               //按键 3
   K_4,               //按键 4
   K_5,               //按键 5
   K_6,               //按键 6
   K_7,               //按键 7
   K_8,               //按键 8
   K_9,               //按键 9
   K_STAR,            //按键 *
   K_POUND,           //按键 #
   K_UP,              //按键 上
   K_DOWN,            //按键 下
   K_LEFT,            //按键 左
   K_RIGHT,           //按键 右
   K_POWER,           //按键 挂机键
   K_SOFTLEFT,        //按键 左软键
   K_SOFTRIGHT,       //按键 右软键
   K_SEND,            //按键 接听键
   K_SELECT           //按键 确认/选择（若方向键中间有确认键，建议设为该键）
};

enum {
   K_PRESS,
   K_RELEASE,
   K_CLICK,
   K_CLICK_UP
};
 to_mr_constant(to_mr_S,"BM_OR",BM_OR);
 to_mr_constant(to_mr_S,"BM_XOR",BM_XOR);
 to_mr_constant(to_mr_S,"BM_COPY",BM_COPY);
 to_mr_constant(to_mr_S,"BM_NOT",BM_NOT);
 to_mr_constant(to_mr_S,"BM_MERGENOT",BM_MERGENOT);
 to_mr_constant(to_mr_S,"BM_ANDNOT",BM_ANDNOT);
 to_mr_constant(to_mr_S,"BM_TRANSPARENT",BM_TRANSPARENT);
 to_mr_constant(to_mr_S,"K_0",K_0);
 to_mr_constant(to_mr_S,"K_1",K_1);
 to_mr_constant(to_mr_S,"K_2",K_2);
 to_mr_constant(to_mr_S,"K_3",K_3);
 to_mr_constant(to_mr_S,"K_4",K_4);
 to_mr_constant(to_mr_S,"K_5",K_5);
 to_mr_constant(to_mr_S,"K_6",K_6);
 to_mr_constant(to_mr_S,"K_7",K_7);
 to_mr_constant(to_mr_S,"K_8",K_8);
 to_mr_constant(to_mr_S,"K_9",K_9);
 to_mr_constant(to_mr_S,"K_STAR",K_STAR);
 to_mr_constant(to_mr_S,"K_POUND",K_POUND);
 to_mr_constant(to_mr_S,"K_UP",K_UP);
 to_mr_constant(to_mr_S,"K_DOWN",K_DOWN);
 to_mr_constant(to_mr_S,"K_LEFT",K_LEFT);
 to_mr_constant(to_mr_S,"K_RIGHT",K_RIGHT);
 to_mr_constant(to_mr_S,"K_POWER",K_POWER);
 to_mr_constant(to_mr_S,"K_SOFTLEFT",K_SOFTLEFT);
 to_mr_constant(to_mr_S,"K_SOFTRIGHT",K_SOFTRIGHT);
 to_mr_constant(to_mr_S,"K_SEND",K_SEND);
 to_mr_constant(to_mr_S,"K_SELECT",K_SELECT);
 to_mr_constant(to_mr_S,"K_PRESS",K_PRESS);
 to_mr_constant(to_mr_S,"K_RELEASE",K_RELEASE);
 to_mr_constant(to_mr_S,"K_CLICK",K_CLICK);
 to_mr_constant(to_mr_S,"K_CLICK_UP",K_CLICK_UP);
 to_mr_constant(to_mr_S,"MF_RDONLY",MF_RDONLY);
 to_mr_constant(to_mr_S,"MF_WRONLY",MF_WRONLY);
 to_mr_constant(to_mr_S,"MF_RDWR",MF_RDWR);
 to_mr_constant(to_mr_S,"MF_CREATE",MF_CREATE);
*/
// to_mr_function(to_mr_S,"DispUpEx",to_mr_mythroad_MRF_DispUpEx00);
// to_mr_function(to_mr_S,"TimerStart",to_mr_mythroad_MRF_TimerStart00);
 to_mr_function(to_mr_S,"TimerStop",to_mr_mythroad_MRF_TimerStop00);
 to_mr_function(to_mr_S,"SpriteSet",to_mr_mythroad_MRF_SpriteSet00);
 to_mr_function(to_mr_S,"SpriteDraw",to_mr_mythroad_MRF_SpriteDraw00);
 to_mr_function(to_mr_S,"SpriteDrawEx",to_mr_mythroad_MRF_SpriteDrawEx00);
 to_mr_function(to_mr_S,"SpriteCheck",to_mr_mythroad_MRF_SpriteCheck00);
 to_mr_function(to_mr_S,"ClearScreen",to_mr_mythroad_MRF_ClearScreen00);
 to_mr_function(to_mr_S,"TileSet",to_mr_mythroad_MRF_TileSet00);
 to_mr_function(to_mr_S,"TileSetRect",to_mr_mythroad_MRF_TileSetRect00);
 to_mr_function(to_mr_S,"TileDraw",to_mr_mythroad_MRF_TileDraw00);
 to_mr_function(to_mr_S,"GetTile",to_mr_mythroad_MRF_GetTile00);
 to_mr_function(to_mr_S,"SetTile",to_mr_mythroad_MRF_SetTile00);
 to_mr_function(to_mr_S,"TileShift",to_mr_mythroad_MRF_TileShift00);
 to_mr_function(to_mr_S,"TileLoad",to_mr_mythroad_MRF_TileLoad00);
 to_mr_function(to_mr_S,"GetRand",to_mr_mythroad_MRF_GetRand00);
 to_mr_function(to_mr_S,"mod",to_mr_mythroad_MRF_mod00);
 to_mr_function(to_mr_S,"DrawText",to_mr_mythroad_MRF_DrawText00);
 to_mr_function(to_mr_S,"DrawRect",to_mr_mythroad_MRF_DrawRect00);
 to_mr_function(to_mr_S,"DrawLine",to_mr_mythroad_MRF_DrawLine00);
 to_mr_function(to_mr_S,"DrawPoint",to_mr_mythroad_MRF_DrawPoint00);
 to_mr_function(to_mr_S,"BgMusicSet",to_mr_mythroad_MRF_BgMusicSet00);
 to_mr_function(to_mr_S,"BgMusicStart",to_mr_mythroad_MRF_BgMusicStart00);
 to_mr_function(to_mr_S,"BgMusicStop",to_mr_mythroad_MRF_BgMusicStop00);
 to_mr_function(to_mr_S,"SoundSet",to_mr_mythroad_MRF_SoundSet00);
 to_mr_function(to_mr_S,"SoundPlay",to_mr_mythroad_MRF_SoundPlay00);
 to_mr_function(to_mr_S,"BitmapLoad",to_mr_mythroad_MRF_BitmapLoad00);
 to_mr_function(to_mr_S,"BitmapShow",to_mr_mythroad_MRF_BitmapShow00);
 to_mr_function(to_mr_S,"BitmapNew",to_mr_mythroad_MRF_BitmapNew00);
 to_mr_function(to_mr_S,"BitmapDraw",to_mr_mythroad_MRF_BitmapDraw00);
 to_mr_function(to_mr_S,"BmGetScr",to_mr_mythroad_MRF_BmGetScr00);
 to_mr_function(to_mr_S,"Exit",to_mr_mythroad_MRF_Exit00);
 to_mr_function(to_mr_S,"EffSetCon",to_mr_mythroad_MRF_EffSetCon00);
 to_mr_function(to_mr_S,"TestCom",to_mr_mythroad_MRF_TestCom00);
 to_mr_endmodule(to_mr_S);
 return 1;
}
