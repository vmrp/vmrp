#ifndef _MR_FORMAKETO_H_
#define _MR_FORMAKETO_H_

#include "mr.h"
extern void MRF_DispUpEx(int16 x, int16 y, uint16 w, uint16 h);

extern void MRF_TimerStart(int n, uint16 thistime, char* pcFunction);
extern void MRF_TimerStop(int n);

extern void MRF_SpriteSet(uint16 i, uint16 h);
extern void MRF_SpriteDraw(uint16 i, uint16 spriteindex, int16 x, int16 y);
extern void MRF_SpriteDrawEx(uint16 i, uint16 spriteindex, int16 x, int16 y, int16 A, int16 B, int16 C, int16 D);
//extern void MRF_SpriteDrawEx1(uint16 i, uint16 spriteindex, int16 x, int16 y, int16 A, int16 B, int16 C, int16 D);
extern int MRF_SpriteCheck(uint16 i, uint16 spriteindex, int16 x, int16 y, uint32 color_check);

extern void MRF_ClearScreen(int r, int g, int b);

extern void MRF_TileSet(uint16 i, int16 x, int16 y, uint16 w, uint16 h, uint16 tileh);
extern void MRF_TileSetRect(uint16 i, int16 x1, int16 y1, int16 x2, int16 y2 );
extern void MRF_TileDraw(uint16 i);
extern int16 MRF_GetTile(uint16 i, uint16 x, uint16 y);
extern void MRF_SetTile(uint16 i, uint16 x, uint16 y, uint16 v);
extern void MRF_TileShift(uint16 i, uint16 mode);
extern void MRF_TileLoad(uint16 i, char * filename);

extern int32 MRF_GetRand(int32 n);
extern int MRF_mod(int n, int m);

extern void MRF_DrawText(char * pcText, int16 x, int16 y, uint8 r, uint8 g, uint8 b);
extern void MRF_DrawRect(int16 x, int16 y, int16 w, int16 h, uint8 r, uint8 g, uint8 b);
extern void MRF_DrawLine(int16 x1, int16 y1, int16 x2, int16 y2, uint8 r, uint8 g, uint8 b);
extern void MRF_DrawPoint(int16 x, int16 y, uint8 r, uint8 g, uint8 b);

extern void MRF_BgMusicSet(char * filename);
extern void MRF_BgMusicStart(char * filename);
extern void MRF_BgMusicStop(void);

extern void MRF_SoundSet(uint16 i, char * filename);
extern void MRF_SoundPlay(uint16 i);

extern void MRF_BitmapLoad(uint16 i, char * filename, int16 x, int16 y, uint16 w, uint16 h, uint16 max_w);
extern void MRF_BitmapShow(uint16 i, int16 x, int16 y, uint16 rop);
extern void MRF_BitmapNew(uint16 i, uint16 w, uint16 h);
extern void MRF_BitmapDraw(uint16 di, uint16 i, int16 x, int16 y, int16 A, int16 B, int16 C, int16 D);
extern void MRF_BmGetScr(uint16 i);

extern void MRF_Exit(void);

extern void MRF_EffSetCon(int16 x, int16 y, int16 w, int16 h, int16 perr, int16 perg, int16 perb);

extern int MRF_TestCom(int input0, int input1);

#endif
