#ifndef _MR_JGRAPHICS_H
#define _MR_JGRAPHICS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mr.h"
#include "mr_helper.h"

#define TOP_Graphics 16
#define BASELINE_Graphics 64
#define BOTTOM_Graphics 32
#define VCENTER_Graphics 0x2

#define LEFT_Graphics 0x4
#define HCENTER_Graphics 0x1
#define RIGHT_Graphics 0x8

#define AP_V_MASK_Graphics (TOP_Graphics | BASELINE_Graphics | BOTTOM_Graphics | VCENTER_Graphics)
#define AP_H_MASK_Graphics (LEFT_Graphics | HCENTER_Graphics | RIGHT_Graphics)

#define TRANS_NONE_Sprite 0
#define TRANS_MIRROR_ROT180_Sprite 1
#define TRANS_MIRROR_Sprite 2
#define TRANS_ROT180_Sprite 3

#define TRANS_MIRROR_ROT270_Sprite 4
#define TRANS_ROT90_Sprite 5
#define TRANS_ROT270_Sprite 6
#define TRANS_MIRROR_ROT90_Sprite 7

typedef struct _mr_jgraphics_context_t {
    struct {
        /*
         *  Clip 变量： 坐标值均为经过translate处理过的。
         *  相对于 ScreenBuffer的坐标。
         */
        int clipX;
        int clipY;
        int clipWidth;
        int clipHeight;
        int clipXRight;  /* = clipX + clipWidth， 为了速度而设置的冗余值 */
        int clipYBottom; /* = clipY + clipBottom，为了速度而设置的冗余值 */

        int translateX;
        int translateY;

        int font;

        uint8 color_R, color_G, color_B;
        uint16 color_565;
    } mutableValues;

    uint16* __SJC_SCREEN_BUFFER__;       //假的屏幕缓冲(缓存)
    int __SJC_SCREEN_WIDTH__;            //假的屏幕宽(缓存宽)
    int __SJC_SCREEN_HEIGHT__;           //假的屏幕高(缓存高)
    int flag;                            //标识是否是屏幕buffer，0-否，1-是
    uint16* __REAL_SJC_SCREEN_BUFFER__;  //真正的屏幕冲缓
    int __REAL_SJC_SCREEN_WIDTH__;       //真正的屏幕宽
    int __REAL_SJC_SCREEN_HEIGHT__;      //真正的屏幕高
} mr_jgraphics_context_t;

typedef struct {
    uint16* data;
    uint16 width;
    uint16 height;
    uint8 trans;  //1:使用透明色;0:不使用
    uint16 transcolor;
} mr_jImageSt;

typedef struct _tagTransBitmap {
    void* pData;
    int32 width;
    int32 height;
    int32 maxWidth;
    uint16 transColor;

    int16* pMatrix;
    int32 markCount;
    uint8* pZion;
} mr_transBitmap;

void _DrawBitmapEx(mr_bitmapDrawSt* srcbmp, mr_bitmapDrawSt* dstbmp, uint16 w, uint16 h, mr_transMatrixSt* pTrans, uint16 transcoler);

int32 mr_transbitmapDraw(mr_transBitmap* hTransBmp, uint16* dstBuf, int32 dest_max_w, int32 dest_max_h, int32 sx, int32 sy, int32 width, int32 height, int32 dx, int32 dy);

// x_src, y_src是相对于图片的坐标。
void mr_drawRegion(mr_jgraphics_context_t* gContext, mr_jImageSt* src, int sx, int sy, int w, int h, int transform, int x, int y, int anchor);

#ifdef __cplusplus
}
#endif

#endif
