#include "./include/mr_graphics.h"

#include "./include/mr.h"
#include "./include/mr_helper.h"
#include "./include/mythroad.h"
#include "./include/string.h"

/*
 *  x，y -- 坐标系： 屏幕， translate之前的坐标
 *
 *  width/height -- 将要渲染的图片或者region的尺寸， 没有Clip之前。
 */
static void calc_anchor(mr_jgraphics_context_t *gContext, int x, int y, int width, int height, int anchor, int *outx, int *outy) {
    int anchor_h, anchor_v;

    x += gContext->mutableValues.translateX;
    y += gContext->mutableValues.translateY;

    if (anchor == 0) {
        anchor_h = LEFT_Graphics;
        anchor_v = TOP_Graphics;
    } else {
        anchor_h = AP_H_MASK_Graphics & anchor;
        anchor_v = AP_V_MASK_Graphics & anchor;
    }

    if (anchor_h == LEFT_Graphics && anchor_v == TOP_Graphics) {
        // quick case
        *outx = x, *outy = y;
        return;
    } else {
        switch (anchor_h) {
            case RIGHT_Graphics:
                *outx = x - width;
                break;
            case LEFT_Graphics:
                *outx = x;
                break;
            case HCENTER_Graphics:
                *outx = x - width / 2;
                break;
            default:
                return;
        }

        switch (anchor_v) {
            case BOTTOM_Graphics:
                *outy = y - height;
                break;
            case TOP_Graphics:
                *outy = y;
                break;
            case BASELINE_Graphics:
                *outy = y - height / 2 - 3;  // XXX - 3 pixels
                break;
            case VCENTER_Graphics:
                *outy = y - height / 2;
                break;
            default:
                return;
        }
    }
}

// x_src, y_src是相对于图片的坐标。
void mr_drawRegion(
    mr_jgraphics_context_t *gContext,
    mr_jImageSt *src,
    int sx,
    int sy,
    int w,
    int h,
    int transform,
    int x,
    int y,
    int anchor) {
    /*
	 *  试图告诉编译器， 这七个变量需要用寄存器。
	 */

    register uint16 transcolor = 0;
    register int k = 0, n = 0;
    register uint16 *dstp, *srcp;  //内层循环像素的指针。
    register int dx, dy;

    int dx_o;
    uint16 *dstp_o;
    int screenWidth = gContext->__REAL_SJC_SCREEN_WIDTH__;
    uint16 *value = NULL;

    int MinX, MaxX, MinY, MaxY; /* 经过clip后的区域， 相对于目标缓冲。 */

    if (!gContext || !src) {
        return;
    }

    if (src->trans != 0) {
        transcolor = (src->trans == 1) ? (*(uint16 *)src->data) : (src->transcolor);
    }

    // 先把锚点算好。
    if (anchor == 20 || anchor == 0) {
        x += gContext->mutableValues.translateX;
        y += gContext->mutableValues.translateY;
    } else {
        if (!(transform >> 2)) {
            // 没有90度翻转的情况
            calc_anchor(gContext, x, y, w, h, anchor, &x, &y);
        } else {
            calc_anchor(gContext, x, y, h, w, anchor, &x, &y);
        }
    }

    // 开始计算Clip
    MinX = MAX(x, gContext->mutableValues.clipX);
    MinY = MAX(y, gContext->mutableValues.clipY);

    if (!(transform >> 2)) {
        // 宽和高互调一下。
        MaxX = MIN(x + w, gContext->mutableValues.clipXRight);
        MaxY = MIN(y + h, gContext->mutableValues.clipYBottom);
    } else {
        MaxX = MIN(x + h, gContext->mutableValues.clipXRight);
        MaxY = MIN(y + w, gContext->mutableValues.clipYBottom);
    }

    dy = MaxY - MinY;
    dx_o = dx = MaxX - MinX;

    if (dy <= 0 || dx <= 0) {
        return;
    }

    switch (transform) {
        case TRANS_NONE_Sprite:

            if (src->trans == 0) {
                value = src->data + (sx + MinY - y) * src->width + (MinX - x + sx);

                srcp = value;
                dstp = (uint16 *)(gContext->__SJC_SCREEN_BUFFER__ + MinY * gContext->__SJC_SCREEN_WIDTH__ + MinX);

                n = (int16)src->width;

                while (dy-- > 0) {
                    //copy一行
                    memcpy2(dstp, srcp, dx * 2);
                    dstp += screenWidth;
                    srcp += n;
                }

                return;
            }

            break;

        case TRANS_MIRROR_ROT180_Sprite:
            value = src->data + (h - 1 - (MinY - y - sy)) * src->width + (MinX - x + sx);

            k = 1;
            n = 0 - (int16)src->width;

            if (src->trans == 0) {
                srcp = value;
                dstp = (uint16 *)(gContext->__SJC_SCREEN_BUFFER__ + MinY * gContext->__SJC_SCREEN_WIDTH__ + MinX);

                while (dy-- > 0) {
                    //copy一行
                    memcpy2(dstp, srcp, dx * 2);
                    dstp += screenWidth;
                    srcp += n;
                }
                return;
            }

            break;

        case TRANS_ROT180_Sprite:
            value = src->data + (h - 1 + sy) * src->width + w - (MinY - y) * src->width - 1 + sx - MinX + x;

            k = -1;
            n = 0 - (int16)src->width;

            break;

        case TRANS_MIRROR_Sprite:  //FLIP_HORI
            value = src->data + (MinY - y + sy) * src->width + sx + w - 1 + x - MinX;
            k = -1;
            n = (int16)src->width;
            break;

        case TRANS_ROT90_Sprite:
            value = src->data + (h + sy - 1) * src->width + (MinY - y) + sx - (MinX - x) * src->width;
            k = 0 - (int16)src->width;
            n = 1;
            break;

        case TRANS_MIRROR_ROT90_Sprite:
            value = src->data + sx + (h + sy - 1) * src->width + w - MinY + y - 1 - MinX * src->width + x * src->width;
            k = 0 - (int16)src->width;
            n = -1;
            break;

        case TRANS_ROT270_Sprite:
            value = src->data + sx + sy * src->width + w - (MinY - y) - 1 + MinX * src->width - x * src->width;
            k = (int16)src->width;
            n = -1;
            break;

        case TRANS_MIRROR_ROT270_Sprite:
            value = src->data + (sy)*src->width - y + sx + MinY + MinX * src->width - x * src->width;
            k = (int16)src->width;
            n = 1;
            break;

        default:
            return;
    }

    dstp = dstp_o = (uint16 *)(gContext->__SJC_SCREEN_BUFFER__ + MinY * gContext->__SJC_SCREEN_WIDTH__ + MinX);

    if (src->trans == 0) {
        while (dy-- > 0) {
            srcp = value;
            while (dx-- > 0) {
                *dstp = *srcp;
                srcp += k;
                dstp++;
            }
            dx = dx_o;
            dstp = dstp_o += screenWidth;
            value += n;
        }
    } else {
        while (dy-- > 0) {
            srcp = value;
            while (dx-- > 0) {
                if (*srcp != transcolor) {
                    *dstp = *srcp;
                }

                srcp += k;
                dstp++;
            }
            dx = dx_o;
            dstp = dstp_o += screenWidth;
            value += n;
        }
    }
}

int32 mr_transbitmapDraw(mr_transBitmap *hTransBmp, uint16 *dstBuf, int32 dest_max_w, int32 dest_max_h, int32 sx, int32 sy,
                         int32 width, int32 height, int32 dx, int32 dy) {
    uint16 *dest;
    int32 dest_maxW, dest_maxH;
    mr_transBitmap *pTransBitmap;
    int32 i, j, k;
    int32 startPixel;
    int32 len, actualLen;
    int32 hasNext = 0, nextPixel = 0;
    uint16 *destLine, *destPixel;
    uint16 *srcLine, *srcPixel;
    int16 *mm;
    int32 pos1_e, pos2_e;

    pTransBitmap = hTransBmp;
    if (!pTransBitmap) {
        return MR_FAILED;
    }

    dest = dstBuf;

    dest_maxW = dest_max_w;
    dest_maxH = dest_max_h;

    hasNext = 0;

    /**先做负值坐标切换**/
    if (dx < 0) {
        sx += -dx;
        width += dx;
        dx = 0;
    }

    if (dy < 0) {
        sy += -dy;
        height += dy;
        dy = 0;
    }

    len = dest_maxW - dx;
    width = width < len ? width : len;

    mm = pTransBitmap->pMatrix + sy * 2 * pTransBitmap->markCount;
    srcLine = (uint16 *)pTransBitmap->pData + pTransBitmap->maxWidth * sy;
    destLine = dest + dest_maxW * dy + dx;

    pos1_e = sx + width;

    if (height > dest_maxH - dy) height = dest_maxH - dy;

    for (i = sy; i < sy + height; i++) {
        for (j = 0; j < pTransBitmap->markCount; j++) {
            startPixel = mm[j * 2];

            if (startPixel < 0) /*表示这个标记位无效,接下去的标记位也必然无效*/
            {
                break;
            }

            len = mm[j * 2 + 1];

            if (j == pTransBitmap->markCount - 1) /*到达最后一个标记栏，这里有是否包含后续点的分析*/
            {
                hasNext = (int32)(len & 0x4000); /*是否有未标识像素*/
                len &= 0x3FFF;

                if (hasNext) {
                    nextPixel = startPixel + len;
                }
            }

            pos2_e = startPixel + len;

            if (pos2_e < startPixel || pos1_e < sx) continue; /*没有相交的部分*/

            startPixel = startPixel > sx ? startPixel : sx;
            pos2_e = pos2_e < pos1_e ? pos2_e : pos1_e;

            actualLen = pos2_e - startPixel;

            srcPixel = srcLine + startPixel;
            destPixel = destLine + (startPixel - sx);

            if (actualLen > 0) {
                if ((((int32)destPixel) & 3) != 0 &&
                    (((int32)srcPixel) & 3) != 0) {
                    *destPixel++ = *srcPixel++;
                    actualLen--;
                }

                if (actualLen > 0)
                    memcpy2(destPixel, srcPixel, actualLen * 2);
            }
        }

        if (hasNext) /*存在剩余的像素不在标识区*/
        {
            hasNext = 0;
            startPixel = nextPixel;
            startPixel = startPixel > sx ? startPixel : sx;

            srcPixel = srcLine + startPixel;
            destPixel = destLine + (startPixel - sx);

            for (k = startPixel; k < sx + width; k++) {
                if (*srcPixel != pTransBitmap->transColor) *destPixel = *srcPixel;
                destPixel++;
                srcPixel++;
            }
        }

        srcLine += pTransBitmap->maxWidth;
        destLine += dest_maxW;
        mm += pTransBitmap->markCount * 2;
    }

    return 0;
}

void _DrawBitmapEx(mr_bitmapDrawSt *srcbmp, mr_bitmapDrawSt *dstbmp, uint16 w, uint16 h, mr_transMatrixSt *pTrans, uint16 transcoler) {
    int32 A = pTrans->A;
    int32 B = pTrans->B;
    int32 C = pTrans->C;
    int32 D = pTrans->D;
    //uint16 rop = pTrans->rop;
    uint16 *dstp, *srcp;
    int16 CenterX = dstbmp->x + w / 2;
    int16 CenterY = dstbmp->y + h / 2;
    int32 dx, dy;
    int32 I = A * D - B * C;
    int16 MaxY = (ABS(C) * w + ABS(D) * h) >> 9;
    int16 MinY = 0 - MaxY;

    MaxY = MIN(MaxY, dstbmp->h - CenterY);
    MinY = MAX(MinY, 0 - CenterY);

    for (dy = MinY; dy < MaxY; dy++) {
        int16 MaxX = (int16)MIN(D == 0 ? 999 : (MAX((((w * I) >> 9) + B * dy) / D, (B * dy - ((w * I) >> 9)) / D)),
                                C == 0 ? 999 : (MAX((A * dy + ((h * I) >> 9)) / C, (A * dy - ((h * I) >> 9)) / C)));
        int16 MinX = (int16)MAX(D == 0 ? -999 : (MIN((B * dy - ((w * I) >> 9)) / D, (((w * I) >> 9) + B * dy) / D)),
                                C == 0 ? -999 : (MIN((A * dy - ((h * I) >> 9)) / C, (A * dy + ((h * I) >> 9)) / C)));
        MaxX = MIN(MaxX, dstbmp->w - CenterX);
        MinX = MAX(MinX, 0 - CenterX);
        dstp = dstbmp->p + (dy + CenterY) * dstbmp->w + (MinX + CenterX);
        switch (pTrans->rop) {
            case BM_TRANSPARENT:
                for (dx = MinX; dx < MaxX; dx++) {
                    int32 offsety = ((A * dy - C * dx) << 8) / I + h / 2;
                    int32 offsetx = ((D * dx - B * dy) << 8) / I + w / 2;
                    if (((offsety < h) && (offsety >= 0)) && ((offsetx < w) && (offsetx >= 0))) {
                        srcp = srcbmp->p + (offsety + srcbmp->y) * srcbmp->w + (offsetx + srcbmp->x);
                        //if (!((rop == BM_TRANSPARENT) && (*srcp == transcoler)))
                        if (*srcp != transcoler)
                            *dstp = *srcp;
                    }
                    dstp++;
                }
                break;
            case BM_COPY:
                for (dx = MinX; dx < MaxX; dx++) {
                    int32 offsety = ((A * dy - C * dx) << 8) / I + h / 2;
                    int32 offsetx = ((D * dx - B * dy) << 8) / I + w / 2;
                    if (((offsety < h) && (offsety >= 0)) && ((offsetx < w) && (offsetx >= 0))) {
                        srcp = srcbmp->p + (offsety + srcbmp->y) * srcbmp->w + (offsetx + srcbmp->x);
                        //if (!((rop == BM_TRANSPARENT) && (*srcp == transcoler)))
                        *dstp = *srcp;
                    }
                    dstp++;
                }
                break;
        }
    }
}
