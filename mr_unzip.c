

#include "./include/mr.h"
#include "./include/mr_gzip.h"
#include "./include/mythroad.h"


/* Globals */

//int mr_decrypt;        /* flag to turn on decryption */
//char *key;          /* not used--needed to link crypt.c */
//int pkzip = 0;      /* set for a pkzip file */

/* ===========================================================================
 * Unzip in to out.  This routine works on both gzip and pkzip files.
 *
 * IN assertions: the buffer inbuf contains already the beginning of
 *   the compressed data, from offsets inptr to insize-1 included.
 *   The magic header has already been checked. The output buffer is cleared.
 */
int mr_unzip(void) {
    ulg orig_crc = 0; /* original crc */
    ulg orig_len = 0; /* original uncompressed length */
    int n;
    uch buf[EXTHDR]; /* extended local header */

    MRDBGPRINTF("mr_unzip");
    mr_updcrc(NULL, 0); /* initialize crc */

    /* Decompress */
    {
        int res = mr_inflate();

        if (res == 3) {
            MRDBGPRINTF("out of memory");
            return -1;
        } else if (res != 0) {
            MRDBGPRINTF("invalid compressed data--format violated");
            return -1;
        }
    }

    /* Get the crc and original length */
    /* crc32  (see algorithm.doc)
	 * uncompressed input size modulo 2^32
         */
#ifdef MR_PKZIP_MAGIC
    if (mr_zipType == PACKED) {
        orig_crc = LG(mr_gzInBuf + LOCCRC);
        orig_len = LG(mr_gzInBuf + LOCLEN);
    }
    for (n = 0; n < 8; n++) {
        buf[n] = (uch)get_byte(); /* may cause an error if EOF */
    }
    if (mr_zipType != PACKED) {
        orig_crc = LG(buf);
        orig_len = LG(buf + 4);
    }
#else
    for (n = 0; n < 8; n++) {
        buf[n] = (uch)get_byte(); /* may cause an error if EOF */
    }
    orig_crc = LG(buf);
    orig_len = LG(buf + 4);
#endif

    /* Validate decompression */
    if (orig_crc != mr_updcrc(mr_gzOutBuf, 0)) {
        MRDBGPRINTF("invalid compressed data--crc error");  //ouli importent  need fix
    }
    if (orig_len != (ulg)LG_gzoutcnt) {
        MRDBGPRINTF("invalid compressed data--length error");
    }

    /* Check if there are more entries in a pkzip file */
    return 0;
}

#ifdef MR_PKZIP_MAGIC

/* ===========================================================================
 * Check zip file and advance inptr to the start of the compressed data.
 * Get ofname from the local header if necessary.
 */
static int mr_check_zipfile(int32 buf_len) {
    uch *h = mr_gzInBuf + LG_gzinptr; /* first local header */
    int method, decrypt;              /* compression method */

    /* Check validity of local header, and skip name and extra fields */
    LG_gzinptr += LOCHDR + SH(h + LOCFIL) + SH(h + LOCEXT);

    if (LG_gzinptr > buf_len || LG(h) != LOCSIG) {
        return MR_FAILED;
    }
    method = h[LOCHOW];
    if (method != DEFLATED) {
        return MR_FAILED;
    }

    /* If entry encrypted, decrypt and validate encryption header */
    if ((decrypt = h[LOCFLG] & CRPFLG) != 0) {
        return MR_FAILED;
    }

    /* Get ofname and time stamp from local header (to be done) */
    return MR_SUCCESS;
}
#endif

int mr_get_method(int32 buf_len) {
    uch flags;     /* compression flags */
    char magic[2]; /* magic header */
    ulg stamp;     /* time stamp */
    int method;    /* compression method */

    MRDBGPRINTF("mr_get_method(%d)", buf_len);
#ifdef MR_PKZIP_MAGIC
    mr_zipType = DEFLATED;
#endif

#if 0
	MRDBGPRINTF("check:%d,%d,%d,%d",mr_gzInBuf[0],mr_gzInBuf[1],mr_gzInBuf[2],LG_gzinptr);
#endif

    magic[0] = (char)get_byte();
    magic[1] = (char)get_byte();
    method = -1; /* unknown yet */
                 //    part_nb++;                   /* number of parts in gzip file */
    //header_bytes = 0;
    //    last_member = RECORD_IO;
    /* assume multiple members in gzip file except for record oriented I/O */

    if (memcmp2(magic, GZIP_MAGIC, 2) == 0 || memcmp2(magic, OLD_GZIP_MAGIC, 2) == 0) {
        method = (int)get_byte();
        if (method != DEFLATED) {
            MRDBGPRINTF("unknown method");
            return -1;
        }
        //work = unzip;
        flags = (uch)get_byte();

        if ((flags & ENCRYPTED) != 0) {
            MRDBGPRINTF("is encrypted");
            return -1;
        }
        if ((flags & CONTINUATION) != 0) {
            MRDBGPRINTF("is a a multi-part gzip file");
            return -1;
        }
        if ((flags & RESERVED) != 0) {
            MRDBGPRINTF("has RESERVED flags");
            return -1;
        }
        stamp = (ulg)get_byte();
        stamp |= ((ulg)get_byte()) << 8;
        stamp |= ((ulg)get_byte()) << 16;
        stamp |= ((ulg)get_byte()) << 24;
        //	if (stamp != 0 && !no_time) time_stamp = stamp;

        (void)get_byte(); /* Ignore extra flags for the moment */
        (void)get_byte(); /* Ignore OS type for the moment */

        if ((flags & EXTRA_FIELD) != 0) {
            unsigned len = (unsigned)get_byte();
            len |= ((unsigned)get_byte()) << 8;
            while (len--) (void)get_byte();
        }

        /* Get original file name if it was truncated */
        if ((flags & ORIG_NAME) != 0) {
            /* Discard the old name */
            char c; /* dummy used for NeXTstep 3.0 cc optimizer bug */
            do {
                c = get_byte();
            } while (c != 0);
        } /* ORIG_NAME */

        /* Discard file comment if any */
        if ((flags & COMMENT) != 0) {
            while (get_byte() != 0) /* null */
                ;
        }

    }
#ifdef MR_PKZIP_MAGIC
    else if (MEMCMP((char *)mr_gzInBuf, PKZIP_MAGIC, 4) == 0) {
        /* To simplify the code, we support a zip file when alone only.
         * We are thus guaranteed that the entire local header fits in inbuf.
         */
        mr_zipType = PACKED;
        LG_gzinptr = 0;
        method = DEFLATED;
        //work = unzip;
        if (mr_check_zipfile(buf_len) != MR_SUCCESS) return -1;
    }
#endif

    if (method >= 0) return method;

    MRDBGPRINTF("nozip");
    return -1;
}
