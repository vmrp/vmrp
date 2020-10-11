#include "./header/utils.h"
#include "./header/fileLib.h"

// 只支持240*320大小
void printScreen(char *filename, uint16_t *buf) {
    // clang-format off
    unsigned char bmpHeader[70] =
    {
        0x42, 0x4D, 0x48, 0x58, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x38, 0x00, 
        0x00, 0x00, 0xF0, 0x00, 0x00, 0x00, 0xC0, 0xFE, 0xFF, 0xFF, 0x01, 0x00, 0x10, 0x00, 0x03, 0x00, 
        0x00, 0x00, 0x02, 0x58, 0x02, 0x00, 0x12, 0x0B, 0x00, 0x00, 0x12, 0x0B, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x00, 0x00, 0xE0, 0x07, 0x00, 0x00, 0x1F, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    } ;
    // clang-format on

    int fh = my_open(filename, MR_FILE_CREATE | MR_FILE_RDWR);

    my_write(fh, bmpHeader, sizeof(bmpHeader));

    my_write(fh, buf, 240*320*2);

    uint16_t end = 0;
    my_write(fh, &end, sizeof(end));

    my_close(fh);
}

char *memTypeStr(uc_mem_type type) {
    // clang-format off
	switch (type)
	{
    case UC_MEM_READ:return "UC_MEM_READ";
    case UC_MEM_WRITE:return "UC_MEM_WRITE";
    case UC_MEM_FETCH:return "UC_MEM_FETCH";
    case UC_MEM_READ_UNMAPPED:return "UC_MEM_READ_UNMAPPED";
    case UC_MEM_WRITE_UNMAPPED:return "UC_MEM_WRITE_UNMAPPED";
    case UC_MEM_FETCH_UNMAPPED:return "UC_MEM_FETCH_UNMAPPED";
    case UC_MEM_WRITE_PROT:return "UC_MEM_WRITE_PROT";
    case UC_MEM_READ_PROT:return "UC_MEM_READ_PROT";
    case UC_MEM_FETCH_PROT:return "UC_MEM_FETCH_PROT";
    case UC_MEM_READ_AFTER:return "UC_MEM_READ_AFTER";
	}
    // clang-format on
    return "<error type>";
}

void dumpREG(uc_engine *uc) {
    uint32_t v;

    // clang-format off
    printf("===========REG=============\n");
    uc_reg_read(uc, UC_ARM_REG_R0, &v); printf("R0=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R1, &v); printf("R1=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R2, &v); printf(" R2=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R3, &v); printf(" R3=0x%08X\n", v);

    uc_reg_read(uc, UC_ARM_REG_R4, &v); printf("R4=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R5, &v); printf("R5=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R6, &v); printf(" R6=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R7, &v); printf(" R7=0x%08X\n", v);

    uc_reg_read(uc, UC_ARM_REG_R8, &v); printf("R8=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R9, &v); printf("R9=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R10, &v); printf("R10=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_R11, &v); printf("R11=0x%08X\n", v);

    uc_reg_read(uc, UC_ARM_REG_R12, &v); printf("R12=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_SP, &v); printf("SP=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_LR, &v); printf(" LR=0x%08X\t", v);
    uc_reg_read(uc, UC_ARM_REG_PC, &v); printf(" PC=0x%08X\n", v);
    printf("===========================\n");
    // clang-format on
}

void dumpMemStr(void *ptr, size_t len) {
    char *p = ptr;
    for (int i = 0; i < len; i++) {
        if (isgraph(*p)) {
            putchar(*p);
        } else {
            putchar('.');
        }
        p++;
    }
}

void runCode(uc_engine *uc, uint32_t startAddr, uint32_t stopAddr, bool isThumb) {
    uint32_t value = stopAddr;
    uc_reg_write(uc, UC_ARM_REG_LR, &value);  // 当程序执行到这里时停止运行(return)

    // Note we start at ADDRESS | 1 to indicate THUMB mode.
    startAddr = isThumb ? (startAddr | 1) : startAddr;
    uc_err err = uc_emu_start(uc, startAddr, stopAddr, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n", err, uc_strerror(err));
        exit(1);
    }
}

#define BUF_LEN (1024 * 1024)  // 1M内存
char *getStrFromUc(uc_engine *uc, uint32_t addr) {
    char *buf = malloc(BUF_LEN);
    uint8_t v;
    uint8_t i = 0;
    do {
        uc_mem_read(uc, addr, &v, 1);
        buf[i] = v;
        addr++;
        i++;
    } while (v && i < BUF_LEN - 1);
    buf[i] = '\0';
    return buf;
}

//////////////////////////////////////////////////////////////////////////////

uIntMap *uIntMap_search(struct rb_root *root, uint32_t key) {
    struct rb_node *n = root->rb_node;
    uIntMap *obj;
    int cmp;

    while (n) {
        obj = rb_entry(n, uIntMap, node);

        cmp = key - obj->key;
        if (cmp < 0) {
            n = n->rb_left;
        } else if (cmp > 0) {
            n = n->rb_right;
        } else {
            return obj;
        }
    }
    return NULL;
}

int uIntMap_insert(struct rb_root *root, uIntMap *obj) {
    struct rb_node **p = &(root->rb_node);
    struct rb_node *parent = NULL;
    uIntMap *cur;
    int cmp;

    while (*p) {
        parent = *p;
        cur = rb_entry(parent, uIntMap, node);
        cmp = obj->key - cur->key;
        if (cmp < 0) {
            p = &(*p)->rb_left;
        } else if (cmp > 0) {
            p = &(*p)->rb_right;
        } else {
            return -1;
        }
    }
    rb_link_node(&obj->node, parent, p);
    rb_insert_color(&obj->node, root);
    return 0;
}

uIntMap *uIntMap_delete(struct rb_root *root, uint32_t key) {
    uIntMap *obj = uIntMap_search(root, key);
    if (!obj) {
        return NULL;
    }
    rb_erase(&obj->node, root);
    return obj;
}

static void testInsert(struct rb_root *root, uint32_t key, void *data) {
    uIntMap *obj;
    int ret;

    obj = malloc(sizeof(uIntMap));
    obj->key = key;
    obj->data = data;
    ret = uIntMap_insert(root, obj);
    if (ret == -1) {
        printf("insert failed %d exists.\n", key);
        return;
    }
    printf("insert %d success.\n", key);
}

static void testSearch(struct rb_root *root, uint32_t key) {
    uIntMap *obj = uIntMap_search(root, key);
    if (obj == NULL) {
        printf("search: not found %d\n", key);
    } else {
        printf("search: %d=%s\n", key, (char *)obj->data);
    }
}

static void printAll(struct rb_root *root) {
    for (struct rb_node *p = rb_first(root); p; p = rb_next(p)) {
        uIntMap *obj = rb_entry(p, uIntMap, node);
        printf("iterator: %d  \t  %s\n", obj->key, (char *)obj->data);
    }
}

static void testDelete(struct rb_root *root, uint32_t key) {
    uIntMap *obj = uIntMap_delete(root, key);
    if (obj != NULL) {
        printf("delete %d %s\n", obj->key, (char *)obj->data);
        free(obj);
    } else {
        printf("delete %d not found\n", key);
    }
}

void uIntMap_testMain() {
    struct rb_root root = RB_ROOT;

    testInsert(&root, 100, "hell");
    testInsert(&root, 0, "world");
    testInsert(&root, 0, "world2");
    testInsert(&root, 990, "test");

    printAll(&root);

    testSearch(&root, 990);
    testSearch(&root, 22);

    testDelete(&root, 990);
    testDelete(&root, 990);
    testSearch(&root, 990);

    printAll(&root);
    testInsert(&root, 990, "test2");
    printAll(&root);
}