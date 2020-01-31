#include "./header/memory.h"

#define HEAP_ALIGNMENT 4

typedef struct Block {
    size_t addr;
    size_t size;
    struct Block *prev;
    struct Block *next;
} Block;

static Block *freeList;
static Block *usedList;

static void printList(Block *list) {
    printf("==================\n");
    while (list != NULL) {
        printf("[addr:%I64d, size:%I64d", list->addr, list->size);
        printf(", prev:%I64d", list->prev ? list->prev->addr : 0);
        printf(", next:%I64d]\n", list->next ? list->next->addr : 0);
        list = list->next;
    }
    printf("==================\n\n");
}

static Block *newBlock(size_t addr, size_t size) {
    Block *ptr = malloc(sizeof(Block));
    ptr->addr = addr;
    ptr->size = size;
    ptr->next = NULL;
    ptr->prev = NULL;
    return ptr;
}

static void insertFreeBlock(Block *block) {
    Block *ptr = freeList;
    if (ptr == NULL) {
        // printf("%I64d insert to head\n", block->addr);
        block->prev = NULL;
        block->next = NULL;
        freeList = block;
        return;
    }
    Block *prev = NULL;
    do {
        if (block->addr <= ptr->addr) {  // 按从小到大的顺序插入
            // printf("%I64d insert before %I64d\n", block->addr, ptr->addr);
            if (ptr->prev != NULL) {
                ptr->prev->next = block;
            } else {
                freeList = block;
            }
            block->prev = ptr->prev;
            block->next = ptr;
            ptr->prev = block;
            return;
        }
        prev = ptr;
        ptr = ptr->next;
    } while (ptr != NULL);

    // printf("%I64d add to tail\n", block->addr);
    prev->next = block;
    block->prev = prev;
    block->next = NULL;
}

bool freeMem(size_t addr) {
    Block *block = usedList;
    while (block != NULL) {
        if (addr == block->addr) {
            if (block->prev) {
                block->prev->next = block->next;
                if (block->next) block->next->prev = block->prev;
            } else {
                usedList = block->next;
                usedList->prev = NULL;
            }
            insertFreeBlock(block);
            return true;
        }
        block = block->next;
    }
    return false;
}

static void freeAllMem() {
    Block *ptr;
    while (usedList != NULL) {
        ptr = usedList;
        usedList = usedList->next;
        insertFreeBlock(ptr);
    }
}

static void compact() {
    Block *ptr = freeList;
    Block *prev;
    Block *scan;
    while (ptr != NULL) {
        prev = ptr;
        scan = ptr->next;
        while (scan != NULL && prev->addr + prev->size == scan->addr) {
            // printf("merge %I64d\n", scan->addr);
            prev = scan;
            scan = scan->next;
        }
        if (prev != ptr) {
            size_t new_size = prev->addr - ptr->addr + prev->size;
            // printf("new size %I64d\n", new_size);
            ptr->size = new_size;
            Block *next = prev->next;

            Block *tmp = ptr->next;
            Block *tmp_next;
            while (tmp != prev->next) {
                // printf("compact-> %I64d\n", tmp->addr);
                tmp_next = tmp->next;
                free(tmp);
                tmp = tmp_next;
            }

            ptr->next = next;
            if (next) next->prev = ptr;
        }
        ptr = ptr->next;
    }
}

static void insertUsedBlock(Block *block) {
    if (usedList) {
        usedList->prev = block;
        block->next = usedList;
        usedList = block;
    } else {
        usedList = block;
        usedList->next = NULL;
        usedList->prev = NULL;
    }
}

static size_t alloc(size_t num) {
    if (freeList == NULL || num == 0) {
        return 0;
    }
    num = (num + HEAP_ALIGNMENT - 1) & -HEAP_ALIGNMENT;
    Block *scan = freeList;
    Block *ptr = NULL;
    int min;
    int tmp;
    while (scan != NULL) {
        tmp = scan->size - num;
        if (tmp >= 0) {
            if (ptr == NULL || tmp <= min) {
                min = tmp;
                ptr = scan;
            }
        }
        scan = scan->next;
    }
    if (ptr == NULL) {
        return 0;
    }
    if (ptr->prev) {
        ptr->prev->next = ptr->next;
    } else {
        freeList = ptr->next;
    }
    if (ptr->next) {
        ptr->next->prev = ptr->prev;
    }

    if (min >= HEAP_ALIGNMENT) {
        // printf("allocMem: %I64d %I64d\n", num, min);
        insertFreeBlock(newBlock(ptr->addr + num, min));
        ptr->size = num;
    }
    insertUsedBlock(ptr);
    return ptr->addr;
}

size_t allocMem(size_t num) {
    size_t v = alloc(num);
    if (v == 0) {
        compact();
        return alloc(num);
    }
    return v;
}

static size_t countBlocks(Block *ptr) {
    size_t num = 0;
    while (ptr != NULL) {
        num++;
        ptr = ptr->next;
    }
    return num;
}

void initMemoryManager(size_t baseAddress, size_t len) {
    insertFreeBlock(newBlock(baseAddress, len));
    printList(freeList);
}

void test() {
    // Block *b1 = newBlock(10000, 12);
    // Block *b2 = newBlock(10012, 24);
    // Block *b3 = newBlock(10036, 16);
    // Block *b4 = newBlock(10056, 48);
    // Block *b4b = newBlock(10104, 4);
    // Block *b5 = newBlock(10200, 8);
    // Block *b5b = newBlock(10208, 8);

    // insertFreeBlock(b2);
    // insertFreeBlock(b3);
    // insertFreeBlock(b1);
    // insertFreeBlock(b5);
    // insertFreeBlock(b4);
    // insertFreeBlock(b4b);
    // insertFreeBlock(b5b);

    insertFreeBlock(newBlock(10000, 10));

    printList(freeList);
    // compact();
    // printList(freeList);
    printf("======================================\n");

    printf("freeList: %I64d\n", countBlocks(freeList));
    printf("usedList: %I64d\n", countBlocks(usedList));

    printf("%I64d\n", allocMem(12));
    printf("%I64d\n", allocMem(12));
    printf("%I64d\n", allocMem(4));
    printf("%I64d\n", allocMem(8));
    printf("%I64d\n", allocMem(8));
    printf("%I64d\n", allocMem(12));
    printf("%I64d\n", allocMem(48));
    printf("%I64d\n", allocMem(48));

    // [addr:10024, size:12, prev:0, next:10048]
    // [addr:10048, size:4, prev:10024, next:0]
    printf("alloc 0: %I64d\n", allocMem(0));
    printf("alloc 4: %I64d\n", allocMem(4));
    printf("alloc 6: %I64d\n", allocMem(6));
    printf("alloc 9: %I64d\n", allocMem(9));
    printf("alloc 4: %I64d\n", allocMem(4));
    printf("alloc 4: %I64d\n", allocMem(4));

    printList(freeList);
    printf("freeList: %I64d\n", countBlocks(freeList));
    printf("usedList: %I64d\n", countBlocks(usedList));
    printList(usedList);

    freeMem(10036);
    printList(usedList);

    printList(freeList);
    printf("freeList: %I64d\n", countBlocks(freeList));
    printf("usedList: %I64d\n", countBlocks(usedList));

    printf("\nfreeAllMem(): -----------------------------\n");
    freeAllMem();
    compact();
    printList(freeList);
    printf("freeList: %I64d\n", countBlocks(freeList));
    printf("usedList: %I64d\n", countBlocks(usedList));
}
