#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define HEAP_ALIGNMENT 4

typedef struct Block {
    size_t addr;
    size_t size;
    struct Block *prev;
    struct Block *next;
} Block;

static Block *freeList;
static Block *usedList;

void printList(Block *list) {
    printf("==================\n");
    while (list != NULL) {
        printf("[addr:%d, size:%d", list->addr, list->size);
        printf(", prev:%d", list->prev ? list->prev->addr : 0);
        printf(", next:%d]\n", list->next ? list->next->addr : 0);
        list = list->next;
    }
    printf("==================\n\n");
}

Block *newBlock(size_t addr, size_t size) {
    Block *ptr = malloc(sizeof(Block));
    ptr->addr = addr;
    ptr->size = size;
    ptr->next = NULL;
    ptr->prev = NULL;
}

static void insertFreeBlock(Block *block) {
    Block *ptr = freeList;
    if (ptr == NULL) {
        printf("%d insert to head\n", block->addr);
        block->prev = NULL;
        block->next = NULL;
        freeList = block;
        return;
    }
    Block *prev = NULL;
    do {
        if (block->addr <= ptr->addr) {
            printf("%d insert before %d\n", block->addr, ptr->addr);
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

    printf("%d add to tail\n", block->addr);
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

void freeAllMem() {
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
            printf("merge %d\n", scan->addr);
            prev = scan;
            scan = scan->next;
        }
        if (prev != ptr) {
            size_t new_size = prev->addr - ptr->addr + prev->size;
            printf("new size %d\n", new_size);
            ptr->size = new_size;
            Block *next = prev->next;

            Block *tmp = ptr->next;
            Block *tmp_next;
            while (tmp != prev->next) {
                printf("release-> %d\n", tmp->addr);
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

void insertUsedBlock(Block *block) {
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

size_t allocMem(size_t num) {
    if (freeList == NULL) {
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
        printf("allocMem: %d %d\n", num, min);
        insertFreeBlock(newBlock(ptr->addr + num, min));
        ptr->size = num;
    }
    insertUsedBlock(ptr);
    return ptr->addr;
}

static size_t countBlocks(Block *ptr) {
    size_t num = 0;
    while (ptr != NULL) {
        num++;
        ptr = ptr->next;
    }
    return num;
}

void main() {
    Block *b1 = newBlock(10000, 12);
    Block *b2 = newBlock(10012, 24);
    Block *b3 = newBlock(10036, 16);
    Block *b4 = newBlock(10056, 48);
    Block *b4b = newBlock(10104, 4);
    Block *b5 = newBlock(10200, 8);
    Block *b5b = newBlock(10208, 8);

    insertFreeBlock(b2);
    insertFreeBlock(b3);
    insertFreeBlock(b1);
    insertFreeBlock(b5);
    insertFreeBlock(b4);
    insertFreeBlock(b4b);
    insertFreeBlock(b5b);

    printList(freeList);
    // compact();
    // printList(freeList);
    printf("======================================\n");

    printf("freeList: %d\n", countBlocks(freeList));
    printf("usedList: %d\n", countBlocks(usedList));

    printf("%d\n", allocMem(12));
    printf("%d\n", allocMem(12));
    printf("%d\n", allocMem(4));
    printf("%d\n", allocMem(8));
    printf("%d\n", allocMem(8));
    printf("%d\n", allocMem(12));
    printf("%d\n", allocMem(48));
    printf("%d\n", allocMem(48));

    printList(freeList);
    printf("freeList: %d\n", countBlocks(freeList));
    printf("usedList: %d\n", countBlocks(usedList));
    printList(usedList);

    freeMem(10036);
    printList(usedList);

    printList(freeList);
    printf("freeList: %d\n", countBlocks(freeList));
    printf("usedList: %d\n", countBlocks(usedList));

    printf("\nfreeAllMem(): -----------------------------\n");
    freeAllMem();
    compact();
    printList(freeList);
    printf("freeList: %d\n", countBlocks(freeList));
    printf("usedList: %d\n", countBlocks(usedList));
}
