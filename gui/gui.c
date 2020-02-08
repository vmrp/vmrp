#include "gui.h"

void event(int code, int p1, int p2)
{
    switch (code)
    {
    case MOUSE_DOWN:
        printf("MOUSE_DOWN x:%d y:%d\n", p1, p2);
        break;
    case MOUSE_UP:
        printf("MOUSE_UP x:%d y:%d\n", p1, p2);
        break;
    case MOUSE_MOVE:
        printf("MOUSE_MOVE x:%d y:%d\n", p1, p2);
        break;
    }
    setPixel(p1, p2, 255, 255, 0);
    refresh();
}
