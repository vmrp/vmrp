
// 这些函数必需单独编译，否则编译出来的结果会有问题

void mr_helper_set_r9(void* data) {
#ifndef __GNUC__
    __asm { mov sb, data }
#endif
}