
// 这些函数必需单独编译，否则编译出来的结果会有问题

//RW：程序中已经初始化的变量所占空间
//ZI：未初始化的static变量和全局变量以及堆栈所占的空间
extern unsigned int Image$$ER_RW$$Length;
extern unsigned int Image$$ER_ZI$$ZI$$Length;
extern unsigned int Image$$ER_RO$$Length;
unsigned int mr_helper_get_rw_len() {
    return (unsigned int)&Image$$ER_RW$$Length + (unsigned int)&Image$$ER_ZI$$ZI$$Length;
}
unsigned int mr_helper_get_rw_lenOnly() {
    return (unsigned int)&Image$$ER_RW$$Length;
}
unsigned int mr_helper_get_ro_len() {
    return (unsigned int)&Image$$ER_RO$$Length;
}