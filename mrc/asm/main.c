#include "mrc_base.h"
/*
生成汇编代码，-O0 关闭优化， -fs 汇编代码中加入c语言源文件注释
armcc -O0 -S -fs a.c
生成thumb代码只需要把armcc改成tcc
*/
char c_isLittleEndian1(){
    union {
        int v;
        char isLittleEndian;
    }check;
    check.v = 1;
    return check.isLittleEndian;
}

char c_isLittleEndian2(){
    int i = 1;
    char j = *((char*)&i);
    return j;
}

int c_add(int a ,int b) {
    int c = a+b;
    return c;
}

int32 mrc_init(void)
{

    mrc_clearScreen(0,0,0);
#ifdef WIN32
    mrc_drawText("hello win32!",0,0,255,255,255,0,1);
#else
    if(isLittleEndian()){
        mrc_drawText("hello LittleEndian!",0,0,255,255,255,0,1);
    }else{
        mrc_drawText("hello BigEndian!",0,0,255,255,255,0,1);
    }

    {
        long a=65539,b=65539,c=0;
        char buf[32];
        
        c = FixedByFrac(a, b);
        mrc_sprintf(buf, "%d * %d = %d", a, b, c);
        mrc_drawText(buf,0,22,255,255,255,0,1);
    }
#endif
    if(c_isLittleEndian1()){
        mrc_drawText("hello cLittleEndian!",0,100,255,0,0,0,1);
    }else{
        mrc_drawText("hello cBigEndian!",0,100,255,0,0,0,1);
    }
    mrc_refreshScreen(0,0,240,320);
	return MR_SUCCESS;
}

int32 mrc_exitApp(void)
{	
	return MR_SUCCESS;
}

int32 mrc_event(int32 code, int32 param0, int32 param1)
{
    char buf[64];

    mrc_sprintf(buf,"code=%d, p0=%d, p1=%d", code, param0, param1);
    //mrc_clearScreen(255,255,255);
    mrc_drawRect(0,50,240,30,255,255,255);
    mrc_drawText(buf,0,50,255,0,0,0,1);
    mrc_refreshScreen(0,0,240,320);
    return MR_SUCCESS;
}

int32 mrc_pause()
{
    return MR_SUCCESS;	
}

int32 mrc_resume()
{
	return MR_SUCCESS;
}

int32 mrc_extRecvAppEventEx(int32 code, int32 param0, int32 param1){
    return MR_SUCCESS;
}

int32 mrc_extRecvAppEvent(int32 app, int32 code, int32 param0, int32 param1){
    return MR_SUCCESS;
}


