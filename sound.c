

#include "./header/types.h"
#include <stdio.h>
#if defined(WIN32)
#include <windows.h>
#include <io.h>
#pragma comment(lib, "Winmm.lib")            //For MCI(Media Control Interface，媒体控制接口)
#endif

#include "./header/sound.h"


/* 要使用以下所有接口请在你的代码中增加“#include "base.h"”和“#include "sound.h"” */


//系统没有预先定义以下结构




static char *FILELIST[10];

/*
设备初始化 每次播放前需调用
[in]:播放设备类型0-4，总共支持5个设备
[return]: 0 初始化成功
-1 初始化失败
1 不支持该功能
*/
int32 soundinit(int32 type){
   #if defined(WIN32)
   if(FILELIST[type]==NULL){
   char *FILENAME = (char *)malloc(300);
   FILELIST[type] = FILENAME;
   }
   #endif
   
}

/*
加载音频文件
[in]
type:设备类型
filename:数据文件名称，相对路径，GB编码，这里注意的是从apk外部读取文件
[return]: 0 初始化成功
-1 初始化失败
1 不支持该功能
*/
int32 soundloadfile(int32 type, char* filename){
    #if defined(WIN32)
    strcpy(FILELIST[type],filename);
    #endif
}

/*
播放音频文件
[in]
type:设备类型
block:1：阻塞式向底层发送播放请求；0：非阻塞凡是向底层发送播放请求
loop:0：单次播放；1：循环播放；2：nes pcm 播放方式
[return]: 0 初始化成功
-1 初始化失败
1 不支持该功能
*/
int32 soundplay(int32 type, int32 block, int32 loop){
    #if defined(WIN32)
     char temp[300];
     sprintf(temp,"play %s", FILELIST[type]);
     mciSendString(temp,        //MCI命令字符串
        NULL,                                //存放反馈信息的缓冲区
        0,                                    //缓冲区的长度
        NULL);                                //回调窗体的句柄，一般为NULL
    #endif
}

/*
暂停播放音频文件
[in]
type:设备类型
[return]: 0 初始化成功
-1 初始化失败
1 不支持该功能
*/
int32 soundpause(int32 type){
    #if defined(WIN32)
    char temp[300];
     sprintf(temp,"pause %s", FILELIST[type]);
     mciSendString(temp,        //MCI命令字符串
        NULL,                                //存放反馈信息的缓冲区
        0,                                    //缓冲区的长度
        NULL);                                //回调窗体的句柄，一般为NULL
    #endif
}

/*
继续播放音频文件
[in]
type:设备类型
[return]: 0 初始化成功
-1 初始化失败
1 不支持该功能
*/

int32 soundresume(int32 type){
    #if defined(WIN32)
    char temp[300];
     sprintf(temp,"play %s", FILELIST[type]);
     mciSendString(temp,        //MCI命令字符串
        NULL,                                //存放反馈信息的缓冲区
        0,                                    //缓冲区的长度
        NULL);                                //回调窗体的句柄，一般为NULL
    #endif
}
/*
停止播放音频文件
[in]
type:设备类型
[return]: 0 初始化成功
-1 初始化失败
1 不支持该功能
*/

int32 soundstop(int32 type){
    #if defined(WIN32)
char temp[300];
     sprintf(temp,"stop %s", FILELIST[type]);
     mciSendString(temp,        //MCI命令字符串
        NULL,                                //存放反馈信息的缓冲区
        0,                                    //缓冲区的长度
        NULL);                                //回调窗体的句柄，一般为NULL
    #endif
}
/*
关闭设备
[in]
type:设备类型
[return]: 0 初始化成功
-1 初始化失败
1 不支持该功能
*/
int32 soundclose(int32 type){
    #if defined(WIN32)
    char temp[300];
     sprintf(temp,"stop %s", FILELIST[type]);
     mciSendString(temp,        //MCI命令字符串
        NULL,                                //存放反馈信息的缓冲区
        0,                                    //缓冲区的长度
        NULL);                                //回调窗体的句柄，一般为NULL
    #endif
return 0;
}

/*
音量调节
[in]
volume:音量大小0~5
[return]: 0 初始化成功
-1 初始化失败
1 不支持该功能
*/
int32 setvolume(int32 volume){
    return 0;
}

/*
获取音乐的总时间秒S
[out]
p:指向这个数据结构（T_DSM_AUDIO_POS）的指针的指针，
这个数据结构的值就是总的时间
[return]: 0 初始化成功
-1 初始化失败
1 不支持该功能

注：mtk上此接口在以文件形式播放的时候有效。
*/
int32 getsoundtotaltime(int32 type, uint8** p){
    return 0;
}


/* 获取当前已经播放的时间秒S
[out]
p:指向这个数据结构（T_DSM_AUDIO_POS）的指针的指针，
这个数据结构的值就是已经播放的时间
[return]: 0 初始化成功
-1 初始化失败
1 不支持该功能

注：mtk上此接口在以文件形式播放的时候有效。 */

int32 getsoundcurtime(int32 type, uint8** p){
    return 0;
}


/*
获取当前已经播放的时间毫秒ms
[out]
p:指向这个数据结构（T_DSM_AUDIO_POS）的指针的指针，
这个数据结构的值就是已经播放的时间
[return]: 0 初始化成功
-1 初始化失败
1 不支持该功能

注：mtk上此接口在以文件形式播放的时候有效。
*/

int32 getsoundcurtimems(int32 type, uint8** p){
    return 0;
}


/*
设置播放位置，相对文件或者缓冲的起始位置的偏移量
［IN］
SOUND_POS pos：相对文件或者缓冲的起始位置的偏移量
[return]: 0 初始化成功
-1 初始化失败
1 不支持该功能
*/
int32 setplaypos(int32 type,T_DSM_AUDIO_POS* pos){
    return 0;
}


/*
设置播放时间，相对文件或者缓冲的起始时间的偏移量
［IN］
SOUND_POS pos：相对文件或者缓冲的起始时间的偏移量，单位：ms
[return]: 0 初始化成功
-1 初始化失败
1 不支持该功能
*/
int32 setplaytime(int32 type,T_DSM_AUDIO_POS* pos){
    return 0;
}

/*
获取当前设备的状态
［IN］
无
［return］
设备状态值 成功
-1 初始化失败
1 不支持该功能

*/
int32 getdevicestate(int32 type){
    return 0;
}

/*播放音频数据*/
int32 mr_playSound(int type, const void* data, uint32 dataLen, int32 loop){
    #if defined(WIN32)
    if(FILELIST[type]==NULL) FILELIST[type]= (char*)malloc(300);
    if(strlen(FILELIST[type])>0){
        mr_stopSound(type);
    }
    sprintf(FILELIST[type],"mythroad\\disk\\%d.mid",type);
    printf("fopen\n");
    FILE *f = fopen((const char*)FILELIST[type],"wb+");
    printf("open %s\n",FILELIST[type]);
    if(f!=NULL){
    fwrite(data, dataLen,1, f);
    printf("write\n");
    fclose(f);
    printf("close\n");
    }
    
    char temp[300];
     sprintf(temp,"play %s", FILELIST[type]);
     mciSendString(temp,        //MCI命令字符串
        NULL,                                //存放反馈信息的缓冲区
        0,                                    //缓冲区的长度
        NULL);                                //回调窗体的句柄，一般为NULL
    #endif
    return 0;
}

/*停止播放音频*/
int32 mr_stopSound(int type){
    #if defined(WIN32)
    char temp[300];
     sprintf(temp,"stop %s", FILELIST[type]);
     mciSendString(temp,        //MCI命令字符串
        NULL,                                //存放反馈信息的缓冲区
        0,                                    //缓冲区的长度
        NULL);                                //回调窗体的句柄，一般为NULL
    #endif
    return 0;
}



