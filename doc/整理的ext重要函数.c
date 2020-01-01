
typedef struct _mrc_extChunk_st mrc_extChunk_st;

typedef struct  _mr_c_function_st       // 我所说的RW描述段
{
   uint8* start_of_ER_RW;	// RW段指针
   uint32 ER_RW_Length;		// RW长度
   int32 ext_type;			// ext启动类型，为1时表示ext启动
   mrc_extChunk_st * mrc_extChunk;	// ext模块描述段，下面的结构体。
   int32 stack;   //stack shell 2008-2-28
} mr_c_function_st;

typedef struct  _mrc_extChunk_st		// 我所说的ext模块描述段
{
   int32 check;		//0x7FD854EB 标志
   MR_LOAD_C_FUNCTION init_func; // mr_c_function_load入口点
   MR_C_FUNCTION event;		// 事件入口函数，其他未知
   uint8* code_buf;		// ext模块地址
   int32   code_len;	// ext模块长度
   uint8* var_buf;		// 全局变量RW段地址
   int32   var_len;		// RW长度
   mr_c_function_st* global_p_buf;		// RW描述段，上面的结构体。
   int32   global_p_len;		// 长度
   int32   timer;		// 定时器句柄，mrc_extLoad调用mrc_timerCreate创建
   mrc_extMainSendAppMsg_t sendAppEvent;	// 好像是ext消息接收函数指针
   mr_table *extMrTable;		// mr_table函数表。
#ifdef MRC_PLUGIN	// 后面的几乎没有使用，因为分配的0x30大小到这为止。
   MR_C_FUNCTION_EX eventEx;
#endif
   int32 isPause;/*1: pause 状态0:正常状态*/
#ifdef SDK_MOD
   mrc_init_t init_f;
   mrc_event_t event_f;
   mrc_pause_t pause_f;
   mrc_resume_t resume_f;
   mrc_exitApp_t exitApp_f;
#endif
} mrc_extChunk_st;

// 假设的一个全局变量，帮助阅读代码
uint32* pMrTable = *(uint32**)(mr_c_function_load - 8);

/************************************
		mrc_extLoad
		展示了ext加载的全过程
************************************/
int32 mrc_extLoad (int32* extAddr, int32 len)
{
	mr_table* ext_table;	// 新ext的MrTable
	mr_extChunk_st* ext_handle; // 新ext模块的描述表
	mr_c_function_st* pSt;	// RW描述段

	
	if(mrc_extInitMainModule() != MR_SUCCESS )
		return -1;//失败
		
	// 为新的ext函数表申请内存
	ext_table = mrc_malloc(0x248); //mr_table里
	if(ext_table == NULL)
		return -1;		
	mrc_memcpy(ext_table, pTable, 0x248);//复制mr_table

	ext_table[25] = mrc_extFunction_new; //用本地函数来替换
	
	// 申请ext描述段内存
	ext_handle = mrc_malloc(0x30); // 分配“ext句柄”内存
	if(ext_handle == NULL)
	{
		mrc_free(ext_table);
		return -1;
	}

	mrc_memset(ext_handle, 0, 30);
	
	// 设置ext描述段
	ext_handle->extMrTable = ext_table; //设置表
	ext_handle->check = 0x7FD854EB; // EXT标志
	ext_handle->timer = mrc_timerCreate();
	ext_handle->sendAppEvent = mrc_extMainSendAppEventShell;
	//分配RW结构体
	ext_handle->global_p_buf = pSt = mrc_malloc(20);
	
	if(pSt == NULL)
	{
		mrc_free(ext_table);
		mrc_free(ext_handle);
		return -1;//失败
	}
	mrc_memset(pSt, 0, 20);
	//
	ext_handle->global_p_len = 20; //结构体大小
	ext_handle->init_func = extAddr + 8;//入口：mr_c_function_load
	ext_handle->code_buf = extAddr;// 首地址
	ext_handle->code_len = len; //ext大小
	
	//设置ext头
	extAddr[0] = ext_table; //设置函数表
	extAddr[1] = pSt; // 设置RW结构体
	pSt->mrc_extChunk = ext_handle; //设置句柄
	
	//好像就是 mrc_event(5001, )
	_mr_testCom1(0, 9, extAddr, len); //调用移植层函数，功能未知
	
	mr_c_function_load(1); //调用目标ext启动函数
	
	// 调用mr_c_function_load后，RW已经分配了。
	// 假定<RW>是RW段基址。
	ext_handle->event = *(<RW> + 0x14);
	ext_handle->var_buf = pSt->pRW;
	ext_handle->var_len = pSt->len;
	
	(ext_handle->event)(pSt, 6, 0, *(<RW>+0xC), 0, 0);//未知
	(ext_handle->event)(pSt, 8, *(<RW>+0x10), 0, 0, 0);
	
	
	return ext_handle; // 返回句柄
}

/******************************
		【 EXT内部函数 】
		mr_c_function_load
		负责部分初始化工作。
*******************************/
int32 mr_c_function_load (int32 code)
{
	mr_c_function_st* pSt = *((uint32)mr_c_function_load - 0x4); // 取RW段描述结构体指针
	void* p; int32 len;

	typedef int (*PFUNC_2) (void*,int);
	if( code == 1 ) // ext启动
	{
		int32 a = _mr_c_function_new(mrc_extHelper, 20); // 调用移植层。
		if( a == -2 ) return -1;
		pSt->ext_type = 1; //设置属性为ext启动
		pMrTable->g_mr_timerStart = mrc_extTimerStart;	// mr_table -> g_mr_timerStart
		pMrTable->g_mr_timerStop = mrc_extTimerStop;	// mr_table -> g_mr_timerStop
	}
	else			// 普通启动
	{
		int32 a = _mr_c_function_new(mr_helper, 20); // 移植层函数
		if( a == -2 ) return -1; //启动失败
		pSt->ext_type = 0; 
	}
	// 设置相关属性
	len = mr_helper_get_rw_len(); //取得RW长度，ext内部的函数，每个ext不同
	pSt->ER_RW_Length = len;

	p = mrc_malloc( len );
	pST->Start_of_ER_RW = p;
	if( p == NULL ) return -1;
	mrc_memset( p, 0, len); // 函数表偏移0x38处的memset。

	return 0; //成功
}

/**************************************
		【EXT内部函数】
		mr_helper
		负责消息分发。
***************************************/
/**
	 * (void* P, int32 code, uint8* input, int32 input_len, uint8** output, int32* output_len);
	 * 参数详解：
	 * input：为一int32数组，用于传递参数
	 * input_len：input字节数
	 * p：global_p_buf 指针
	 * 	code 及参数定义如下：
	 *		0：mrc_init input null
	 *		1：mrc_event input数组前3个为mrc_event参数 input_len=20
	 *					其中 input[0] == 8 时为ext退出消息，将调用mrc_exitApp
	 *		4：mrc_pause input=null input_len=0
	 *		5：mrc_resume input=null input_len=0	 
	 */
int32 mr_helper (void** pRW, int32 msg, int32 c[], int32 d)
{
	uint32* RWAddr = *(uint32*)pRW + 4; // 取RW段
	int32 ret = 0;  //返回值

	if(msg >= 9) return 0;
	switch(msg) //消息分派
	{
	case 0: // mrc_init
		_mr_init_c_helper_function(); // 初始化RW段
		ret = mrc_init();
		mrc_refreshScreenReal();
		pMrTable->mr_internal_table->mr_timer_p = "dealtimer";
		break;
	case 1: // mrc_event
		ret = mrc_event(c[0], c[1], c[2]);
		if(c[0] == 0x8) // 0x8 是平台退出消息
			ret = mrc_exitApp();
		mrc_refreshScreenReal();
		break;
	case 2: 
		mrc_timerTimeout(); //未知
		mrc_refreshScreenReal();
		break;
	case 4:
		mrc_pause();
		mrc_refreshScreenReal();
		break;
	case 5:
		mrc_resume();
		mrc_refreshScreenReal();
		break;
	case 6:
		*(RWAddr + 0xC) = d; // 位于RW
		break;
	case 8:
		*(RWAddr + 0x10) = c; // 位于RW
		break;
	case 9:
		typedef int (*PFUNC_6) (int,int,int,int,int,int);
		{
			PFUNC_6* pfunc = (PFUNC) c[0];
			if(pfunc) 
				ret = (*pfunc)(c[1],c[2],c[3],c[4],c[5],c[6]);
		}
		break;
	default:
		return 0;
	}
	return ret;
}

int __cdecl _mr_intra_start(char *Str1, char *Source)
{
  char v3; // [sp+Ch] [bp-4Ch]@1
  int v4; // [sp+4Ch] [bp-Ch]@2
  int v5; // [sp+50h] [bp-8h]@15
  int i; // [sp+54h] [bp-4h]@10

  memset(&v3, -858993460, 0x4Cu);
  getAppInfo();
  Origin_LG_mem_len = _mr_getMetaMemLimit();
  if ( !_mr_mem_init_ex(*((_DWORD *)&mrc_appInfo_st + 3)) )
  {
    mr_event_function = 0;
    mr_timer_function = 0;
    mr_stop_function = 0;
    mr_pauseApp_function = 0;
    mr_resumeApp_function = 0;
    mr_ram_file = 0;
    mr_c_function_P = 0;
    mr_c_function_P_len = 0;
    mr_c_function_fix_p = 0;
    mr_exception_str = 0;
    mr_printf("Total memory:%d", LG_mem_len);
    v4 = 0;
    mr_screenBuf = 0;
    if ( !mr_platEx(1001, 0, 0, &mr_screenBuf, &v4, 0) )
    {
      if ( mr_screenBuf && v4 >= 2 * mr_screen_h * mr_screen_w )
      {
        dword_18D0 = 1;
        dword_18CC = v4;
      }
      else
      {
        if ( mr_screenBuf )
        {
          mr_platEx(1002, mr_screenBuf, v4, 0, 0, 0);
          mr_screenBuf = 0;
        }
      }
    }
    if ( !mr_screenBuf )
    {
      mr_screenBuf = mr_malloc(2 * mr_screen_h * mr_screen_w);
      dword_18D0 = 0;
      dword_18CC = 2 * mr_screen_h * mr_screen_w;
    }
	
    dword_18D4 = mr_screenBuf;
    word_18CA = mr_screen_h;
    word_18C8 = mr_screen_w;
    vm_state = 0;
    mr_timer_state = 0;
    mr_timer_run_without_pause = 0;
    bi &= 2u;
    memset(&mr_bitmap, 0, 0x1E0u);
    memset(&mr_sound, 0, 0x3Cu);
    memset(&mr_sprite, 0, 0x14u);
    memset(&mr_tile, 0, 0x3Cu);
    memset(&mr_map, 0, 0xCu);
	
    for ( i = 0; i < 3; ++i )
    {
      word_1610[10 * i] = 0;
      word_1612[10 * i] = 0;
      word_1614[10 * i] = mr_screen_w;
      word_1616[10 * i] = mr_screen_h;
    }
	
    if ( !Source )
      Source = "_dsm";
	  
    mr_strncpy(mr_entry, Source, 0x7Fu);
    mr_printf("Used by VM(include screen buffer):%d bytes", LG_mem_len - LG_mem_left);
    mr_state = 1;
    v5 = mr_doExt(Str1);
	
    if ( v5 )
    {
      mr_state = 5;
      mr_stop();
      mr_printf("init failed");
      mr_connectWAP("http://wap.skmeg.com/dsmWap/error.jsp");
    }
  }
  return _chkesp();
}

int __cdecl mr_timer()
{
  char v1; // [sp+Ch] [bp-44h]@1
  int v2; // [sp+4Ch] [bp-4h]@11

  memset(&v1, -858993460, 0x44u);
  if ( mr_timer_state == 1 )
  {
    mr_timer_state = 0;
    if ( mr_state == 1 || mr_timer_run_without_pause && mr_state == 2 )
    {
      if ( !mr_timer_function || (mr_timer_function(), v2 = _chkesp(), v2 == 1) )
        _mr_TestComC(801, 0, 1, 2);
    }
    else
    {
      if ( mr_state == 3 )
      {
        mr_stop();
        _mr_intra_start(start_filename, &_pad__1__mr_md5_finish__9_9);
      }
    }
  }
  else
  {
    mr_printf("warning:mr_timer event unexpected!");
  }
  return _chkesp();
}

int __cdecl mr_start_dsm(char *Source)
{
  char v2; // [sp+Ch] [bp-4Ch]@1
  int v3; // [sp+4Ch] [bp-Ch]@1
  int v4; // [sp+50h] [bp-8h]@2
  int v5; // [sp+54h] [bp-4h]@2

  memset(&v2, -858993460, 0x4Cu);
  if ( !mr_getScreenInfo(&v3) )
  {
    mr_screen_w = v3;
    mr_screen_h = v4;
    mr_screen_bit = v5;
	
    memset(&pack_filename, 0, 0x80u);
	
    if ( Source && *Source == 42 )
    {
      strcpy(&pack_filename, Source);
    }
    else
    {
      if ( Source && *Source == 37 )
      {
        strcpy(&pack_filename, Source + 1);
      }
      else
      {
        if ( Source && *Source == 35 && Source[1] == 60 )
          strcpy(&pack_filename, Source + 2);
        else
          strcpy(&pack_filename, "*A");
      }
    }
	
    mr_printf(&pack_filename);
    memset(old_pack_filename, 0, 0x80u);
    memset(old_start_filename, 0, 0x80u);
    memset(start_fileparameter, 0, 0x80u);
    *((_DWORD *)&mrc_appInfo_st + 3) = 0;
    _mr_intra_start("cfunction.ext", Source);
	
  }
  return _chkesp();
}