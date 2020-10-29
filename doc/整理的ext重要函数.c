
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

