

/*************************************************************************************
文件说明: 本文件实现了如何将一个定时器进行分流成多个定时
                        器
创建者  : 唐彦
历史记录: 20060707创建
*************************************************************************************/

timer = {}

def debugTrace()
end


/******************************************************************************
tim_struct =
{
timerId        定时器的id号  这个必须是唯一的，并且其他的模块
                       必须通过这个id才能进行定时器的相关操作。
timTime       当前定定时器启动的时间间隔
timActive     当前的定时器是否被激活
timRepeat    定时器是否是可重复的
autoDelete   需要删除的定时器，用于控制在定时器的回调函数中
                      有需要删除定时器请求的。
timLeft         定时器剩余的时间
timFunc        定时器对应的回调函数
}
******************************************************************************/  
#define  TIME_METHOD_2
//#define  TIME_METHOD_1
//用于方法2，作为心跳。用于循环检测的定时器。
#define  TIME_TICK 200   
local timList = {}
//timer的id，从1000开始计数，每次增加1。
local timeIdUuid
//用于对于回调函数中会出现启动定时器、停止定时器和删除定时器的情况，用于互斥。
local timeInSystemCycleCb 
//local TIM_timInit, TIM_timCreate, TIM_timStart, TIM_timStop, TIM_timSetTime, TIM_timDelete
local TIM_timInit
local i_timCompare, sortTimerList, i_timGetUuid, i_timAdjust, i_timStart, i_timStop, i_timCycleCb
/*$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
说明:     对外的接口
        TIM_timCreate(aTimTime, aTimFunc)  创建一个定时器，返回定时器的timerId
        TIM_timStart(aTimRepeat, aTimerId)    启动一个定时器，aRimRepeat是否重复
        TIM_timStop(aTimerId)暂停一个定时器，但是最近一次的回调也因此
                                          可能被暂停掉。
        TIM_timSetTime(aTimerId, aTimTime)重新设置定时器的时间间隔，但是
                                          如果这个定时器已经被启动可能不会对最近的
                                          一次定时器的回调有影响。
        TIM_timDelete(aTimerId) 删除一个定时器，并且最近的一次回调也不会
                                          被执行
                                          
        TIM_timInit()               定时器功能部分的初始化。只有在程序初始化
                                         的时候调用。
       
历史记录:  20060710 创建这部分代码
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$*/

/******************************************************************************
函数名称:  TIM_timInit()
参数说明:  
函数说明:  定时器初始化
创建者  :     唐彦
历史记录: 20060710创建
******************************************************************************/   
def TIM_timInit()
  debugTrace ("TIM_timInit")
  timList= {}
  timeIdUuid = 1000
  timeInSystemCycleCb = 0
  #ifdef TIME_METHOD_2
  i_timStart(TIME_TICK)      
  #endif

end

/******************************************************************************
函数名称:  TIM_timCreate(aTimTime, aTimFunc)
参数说明:  
函数说明:  创建一个定时器，这里需要注意的是创建了的
                         定时器，需要在启动以后才能开始。另外要求
                         定时器的最小时间间隔是100ms。必须要有回调
                         函数
函数返回: 创建的定时器的id，如果id为0，那么就表示有问题                              
创建者  :     唐彦
历史记录: 20060710创建
******************************************************************************/   
def timer.create(aTimTime, aTimFunc)
  local time = {}
  
  if aTimFunc == nil then
    debugTrace ("TIM_timCreate error aTimFunc if nil")
    return 0
  end
  debugTrace ("TIM_timCreate time.time " .. aTimTime)
   
  if aTimTime <100 then 
     aTimTime =100
  end
  
  time.timRepeat = 0
  time.timActive = 0
  time.timLeft = 0 
  time.autoDelete = 0  
  time.timTime = aTimTime
  time.timFunc = aTimFunc
  time.timerId = i_timGetUuid()
  time.autoDelete = 0
  
  table.insert(timList, time)
  
  return time.timerId
end


/******************************************************************************
函数名称:  TIM_timStart(aTimRepeat, aTimerId)
参数说明:  
函数说明:  启动一个定时器。这里有一点需要注意的是如果
           定时器已经启动，那么将不会对之前的timleft设置
           产生影响。
创建者  :     唐彦
历史记录: 20060710创建
******************************************************************************/   
def timer.start(aTimRepeat, aTimerId)
  local time = {}
  local timNum = table.getn(timList)

  if aTimRepeat == nil || timNum == 0 then
     return
  end

  if(aTimerId ==nil || aTimerId <1000) then
     debugTrace ("TIM_timStop error id")
     return
  end
  debugTrace ("TIM_timStart aTimerId =" .. aTimerId .. " numoftimetable = ".. timNum)
  
  for i = 1,  timNum do
     time = timList[i] 
     if time.timerId == aTimerId then
         debugTrace ("TIM_timStart aTimerId is found")
         if time.timActive == 1 then
            debugTrace ("TIM_timStart tim is activing")
         else
            time.timLeft = time.timTime  + TIME_TICK/2
         end
         time.timRepeat = aTimRepeat 
         time.timActive = 1
         break
     end   //        if time.timerId == aTimerId then
  end //    for i = 1,  timNum do
  /*
  如果当前定时器的timleft不大于列表中第一个定时器的timleft
  则需要启动一次系统的定时器，保证定时器正常运行
  如果定时器当前正在循环，那么就不需要进行排序和
  启动，系统的定时器回调函数中，自己会完成h

  这个地方原先有bug，假设当前列表中没有激活的定时器，那么只是重新排序
  那么必然会出现的问题就是没有定时器会运行。
*/
  if timeInSystemCycleCb == 0 then
    if timList[1].timActive == 0  then
       sortTimerList()
       
       #ifdef TIME_METHOD_1
       local nextTime = (timList[1].timLeft < 100 && 100) || timList[1].timLeft 
       i_timStart(nextTime)
       i_timAdjust(nextTime)	
       #endif
    elif time.timLeft > timList[1].timLeft  then
       //table.sort(timList, i_timCompare)
       debugTrace ("TIM_timStart time1")
       sortTimerList()
    else
       //table.sort(timList, i_timCompare)
       sortTimerList()

       #ifdef TIME_METHOD_1
  local nextTime = (timList[1].timLeft < 100 && 100) || timList[1].timLeft 
  debugTrace ("TIM_timStart nextTime = " .. nextTime)
       i_timStart(nextTime)
       i_timAdjust(nextTime)	  
       #endif
    end
  end

  return
end


/******************************************************************************
函数名称:  TIM_timStop(aTimerId)
参数说明:  
函数说明:  暂停一个定时器，将定时器置位非活，将定时器
                         的timleft置位
创建者  :     唐彦
历史记录: 20060710创建
******************************************************************************/   
def timer.stop(aTimerId)
   local time = {}
   local timNum = table.getn(timList)
   
  if(aTimerId ==nil || aTimerId <1000 || timNum == 0) then
     debugTrace ("TIM_timStop error id")
     return
  end
   debugTrace ("TIM_timStop aTimerId = " .. aTimerId .." numoftimetable = ".. timNum)
   
   for i = 1,  timNum do
      time = timList[i] 
      if time.timerId == aTimerId then
         if time.timActive == 1 then
     	    debugTrace ("TIM_timStop tim is activing")
         else
     	    debugTrace ("TIM_timStop tim is inactive")
         end
          time.timRepeat = 0
          time.timActive = 0
          time.timLeft = 0
      end //    if time.timerId == aTimerId then
   end //  for i = 1,  timNum do
 
   if timeInSystemCycleCb == 0 then
      //table.sort(timList, i_timCompare)
      sortTimerList()
   end
   
   return
end


/******************************************************************************
函数名称:  TIM_timSetTime(aTimerId, aTimTime)
参数说明:  
函数说明:  重新设置一个定时器的定时时间，这里需要注意
                         的是，如果定时器的时间原先已经被激活，那么
                         这次修改不会影响到之前的定时器剩余时间设置。
                         当然可以先调用TIM_timSetTime，然后在调用TIM_timStart。
创建者  :     唐彦
历史记录: 20060710创建
******************************************************************************/   
def timer.setTime(aTimerId, aTimTime)
  local time = {}
  local timNum = table.getn(timList)
  
  if(aTimerId ==nil || aTimerId <1000 || timNum == 0) then
     debugTrace ("TIM_timSetTime error id")
     return
  end
  //debugTrace ("TIM_timSetTime aTimerId =" .. aTimerId)
  
  for i = 1,  timNum do
      time = timList[i] 
      if time.timerId == aTimerId then
          if time.timActive == 1 then
      	debugTrace ("TIM_timSetTime tim is activing")
          else
      	debugTrace ("TIM_timSetTime tim is inactive")
          end
          time.timTime = aTimTime
      end
  end
  
  return
end


/******************************************************************************
函数名称:  TIM_timDelete(aTimerId)
参数说明:  
函数说明:  删除一个定时器，如果原先定时器是被激活，
                         那么删除这个定时器将导致函数不会被调用。
创建者  :     唐彦
历史记录: 20060710创建
******************************************************************************/   
def timer.delete(aTimerId)
  local time = {}
  local timNum = table.getn(timList)
  
  if(aTimerId ==nil || aTimerId <1000 || timNum == 0) then
     debugTrace ("TIM_timDelete error id")
     return
  end
//  debugTrace ("TIM_timDelete aTimerId =" .. aTimerId .." numoftimetable = ".. timNum)
  
  for i = 1,  timNum do
     time = timList[i] 
     if time.timerId == aTimerId then
         if time.timActive == 1 then
            debugTrace ("TIM_timDelete tim is activing")
         else
            debugTrace ("TIM_timDelete tim is inactive")
         end
         if timeInSystemCycleCb == 0 then
            table.remove(timList , i)
         else
            time.autoDelete = 1	   	
            debugTrace ("TIM_timDelete  time.autoDelete")
         end     	    
         return
     end //       if time.timerId == aTimerId then
  end //    for i = 1,  timNum do
  
  local timNum = table.getn(timList)
  
  debugTrace ("TIM_timDelete aTimerId =" .. aTimerId .." numoftimetable = ".. timNum)
  
  debugTrace ("TIM_timDelete error not foud aTimerId =" .. aTimerId)
  
  return
end //  def TIM_timDelete(aTimerId)


/*$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
说明:     内部实现
历史记录:  20060707 创建这部分代码
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$*/
  /******************************************************************************
函数名称:  i_timCompare()
参数说明:  
函数说明:  比较定时器列表中两个元素的大小
创建者  :     唐彦
历史记录: 20060710创建
******************************************************************************/   
def i_timCompare(aTimer1, aTimer2)
    if aTimer2.timActive == 0 then
	 return true
    end
    if aTimer1.timActive == 0 && aTimer2.timActive == 1 then
	 return false
    end
    return aTimer1.timLeft <= aTimer2.timLeft
end

/******************************************************************************
函数名称:  sortTimerList()
参数说明:  
函数说明:  定时器的列表进行排序。
创建者  :     唐彦
历史记录: 20060710创建
******************************************************************************/   
def sortTimerList()
    local time1 = {}
    local time2 = {}
    local timNum = table.getn(timList)

    for i = 1,timNum-1 do
   time1 = timList[i]
        for j = i+1,  timNum do
	 time2 = timList[j]
        if i_timCompare(time1, time2) then
	    //do nothing
	 else
	    timList[i] = timList[j]
	    timList[j] = time1
	    time1 = timList[i] 
	 end
   end
    end
end

/******************************************************************************
函数名称:  i_timGetUuid()
参数说明:  
函数说明: 获取定时器的id
创建者  :     唐彦
历史记录: 20060710创建
******************************************************************************/   
def i_timGetUuid()
  timeIdUuid = timeIdUuid +1
  return timeIdUuid
end

/******************************************************************************
函数名称:  i_timAdjust(nextTimeLeft)
参数说明:  
函数说明:  统一将定时器中的定时器的当前值减去1
创建者  :     唐彦
历史记录: 20060710创建
******************************************************************************/   
def i_timAdjust(nextTimeLeft)	 
     for n,timeItem in timList do
        //debugTrace ("i_timAdjust n   " .. n .. " timeItem.timLeft " .. timeItem.timLeft)	 
        timeItem.timLeft = timeItem.timLeft - nextTimeLeft	
     end
end

/******************************************************************************
函数名称:  i_systemTimFunc()
参数说明:  
函数说明:  定时器的系统回调函数
创建者  :     唐彦
历史记录: 20060710创建
******************************************************************************/   
i_systemTimFunc = def()
    //debugTrace ("i_systemTimFunc \n")
    //调试定时器，调试完成删除
    #ifdef TIME_METHOD_2
    i_timStart(TIME_TICK)     
    i_timAdjust(TIME_TICK)
    //i_timStart(TIME_TICK)     
    #endif
    
    timeInSystemCycleCb = 1   
    local nextTimeLeft = i_timCycleCb()
    //调试定时器，调试完成删除
    
    timeInSystemCycleCb = 0
    #ifdef TIME_METHOD_1
    if nextTimeLeft != 0 then 
       if (nextTimeLeft <100 ) then
          nextTimeLeft = 100
       end
       i_timAdjust(nextTimeLeft)
       //debugTrace ("i_systemTimFunc nextTimeLeft" .. nextTimeLeft)	  
 i_timStart(nextTimeLeft)
    end
    #endif  
end

/******************************************************************************
函数名称:  i_timStart(ms)
参数说明:  
函数说明:  启动系统定时器
创建者  :     唐彦
历史记录: 20060710创建
******************************************************************************/   
def i_timStart(ms)
  TimerStop(0)
  TimerStart(0, ms, "i_systemTimFunc")
  //调试定时器，调试完成删除
end

/******************************************************************************
函数名称: i_timStop()
参数说明:  
函数说明:  停止系统定时器
创建者  :     唐彦
历史记录: 20060710创建
******************************************************************************/  
def i_timStop()
  TimerStop(0)
end

/******************************************************************************
函数名称:  i_timCycleCb()
参数说明:  
函数说明:  定时器的内部循环函数
创建者  :     唐彦
历史记录: 20060710创建
******************************************************************************/   
def i_timCycleCb()

    local time = {}
    local timNum = table.getn(timList)

    if timNum <= 0 then
       return 0;
    end
    
    if (timList[1].timActive == 0) then
       debugTrace ("i_timCycleCb error ocur no active timer")
       sortTimerList()
       return 0
    end


    
    for i = 1, timNum do
        time = timList[i] 
        
        if time.timActive != 0 then
            if time.timLeft < 1 then
              //  debugTrace ("tim func is execute timid = " .. time.timerId)
	    time.timActive = 0  	
	    time.timLeft = 0    
                if time.timRepeat == 1 &&  time.autoDelete == 0   then
                   //debugTrace ("tim func")
                    time.timLeft = time.timTime
                    time.timActive = 1
                end  // if time.timRepeat == 1  &&  time.autoDelete == 0   
	    //用于调试定时器停止问题，完成后删除
                time.timFunc()
	    //用于调试定时器停止问题，完成后删除
            end // if time.timeLeft < 1 then
        end//if time.timActive != 0 then
    end//    for i = 1, timNum do

     //统一删除哪些在回调函数中要求删除的定时器
     for n,timeItem in timList do
        if timeItem.autoDelete == 1 then
	//debugTrace ("timeItem.autoDelete")
            table.remove(timList , n)
  end		 	
     end

     local timNum = table.getn(timList)
     
     if timNum <= 0 then
        return 0;
     end
     //对定时器的队列进行排序
    //for i = 1, timNum do
    //     debugTrace ("i_timCycleCb 1 timerId == " .. timList[i].timerId .. " timeItem.timLeft =  " .. timList[i].timLeft) 
   // end
     
     // table.sort(timList, i_timCompare)
     sortTimerList()
     
   // for i = 1, timNum do
   //      debugTrace ("i_timCycleCb 1 timerId == " .. timList[i].timerId .. " timeItem.timLeft =  " .. timList[i].timLeft) 
  // end
    
     if timList[1].timActive == 1 then
        return timList[1].timLeft
else
   return 0
end
end

//end do
TIM_timInit()

print("mythroad init finish")
_loadFile("main.mr")()
