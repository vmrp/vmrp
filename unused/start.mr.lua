
_com(3629, 2913)
def _mr_c_load ()
   _mr_c_buf = _strCom(601, "cfunction.ext")
   if _mr_c_buf then
      local ret = _strCom(800, _mr_c_buf, 0)
      return ret
   else
      return -1
   end
end

gc_times = 0

def dealevent(code, p0, p1, p2)
   if gc_times > 20 then
      TestCom(403, 0)
      gc_times = 0
   else
      gc_times = gc_times + 1
   end
   if _t(p0) == "str" then
      local p00 = p0 .. "\0"
      local p10 = p1 .. "\0"
      local pContent, clen = string.subV(p00)
      local pNum, nlen = string.subV(p10)
      d_s = string.pack("iiiii", code, pContent, pNum, p2, clen)
   else
      d_s = string.pack("iii", code, p0 || 0, p1 || 0)
   end
   local v, ret = _strCom(801, d_s, 1)
   return ret
end

def dealtimer()
   t_v, t_ret = _strCom(801, "", 2), 801
   return t_ret
end

def suspend()
   s_v, s_ret = _strCom(801, "", 4), 801
   return s_ret
end

def resume()
   r_v, r_ret = _strCom(801, "", 5), 801
   return r_ret
end

sysinfo = GetSysInfo()
/*
if sysinfo.hsman ~= "sdk" then
   local f = file.open("sdk_key.dat", 1)
   if f then
      local key = f:read(500)
      f:close()
      local this_key = _strCom(500, _strCom(501, sysinfo.vmver .. string.sub(sysinfo.IMEI, 3)))
      this_key = this_key .. _strCom(500, _strCom(501, string.sub(sysinfo.IMEI, 2, 7) .. sysinfo.hsman .. string.sub(sysinfo.hstype, 2)))
      this_key = this_key .. _strCom(500, _strCom(501, string.sub(sysinfo.IMEI, 9, 14) .. string.sub(sysinfo.hstype, 1, 3)))
      if key ~= this_key then
         _error("cann`t find sdk key!")
         return 
      else
         _error("cann`t find sdk key!")
         return 
      end
   end
end
*/

_clearScr(128,128,0)
_drawRect(50,50,50,50,  255,255,0)
EffSetCon(75,75,50,50, 128,128,128)
_drawText("hello, world",0,0,255,255,0)

DrawText("20201106",50,140,111,222,0)
_dispUp(0,0,240,320)

_com(400, 3000) // sleep(3000)

if _mr_c_load() == 0 then
   _strCom(801, {1, sysinfo.vmver}, 6)
   _gc()
   _strCom(801, "", 0)
   if _mr_param then
      local p_mr_param, param_len = string.subV(_mr_param)
      _strCom(801, string.pack("iii", 5001, p_mr_param, param_len), 1)
   end
else
   Exit()
end
