



def dealevent(code, param0, param1, param2)
  local s
  if _t(param0) == "str" then
    local pContent, clen = string.subV(param0)
    local pNum, nlen = string.subV(param1)
    s = string.pack("iiiii", code, pContent, pNum, param2, clen)
  else
    param0 = param0 || 0
    param1 = param1 || 0
    s = string.pack("iii", code, param0, param1)
  end
  
  local v, ret = _strCom(801, s, 1)
  
  return ret 
end




/*******************payment begin***********************/
sysinfo = GetSysInfo()
def pay_getVersion(mrpfilename)
    local firstchar = string.sub(mrpfilename,1,1)
    local sId,appId,appVer
    
    if firstchar == "*" || firstchar == "$" then
        sId = _strCom(600,mrpfilename,68,4)
        appId = _strCom(600,mrpfilename,192,4)
        appVer = _strCom(600,mrpfilename,196,4)
    else
        local f = file.open(mrpfilename, 1)
        if f then
            f:seek(0, 68)
            sId = f:read(4) 
            f:seek(0, 192)
            appId = f:read(4) 
            f:seek(0, 196)
            appVer = f:read(4) 
            f:close()
        end       
    end
    if sId then
        return sId,appId,appVer
    else
        return
    end
end

def pay_conToNum(buf)
   return string.byte(buf, 1)*16777216+string.byte(buf, 2)*65536+string.byte(buf, 3)*256+string.byte(buf, 4);
end

def appDisburse()
    local l_pay = {}
    
    
    l_pay.sssid,l_pay.ssappid,l_pay.ssappver = pay_getVersion(sysinfo.packname)
    
    if l_pay.sssid == nil || l_pay.ssappid == nil ||l_pay.ssappver == nil then
        l_pay.sssid,l_pay.ssappid,l_pay.ssappver = "\x03\x45\x98\x35","\x03\x43\x76\x25","\x02\x49\x76\x15"
    end
    return l_pay
end


/*******************payment end***********************/

def c_before_init()
  local pay = appDisburse()
  sid_name = "unknow"
  app_info = string.pack("iii", pay_conToNum(pay.ssappid), pay_conToNum(pay.ssappver), 
                                   string.subV(sid_name))
  _strCom(801, {1, sysinfo.vmver}, 6)
  _strCom(801, app_info, 8)
end

if _mr_c_load() == 0 then
   c_before_init()
	local v,ret = _strCom(801, "", 0)
else
   Exit()
end


/*
def pay_getVersion(mrpfilename)
local firstchar = string.sub(mrpfilename,1,1)
local sId,appId,appVer

if firstchar == "*" || firstchar == "$" then
sId = _strCom(600,mrpfilename,68,4)
appId = _strCom(600,mrpfilename,192,4)
appVer = _strCom(600,mrpfilename,196,4)
else
local f = file.open(mrpfilename, 1)
if f then
f:seek(0, 68)
sId = f:read(4) 
f:seek(0, 192)
appId = f:read(4) 
f:seek(0, 196)
appVer = f:read(4) 
f:close()
end       
end
if sId then
return sId,appId,appVer
else
return
end
end
*/
