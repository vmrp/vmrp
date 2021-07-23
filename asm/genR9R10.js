// node getR9R10.js

const obj = {
    'asm_mr_malloc': 'mr_malloc',
    'asm_mr_free': 'mr_free',
    'asm_mr_realloc': 'mr_realloc',
    'asm_mr_getDatetime': 'mr_getDatetime',
    'asm_mr_sleep': 'mr_sleep',
    'asm_DrawRect': 'DrawRect',
    'asm_mr_drawBitmap': 'mr_drawBitmap',
    'asm_DrawText': '_DrawText',
    'asm_mr_getScreenInfo': 'mr_getScreenInfo',
    'asm_mr_smsSetBytes': '_mr_smsSetBytes',
    'asm_mr_smsAddNum': '_mr_smsAddNum',
    'asm_mr_newSIMInd': '_mr_newSIMInd',
    'asm_mr_isMr': '_mr_isMr',
    'asm_mr_rand': 'mr_rand',
    'asm_mr_stop_ex': 'mr_stop_ex',
    'asm_mr_printf': 'mr_printf',
    'asm_mr_mem_get': 'mr_mem_get',
    'asm_mr_mem_free': 'mr_mem_free',
    'asm_mr_getCharBitmap': 'mr_getCharBitmap',
    'asm_mr_timerStart': 'mr_timerStart',
    'asm_mr_timerStop': 'mr_timerStop',
    'asm_mr_getTime': 'mr_getTime',
    'asm_mr_getUserInfo': 'mr_getUserInfo',
    'asm_mr_plat': 'mr_plat',
    'asm_mr_platEx': 'mr_platEx',
    'asm_mr_open': 'mr_open',
    'asm_mr_close': 'mr_close',
    'asm_mr_read': 'mr_read',
    'asm_mr_write': 'mr_write',
    'asm_mr_seek': 'mr_seek',
    'asm_mr_info': 'mr_info',
    'asm_mr_remove': 'mr_remove',
    'asm_mr_rename': 'mr_rename',
    'asm_mr_mkDir': 'mr_mkDir',
    'asm_mr_rmDir': 'mr_rmDir',
    'asm_mr_findGetNext': 'mr_findGetNext',
    'asm_mr_findStop': 'mr_findStop',
    'asm_mr_findStart': 'mr_findStart',
    'asm_mr_getLen': 'mr_getLen',
    'asm_mr_exit': 'mr_exit',
    'asm_mr_startShake': 'mr_startShake',
    'asm_mr_stopShake': 'mr_stopShake',
    'asm_mr_playSound': 'mr_playSound',
    'asm_mr_stopSound': 'mr_stopSound',
    'asm_mr_sendSms': 'mr_sendSms',
    'asm_mr_call': 'mr_call',
    'asm_mr_connectWAP': 'mr_connectWAP',
    'asm_mr_dialogCreate': 'mr_dialogCreate',
    'asm_mr_dialogRelease': 'mr_dialogRelease',
    'asm_mr_dialogRefresh': 'mr_dialogRefresh',
    'asm_mr_textCreate': 'mr_textCreate',
    'asm_mr_textRelease': 'mr_textRelease',
    'asm_mr_textRefresh': 'mr_textRefresh',
    'asm_mr_editCreate': 'mr_editCreate',
    'asm_mr_editRelease': 'mr_editRelease',
    'asm_mr_editGetText': 'mr_editGetText',
    'asm_mr_initNetwork': 'mr_initNetwork',
    'asm_mr_closeNetwork': 'mr_closeNetwork',
    'asm_mr_getHostByName': 'mr_getHostByName',
    'asm_mr_socket': 'mr_socket',
    'asm_mr_connect': 'mr_connect',
    'asm_mr_closeSocket': 'mr_closeSocket',
    'asm_mr_recv': 'mr_recv',
    'asm_mr_recvfrom': 'mr_recvfrom',
    'asm_mr_send': 'mr_send',
    'asm_mr_sendto': 'mr_sendto',
    'asm_mr_load_sms_cfg': '_mr_load_sms_cfg',
    'asm_mr_save_sms_cfg': '_mr_save_sms_cfg',
    'asm_DispUpEx': '_DispUpEx',
    'asm_DrawPoint': '_DrawPoint',
    'asm_DrawBitmap': '_DrawBitmap',
    'asm_DrawBitmapEx': '_DrawBitmapEx',
    'asm_BitmapCheck': '_BitmapCheck',
    'asm_mr_readFile': '_mr_readFile',
    'asm_mr_registerAPP': 'mr_registerAPP',
    'asm_DrawTextEx': '_DrawTextEx',
    'asm_mr_EffSetCon': '_mr_EffSetCon',
    'asm_mr_TestCom': '_mr_TestCom',
    'asm_mr_TestCom1': '_mr_TestCom1',
    'asm_c2u': 'c2u',
    'asm_mr_updcrc': 'mr_updcrc',
    'asm_mr_unzip': 'mr_unzip',
    'asm_mr_transbitmapDraw': 'mr_transbitmapDraw',
    'asm_mr_drawRegion': 'mr_drawRegion',
    'asm_mr_platDrawChar': 'mr_platDrawChar',
};

const fullObj = {
    'asm_mrp_gettop': 'mrp_gettop',
    'asm_mrp_settop': 'mrp_settop',
    'asm_mrp_pushvalue': 'mrp_pushvalue',
    'asm_mrp_remove': 'mrp_remove',
    'asm_mrp_insert': 'mrp_insert',
    'asm_mrp_replace': 'mrp_replace',
    'asm_mrp_isnumber': 'mrp_isnumber',
    'asm_mrp_isstring': 'mrp_isstring',
    'asm_mrp_iscfunction': 'mrp_iscfunction',
    'asm_mrp_isuserdata': 'mrp_isuserdata',
    'asm_mrp_type': 'mrp_type',
    'asm_mrp_typename': 'mrp_typename',
    'asm_mrp_shorttypename': 'mrp_shorttypename',
    'asm_mrp_equal': 'mrp_equal',
    'asm_mrp_rawequal': 'mrp_rawequal',
    'asm_mrp_lessthan': 'mrp_lessthan',
    'asm_mrp_tonumber': 'mrp_tonumber',
    'asm_mrp_toboolean': 'mrp_toboolean',
    'asm_mrp_tostring': 'mrp_tostring',
    'asm_mrp_strlen': 'mrp_strlen',
    'asm_mrp_tostring_t': 'mrp_tostring_t',
    'asm_mrp_strlen_t': 'mrp_strlen_t',
    'asm_mrp_tocfunction': 'mrp_tocfunction',
    'asm_mrp_touserdata': 'mrp_touserdata',
    'asm_mrp_tothread': 'mrp_tothread',
    'asm_mrp_topointer': 'mrp_topointer',
    'asm_mrp_pushnil': 'mrp_pushnil',
    'asm_mrp_pushnumber': 'mrp_pushnumber',
    'asm_mrp_pushlstring': 'mrp_pushlstring',
    'asm_mrp_pushstring': 'mrp_pushstring',
    'asm_mrp_pushvfstring': 'mrp_pushvfstring',
    'asm_mrp_pushfstring': 'mrp_pushfstring',
    'asm_mrp_pushboolean': 'mrp_pushboolean',
    'asm_mrp_pushcclosure': 'mrp_pushcclosure',
    'asm_mrp_gettable': 'mrp_gettable',
    'asm_mrp_rawget': 'mrp_rawget',
    'asm_mrp_rawgeti': 'mrp_rawgeti',
    'asm_mrp_newtable': 'mrp_newtable',
    'asm_mrp_getmetatable': 'mrp_getmetatable',
    'asm_mrp_settable': 'mrp_settable',
    'asm_mrp_rawset': 'mrp_rawset',
    'asm_mrp_rawseti': 'mrp_rawseti',
    'asm_mrp_call': 'mrp_call',
    'asm_mrp_pcall': 'mrp_pcall',
    'asm_mrp_load': 'mrp_load',
    'asm_mrp_getgcthreshold': 'mrp_getgcthreshold',
    'asm_mrp_setgcthreshold': 'mrp_setgcthreshold',
    'asm_mrp_error': 'mrp_error',
    'asm_mrp_checkstack': 'mrp_checkstack',
    'asm_mrp_newuserdata': 'mrp_newuserdata',
    'asm_mrp_getfenv': 'mrp_getfenv',
    'asm_mrp_setfenv': 'mrp_setfenv',
    'asm_mrp_setmetatable': 'mrp_setmetatable',
    'asm_mrp_cpcall': 'mrp_cpcall',
    'asm_mrp_next': 'mrp_next',
    'asm_mrp_concat': 'mrp_concat',
    'asm_mrp_pushlightuserdata': 'mrp_pushlightuserdata',
    'asm_mrp_getgccount': 'mrp_getgccount',
    'asm_mrp_dump': 'mrp_dump',
    'asm_mrp_yield': 'mrp_yield',
    'asm_mrp_resume': 'mrp_resume',
}

const asm = `
        ; armcc asm
        CODE32
        AREA ||.text||, CODE, READONLY
        IMPORT       fixR9_begin
        IMPORT       fixR9_end

getR9 PROC
        MOV      r0,r9
        BX       lr
        ENDP
        EXPORT getR9

setR9 PROC
        MOV      r9,r0
        BX       lr
        ENDP
        EXPORT setR9

getR10 PROC
        MOV      r0,r10
        BX       lr
        ENDP
        EXPORT getR10

setR10 PROC
        MOV      r10,r0
        BX       lr
        ENDP
        EXPORT setR10

setR9R10 PROC
        MOV      r9,r0
        MOV      r10,r1
        BX       lr
        ENDP
        EXPORT setR9R10
    
{{replace}}

        END
`;

const tpl = `
        IMPORT   {{targetFuncName}}
{{asmFuncName}} PROC
        stmfd    sp,{ r0-r8, r11, r12, sp, lr } ; 因为不确定fixR9_xxx的c函数编译后会使用哪些寄存器，所以干脆全部保存
        sub      sp,sp,#52      ; r0-r8, r11, r12, sp, lr 一共13个寄存器 13*4=52
        mov      r0,r9
        mov      r1,r10
        mov      r2,lr
        bl       fixR9_begin
        ldmfd    sp,{ r0-r8, r11, r12, sp, lr } ; 现在完全恢复调用参数
        bl       {{targetFuncName}}      ; 调用目标函数
        stmfd    sp,{ r0-r8, r11, r12, sp } ; 注意这里没有保存lr，因为lr的值已经在调用目标函数后破坏
        sub      sp,sp,#48      ; 12个寄存器
        bl       fixR9_end
        mov      lr,r0
        ldmfd    sp,{ r0-r8, r11, r12, sp }
        bx       lr
        ENDP
        EXPORT {{asmFuncName}}
`;

const asm_gnu = `
        @ gcc asm
	.arch armv5te
	.arm

	.global	getR9
getR9:
        MOV      r0,r9
        BX       lr

	.global	setR9
setR9:
        MOV      r9,r0
        BX       lr

        .global	getR10
getR10:
        MOV      r0,r10 @ 注意getR10函数可能无法生成
        BX       lr

	.global	setR10
setR10:
        MOV      r10,r0
        BX       lr

	.global	setR9R10
setR9R10:
        MOV      r9,r0
        MOV      r10,r1
        BX       lr
    
{{replace}}

`;

const tpl_gnu = `
        .global {{asmFuncName}}
{{asmFuncName}}:
        stmfd    sp,{ r0-r8, r11, r12, sp, lr } @ 因为不确定fixR9_xxx的c函数编译后会使用哪些寄存器，所以干脆全部保存
        sub      sp,sp,#52      @ r0-r8, r11, r12, sp, lr 一共13个寄存器 13*4=52
        mov      r0,r9
        mov      r1,r10
        mov      r2,lr
        bl       fixR9_begin
        ldmfd    sp,{ r0-r8, r11, r12, sp, lr } @ 现在完全恢复调用参数
        bl       {{targetFuncName}}(PLT)      @ 调用目标函数
        stmfd    sp,{ r0-r8, r11, r12, sp } @ 注意这里没有保存lr，因为lr的值已经在调用目标函数后破坏
        sub      sp,sp,#48      @ 12个寄存器
        bl       fixR9_end
        mov      lr,r0
        ldmfd    sp,{ r0-r8, r11, r12, sp }
        bx       lr
`;

const fs = require('fs');
const process = require('process');


function getAsmStr(str) {
    const arr = [];
    Object.keys(obj).forEach(function(key) {
        arr.push(str.replace(/\{\{asmFuncName\}\}/g, key).replace(/\{\{targetFuncName\}\}/g, obj[key]));
    });
    return arr.join('');
}

function doit(asm, tpl) {
    fs.writeFileSync('./r9r10.s', asm.replace('{{replace}}', getAsmStr(tpl)));
}

if (process.argv.length == 4) {
    if (process.argv[3] === '1') {
        Object.assign(obj, fullObj);
    }
    if (process.argv[2] === '0') {
        doit(asm, tpl);
    } else {
        doit(asm_gnu, tpl_gnu);
    }
    console.log('done.');
} else {
    console.log('err: node genR9R10.js isGNU(0|1) isFull(0|1)');
}