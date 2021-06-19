var Module = typeof Module !== 'undefined' ? Module : {};
(function () {
    function runWithFS() {
        const path = window.location.pathname.substring(0, window.location.pathname.lastIndexOf('/')) + '/fs/';

        const dirs = [
            "/mythroad",
            "/mythroad/plugins",
            "/mythroad/plugins/ose",
            "/mythroad/system",
        ];

        const files = [
            "/mythroad/dsm_gm.mrp", // 入口mrp
            "/mythroad/mpc.mrp",
            "/mythroad/ydqtwo.mrp", // 电子书阅读器
            "/mythroad/plugins/netpay.mrp", // 支付模块
            "/mythroad/plugins/flaengine.mrp", // flash播放器
            "/mythroad/plugins/ose/brwcore.mrp", // 冒泡浏览器插件
            "/mythroad/system/gb12.uc2",  // 12号字体
            "/mythroad/system/gb16.uc2",  // 16号字体
            "/cfunction.ext",  // mythroad层
        ];


        for (const v of dirs) {
            FS.mkdir(v);
        }

        const dsm_gm = GetQueryString('f');
        for (const v of files) {
            const parent = v.substring(0, v.lastIndexOf('/'));
            const name = v.substring(v.lastIndexOf('/') + 1);
            if (dsm_gm && name === 'dsm_gm.mrp') {
                FS.createPreloadedFile(parent, name, dsm_gm, true, true);
            } else {
                FS.createPreloadedFile(parent, name, path + v, true, true);
            }
        }
    }

    if (!Module['preRun']) Module['preRun'] = [];
    Module["preRun"].push(runWithFS);
})();
