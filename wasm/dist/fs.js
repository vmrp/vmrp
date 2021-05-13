var Module = typeof Module !== 'undefined' ? Module : {};
(function () {
    function runWithFS() {
        const path = window.location.pathname.substring(0, window.location.pathname.lastIndexOf('/')) + '/fs/';

        const files = [
            "/mythroad/dsm_gm.mrp",
            "/mythroad/mpc.mrp",
            "/mythroad/ydqtwo.mrp",
            "/mythroad/plugins/netpay.mrp",
            "/mythroad/plugins/ose/brwcore.mrp",
            "/mythroad/system/gb12.uc2",
            "/mythroad/system/gb16.uc2",
            "/vmrp.mrp",
        ];
        const dirs = [
            "/mythroad",
            "/mythroad/plugins",
            "/mythroad/plugins/ose",
            "/mythroad/system",
        ]


        for (const v of dirs) {
            FS.mkdir(v);
        }

        function GetQueryString(name) {
            var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)");
            var r = window.location.search.substr(1).match(reg);
            if (r != null) return decodeURI(r[2]);
            return null;
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
