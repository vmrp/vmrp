var Module = typeof Module !== 'undefined' ? Module : {};

(function () {
    function GetQueryString(name) {
        var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)");
        var r = window.location.search.substr(1).match(reg);
        if (r != null) return decodeURI(r[2]);
        return null;
    }
    var url = GetQueryString('f');
    if (url === null) {
        return;
    }

    if (!Module.expectedDataFileDownloads) {
        Module.expectedDataFileDownloads = 0;
    }
    Module.expectedDataFileDownloads++;
    Module.dsm_gm = true;


    var PACKAGE_NAME = url;
    var fetched = null;
    var fetchedCallback = null;

    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, true);
    xhr.responseType = 'arraybuffer';
    xhr.onprogress = function (event) {
        if (event.loaded) {
            if (!xhr.addedTotal) {
                xhr.addedTotal = true;
                if (!Module.dataFileDownloads) Module.dataFileDownloads = {};
                Module.dataFileDownloads[url] = { loaded: event.loaded, total: event.total };
            } else {
                Module.dataFileDownloads[url].loaded = event.loaded;
            }
            var total = 0;
            var loaded = 0;
            var num = 0;
            for (var download in Module.dataFileDownloads) {
                var data = Module.dataFileDownloads[download];
                total += data.total;
                loaded += data.loaded;
                num++;
            }
            total = Math.ceil(total * Module.expectedDataFileDownloads / num);
            if (Module['setStatus']) Module['setStatus']('Downloading data... (' + loaded + '/' + total + ')');
        } else if (!Module.dataFileDownloads) {
            if (Module['setStatus']) Module['setStatus']('Downloading data...');
        }
    };
    xhr.onerror = function (event) {
        throw new Error("NetworkError for: " + url);
    }
    xhr.onload = function (event) {
        if (xhr.status == 200 || xhr.status == 304 || xhr.status == 206 || (xhr.status == 0 && xhr.response)) { // file URLs can return 0
            var data = xhr.response;
            if (fetchedCallback) {
                fetchedCallback(data);
                fetchedCallback = null;
            } else {
                fetched = data;
            }
        } else {
            throw new Error(xhr.statusText + " : " + xhr.responseURL);
        }
    };
    xhr.send();


    function runWithFS() {
        function assert(check, msg) {
            if (!check) throw msg + new Error().stack;
        }
        function processPackageData(arrayBuffer) {
            assert(arrayBuffer, 'Loading data file failed.');
            assert(arrayBuffer instanceof ArrayBuffer, 'bad input to processPackageData');
            // canOwn this data in the filesystem, it is a slide into the heap that will never change
            Module['FS_createDataFile']('/mythroad/dsm_gm.mrp', null, new Uint8Array(arrayBuffer), true, true, false);
            Module['removeRunDependency']('datafile_dsm_gm.mrp');
        };
        Module['addRunDependency']('datafile_dsm_gm.mrp');

        if (!Module.preloadResults) Module.preloadResults = {};
        Module.preloadResults[PACKAGE_NAME] = { fromCache: false };

        if (fetched) {
            processPackageData(fetched);
            fetched = null;
        } else {
            fetchedCallback = processPackageData;
        }
    }

    if (Module['calledRun']) {
        runWithFS();
    } else {
        if (!Module['preRun']) Module['preRun'] = [];
        Module["preRun"].push(runWithFS); // FS is not initialized yet, wait for it
    }
})();
