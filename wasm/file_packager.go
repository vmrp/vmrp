package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

/*
自定义文件系统的工具，实现原理参考：
// /c/Users/zengming/Desktop/emsdk/upstream/emscripten/tools
// $ python file_packager.py vmrp.data --preload /c/Users/zengming/Desktop/src/vmrp/wasm/fs@/ --js-output=vmrp2.js

用法很简单，传入文件夹路径就行了
file_packager.exe ./fs
把生成的fs.js和fs.data放进dist文件夹
dist文件夹中的内容就是最终的vmrp网页版
*/

type FileInfo struct {
	FileName string `json:"filename"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	Audio    int    `json:"audio"`
}
type PackageInfo struct {
	Files             []FileInfo `json:"files"`
	RemotePackageSize int        `json:"remote_package_size"`
	PackageUUID       string     `json:"package_uuid"`
}

var data []byte
var rootDir string
var dirs []string
var packageInfo PackageInfo

func main() {
	rootDir = "."
	if len(os.Args) == 2 {
		rootDir = os.Args[1]
	}
	rootDir = filepath.Clean(rootDir)
	packageInfo.Files = make([]FileInfo, 0)
	packageInfo.PackageUUID = uuid.NewString()
	readDir(rootDir, 0)
	bts, err := json.MarshalIndent(packageInfo, "", "    ")
	if err != nil {
		panic(err)
	}
	str := strings.ReplaceAll(tpl, "{{packageInfo}}", string(bts))
	str = strings.ReplaceAll(str, "{{dirs}}", strings.Join(dirs, "\n"))
	ioutil.WriteFile("fs.js", []byte(str), 0666)
	ioutil.WriteFile("fs.data", data, 0666)
}

func cleanPath(v string) string {
	v = strings.ReplaceAll(v, "\\", "/")
	v = strings.TrimLeft(v, rootDir+"/")
	return v
}

func readDir(dirname string, level int) {
	if level > 0 {
		v := cleanPath(dirname)
		i := strings.LastIndex(v, "/")
		if i != -1 {
			dirs = append(dirs, "Module['FS_createPath']('/"+v[:i]+"', '"+v[i+1:]+"', true, true);")
		} else {
			dirs = append(dirs, "Module['FS_createPath']('/', '"+v+"', true, true);")
		}
	}
	files, err := ioutil.ReadDir(dirname)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		if file.IsDir() {
			readDir(filepath.Join(dirname, file.Name()), level+1)
		} else {
			s := filepath.Join(dirname, file.Name())
			bts, err := ioutil.ReadFile(s)
			if err != nil {
				panic(err)
			}
			data = append(data, bts...)

			start := 0
			var end int = int(file.Size())
			if len(packageInfo.Files) > 0 {
				start = packageInfo.Files[len(packageInfo.Files)-1].End
				end += start
			}
			f := FileInfo{
				FileName: "/" + cleanPath(s),
				Start:    start,
				End:      end,
			}
			packageInfo.Files = append(packageInfo.Files, f)
			packageInfo.RemotePackageSize += int(file.Size())
		}
	}
}

var tpl = `var Module = typeof Module !== 'undefined' ? Module : {};
if (!Module.expectedDataFileDownloads) {
    Module.expectedDataFileDownloads = 0;
}
Module.expectedDataFileDownloads++;
(function() {
    var loadPackage = function(metadata) {

        var PACKAGE_PATH;
        if (typeof window === 'object') {
            PACKAGE_PATH = window['encodeURIComponent'](window.location.pathname.toString().substring(0, window.location.pathname.toString().lastIndexOf('/')) + '/');
        } else if (typeof location !== 'undefined') {
            // worker
            PACKAGE_PATH = encodeURIComponent(location.pathname.toString().substring(0, location.pathname.toString().lastIndexOf('/')) + '/');
        } else {
            throw 'using preloaded data can only be done on a web page or in a web worker';
        }
        var PACKAGE_NAME = 'fs.data';
        var REMOTE_PACKAGE_BASE = 'fs.data';
        if (typeof Module['locateFilePackage'] === 'function' && !Module['locateFile']) {
            Module['locateFile'] = Module['locateFilePackage'];
            err('warning: you defined Module.locateFilePackage, that has been renamed to Module.locateFile (using your locateFilePackage for now)');
        }
        var REMOTE_PACKAGE_NAME = Module['locateFile'] ? Module['locateFile'](REMOTE_PACKAGE_BASE, '') : REMOTE_PACKAGE_BASE;

        var REMOTE_PACKAGE_SIZE = metadata['remote_package_size'];
        var PACKAGE_UUID = metadata['package_uuid'];

        function fetchRemotePackage(packageName, packageSize, callback, errback) {
            var xhr = new XMLHttpRequest();
            xhr.open('GET', packageName, true);
            xhr.responseType = 'arraybuffer';
            xhr.onprogress = function(event) {
                var url = packageName;
                var size = packageSize;
                if (event.total) size = event.total;
                if (event.loaded) {
                    if (!xhr.addedTotal) {
                        xhr.addedTotal = true;
                        if (!Module.dataFileDownloads) Module.dataFileDownloads = {};
                        Module.dataFileDownloads[url] = {
                            loaded: event.loaded,
                            total: size
                        };
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
            xhr.onerror = function(event) {
                throw new Error("NetworkError for: " + packageName);
            }
            xhr.onload = function(event) {
                if (xhr.status == 200 || xhr.status == 304 || xhr.status == 206 || (xhr.status == 0 && xhr.response)) { // file URLs can return 0
                    var packageData = xhr.response;
                    callback(packageData);
                } else {
                    throw new Error(xhr.statusText + " : " + xhr.responseURL);
                }
            };
            xhr.send(null);
        };

        function handleError(error) {
            console.error('package error:', error);
        };

        var fetchedCallback = null;
        var fetched = Module['getPreloadedPackage'] ? Module['getPreloadedPackage'](REMOTE_PACKAGE_NAME, REMOTE_PACKAGE_SIZE) : null;

        if (!fetched) fetchRemotePackage(REMOTE_PACKAGE_NAME, REMOTE_PACKAGE_SIZE, function(data) {
            if (fetchedCallback) {
                fetchedCallback(data);
                fetchedCallback = null;
            } else {
                fetched = data;
            }
        }, handleError);

        function runWithFS() {

            function assert(check, msg) {
                if (!check) throw msg + new Error().stack;
            }
{{dirs}}
            /** @constructor */
            function DataRequest(start, end, audio) {
                this.start = start;
                this.end = end;
                this.audio = audio;
            }
            DataRequest.prototype = {
                requests: {},
                open: function(mode, name) {
                    this.name = name;
                    this.requests[name] = this;
                    Module['addRunDependency']('fp ' + this.name);
                },
                send: function() {},
                onload: function() {
                    var byteArray = this.byteArray.subarray(this.start, this.end);
                    this.finish(byteArray);
                },
                finish: function(byteArray) {
                    var that = this;

                    Module['FS_createDataFile'](this.name, null, byteArray, true, true, true); // canOwn this data in the filesystem, it is a slide into the heap that will never change
                    Module['removeRunDependency']('fp ' + that.name);

                    this.requests[this.name] = null;
                }
            };

            var files = metadata['files'];
            for (var i = 0; i < files.length; ++i) {
                new DataRequest(files[i]['start'], files[i]['end'], files[i]['audio']).open('GET', files[i]['filename']);
            }


            function processPackageData(arrayBuffer) {
                assert(arrayBuffer, 'Loading data file failed.');
                assert(arrayBuffer instanceof ArrayBuffer, 'bad input to processPackageData');
                var byteArray = new Uint8Array(arrayBuffer);
                var curr;

                // Reuse the bytearray from the XHR as the source for file reads.
                DataRequest.prototype.byteArray = byteArray;

                var files = metadata['files'];
                for (var i = 0; i < files.length; ++i) {
                    DataRequest.prototype.requests[files[i].filename].onload();
                }
                Module['removeRunDependency']('datafile_fs.data');

            };
            Module['addRunDependency']('datafile_fs.data');

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

    }
    loadPackage({{packageInfo}});
})();
`
