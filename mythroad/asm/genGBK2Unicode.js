// gbk转unicode转换表生成器 数据来源 https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP936.TXT

const fs = require('fs');

function parseLine(line) {
    return line.split('#')[0].trim().split(/\t/).map(v => Number(v));
}

function getAll() {
    const strs = fs.readFileSync('./CP936.TXT').toString().split('\n');
    const arr = [];
    for (const line of strs) {
        if (line.startsWith('0x')) {
            const currLine = parseLine(line);
            if (currLine[0] < 0x8140) {
                continue;
            }
            arr.push(currLine);
        }
    }
    return arr;
}

// 统计连续块
function getStat(index) {
    const arr = getAll();
    arr.sort((a, b) => a[index] - b[index]);
    let start = undefined;
    let tmp = [];
    const res = [];
    for (let i = 0; i < arr.length; i++) {
        const curr = arr[i];
        const next = arr[i + 1];
        tmp.push(curr);
        if (start === undefined) {
            start = curr[index];
        }
        if ((next === undefined) || (curr[index] + 1 !== next[index])) {
            res.push({
                start: start,
                startStr: start.toString(16),
                end: curr[index],
                endStr: curr[index].toString(16),
                n: curr[index] - start + 1,
                data: tmp,
            });
            tmp = [];
            if (next === undefined) {
                break;
            }
            start = next[index];
        }
    }

    res.sort((a, b) => b.n - a.n);
    // console.log(res[0]);
    // console.log(res);
    console.log(res.length);
    return res;
}

function exportUnicode2GB() {
    let datas = getStat(1);

    // 0x4E00 - 0x9FA5 线性表 共20902
    function exportData(o) {
        const dataStr = o.data.map(v => '0x' + v[0].toString(16).toUpperCase()).reduce(function (prev, curr, currIndex) {
            let ret = prev + curr + ', ';
            if ((currIndex + 1) % 9 === 0) {
                ret += '\n\t';
            }
            return ret;
        }, '\t');
        return `static const unsigned short ucs2gb_${o.startStr}_${o.endStr}[${o.n}] = {\n${dataStr}\n};`;
    }
    fs.writeFileSync("tab.txt", exportData(datas[0]));

    // 剩余表
    datas.shift();
    datas = datas.reduce(function (prev, curr) {
        return prev.concat(curr.data);
    }, []).sort((a, b) => a[1] - b[1]);
    datas = datas.map(function (v) {
        return v.map(v => '0x' + ('00' + v.toString(16).toUpperCase()).substr(-4));
    })
    console.log(datas[0]);
    console.log(datas[datas.length - 1]);
    console.log(datas.length);

    const dataStr = datas.reduce(function (prev, curr, currIndex) {
        let ret = prev + `{${curr[1]}, ${curr[0]}}, `;
        if ((currIndex + 1) % 9 === 0) {
            ret += '\n\t';
        }
        return ret;
    }, '\t');

    const result = `typedef struct ucs2gb_st {\n\tunsigned short ucs;\n\tunsigned short gb;\n} ucs2gb_st;\n` +
        `static const ucs2gb_st ucs2gb_other[${datas.length}] = {\n${dataStr}\n};`;

    fs.writeFileSync("tab2.txt", result);
}

function exportGB2Unicode() {
    let arr = getAll();
    arr.sort((a, b) => a[0] - b[0]);
    arr = arr.map(function (v) {
        return v.map(v => '0x' + ('00' + v.toString(16).toUpperCase()).substr(-4));
    });
    console.log(arr[0]);
    console.log(arr[arr.length - 1]);
    console.log(arr.length);

    const dataStr = arr.reduce(function (prev, curr, currIndex) {
        let ret = prev + `{${curr[0]}, ${curr[1]}}, `;
        if ((currIndex + 1) % 9 === 0) {
            ret += '\n\t';
        }
        return ret;
    }, '\t');

    const result = `typedef struct gb2ucs_st {\n\tunsigned short gb;\n\tunsigned short ucs;\n} gb2ucs_st;\n` +
        `static const gb2ucs_st tab_gb2ucs_${arr[0][0]}_${arr[arr.length - 1][0]}[${arr.length}] = {\n${dataStr}\n};`;

    fs.writeFileSync("gb2ucs.txt", result);
}

exportUnicode2GB();
exportGB2Unicode();

