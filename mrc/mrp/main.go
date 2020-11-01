package main

// ext文件实际是fmt(elf)文件仅保留ro/rw/zi段，然后在开始处增加8字节MRPGCMAP
// 中间要保留下来的长度这样得到：
// Program header在文件开头偏移量28的4字节记录
// 这个偏移量再加上16得到一个新的偏移量，在这个位置的4字节就是代码的长度
// 最后删除开始52字节(elf头)和保留长度之后的东西

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func paif(err error) {
	if err != nil {
		panic(err)
	}
}

func gzipFile(file string) []byte {
	inFile, err := os.Open(file)
	paif(err)
	defer inFile.Close()

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err = io.Copy(zw, inFile)
	paif(err)
	err = zw.Close()
	paif(err)
	return buf.Bytes()
}

func toExt(elfFileName string, outputFileName string) {
	fmt.Println(elfFileName, "->", outputFileName)
	ef, err := elf.Open(elfFileName)
	paif(err)
	if len(ef.Progs) != 1 {
		panic(errors.New("len(ef.Progs) != 1"))
	}
	filesz := ef.Progs[0].Filesz
	ef.Close()

	f, err := os.Open(elfFileName)
	paif(err)
	defer f.Close()

	_, err = f.Seek(52, os.SEEK_SET)
	paif(err)

	buf := make([]byte, filesz)
	n, err := f.Read(buf)
	paif(err)
	if n != len(buf) {
		panic(errors.New("n != len(buf)"))
	}
	buf = append([]byte("MRPGCMAP"), buf...)
	err = ioutil.WriteFile(outputFileName, buf, 0666)
	paif(err)
}

type MRPHeader struct {
	Magic         [4]byte
	FileStart     uint32
	MrpTotalLen   uint32
	MRPHeaderSize uint32
	FileName      [12]byte
	DisplayName   [24]byte
	Unknown       [16]byte
	AppidLE       uint32
	VersionLE     uint32
	Unknown2      [12]byte
	Vendor        [40]byte
	Desc          [64]byte
	AppidBE       uint32
	VersionBE     uint32
	Unknown3      [40]byte
}

func main2() {
	buf, err := ioutil.ReadFile("asm.mrp")
	paif(err)

	var data MRPHeader
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &data); err != nil {
		fmt.Println("binary.Read failed:", err)
	}
	printHeader(&data)
}

func printHeader(data *MRPHeader) {
	fmt.Println("Magic:", string(data.Magic[:]))
	fmt.Println("FileStart:", data.FileStart)
	fmt.Println("MrpTotalLen:", data.MrpTotalLen)
	fmt.Println("MRPHeaderSize:", data.MRPHeaderSize)
	fmt.Println("FileName:", string(data.FileName[:]))
	fmt.Println("DisplayName:", foo(data.DisplayName[:]))
	fmt.Println("Unknown:", data.Unknown)
	fmt.Println("AppidLE:", data.AppidLE)
	fmt.Println("VersionLE:", data.VersionLE)
	fmt.Println("Unknown2:", data.Unknown2)
	fmt.Println("Vendor:", foo(data.Vendor[:]))
	fmt.Println("Desc:", foo(data.Desc[:]))
	fmt.Println("AppidBE:", data.AppidBE)
	fmt.Println("VersionBE:", data.VersionBE)
	fmt.Println("Unknown3:", data.Unknown3)

	fmt.Println("test AppidLE:", BigEndianToLittleEndian(data.AppidBE))
	fmt.Println("test AppidBE:", LittleEndianToBigEndian(data.AppidLE))
}

func foo(bts []byte) string {
	var dec = simplifiedchinese.GBK.NewDecoder()
	r, err := dec.Bytes(bts)
	paif(err)
	return string(r)
}

func BigEndianToLittleEndian(v uint32) uint32 {
	a := make([]byte, 4)
	binary.BigEndian.PutUint32(a, v)
	return binary.LittleEndian.Uint32(a)
}

func LittleEndianToBigEndian(v uint32) uint32 {
	a := make([]byte, 4)
	binary.LittleEndian.PutUint32(a, v)
	return binary.BigEndian.Uint32(a)
}

func getUint32Data(v uint32) []byte {
	a := make([]byte, 4)
	binary.LittleEndian.PutUint32(a, v)
	return a
}

type Config struct {
	Display     string   `json:"display"`
	FileName    string   `json:"filename"`
	Appid       uint32   `json:"appid"`
	Version     uint32   `json:"version"`
	Vendor      string   `json:"vendor"`
	Description string   `json:"description"`
	Files       []string `json:"files"`
}

type FileList struct {
	FileNameLen uint32
	FileName    []byte
	FilePos     uint32
	FileLen     uint32
	Unknown     uint32
	FileData    []byte
}

func initHeader(header *MRPHeader, config *Config) {
	header.Magic = [4]byte{'M', 'R', 'P', 'G'}
	header.MRPHeaderSize = 240
	header.AppidLE = config.Appid
	header.VersionLE = config.Version
	header.AppidBE = LittleEndianToBigEndian(config.Appid)
	header.VersionBE = LittleEndianToBigEndian(config.Version)

	// 不知道是什么，复制一个mrp文件里的
	header.Unknown = [16]byte{55, 49, 97, 56, 56, 97, 57, 53, 101, 0, 0, 0, 0, 0, 0, 0}
	header.Unknown2 = [12]byte{7, 0, 0, 0, 18, 39, 0, 0, 172, 210, 69, 95}

	tmp := utf8Togbk(config.FileName)
	if len(tmp) > 11 {
		paif(errors.New("FileName.length > 11"))
	}
	for i, v := range tmp {
		header.FileName[i] = v
	}

	tmp = utf8Togbk(config.Display)
	if len(tmp) > 23 {
		paif(errors.New("Display.length > 11"))
	}
	for i, v := range tmp {
		header.DisplayName[i] = v
	}

	tmp = utf8Togbk(config.Vendor)
	if len(tmp) > 39 {
		paif(errors.New("Vendor.length > 11"))
	}
	for i, v := range tmp {
		header.Vendor[i] = v
	}

	tmp = utf8Togbk(config.Description)
	if len(tmp) > 23 {
		paif(errors.New("Description.length > 11"))
	}
	for i, v := range tmp {
		header.Desc[i] = v
	}
}

func main() {
	var config Config
	var header MRPHeader

	bts, err := ioutil.ReadFile("pack.json")
	paif(err)
	err = json.Unmarshal(bts, &config)
	paif(err)

	initHeader(&header, &config)

	fileList := make([]FileList, len(config.Files))
	var listLen, dataLen uint32
	for i, v := range config.Files {
		if strings.ToLower(path.Ext(v)) == ".elf" {
			ext := strings.Replace(v, ".elf", ".ext", -1)
			toExt(v, ext)
			v = ext
		}
		_, file := path.Split(v)
		// []byte(file) 转换出来的slice是没有'\0'结尾的
		tmp := append([]byte(file), 0x00)
		listItem := &fileList[i]
		listItem.FileName = tmp
		listItem.FileNameLen = uint32(len(tmp))
		listItem.FileData = gzipFile(v)
		listItem.FileLen = uint32(len(listItem.FileData))
		// 每个列表项中由文件名长度、文件名、文件偏移、文件长度、0 组成，数值都是uint32因此需要4*4
		listLen += listItem.FileNameLen + 4*4
		dataLen += listItem.FileNameLen + 4*2 + listItem.FileLen
	}
	// 第一个文件数据的开始位置
	var filePos uint32 = header.MRPHeaderSize + listLen
	header.FileStart = filePos - 8 // 不明白为什么要减8，但是必需这样做
	header.MrpTotalLen = header.MRPHeaderSize + listLen + dataLen

	mrpf, err := os.Create(config.FileName)
	paif(err)
	defer mrpf.Close()

	// 写文件头
	err = binary.Write(mrpf, binary.LittleEndian, &header)
	paif(err)

	// 写出文件列表
	for i := range fileList {
		listItem := &fileList[i]
		// 每个文件数据由：文件名长度、文件名、文件大小组成，数值都是uint32因此需要4*2
		filePos += listItem.FileNameLen + 4*2
		listItem.FilePos = filePos
		// 下一个文件数据的开始位置
		filePos += listItem.FileLen

		mrpf.Write(getUint32Data(listItem.FileNameLen))
		mrpf.Write(listItem.FileName)
		mrpf.Write(getUint32Data(listItem.FilePos))
		mrpf.Write(getUint32Data(listItem.FileLen))
		mrpf.Write(getUint32Data(0))
		fmt.Println(string(listItem.FileName), listItem.FilePos, listItem.FileLen)
	}

	// 写出文件数据
	for i := range fileList {
		listItem := &fileList[i]
		mrpf.Write(getUint32Data(listItem.FileNameLen))
		mrpf.Write(listItem.FileName)
		mrpf.Write(getUint32Data(listItem.FileLen))
		mrpf.Write(listItem.FileData)
	}
	fmt.Println("done.")
}

func utf8Togbk(str string) []byte {
	var enc = simplifiedchinese.GBK.NewEncoder()
	bts, err := enc.Bytes([]byte(str))
	paif(err)
	return bts
}
