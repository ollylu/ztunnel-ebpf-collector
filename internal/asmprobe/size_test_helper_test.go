package asmprobe

import (
	"unsafe"
)

// unsafeSizeof 仅供 ABI 长度测试使用（避免在测试里直接依赖 unsafe 于生产文件）。
func unsafeSizeof(e Event) uintptr { return unsafe.Sizeof(e) }

// binaryLittleEndianPut 仅供 reserved 位断言：写入非零前缀，保留位应保持 0。
func binaryLittleEndianPut(b []byte) {
	for i := 0; i < 24; i++ {
		b[i] = 0xAB
	}
}
