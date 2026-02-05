/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	dnsmessage "github.com/miekg/dns"
)

const (
	maxJumpCount = 10 // 限制跳转次数，防止死循环
)

type RRInfo struct {
	Type      uint16
	RROffset  int    // 整个 RR 记录的起始位置（Name 之后，Type 开始的位置）
	TTLOffset int    // TTL 字段的起始位置
	TTL       uint32 // 原始 TTL
}

type RscWrapper struct {
	Rsc dnsmessage.RR
}

func (w RscWrapper) String() string {
	var strBody string
	switch body := w.Rsc.(type) {
	case *dnsmessage.A:
		strBody = body.A.String()
	case *dnsmessage.AAAA:
		strBody = body.AAAA.String()
	case *dnsmessage.CNAME:
		strBody = body.Target
	default:
		strBody = body.String()
	}
	return fmt.Sprintf("%v(%v): %v", w.Rsc.Header().Name, QtypeToString(w.Rsc.Header().Rrtype), strBody)
}

func FormatDnsRsc(data []byte) string {
	msg := &dnsmessage.Msg{}
	if err := msg.Unpack(data); err != nil {
		return fmt.Sprintf("FormatDnsRsc: unpack failed: %v", err)
	}
	var w []string
	for _, a := range msg.Answer {
		w = append(w, RscWrapper{Rsc: a}.String())
	}
	return strings.Join(w, "; ")
}

func QtypeToString(qtype uint16) string {
	str, ok := dnsmessage.TypeToString[qtype]
	if !ok {
		str = strconv.Itoa(int(qtype))
	}
	return str
}

func dnsDomain(data []byte, startOffset int) (string, int, error) {
	off := startOffset
	jumped := false
	nextOff := 0 // 用于记录逻辑上的“下一个字段”的起始位置
	jumpCount := 0

	var labels []string

	for {
		if off >= len(data) {
			return "", 0, errors.New("offset out of range")
		}

		length := int(data[off])

		// 1. 检查是否为指针 (0xC0)
		if length&0xC0 == 0xC0 {
			if off+1 >= len(data) {
				return "", 0, errors.New("invalid pointer")
			}

			// 指针地址由当前字节的低 6 位和下一个字节组成 (共 14 位)
			pointer := int(length&0x3F)<<8 | int(data[off+1])

			if !jumped {
				nextOff = off + 2 // 第一次跳转前，记录下 Question 字段后面该从哪读
				jumped = true
			}

			off = pointer
			jumpCount++
			if jumpCount > maxJumpCount {
				return "", 0, errors.New("too many DNS compression jumps")
			}
			continue
		}

		// 2. 检查是否为结束符 (0x00)
		if length == 0 {
			off++
			break
		}

		// 3. 普通标签解析
		off++
		if off+length > len(data) {
			return "", 0, errors.New("label length exceeds packet size")
		}

		labels = append(labels, string(data[off:off+length]))
		off += length
	}

	// 计算返回的偏移量
	if !jumped {
		nextOff = off
	}

	return strings.Join(labels, "."), nextOff, nil
}

func dnsSkipDomain(data []byte, off int) (int, error) {
	for {
		if off >= len(data) {
			return 0, fmt.Errorf("offset out of range")
		}
		b := data[off]
		if b == 0 { // 结束符
			return off + 1, nil
		}
		if b&0xc0 == 0xc0 { // 压缩指针，占用 2 字节
			if off+2 > len(data) {
				return 0, fmt.Errorf("truncated pointer")
			}
			return off + 2, nil
		}
		// 普通标签：b 是长度，跳过 b 字节再加长度字节本身
		off += int(b) + 1
	}
}

func dnsId(data []byte) uint16 {
	return uint16(data[0])<<8 | uint16(data[1])
}

func dnsIdSet(data []byte, id uint16) {
	data[0] = byte(id >> 8)
	data[1] = byte(id & 0xff)
}

func dnsRcode(data []byte) uint8 {
	if len(data) < 4 {
		return 0
	}
	return data[3] & 0x0F
}

func dnsRcodeSet(data []byte, rcode uint8) {
	if len(data) >= 4 {
		data[2] |= 0x80
		data[3] = (data[3] & 0xF0) | (rcode & 0x0F)
	}
}

func dnsResponse(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	return data[2]&0x80 != 0 // QR
}

func dnsResponseSet(data []byte, res bool) {
	if len(data) >= 3 {
		if res {
			data[2] |= 0x80
		} else {
			data[2] &= 0x7F
		}
	}
}

func isDnsResponseValid(resp []byte) bool {
	// DNS Header 固定为 12 字节
	if len(resp) < 12 {
		return false
	}

	// 1. 检查是否为响应包 (QR 位)
	// 第 2 字节最高位必须为 1
	if resp[2]&0x80 == 0 {
		return false
	}

	// 2. 检查 Rcode 是否为 Success (0)
	// 第 3 字节低 4 位必须为 0
	if resp[3]&0x0F != 0 {
		return false
	}

	// 3. 检查 Question 数量 (QDCOUNT) 是否 > 0
	// 偏移量 4-5 字节
	qdCount := binary.BigEndian.Uint16(resp[4:6])
	if qdCount == 0 {
		return false
	}

	// 4. 检查 Answer 数量 (ANCOUNT) 是否 > 0
	// 偏移量 6-7 字节
	anCount := binary.BigEndian.Uint16(resp[6:8])
	if anCount == 0 {
		return false
	}

	return true
}

func dnsAnswers(data []byte) (ips []netip.Addr, minTTL uint32) {
	// 1. 第一步：扫描报文，获取所有 RR 的元数据索引和全局最小 TTL
	// 这个函数负责了最繁重的域名跳过和偏移量计算工作
	infos, minTTL := dnsExtractMetadata(data)
	if len(infos) == 0 {
		return nil, 0
	}

	// 2. 第二步：根据索引快速提取 IP 地址
	// 由于有了 RROffset，我们现在可以"随机访问" RDATA 区
	ips = make([]netip.Addr, 0, len(infos))
	for _, info := range infos {
		if ip, ok := getIPFromRR(data, &info); ok {
			ips = append(ips, ip)
		}
	}

	return ips, minTTL
}

func dnsExtractMetadata(data []byte) (infos []RRInfo, minTTL uint32) {
	if len(data) < 12 {
		return nil, 0
	}

	qdCount := int(binary.BigEndian.Uint16(data[4:6]))
	anCount := int(binary.BigEndian.Uint16(data[6:8]))
	if anCount == 0 {
		return nil, 0
	}

	// 1. 跳过 Question 区
	off := 12
	for i := 0; i < qdCount; i++ {
		nextOff, err := dnsSkipDomain(data, off)
		if err != nil {
			return nil, 0
		}
		off = nextOff + 4
	}

	// 2. 遍历 Answer 区
	infos = make([]RRInfo, 0, anCount)
	minTTL = ^uint32(0)

	for i := 0; i < anCount; i++ {
		// 记录 Name 之后的起始位置，即 RR 核心数据的开始
		rrDataStart, err := dnsSkipDomain(data, off)
		if err != nil {
			break
		}

		if rrDataStart+10 > len(data) {
			break
		}

		rtype := binary.BigEndian.Uint16(data[rrDataStart : rrDataStart+2])
		ttlOff := rrDataStart + 4
		ttl := binary.BigEndian.Uint32(data[ttlOff : ttlOff+4])
		rdLen := int(binary.BigEndian.Uint16(data[rrDataStart+8 : rrDataStart+10]))

		infos = append(infos, RRInfo{
			Type:      rtype,
			RROffset:  rrDataStart,
			TTLOffset: ttlOff,
			TTL:       ttl,
		})

		if ttl < minTTL {
			minTTL = ttl
		}

		// 下一个 RR 的起始位置 = 当前核心数据开始 + 固定头(10) + RData长度
		off = rrDataStart + 10 + rdLen
	}

	return infos, minTTL
}

func getIPFromRR(data []byte, info *RRInfo) (netip.Addr, bool) {
	// A 记录：Type=1, RdLen=4
	if info.Type == 1 {
		// RData 偏移量 = RROffset + Type(2) + Class(2) + TTL(4) + RdLen(2) = 10
		rdataOff := info.RROffset + 10
		if rdataOff+4 <= len(data) {
			return netip.AddrFrom4([4]byte(data[rdataOff : rdataOff+4])), true
		}
	}
	// AAAA 记录：Type=28, RdLen=16
	if info.Type == 28 {
		rdataOff := info.RROffset + 10
		if rdataOff+16 <= len(data) {
			return netip.AddrFrom16([16]byte(data[rdataOff : rdataOff+16])), true
		}
	}
	return netip.Addr{}, false
}

func dnsSwitchQtype(data []byte) {
	// DNS Header 固定 12 字节
	if len(data) < 12 {
		return
	}

	// 1. 定位 QTYPE 的位置
	// 我们需要跳过 Header(12字节) 和 变长的 QNAME
	_, nextOff, err := dnsDomain(data, 12)
	if err != nil {
		return
	}

	// 2. 检查长度是否足够读取 QTYPE (2 字节)
	if len(data) < nextOff+2 {
		return
	}

	// 3. 读取并切换 QTYPE
	// QTYPE 的偏移量就是 nextOff
	qtype := binary.BigEndian.Uint16(data[nextOff : nextOff+2])

	switch qtype {
	case 1: // dnsmessage.TypeA (1)
		// 改为 TypeAAAA (28)
		binary.BigEndian.PutUint16(data[nextOff:nextOff+2], 28)
	case 28: // dnsmessage.TypeAAAA (28)
		// 改为 TypeA (1)
		binary.BigEndian.PutUint16(data[nextOff:nextOff+2], 1)
	}
}
