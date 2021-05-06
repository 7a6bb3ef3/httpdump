package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
	"time"
)

func CapHTTP(ctx *cli.Context) error {
	if ctx.Bool("v") {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if handle, err := pcap.OpenLive(ctx.String("d"), int32(ctx.Int64("l")), ctx.Bool("p"), pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(ctx.String("bpf")); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		streamFactory := NewHTTPStreamFactory(ctx)
		streamPool := tcpassembly.NewStreamPool(streamFactory)
		assembler := tcpassembly.NewAssembler(streamPool)

		flushtk := time.NewTicker(time.Minute)
		for packet := range packetSource.Packets() {
			select {
			case <-flushtk.C:
				assembler.FlushOlderThan(time.Now().Add(-time.Minute * 2))
			default:
			}

			if packet == nil ||
				packet.NetworkLayer() == nil ||
				packet.TransportLayer() == nil ||
				packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		}
	}
	return nil
}

// httpStreamFactory implements tcpassembly.StreamFactory
type HTTPStreamFactory struct {
	ctx        *cli.Context
	httpFilter *HTTPFilter
}

func NewHTTPStreamFactory(ctx *cli.Context) *HTTPStreamFactory {
	return &HTTPStreamFactory{
		ctx:        ctx,
		httpFilter: NewHTTPFilter(ctx),
	}
}

func (h *HTTPStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	rs := tcpreader.NewReaderStream()
	if NetworkFilter(h.ctx, net, transport) {
		go Handle(h.httpFilter, net, transport, &rs)
	}
	return &rs
}

func Handle(f *HTTPFilter, net, transport gopacket.Flow, stream *tcpreader.ReaderStream) {
	defer tcpreader.DiscardBytesToEOF(stream)

	logrus.Debugf("%s:%s -> %s:%s", net.Src().String(), transport.Src().String(), net.Dst().String(), transport.Dst().String())

	for {
		i, stat, e := CapHTTPFromStream(stream)
		if e != nil {
			logrus.Debugf("CapHTTPFromStream: %s", e.Error())
			return
		}

		var dumpdata []byte
		if stat.Request {
			req, ok := i.(*http.Request)
			if !ok {
				logrus.Debug("Assert: i.(*http.Request) failed")
				return
			}
			if !f.FilterRequest(req) {
				continue
			}
			dumpdata, e = DumpReq(f.IgnoreBody, req)
			if e != nil {
				logrus.Debugf("DumpReq: %s", e.Error())
				return
			}
		} else if stat.Response {
			resp, ok := i.(*http.Response)
			if !ok {
				logrus.Debug("Assert: i.(*http.Request) failed")
				return
			}
			if !f.FilterResponse(resp) {
				continue
			}
			dumpdata, e = DumpResp(f.IgnoreBody, resp)
			if e != nil {
				logrus.Debugf("DumpResp: %s", e.Error())
				return
			}
		} else {
			logrus.Debug("Neither stat.Request nor stat.Response")
			return
		}

		if f.Regexp(dumpdata) {
			PrintDump(net, transport, dumpdata)
		}
	}
}

func PrintDump(net, transport gopacket.Flow, dumpBytes []byte) {
	fmt.Printf("%s:%s -> %s:%s\n%s\n\n", net.Src().String(), transport.Src().String(), net.Dst().String(), transport.Dst().String(), string(dumpBytes))
}

func DumpResp(ignore bool, resp *http.Response) ([]byte, error) {
	b, e := httputil.DumpResponse(resp, !ignore)
	if e != nil {
		return nil, e
	}
	return b, nil
}

func DumpReq(ignore bool, req *http.Request) ([]byte, error) {
	b, e := httputil.DumpRequest(req, !ignore)
	if e != nil {
		return nil, e
	}
	return b, nil
}

func NetworkFilter(ctx *cli.Context, net, transport gopacket.Flow) bool {
	netsrc, netdst := net.Endpoints()
	trsrc, trdst := transport.Endpoints()

	dstip := ctx.String("dst.ip")
	if dstip != "" && netdst.String() != dstip {
		logrus.Debugf("Drop packet: mismatched dst.ip ,expected: %s ,got: %s", dstip, netdst.String())
		return false
	}
	srcip := ctx.String("src.ip")
	if srcip != "" && netsrc.String() != srcip {
		logrus.Debugf("Drop packet: mismatched src.ip ,expected: %s ,got: %s", srcip, netsrc.String())
		return false
	}

	dstp := ctx.Int("dst.port")
	if dstp != 0 && trdst.String() != strconv.Itoa(dstp) {
		logrus.Debugf("Drop packet: mismatched dst.port ,expected: %d ,got: %s", dstp, trdst.String())
		return false
	}
	srcp := ctx.Int("src.port")
	if srcp != 0 && trsrc.String() != strconv.Itoa(srcp) {
		logrus.Debugf("Drop packet: mismatched src.port ,expected: %d ,got: %s", srcp, trsrc.String())
		return false
	}

	return true
}

type HTTPFilter struct {
	StatusCode   int
	Method       string
	RequestOnly  bool
	ResponseOnly bool
	IgnoreBody   bool
	reg          *regexp.Regexp
}

func NewHTTPFilter(ctx *cli.Context) *HTTPFilter {
	var reg *regexp.Regexp
	if r := ctx.String("regexp"); r != "" {
		reg = regexp.MustCompile(r)
	}
	return &HTTPFilter{
		StatusCode:   ctx.Int("status"),
		Method:       ctx.String("method"),
		RequestOnly:  ctx.Bool("req"),
		ResponseOnly: ctx.Bool("resp"),
		IgnoreBody:   ctx.Bool("ignoreBody"),
		reg:          reg,
	}
}

func (f *HTTPFilter) Regexp(dump []byte) bool {
	if f.reg == nil {
		return true
	}

	return f.reg.Match(dump)
}

func (f *HTTPFilter) FilterRequest(req *http.Request) bool {
	if req == nil {
		return false
	}
	if f.ResponseOnly || f.StatusCode != 0 {
		logrus.Debugf("Drop packet: mismatched packet type: request")
		return false
	}
	if f.Method != "" && f.Method != req.Method {
		logrus.Debugf("Drop packet: mismatched request method ,expected: %s ,got: %s", f.Method, req.Method)
		return false
	}
	return true
}

func (f *HTTPFilter) FilterResponse(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if f.RequestOnly || f.Method != "" {
		logrus.Debugf("Drop packet: mismatched packet type: response")
		return false
	}
	if f.StatusCode != 0 && f.StatusCode != resp.StatusCode {
		logrus.Debugf("Drop packet: mismatched response status ,expected: %d ,got: %d", f.StatusCode, resp.StatusCode)
		return false
	}
	return true
}
