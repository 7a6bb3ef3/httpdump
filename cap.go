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
	ctx *cli.Context
}

func NewHTTPStreamFactory(ctx *cli.Context) *HTTPStreamFactory {
	return &HTTPStreamFactory{ctx: ctx}
}

func (h *HTTPStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	rs := tcpreader.NewReaderStream()
	go Handle(h.ctx, net, transport, &rs)
	return &rs
}

func Handle(ctx *cli.Context, net, transport gopacket.Flow, stream *tcpreader.ReaderStream) {
	defer tcpreader.DiscardBytesToEOF(stream)

	logrus.Debugf("%s:%s -> %s:%s", net.Src().String(), transport.Src().String(), net.Dst().String(), transport.Dst().String())
	if !NetworkFilter(ctx, net, transport) {
		return
	}

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
		if !HTTPFilter(ctx, req, nil) {
			return
		}
		dumpdata, e = DumpReq(ctx, req)
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
		if !HTTPFilter(ctx, nil, resp) {
			return
		}
		dumpdata, e = DumpResp(ctx, resp)
		if e != nil {
			logrus.Debugf("DumpResp: %s", e.Error())
			return
		}
	} else {
		logrus.Debug("Neither stat.Request nor stat.Response")
		return
	}
	PrintDump(net, transport, dumpdata)
}

func PrintDump(net, transport gopacket.Flow, dumpBytes []byte) {
	fmt.Printf("%s:%s -> %s:%s\n%s\n\n", net.Src().String(), transport.Src().String(), net.Dst().String(), transport.Dst().String(), string(dumpBytes))
}

func DumpResp(ctx *cli.Context, resp *http.Response) ([]byte, error) {
	b, e := httputil.DumpResponse(resp, !ctx.Bool("i"))
	if e != nil {
		return nil, e
	}
	return b, nil
}

func DumpReq(ctx *cli.Context, req *http.Request) ([]byte, error) {
	b, e := httputil.DumpRequest(req, !ctx.Bool("i"))
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

func HTTPFilter(ctx *cli.Context, req *http.Request, resp *http.Response) bool {
	reqMethod := ctx.String("method")
	if req != nil && reqMethod != "" && reqMethod != req.Method {
		logrus.Debugf("Drop packet: mismatched request method ,expected: %s ,got: %s", reqMethod, req.Method)
		return false
	}

	respCode := ctx.Int("status")
	if resp != nil && respCode != 0 && respCode != resp.StatusCode {
		logrus.Debugf("Drop packet: mismatched response status ,expected: %d ,got: %d", respCode, resp.StatusCode)
		return false
	}

	return true
}
