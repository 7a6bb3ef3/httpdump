package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/urfave/cli/v2"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"
)

func CapHTTP(ctx *cli.Context) error {
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

	if !filterNet(ctx, net, transport) {
		return
	}
	buf := bufio.NewReader(stream)
	b, e := ioutil.ReadAll(buf)
	if e != nil {
		fmt.Printf("Handle.ReadAll: %s\n", e.Error())
		return
	}
	data := string(b)
	if strings.HasPrefix(data, "HTTP") && !ctx.Bool("req") {
		resp, e := http.ReadResponse(bufio.NewReader(bytes.NewBuffer(b)), nil)
		if e != nil {
			fmt.Printf("Handle.ReadResponse: %s\n", e.Error())
			return
		}
		if !filter(ctx, nil, resp) {
			return
		}
		b, e := dumpResp(ctx, resp)
		if e != nil {
			fmt.Printf("Handle.DumpResponse: %s", e.Error())
			return
		}
		printDump(net, transport, b)
	} else if strings.HasPrefix(data, http.MethodGet) || strings.HasPrefix(data, http.MethodPost) ||
		strings.HasPrefix(data, http.MethodPut) || strings.HasPrefix(data, http.MethodDelete) ||
		strings.HasPrefix(data, http.MethodConnect) || strings.HasPrefix(data, http.MethodOptions) ||
		strings.HasPrefix(data, http.MethodTrace) || strings.HasPrefix(data, http.MethodHead) || strings.HasPrefix(data, http.MethodPatch) {
		if ctx.Bool("resp") {
			return
		}
		req, e := http.ReadRequest(bufio.NewReader(bytes.NewBuffer(b)))
		if e != nil {
			fmt.Printf("Handle.ReadRequest: %s\n", e.Error())
			return
		}
		if !filter(ctx, req, nil) {
			return
		}
		b, e := dumpReq(ctx, req)
		if e != nil {
			fmt.Printf("Handle.DumpRequest: %s", e.Error())
			return
		}
		printDump(net, transport, b)
	}
}

func printDump(net, transport gopacket.Flow, dumpBytes []byte) {
	fmt.Printf("%s:%s -> %s:%s\n%s\n\n", net.Src().String(), transport.Src().String(), net.Dst().String(), transport.Dst().String(), string(dumpBytes))
}

func dumpResp(ctx *cli.Context, resp *http.Response) ([]byte, error) {
	b, e := httputil.DumpResponse(resp, !ctx.Bool("i"))
	if e != nil {
		return nil, e
	}
	return b, nil
}

func dumpReq(ctx *cli.Context, resp *http.Request) ([]byte, error) {
	b, e := httputil.DumpRequest(resp, !ctx.Bool("i"))
	if e != nil {
		return nil, e
	}
	return b, nil
}

func filterNet(ctx *cli.Context, net, transport gopacket.Flow) bool {
	netsrc, netdst := net.Endpoints()
	dstip := ctx.String("dst.ip")
	if dstip != "" && netdst.String() != dstip {
		return false
	}
	srcip := ctx.String("src.ip")
	if srcip != "" && netsrc.String() != dstip {
		return false
	}

	trsrc, trdst := transport.Endpoints()
	dstp := ctx.Int("dst.port")
	if dstp != 0 && trdst.String() != strconv.Itoa(dstp) {
		return false
	}
	srcp := ctx.Int("src.port")
	if srcp != 0 && trsrc.String() != strconv.Itoa(srcp) {
		return false
	}

	return true
}

func filter(ctx *cli.Context, req *http.Request, resp *http.Response) bool {
	reqMethod := ctx.String("method")
	if req != nil && reqMethod != "" && reqMethod != req.Method {
		return false
	}

	respCode := ctx.Int("status")
	if resp != nil && respCode != 0 && respCode != resp.StatusCode {
		return false
	}

	return true
}
