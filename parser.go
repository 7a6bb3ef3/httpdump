package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const (
	lowerClKey = "content-length:"
	lowerTf    = "transfer-encoding: chunked"
)

func CapHTTPFromStream(rd io.Reader) (interface{}, HeaderStat, error) {
	data, stat, e := ReadHTTPFromStream(rd)
	if e != nil {
		return nil, stat, fmt.Errorf("ReadHTTPFromStream: %w", e)
	}

	bufrd := bufio.NewReader(bytes.NewBuffer(data))
	if stat.Request {
		req, e := http.ReadRequest(bufrd)
		return req, stat, e
	} else if stat.Response {
		resp, e := http.ReadResponse(bufrd, nil)
		return resp, stat, e
	}
	return nil, HeaderStat{}, nil
}

type HeaderStat struct {
	ContentLength int
	Chunked       bool
	Request       bool
	Response      bool
}

func ParseHeader(header string) (HeaderStat, error) {
	stat := HeaderStat{}
	lines := strings.Split(header, "\r\n")
	// Only check prefix HTTP
	if len(lines) > 0 && strings.HasPrefix(lines[0], "HTTP") {

		stat.Response = true
		if findTransferEncoding(lines) {
			stat.Chunked = true
			return stat, nil
		}
		l, e := findContentLength(lines)
		if e != nil {
			return stat, fmt.Errorf("findContentLength: %w", e)
		}
		stat.ContentLength = l
		return stat, nil

	} else if strings.HasPrefix(lines[0], http.MethodGet) || strings.HasPrefix(lines[0], http.MethodDelete) || strings.HasPrefix(lines[0], http.MethodTrace) ||
		strings.HasPrefix(lines[0], http.MethodHead) || strings.HasPrefix(lines[0], http.MethodOptions) {

		// Empty request body
		stat.Request = true
		return stat, nil

	} else if strings.HasPrefix(lines[0], http.MethodConnect) || strings.HasPrefix(lines[0], http.MethodPost) ||
		strings.HasPrefix(lines[0], http.MethodPut) || strings.HasPrefix(lines[0], http.MethodPatch) {

		stat.Request = true
		l, e := findContentLength(lines)
		if e != nil {
			return stat, fmt.Errorf("findContentLength: %w", e)
		}
		stat.ContentLength = l

	}
	return stat, errors.New("can not find 'Content-length' or 'Transfer-Encoding: chunked'")
}

// findContentLength content-length 0 if not exist
func findContentLength(lines []string) (int, error) {
	for _, v := range lines {
		lv := strings.ToLower(v)
		// Content-Length
		if strings.HasPrefix(lv, lowerClKey) {
			l, e := strconv.Atoi(strings.TrimSpace(lv[len(lowerClKey):]))
			if e != nil {
				return 0, fmt.Errorf("Content-Length exists but it can not be parsed: %w", e)
			}
			return l, nil
		}
	}
	return 0, nil
}

func findTransferEncoding(lines []string) bool {
	for _, v := range lines {
		lv := strings.ToLower(v)
		if strings.HasPrefix(lv, lowerTf) {
			return true
		}
	}
	return false
}

func ReadHTTPFromStream(rd io.Reader) ([]byte, HeaderStat, error) {
	header, e := ReadBytes(rd, "\r\n\r\n")
	if e != nil {
		return nil, HeaderStat{}, fmt.Errorf("ReadBytes: %w", e)
	}

	stat, e := ParseHeader(string(header))
	if e != nil {
		return nil, stat, fmt.Errorf("ParseHeader: %w", e)
	}

	if stat.Chunked {
		body, e := ReadChunked(rd)
		if e != nil {
			return nil, stat, fmt.Errorf("ReadChunked: read chunked body %w", e)
		}
		return append(header, body...), stat, nil
	}

	if !stat.Chunked && stat.ContentLength == 0 {
		return header, stat, nil
	}

	// Content-Length > 0
	body := make([]byte, stat.ContentLength)
	_, e = io.ReadFull(rd, body)
	if e != nil {
		return nil, stat, fmt.Errorf("ReadFull: read body(%db) %w", stat.ContentLength, e)
	}
	return append(header, body...), stat, nil
}

func ReadBytes(rd io.Reader, delim string) ([]byte, error) {
	if delim == "" {
		return nil, errors.New("empty delim string")
	}
	dst := &bytes.Buffer{}
	buf := make([]byte, 1)
	c := 0
	for {
		_, e := rd.Read(buf)
		if e != nil {
			return nil, e
		}

		dst.WriteByte(buf[0])
		if delim[c] == buf[0] {
			c++
			logrus.Debug(dst.String())
		} else {
			c = 0
		}

		if c == len(delim) {
			return dst.Bytes(), nil
		}
	}
}

func ReadChunked(rd io.Reader) ([]byte ,error){
	//buf := make([]byte ,1)
	//c := 0
	//for {
	//	n ,e := rd.Read(buf)
	//	if e != nil {
	//		panic(e)
	//	}
	//	c++
	//	logrus.Debug(string(buf[:n]) ," " ,c)
	//}
	var chunkLen int64
	dst := &bytes.Buffer{}
	for {
		hexlen ,e := ReadBytes(rd ,"\r\n")
		if e != nil {
			return nil ,fmt.Errorf("ReadBytes: %w" ,e)
		}
		dst.Write(hexlen)
		// end of chunk
		if string(hexlen) == "0\r\n" {
			dst.WriteString("\r\n")
			return dst.Bytes() ,nil
		}
		tr := strings.TrimSpace(string(hexlen))
		chunkLen ,e = strconv.ParseInt(tr ,16 ,64)
		if e != nil {
			return nil ,fmt.Errorf("strconv.ParseInt: %w" ,e)
		}
		logrus.Debugf("read chunk length: %d(%s)" ,chunkLen ,tr)
		buf := make([]byte ,chunkLen)
		_ ,e = io.ReadFull(rd ,buf)
		if e != nil {
			return nil ,fmt.Errorf("io.ReadFull: %w" ,e)
		}
		dst.Write(buf)
	}
}