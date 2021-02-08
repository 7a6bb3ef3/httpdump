package main

import (
	"bufio"
	"bytes"
	"net/http"
	"strconv"
	"testing"
)

var respHeader = "HTTP/1.1 301 Moved Permanently\r\n" +
	"Content-Length: 2\r\n" +
	"Cache-Control: public, max-age=2592000\r\n" +
	"Connection: keep-alive\r\n" +
	"Content-Type: text/html; charset=UTF-8\r\n" +
	"Date: Sun, 07 Feb 2021 03:52:31 GMT\r\n" +
	"Expires: Tue, 09 Mar 2021 03:52:31 GMT\r\n" +
	"Keep-Alive: timeout=4\r\n" +
	"Location: http://www.google.com/\r\n" +
	"Proxy-Connection: keep-alive\r\n" +
	"Server: gws\r\n" +
	// "Transfer-Encoding: chunked\r\n" +
	"X-Frame-Options: SAMEORIGIN\r\n" +
	"X-Xss-Protection: 0\r\n\r\n" +
	"OKPOST /cgi-bin/process.cgi HTTP/1.1\r\n" +
	"User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)\r\n" +
	"Host: www.tutorialspoint.com\r\n" +
	"Content-Type: application/x-www-form-urlencoded\r\n" +
	"Content-Length: 49\r\n" +
	"Accept-Language: en-us\r\n" +
	"Accept-Encoding: gzip, deflate\r\n" +
	"Connection: Keep-Alive\r\n\r\n" +
	"licenseID=string&content=string&/paramsXML=string"

var chunked = "HTTP/1.1 200 OK\r\n" +
	"Transfer-Encoding: chunked\r\n" +
	"Content-Type: text/html; charset=UTF-8\r\n" +
	"Date: Sun, 07 Feb 2021 06:52:40 GMT\r\n\r\n" +
	"7\r\n" +
	"Mozilla\r\n" +
	"9\r\n" +
	"Developer\r\n" +
	"7\r\n" +
	"Network\r\n" +
	"0\r\n\r\n"

func TestReadHTTPFromStream2(t *testing.T) {
	buf := bytes.NewBufferString(chunked)
	b, stat, e := ReadHTTPFromStream(buf)
	if e != nil {
		t.Fatal(e)
	}
	t.Log(string(b), "\r\n", stat)
}

func TestCapHTTPFromStream(t *testing.T) {
	rd := bufio.NewReader(bytes.NewBufferString(respHeader))
	for {
		i, stat, e := CapHTTPFromStream(rd)
		if e != nil {
			t.Fatal(e)
		}
		if stat.Response {
			r := i.(*http.Response)
			t.Log(r)
		} else {
			r := i.(*http.Request)
			t.Log(r)
		}
	}
}

func TestParseHeader(t *testing.T) {
	stat, e := ParseHeader(respHeader)
	if e != nil {
		t.Fatal(e)
	}
	if stat.ContentLength != 2 {
		t.Fail()
	}
	t.Log(stat, e)
}

func TestReadHTTPFromStream(t *testing.T) {
	buf := bytes.NewBufferString(respHeader)
	b, stat, e := ReadHTTPFromStream(buf)
	if e != nil {
		t.Fatal(e)
	}
	t.Log(string(b), "\r\n", stat)
}

func TestReadBytes(t *testing.T) {
	test := "1234nynicg567890"
	w := bytes.NewBufferString(test)
	bufw := bufio.NewReader(w)
	b, e := ReadBytes(bufw, "nynicg")
	if e != nil {
		t.Fatal(e)
	}
	t.Log(string(b))
}

func TestParseInt(t *testing.T) {
	i, e := strconv.ParseInt("1ec1", 16, 64)
	if e != nil {
		t.Fatal(e)
	}
	t.Log(i)
}
