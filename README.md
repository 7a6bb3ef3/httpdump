#### Compile
go build github.com/nynicg/httpdump
#### Usage

```
#./httpdump -h

NAME:
nynicg/httpdump - :D

USAGE:
httpdump [command] [options]

DESCRIPTION:
HTTP dump

COMMANDS:
device   Print all devices
cap      Capture
help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
--help, -h  show help (default: false)



# ./httpdump help cap
NAME:
   httpdump cap - Capture

USAGE:
   httpdump cap [command options] [arguments...]

OPTIONS:
   --dst.ip value             Request dst ip
   --dst.port value           Request dst port (default: 0)
   --src.ip value             Request src ip
   --src.port value           Request src port (default: 0)
   --method value, -m value   Request method
   --device value, -d value   Device name (default: "eth0")
   --status value, -s value   Response status code (default: 0)
   --snapLen value, -l value  The maximum size to read for each packet (snaplen) (default: 2048)
   --ignoreBody, -i           Do not print response/request body (default: false)
   --regexp value, -R value   Regexp(Go) filter
   --request, --req           Request only (default: false)
   --response, --resp         Response only (default: false)
   --promiscuous, -p          Read data in promiscuous mode (default: false)
   --verbose, -v              Verbose mode (default: false)
   
   
# ./httpdump help device
NAME:
   httpdump device - Print all devices

USAGE:
   httpdump device [command options] [arguments...]

OPTIONS:
   --full, -f  Full information (default: false)
```

#### Example
  ```
  # sudo ./httpdump cap -d en0 -i -R "Content-Type: text.*"
  ```