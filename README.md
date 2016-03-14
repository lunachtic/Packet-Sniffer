# Packet-Sniffer
Just a simple packet sniffer. Nothing too fancy. 
My shout out to Silver Moon for his guide. He's got some pretty cool stuff going on over at Binary Tides. Check it out.

## Synopsis
This is a python implementation of sniffing packets using sockets.

## Code Example
The code is commented to provide clarity.
Note :  `s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)` , IPPROTO_IP is a dummy protocol not a real one.
To get all you want with any packet having a Ethernet header, do this : `s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))`
With this you get : All of the incoming and outgoing traffic : `IP packets(TCP , UDP , ICMP)`, packets(like `ARP`), Ethernet Header as well.
If you have trouble understanding it, email me at : [shreyas.enug@gmail.com](shreyas.enug@gmail.com)

##Theory Background
Some background info by Srinidhi Varadarajan from Vrigina Tech in `ppt` for your reference : [here](http://courses.cs.vt.edu/cs4254/fall04/slides/raw_1.pdf)


###Ethernet Header
```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Ethernet destination address (first 32 bits)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ethernet dest (last 16 bits)  |Ethernet source (first 16 bits)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Ethernet source address (last 32 bits)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Type code              |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```
###IP Header
```
0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   
```
###TCP Header
```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

###Whats going on with pack and unpack?
You basically get a packet string from tuple : `packet = packet[0]`
Then you take first 20 characters for the ip header : `ip_header = packet[0:20]`
Extracting information from a buffer like this is kinda hard. We need to only parse stuff thats important.
The `unapack()` takes two parameters : 
1. string that defines the format of the data held in the buffer.
2. the buffer that needs to be parsed.

(image for ipv4format)

Look at IPV4 packet header above.
So what is `"!BBHHHBBH4 s4 s."` ?

`! => Python Type Big Endian`
`B => Python Type Integer (1 byte)`
`H => Python Type Integer (2 bytes)`
`s => Python Type String (n bytes)`

 The first character represents the byte order of the data, for network packets, it's Big Endian.
(image for data sheet)

(image for tcp format)

## Motivation
I always wondered how Wireshark worked. This was my attempt to get under the hood and see for myself what exactly was going on.
Networking can be so abstract until you peek into the RAW data and see what is up.


## Installation
The way things work in Linux are different from Windows. The API bindings for Sockets on Windows use Winsock and some other drivers.
My implementation is is for Linux because things are a bit straightforward. 
Clone the git : `git clone <repo-url>` or `wget` it or something. 
Then just do : `sudo python <path>\sniff-it.py` . Doing `sudo` is important. Gotta have `root` priviledges.



## API Reference
All about Python Sockets [here](https://docs.python.org/2/library/socket.html)
All about Python Structs [here](https://docs.python.org/2/library/struct.html)
All about Python Sys     [here](https://docs.python.org/2/library/sys.html)


## Tests
No test cases were written. I manually tested it relentlessly but I never wrote automated tests. I know I should've have, but I just wanted to hack it enough to make it work.

## Contributors
If you want to contribute or add to it or make it better, more readable, go for it. Tweet me issues if you can  : [@shreyaslumos](https://www.twitter.com/shreyaslumos) 

## License
<a rel="license" href="http://creativecommons.org/licenses/by-nc/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-nc/4.0/88x31.png" /></a><br /><span xmlns:dct="http://purl.org/dc/terms/" property="dct:title">Python Packet Sniffer</span> is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-nc/4.0/">Creative Commons Attribution-NonCommercial 4.0 International License</a>.

