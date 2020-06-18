# Assignment #1

## Part I
In this task you need to implement a packet sniffer using "_libpcap_" library that will capture all the packets sent in the network of 3 nodes (set Ubuntu VMs in host-only mode inside the VirtualBox). Then, as output, the program must print the source and destination IP addresses of every received packet.
<br/>
<br/>
Few Questions to be answered:
1. What are the sequence of library calls you used to implement the sniffer program?
	a. Before reaching question 3 of this task, my program did the following calls to create an individual packet sniffer, in order (see sniffer.c:33-38):
		- `pcap_lookupdev` which returns the name of the first device of all possible devices that can be used for live capture, then
		- `pcap_open_live` to open the stream for network packet captures, then
		- `pcap_loop` to continuously process the packet information (for this task, this means printing out the packet data, and the source/destination IP addresses)
		- `pcap_close` to close the connection once the loop has completed (test values were 100, 1000, and 0 or _infinite_ packet captures.
	b. After modifying the properties of the handler, instead, my program runs the following commands:
		- `pcap_lookupdev` which returns the name of the first device of all possible devices that can be used for live capture, then
		- `pcap_create` to create the handlers using wired or wireless communications,
		- `pcap_set_rfmon` to enable (any non-zero value, such as 1) or disable (0) monitor mode,
		- `pcap_set_promisc` to enable (any non-zero value, such as 1) or turn off (0) promiscuous mode,
		- `pcap_set_snaplen` the first N bytes to store on the system of each packet captured,
		- `pcap_set_timeout` to 10s before closing, and
		- `pcap_activate` to open the stream
		- still, `pcap_loop` and `pcap_close` are used as described above
2. Do you need root privileges to run the sniffer program? If yes/no, discuss your observations?
	a. [This resource](https://askubuntu.com/questions/530920/tcpdump-permissions-problem) provided me the `sudo` calls needed to modify the user permissions to manipulate network data. Without these permissions to `cap_net_raw` and `cap_net_admin`, the program would be unable to access network communications, therefore would run into segmentation faults (or, if printing errors, a nice error message: _You don't have permission to capture on that device_.
	b. Even after running these commands and ensuring the permissions were set, the program still ran into permissions errors. My solution was to run the program as a `root` user by use of the `sudo` command to allow the program to run successfully and capture packets to print out data.
3. Turn on and off the promiscuous mode in sniffer program. What differences do you observe? Demonstrate this through examples.
	a. First, we must know which network interfaces are available on the system. By running `ip link show` there are two network devices available for use by the sniffer program:
		- _lo_opback, and
		- _enp0s3_ (ethernet)
	b. To turn OFF promiscuous mode, the second parameter of LOC 47 must be 0: `pcap_set_promisc(handle, 0);`.
	c. To turn ON promiscuous mode, the second parameter of LOC 47 must be 1: `pcap_set_promisc(handle, 1);`

## Part II: Writing Filters
Use the above implemented sniffer program to capture the following types of packets.
a. ICMP packets between 2 specific hosts
b. TCP packets with destination port # from 10 to 100.

## Part III
Use your sniffer program to capture the PASSWORD when another node in the same network is trying to make a TELNET connection. Here, you would have to modify the data part of the captured TCP packet.

## Reference
[Programming with Libpcap -- Sniffing the Network From Our Own Application](http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf)

## To Compile and Run
1. Compile the code with `sudo make` to build an executable entitled `build`
2. Run with `sudo ./build`
