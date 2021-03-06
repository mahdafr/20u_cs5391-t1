# Assignment #1

## Part I
In this task you need to implement a packet sniffer using "_libpcap_" library that will capture all the packets sent in the network of 3 nodes (set Ubuntu VMs in host-only mode inside the VirtualBox). Then, as output, the program must print the source and destination IP addresses of every received packet.

Few Questions to be answered:

1. What are the sequence of library calls you used to implement the sniffer program?
	- Before reaching Part 2 of this task, my program did the following calls to create an individual packet sniffer, in order (see `sniffer.c:32-37`):
		- `pcap_lookupdev` which returns the name of the first device of all possible devices that can be used for live capture, then
		- `pcap_open_live` to open the stream for network packet captures, then
		- `pcap_loop` to continuously process the packet information (for this task, this means printing out the packet data, and the source/destination IP addresses)
		- `pcap_close` to close the connection once the loop has completed (test values were 100, 1000, and 0 for _infinite_ packet captures).
 	- After modifying the properties of the handler, instead, my program runs the following commands:
		- `pcap_lookupdev` which returns the name of the first device of all possible devices that can be used for live capture, then
		- `pcap_create` to create the handlers using wired or wireless communications,
		- `pcap_can_set_rfmon` to check if the system is able to change monitor modes,
		- `pcap_set_rfmon` to enable (any non-zero value, such as 1) or disable (0) monitor mode,
		- `pcap_set_promisc` to enable (any non-zero value, such as 1) or turn off (0) promiscuous mode,
		- `pcap_set_snaplen` the first N bytes to store on the system of each packet captured,
		- `pcap_set_timeout` to 10s before closing, and
		- `pcap_activate` to open the stream
	- see [out/p1-on.png](https://github.com/mahdafr/20u_cs5391-t1/blob/master/out/p1-on.png) image for the screenshots of the sniffer with promiscuous mode ON and [out/p1-off.png](https://github.com/mahdafr/20u_cs5391-t1/blob/master/out/p1-off.png) for results with promiscuous mode OFF

2. Do you need root privileges to run the sniffer program? If yes/no, discuss your observations?
	- [This resource](https://askubuntu.com/questions/530920/tcpdump-permissions-problem) provided me the `sudo` calls needed to modify the user permissions to manipulate network data. Without these permissions to `cap_net_raw` and `cap_net_admin`, the program would be unable to access network communications, therefore would run into segmentation faults (or, if printing errors, a nice error message: _You don't have permission to capture on that device_).
	- Even after running these commands and ensuring the permissions were set, the program still ran into permissions errors. My solution was to run the program as a _root_ user by use of the `sudo` command to allow the program to run successfully and capture packets to print out data.

3. Turn on and off the promiscuous mode in sniffer program. What differences do you observe? Demonstrate this through examples.
	- First, we must know which network interfaces are available on the system. By running `ip link show` there are two network devices available for use by the sniffer program (1) _lo_opback, and (2) _enp0s3_ (ethernet).
	- Secondly, I needed set the network settings of the VM to promiscuous mode (to either VMs only or Allow All).
	- To turn OFF promiscuous mode, the second parameter of `sniffer.c:47` must be 0: `pcap_set_promisc(handle, 0);`. In this mode, less packets are captured because the stream only captures packets that are being watched: those that are meant for this host node. For example, if the max amount of packets to be captured in the loop is set to 100, when promiscuous mode is off, then this will take more time to finish the program's execution. Further, the packets caught will have this node as a target.
	- To turn ON promiscuous mode, the second parameter of `sniffer.c:47` must be 1: `pcap_set_promisc(handle, 1);`. In this mode, more packets are captured because the stream does not only capture packets that are being watched. Instead, it will capture packets in the network that may not meant for the host node. For example, if the max amount of packets to be captured in the loop is set to 100, when promiscuous mode is on, then this program's execution will complete in much shorter time than in (b). Further, the packets caught will have any node in the network as a src/dst target (varying IP addresses).

## Part II: Writing Filters
Use the above implemented sniffer program to capture the following types of packets.
- ICMP packets between 2 specific hosts, where the filter expression is `"icmp and host 192.168.56.103 and host 102.168.56.102"`, (2 of the VMs' IP addrseses) and
- TCP packets with destination port # from 10 to 100, where the filter expression is `"tcp dst portrange 10-100"`.
- Observations:
	- using the `ping` command to allow the hosts to communicate to each other. Therefore, 6 terminals are running: one for ComputerA to contact ComputerB and another to contact ComputerC, and the same for ComputerB and ComputerC to contact the opposite nodes in the network. Since `ping` uses ICMP, the packets between VM2 and VM3 should be caught by the sniffer running on VM1
	- there are rarely TCP packets passed with destination ports 10-100 (as these have been reserved and/or assigned); the easiest to observe in this program is `port 23` through the use of TELNET (see Part 3 below)
- see [out/p2-a.png](https://github.com/mahdafr/20u_cs5391-t1/blob/master/out/p2-a.png) folder for screenshots of the results from filter (a) and [out/p2-b.png](https://github.com/mahdafr/20u_cs5391-t1/blob/master/out/p2-b.png) for results from filter (b) and [out/p2-a_and_b.png](https://github.com/mahdafr/20u_cs5391-t1/blob/master/out/p2-a_and_b.png) for results from the filters in one screenshot

## Part III
Use your sniffer program to capture the PASSWORD when another node in the same network is trying to make a TELNET connection. Here, you would have to modify the data part of the captured TCP packet.
- To open the connection with TELNET from one computer to another: `telnet 192.168.56.101`, and to close the connection is CTRL+], `quit`.
- once the connection opens, provide the machine's login info and catch packet transfers of the username and password (printed out as _packet contents_ in program run time)
- each character of the password/username is sent as individual packets
- see [out/p3.png](https://github.com/mahdafr/20u_cs5391-t1/blob/master/out/p3.png) folder for results

## Reference
[Programming with Libpcap -- Sniffing the Network From Our Own Application](http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf)

## To Compile and Run
1. Contact the machines/nodes in the network with `ping [IP address]`*_requires known IP addresses of other machines (use `ip addr` to get a machine's IP address)_
2. Compile the code with `sudo make` to build an executable entitled `build`
3. Run with `sudo ./build`
4. Run the TELNET command `telnet 192.168.56.101` to start the connection
