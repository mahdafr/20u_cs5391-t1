all: build

build: sniffer.c net_info.h
	gcc sniffer.c -o build -lpcap

clean:
	rm build *~ *.o
