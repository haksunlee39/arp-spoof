
LDLIBS=-lpcap -pthread

all: arp-spoof

arp-spoof: main.o src/arphdr.o src/ethhdr.o src/ip.o src/mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
	rm -f arp-spoof src/*.o
