LDLIBS=-lpcap -lpthread
CXXFLAGS=-std=c++11

all: arp-spoof

main.o: mac.h ip.h ethhdr.h arphdr.h  attack.hpp attack_util.hpp main.cpp  attack.o
 
attack.o: attack.cpp attack.hpp  mac.h ip.h arphdr.h 
attack_util.o: attack_util.cpp attack_util.hpp 

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

arp-spoof: main.o attack_util.o attack.o  arphdr.o ethhdr.o ip.o mac.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o *.d
