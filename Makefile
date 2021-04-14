
CXXFLAGS  =-std=c++14 $(shell pkg-config --cflags libpcap libndn-cxx)
LDFLAGS =-std=c++14 $(shell pkg-config --libs libpcap libndn-cxx) -L/usr/lib
CC = $(CXX)

app: gateway

gateway: gateway.o

clean:
	rm -rf -- gateway *.o