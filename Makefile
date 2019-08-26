all: netfilter_test

netfilter_test: nfqnl_test.cpp
	g++ -o netfilter_test nfqnl_test.cpp -lnetfilter_queue 

clean:
	rm -f netfilter_test
