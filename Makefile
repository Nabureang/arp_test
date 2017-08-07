send_arp : main.o
	gcc -o send_arp main.o -lpcap -lpthread

main.o : main.c
	gcc -c -o main.o main.c
	

clean :
	rm *.o send_arp
