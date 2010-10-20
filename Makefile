SSLDIR = ./openssl-0.9.8k
CC = gcc -g -I$(SSLDIR)/include -ldl 


default : client server

clean : 
	rm cli serv ; 

client : 
	$(CC) -o cli src/cli.c \
	$(SSLDIR)/lib/libssl.a $(SSLDIR)/lib/libcrypto.a

server : 
	$(CC) -o serv src/serv.c \
	$(SSLDIR)/lib/libssl.a $(SSLDIR)/lib/libcrypto.a

