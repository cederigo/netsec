CC = gcc

default : client server

clean : 
	rm cli serv ; 

client : 
	$(CC) -lssl -lcrypto -o cli src/cli.c

server : 
	$(CC) -lssl -lcrypto -o serv src/serv.c

