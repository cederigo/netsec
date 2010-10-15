CC = gcc -Wall

default : client server

clean : 
	rm cli serv ; 

client : 
	$(CC) -lssl -lcrypto -o cli cli.c

server : 
	$(CC) -lssl -lcrypto -o serv serv.c

