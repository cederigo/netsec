#!/bin/sh

OUTFILE=$1

if [ -z $OUTFILE ]
then
 echo "usage $0 out-file"
 exit 1
fi

openssl req -new -nodes -out $OUTFILE -keyout private/$OUTFILE -config ./openssl.cnf
#openssl req -key private/cakey.pem -config openssl.cnf -days 365 -new -out $OUTFILE
