#!/bin/sh

INFILE=$1
OUTFILE=$2


if [ -z $OUTFILE ]
then
 echo "usage $0 in-file(request) out-file"
 exit 1
fi

openssl ca -out $OUTFILE -config ./openssl.cnf -infiles $INFILE
