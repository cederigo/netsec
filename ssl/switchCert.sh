#!/bin/sh

if [ -z $1 ]
then
  echo "usage: $0 ext | no-ext"
  exit 1
fi

if [ $1 = "ext" ]
then
 echo "switching to certificat with helloworld extension"
 cd certs/
   ln -sf client-cert-wExt.pem client-cert.pem
 cd -
 cd keys/
   ln -sf client-key-wExt.pem client-key.pem
 cd -
else
 echo "switching to no extension certificate"
 cd certs/
   ln -sf client-cert-woExt.pem client-cert.pem
 cd -
 cd keys/
   ln -sf client-key-woExt.pem client-key.pem
 cd -
fi


