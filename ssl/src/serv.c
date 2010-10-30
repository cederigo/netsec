/* serv.cpp  -  Minimal ssleay server for Unix
   30.9.1996, Sampo Kellomaki <sampo@iki.fi> */


/* mangled to work with SSLeay-0.9.0b and OpenSSL 0.9.2b
   Simplified to be even more minimal
   12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */

/* require client auth. added root cert
   check for helloworld extension in client cert
   17.10.2010 Cédric Reginster <cederigo@gmail.com> */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define CERTF  HOME "certs/server-cert.pem"
#define KEYF  HOME  "keys/server-key.pem"
#define CA_LIST HOME "certs/cacert.pem"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }
/* for x509 certificat extensions */
int verify_callback(int level, X509_STORE_CTX *ctx){
  printf("verify_callback\n");
  /* do nothing here 
     just return a positive value, could add some logic
   */
  return 1;

}

/* tls extension*/
int hello_extension_cb(SSL *s, TLS_EXTENSION * ext, void * arg){
  printf("hello from tls callback\n");
  printf("extension data: %s\n",(char *)ext->data);
  
  /* 0 means success, could add some checks here..*/
  return 0;
}





int main (int argc, char **argv)
{
  int err;
  int listen_sd;
  int sd;
  int nid; /* id for our extension*/
  int extPos;
  struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
  size_t client_len;
  SSL_CTX* ctx;
  SSL*     ssl;
  X509*    client_cert;
  X509_EXTENSION *client_extension; /*hello world extension*/ 
  char*    str;
  char     buf [4096];
  char*    extname;
  SSL_METHOD *meth;
  struct hostent *he;

  /* SSL preliminaries. We keep the certificate and key with the context. */
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();
  meth = TLSv1_server_method();
  ctx = SSL_CTX_new (meth);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(2);
  }
  
  if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(3);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(4);
  }
  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr,"Private key does not match the certificate public key\n");
    exit(5);
  }
  
  /* root cert */
  if(!(SSL_CTX_load_verify_locations(ctx,CA_LIST,0))){
    fprintf(stderr,"Can't read CA list\n");
    exit(6);
  }
  
  /* require client auth */
  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER |
    SSL_VERIFY_FAIL_IF_NO_PEER_CERT,verify_callback);


  /* ----------------------------------------------- */
  /* Prepare TCP socket for receiving connections */

  listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket");
  
  memset (&sa_serv, '\0', sizeof(sa_serv));
  sa_serv.sin_family      = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port        = htons (1111);          /* Server Port number */
  
  err = bind(listen_sd, (struct sockaddr*) &sa_serv,
	     sizeof (sa_serv));                   CHK_ERR(err, "bind");
	     
  /* Receive a TCP connection. */
	     
  err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");
  
  client_len = sizeof(sa_cli);
  sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
  CHK_ERR(sd, "accept");
  close (listen_sd);

  he = gethostbyaddr(&sa_cli.sin_addr, sizeof sa_cli.sin_addr, AF_INET);
  printf ("Connection from %s, port %d\n",he->h_name, htons(sa_cli.sin_port));

  
  /* ----------------------------------------------- */
  /* TCP connection is ready. Do server side SSL. */

  ssl = SSL_new (ctx);                           CHK_NULL(ssl);
  /*set tls extension callback here*/
  SSL_set_hello_extension_cb(ssl,hello_extension_cb, "hello"); 
  SSL_set_fd (ssl, sd);
  err = SSL_accept (ssl);                        CHK_SSL(err);
  
  
  /* Get the cipher - opt */
  
  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  
  /* Get client's certificate (note: beware of dynamic allocation) - opt */

  client_cert = SSL_get_peer_certificate (ssl);
  
  if (client_cert != NULL) {
  
    printf ("Client certificate:\n");
    
    str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
    CHK_NULL(str);
    printf ("\t subject: %s\n", str);
    OPENSSL_free (str);
    
    str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
    CHK_NULL(str);
    printf ("\t issuer: %s\n", str);
    OPENSSL_free (str);

    /* get our extension */
    nid = OBJ_create("1.2.3.4","helloworld","hello world longname");
    extPos = X509_get_ext_by_NID(client_cert,nid,-1);

    if( extPos == -1 ){
      printf("\t helloworld extension not found in client certificate\n") ;
    }else{
      printf("\t helloworld extension found at position %u\n",extPos);
      /*get the extension*/
      client_extension = X509_get_ext(client_cert,extPos);
      /*just print it for now */
      err = X509V3_EXT_print_fp(stdout, client_extension,X509V3_EXT_PARSE_UNKNOWN,3); 
      

    }
    
    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */
    
    X509_free (client_cert);
  } else
    printf ("Client does not have certificate.\n");

  /* DATA EXCHANGE - Receive message and send reply. */

  err = SSL_read (ssl, buf, sizeof(buf) - 1);                   CHK_SSL(err);
  buf[err] = '\0';
  printf ("Got %d chars:'%s'\n", err, buf);
  
  err = SSL_write (ssl, "I hear you.", strlen("I hear you."));  CHK_SSL(err);

  /* Clean up. */

  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);
}
/* EOF - serv.cpp */
