#include <iostream>
#include <unistd.h>

using namespace std;

void generate_root_CA()
{
    system("mkdir root_CA\n chmod 0770 root_CA\n");
    cout << "\n\n Gerar chave do Administrador\n";
    system("cd root_CA\n openssl genrsa -out root_ca.key 2048\n");  //removed -des3 to create without pass
    cout << "\n\n Gerar certificado do Administrador\n";
    system("cd root_CA\n openssl req -new -x509 -days 3650 -key root_ca.key -out root_ca.crt\n");

    // Put the root certificate in the tally official app
    // system("mkdir TallyFiles\n chmod 0770 TallyFiles\n mv TallyFiles /home/mariana/Desktop/Project/TallyOfficial\n");
    // system("cd root_CA\n cp root_ca.crt /home/mariana/Desktop/Project/TallyOfficial/TallyFiles\n");
}

int main()
{
    //Generate a root CA certificate and private key;
    generate_root_CA();
}

/*
1) Generate a root CA certificate and private key;
2) Install the root certificate in the clients and server;
3) Generate a certificate for every client (e.g. with OpenSSL);
4) Generate a certificate for the server (e.g. with OpenSSL);
5) Generate the database key - a special homomorphic key pair (e.g. using Microsoft
SEAL library, see below);
6) Install on each client app:
    a. The root CA certificate;
    b. The client private key and certificate;
    c. The server certificate;
    d. The database key.
*/