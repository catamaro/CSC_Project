#include "../resources.h"

using namespace seal;
using namespace std;

void generate_root_CA()
{
    system("mkdir root_CA\n chmod 0770 root_CA\n");
    cout << "\nGenarating root key\n";
    system("cd root_CA\n openssl genrsa -out root_ca.key 2048\n"); 
    cout << "\nGenerate root certificate\n";
    system("cd root_CA\n openssl req -new -x509 -days 3650 -key root_ca.key -out root_ca.crt -subj /C=PT/ST=Lisbon/L=Lisbon/O=Cripto/OU=CSC-Project/CN=root  \n");
}

void install_db_key(string name){
    cout << "\nInstalling Homomorphic Keys\n";

    if(name.compare("Server") == 0){
        string db_key("cd homomorphic_keys\n cp -t ../../");
        db_key.append(name);//Pasta do cliente
        db_key.append("/Files/ DB_relin.key");

        const char * mov_db_key = db_key.c_str();
        system(mov_db_key);

        string db_crt("cd homomorphic_keys\n cp -t ../../");
        db_crt.append(name);//Pasta do cliente
        db_crt.append("/Files/ DB_relin.sha256");

        const char * mov_db_crt = db_crt.c_str();
        system(mov_db_crt);
    }
    else{
        string db_key("cd homomorphic_keys\n cp -t ../../");
        db_key.append(name);//Pasta do cliente
        db_key.append("/Files/ DB_private.key DB_public.key");

        const char * mov_db_key = db_key.c_str();
        system(mov_db_key);

        string db_crt2("cd homomorphic_keys\n cp -t ../../");
        db_crt2.append(name);//Pasta do cliente
        db_crt2.append("/Files/ DB_private.sha256 DB_public.sha256");

        const char * mov_db_crt2 = db_crt2.c_str();
        system(mov_db_crt2);
    }
}

void generate_db_key(){

    system("mkdir homomorphic_keys\n");
    
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(64);
    SEALContext context(parms);

    KeyGenerator keygen(context);
    SecretKey private_key = keygen.secret_key();
    PublicKey public_key;
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    keygen.create_public_key(public_key);

    ofstream public_key_file;
    ofstream private_key_file;
    ofstream relin_keys_file;
    public_key_file.open("homomorphic_keys/DB_public.key");
    private_key_file.open("homomorphic_keys/DB_private.key");
    relin_keys_file.open("homomorphic_keys/DB_relin.key");

    private_key.save(private_key_file);
 	public_key.save(public_key_file);
 	relin_keys.save(relin_keys_file);

 	private_key_file.close();
 	public_key_file.close();
 	relin_keys_file.close();

    system("openssl dgst -sha256 -sign root_CA/root_ca.key -out homomorphic_keys/DB_private.sha256 homomorphic_keys/DB_private.key");
    system("openssl dgst -sha256 -sign root_CA/root_ca.key -out homomorphic_keys/DB_public.sha256 homomorphic_keys/DB_public.key");
    system("openssl dgst -sha256 -sign root_CA/root_ca.key -out homomorphic_keys/DB_relin.sha256 homomorphic_keys/DB_relin.key");
}

void install_CA_certificate(string name)
{
    // The root CA certificate
    string rca("cd root_CA\ncp root_ca.crt ../../");
    rca.append(name);
    rca.append("/");
    rca.append("Files/");

    const char * root_ca = rca.c_str();
    system(root_ca);
}

void create_directories(string name){
    // Create Files directory
    string make_dir("mkdir ../");
    make_dir.append(name);
    make_dir.append("/");
    make_dir.append("Files");

    const char * run_comm = make_dir.c_str();
    system(run_comm);

    if(name.compare("Server") == 0){
        make_dir = "mkdir ../";
        make_dir.append(name);
        make_dir.append("/");
        make_dir.append("Messages");

        const char * comm = make_dir.c_str();
        system(comm);
    }
    else{
        make_dir = "mkdir ../";
        make_dir.append(name);
        make_dir.append("/");
        make_dir.append("Answers");

        const char * comm1 = make_dir.c_str();
        system(comm1);
    }
}

void generate_certificate(string name){
    cout << "\nGenerating Private Key\n";

    string p_key("cd root_CA\n openssl genrsa -out ");
    p_key.append(name);
    p_key.append("-priv.pem 1024\n");

    const char * gen_key = p_key.c_str();
    system(gen_key);

    cout << "\nGenerate sign request";

    string req("cd root_CA\n openssl req -new -key ");
    req.append(name);
    req.append("-priv.pem -out ");
    req.append(name);
    req.append("-cert.csr -subj /C=PT/ST=Lisbon/L=Lisbon/O=Cripto/OU=CSC-Project/CN=cklevn\n");

    const char * gen_req = req.c_str();
    system(gen_req);

    cout << "\nSigning Certificate\n";

    string sign("cd root_CA\n openssl x509 -req -in ");
    sign.append(name);
    sign.append("-cert.csr -out ");
    sign.append(name);
    sign.append("-cert.crt -sha1 -CA root_ca.crt -CAkey root_ca.key -CAcreateserial -days 3650");
    
    const char * gen_sign = sign.c_str();
    system(gen_sign);

    string csr("cd root_CA\n rm ");
    csr.append(name);
    csr.append("-cert.csr \n");

    const char * rm_csr = csr.c_str();
    system(rm_csr);
}

void install_certificate(string name){
    cout << "\nInstalling Keys\n";

    string p_key("chmod 0770 ../");
    p_key.append(name);
    p_key.append("/Files\n");
    p_key.append("cd root_CA\n mv -t ../../");
    p_key.append(name);
    p_key.append("/Files/ ");
    p_key.append(name);
    p_key.append("-cert.crt ");
    p_key.append(name);
    p_key.append("-priv.pem\n");

    const char * mov_key = p_key.c_str();
    system(mov_key);

    if(name.compare("Server") != 0){
        string p_key("cd root_CA\n cp Server-cert.crt ../../");
        p_key.append(name);
        p_key.append("/Files/ ");

        const char * mov_key = p_key.c_str();
        system(mov_key);
    }


}

int main()
{
    //Generate a root CA certificate and private key;
    generate_root_CA();

    generate_db_key();

    create_directories("Client1");
    create_directories("Client2");
    create_directories("Client3");
    create_directories("Server");

    install_db_key("Client1");
    install_db_key("Client2");
    install_db_key("Client3");
    install_db_key("Server");

    //Install root CA in all entities;
    install_CA_certificate("Client1");
    install_CA_certificate("Client2");
    install_CA_certificate("Client3");
    install_CA_certificate("Server");

    //Generate client and serrver certificates
    generate_certificate("Client1");
    generate_certificate("Client2");
    generate_certificate("Client3");
    generate_certificate("Server");

    //Install client and server certificates
    install_certificate("Client1");
    install_certificate("Client2");
    install_certificate("Client3");
    install_certificate("Server");
}

/*
1) Generate a root CA certificate and private key; ✔️
2) Install the root certificate in the clients and server; ✔️
3) Generate a certificate for every client (e.g. with OpenSSL); ✔️
4) Generate a certificate for the server (e.g. with OpenSSL); ✔️
5) Generate the database key - a special homomorphic key pair (e.g. using Microsoft
SEAL library, see below); ✔️
6) Install on each client app:
    a. The root CA certificate; ✔️ 
    b. The client private key and certificate; ✔️
    c. The server certificate; ✔️
    d. The database key. ✔️
*/