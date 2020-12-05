#include "../resources.h"

using namespace std;

std::string load_string(string path)
{
	ifstream f(path);
	string str;
	if (f) {
		ostringstream ss;
		ss << f.rdbuf();
		str = ss.str();
	}
	f.close();

	return str;
}

void decode_message(string name){

    // descrypt session key with server's private key
    string comm("openssl rsautl -decrypt -inkey Files/Server-priv.pem -in Files/");
    comm.append(name);
    comm.append("-session.key.enc -out session.key\n");

    const char * run_comm = comm.c_str();
    system(run_comm);

    // descrypt message with session key
    string comm2("openssl enc -d -aes-256-cbc -pbkdf2 -in Files/");
    comm2.append(name);
    comm2.append("-message.enc -out Files/message.sign -pass file:./session.key\n");

    const char * run_comm2 = comm2.c_str();
    system(run_comm2);

    // remove aux files
    system("rm Files/Client1-message.enc\n rm Files/Client1-session.key.enc");
}

string verify_client_signature(string name){

    string message_decoded;
    // extract client's public key from certificate
    string comm("openssl x509 -pubkey -noout -in Files/");
    comm.append(name);
    comm.append("-cert.crt > Files/Client-publ.pem\n");

    const char * run_comm = comm.c_str();
    system(run_comm);

    system("openssl rsautl -verify -inkey Files/Client-publ.pem -in Files/message.sign -pubin > Files/message.txt\n");

    message_decoded = load_string("Files/message.txt");
    cout << "message decoded: " << message_decoded << endl;
        
    system("rm Files/Client-publ.pem\n rm Files/message.sign\n");

    return message_decoded;
}

bool verify_root_CA()
{
	string root_id;

	ifstream root("Files/root_ca.crt");
	if (!root.fail()) {

		system("openssl x509 -in Files/root_ca.crt -noout -pubkey > Files/root-publ.key\n");
		system("openssl x509 -noout -subject -in Files/root_ca.crt | sed -n 's/.*CN = \\([^,]*\\).*/\\1/p' > Files/root_id.txt\n");
		root_id = load_string("Files/root_id.txt");

		if(root_id.compare("CSC-4\n") == 0)
		{
			root.close();
			system("rm Files/root_id.txt");
			return true;
		}
		else
		{
			root.close();
			cout << "CA inválido: não corresponde à root\n";
		}
	}
	return false;

}

void create_database(){

    if (system("[ -d 'Encrypted_Database' ]")){//if not exists - create directory
        system("mkdir Encrypted_Database");
        cout << "Database created!\n";
    
    }
    else{
        cout << "Database already exists!\n";
    }

}

void create_table(string name){

    string tbl("cd Encrypted_Database\n[ -d '");
    tbl.append(name);
    tbl.append("' ]");
    const char * table = tbl.c_str();

    if(system(table)){
        cout << "table1 not exists !\n";
        string tbl("cd Encrypted_Database\n mkdir table1");
        const char * table = tbl.c_str();
        system(table);
        cout << "created table !\n";

    }
    else
    {
        cout << "table1  exists !\n";
    }

}
void execute_query(string message_decoded){
    if (message_decoded.find("CREATE") == 0) {
            cout << "found CREATE!" << '\n';
            create_table("table1");
    }
    else if (message_decoded.find("INSERT") == 0)
    {
        cout << "found INSERT!" << '\n';
    }
    else if (message_decoded.find("DELETE") == 0)
    {
        cout << "found DELETE!" << '\n';
    }
    else if (message_decoded.find("SELECT") == 0)
    {
        cout << "found SELECT!" << '\n';
    }
    else{
        cout << "Command not found!" << '\n';
    }
}
int main(int argc, char* argv[]){

    /************************************ setup socket ************************************/

    struct sockaddr_in local_addr;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_size = sizeof(client_addr);
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1)
	{
		perror("socket: ");
		exit(EXIT_FAILURE);
	}

	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = INADDR_ANY;
	local_addr.sin_port = htons(5000);
	int err = bind(server_fd, (struct sockaddr *)&local_addr,
				   sizeof(local_addr));
	if (err == -1)
	{
		perror("bind: ");
		exit(EXIT_FAILURE);
	}

	if (listen(server_fd, 5) == -1)
	{
		perror("listen: ");
		exit(EXIT_FAILURE);
	}

    /************************************ setup socket ************************************/

    /*********************************** accept messages **********************************/
    bool run = true;
    string message(25, ' '); // stores the client name
    string reply = "finished"; 
    string message_decoded;

    while (run) {
        // accepting messages from clients
        int newFD = accept(server_fd, (sockaddr *) &client_addr, &client_addr_size);
        if (newFD == -1) {
            cerr << "Error while Accepting on socket\n";
            continue;
        }
            
        // receives message that indicates wich client sent files
        auto bytes_received = recv(newFD, &message.front(), message.length(), 0);
        cout << "received message: " << message << endl;

        // remove \n from message
        if (!message.empty()) message = message.substr(0, 7);
        
        // check if root certificate is valid
        run = verify_root_CA();
        if (run == false) continue;
        
        // decode message and session key
        decode_message(message);
        // verify if message was really signed by the client
        message_decoded = verify_client_signature(message);
        
        // creates the directory that will store the tables
        create_database();
        // execute the decrypted query with homomorphic encrypted values
        execute_query(message_decoded);

        // message to alert client that the answer is already the files directory
        auto bytes_sent = send(newFD, &reply.front(), reply.length(), 0);

        cout << "sent message: " << reply << endl;
        // ends communication between client and server
        close(newFD);
    }
    /*********************************** accept messages **********************************/
}


