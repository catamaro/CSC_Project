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

string decode_message(string name){

    // descrypt session key with server's private key
    string comm("openssl rsautl -decrypt -inkey Files/Server-priv.pem -in Files/");
    comm.append(name);
    comm.append("-session.key.enc -out session.key\n");

    const char * run_comm = comm.c_str();
    system(run_comm);

    // descrypt message with session key
    comm = "openssl enc -d -aes-256-cbc -pbkdf2 -in Files/";
    comm.append(name);
    comm.append("-message.enc -out Files/message.txt -pass file:./session.key\n");

    const char * run_comm2 = comm.c_str();
    system(run_comm2);

    // remove unecessary files - encoded message with session key
    comm = "rm Files/";
    comm.append(name);
    comm.append("-message.enc\n");

    const char * run_comm3 = comm.c_str();
    system(run_comm3);

    // import message into variable
    string message_decoded = load_string("Files/message.txt");
    cout << "\nMessage decoded: " << message_decoded << endl;
    
    return message_decoded;
}

void encode_message(string query_result, string name){
    
    // create file with message to be encrypted
    ofstream infile("Files/query_result.txt");

    infile << query_result << endl;

    infile.close();

    // encrypt query result with session key
    system("openssl enc -aes-256-cbc -pbkdf2 -salt -in Files/query_result.txt -out Files/query_result.enc -pass file:./session.key\n");

    // moves encoded file to client folder
    string comm("mv Files/query_result.enc ../");
    comm.append(name);
    comm.append("/Files\n");

    const char * run_comm = comm.c_str();
    system(run_comm);

    // remove unnecessary files: session key and plain-text message
    system("rm session.key\n rm Files/query_result.txt");
}

int verify_client_signature(string name){

    // extract client's public key from certificate
    string comm("openssl x509 -pubkey -noout -in Files/");
    comm.append(name);
    comm.append("-cert.crt > Files/");
    comm.append(name);
    comm.append("-publ.pem\n\n");

    const char * run_comm = comm.c_str();
    system(run_comm);

    // verify encrypted session key signature
    comm = "openssl dgst -sha256 -verify Files/";
    comm.append(name);
    comm.append("-publ.pem -signature Files/");
    comm.append(name);
    comm.append("-sign.sha256 Files/");
    comm.append(name);
    comm.append("-session.key.enc > Files/verified.txt\n");

    const char * run_comm2 = comm.c_str();
    system(run_comm2);

    // remove unecessary files - encrypted sesion key
    comm = "rm Files/";
    comm.append(name);
    comm.append("-session.key.enc");

    const char * run_comm3 = comm.c_str();
    system(run_comm3);

    // load verified.txt to confirm signature
    string sign_check = load_string("Files/verified.txt");
    cout << "\nSignature Validation: " << sign_check << endl;

    system("rm Files/verified.txt\n");

    if(sign_check.compare("Verified OK\n") == 0){
        cout << "\nSignature is valid!" << endl;
        return true;
    }
    else{
        cout << "\nerror: Signature not valid! Message will not be considered" << endl;
        return false;
    }

}

bool verify_root_CA()
{
	string root_id;

	ifstream root("Files/root_ca.crt");
	if (!root.fail()) {

		system("openssl x509 -in Files/root_ca.crt -noout -pubkey > Files/root-publ.key\n");
		system("openssl x509 -noout -subject -in Files/root_ca.crt | sed -n 's/.*CN = \\([^,]*\\).*/\\1/p' > Files/root_id.txt\n");
		root_id = load_string("Files/root_id.txt");

		if(root_id.compare("root\n") == 0)
		{
			root.close();
			system("rm Files/root_id.txt\n");
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

int check_exists_table(string name){
    
    string tbl("cd Encrypted_Database\n[ -d '");
    tbl.append(name);
    tbl.append("' ]");
    const char * table = tbl.c_str();
    if(system(table)){
        string tbl("cd Encrypted_Database\n mkdir ");
        tbl.append(name);
        const char * table = tbl.c_str();
        system(table);
        cout << "Created table!\n";
        return 1;
    }
    else{
        cout << "Table already exists !\n";
        return 0;
    }
}

void create_clients_file(string name){
    string filename ("");
    filename.append(name);
    filename.append("_clients.txt");
    
    //directory to create the file
    string path1("/home/catarinamaro/Documents/Técnico/Cripto/Projeto/CSC_Project/Server/Encrypted_Database/");
    path1.append(name);
    path1.append("/");
    path1.append(filename);

    ofstream myfile(path1);

    string data("Clients that have access to this table:");
    myfile << data;
    myfile.close();
}

void create_column(string name, string column){
    string tbl("cd Encrypted_Database\n cd ");
    tbl.append(name);
    tbl.append("\n");
    tbl.append(" mkdir ");
    tbl.append(column);
    tbl.append("\n");
    const char * col = tbl.c_str();
    system(col);

    string filename ("");
    filename.append(column);
    filename.append("_data.txt");
    //directory to create the file
    string path1("/mnt/d/Drive_PC/IST/Mestrado/Cripto/Project/OurProject/Server/Encrypted_Database/");
    path1.append(name);
    path1.append("/");
    path1.append(column);
    path1.append("/");
    path1.append(filename);
    ofstream myfile(path1);
    //myfile.open(filename);
    string data("INT");
    myfile << data;
    myfile.close();
}

int create_table(string message){

    string word = "";
    string name = "";
    int i = 1;
    int j = 0;
    int get_col = 0;
    int type = 0;
    char colnames[10][10] = {"", "", "", "", "", "", "","", "", "" }; //maximum 10 columns and 10 size
    //Get name of the table and the columns
    for (auto x : message) 
    {
        if( x == '('){
            word = "";
            get_col = 1;
        }
        else if(x == ')') break;

        else if (x == ' ')
        {
            if(i == 3){
                cout << "Table name is " + word << endl;
                name = word;
                i = 100;
            }
            if(get_col){
                //const char * coluna = word.c_str();
                strcpy(colnames[j], word.c_str());
                j += 1;
                word = "";
            }
            word = "";
            i += 1;
        }
        else word = word + x;
    }
    
    if (i == 3){
        cout << "Table name is " + word << endl;
        name = word;
    }
    //remove \n
    if (!name.empty() && name[name.length()-1] == '\n') name.erase(name.length()-1);

    // Check if table already exists, if not, create
    if(check_exists_table(name) == 0){
        //table already exists
        return 0;
    }

    create_clients_file(name);
    //Creating name of the file that contains clients ID

    for (int k = 0; k<10; k++){
        if(strcmp(colnames[k], "") != 0){
            cout << colnames[k] << endl;
            create_column(name, colnames[k]);
        }
    }    
    return 1;
}

string execute_query(string message_decoded){
    if (message_decoded.find("CREATE TABLE") == 0) {
        cout << "Found CREATE TABLE!" << '\n';
        create_table(message_decoded);
    }
    else if (message_decoded.find("INSERT") == 0)
    {
        cout << "Found INSERT!" << '\n';
    }
    else if (message_decoded.find("DELETE") == 0)
    {
        cout << "Found DELETE!" << '\n';
    }
    else if (message_decoded.find("SELECT") == 0)
    {
        cout << "Found SELECT!" << '\n';
    }
    else{
        cout << "Command not found!" << '\n';
    }

    return "return query result?";
}

void send_reply(int newFD, string reply){
    // message to alert client that the answer is already the files directory
    auto bytes_sent = send(newFD, &reply.front(), reply.length(), 0);

    cout << "\nSent message: " << reply << endl;
    // ends communication between client and server
    close(newFD);
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
	local_addr.sin_port = htons(PORT);
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
    string client_name(25, ' '); // stores the client name
    string message_decoded, query_result;

    while (run) {
        // accepting messages from clients
        int newFD = accept(server_fd, (sockaddr *) &client_addr, &client_addr_size);
        if (newFD == -1) {
            cerr << "Error while Accepting on socket\n";
            continue;
        }
            
        // receives message that indicates wich client sent files
        auto bytes_received = recv(newFD, &client_name.front(), client_name.length(), 0);
        cout << "\nReceived Query from " << client_name << endl;

        // remove \n from message
        if (!client_name.empty()) client_name = client_name.substr(0, 7);
        
        // verify if root certificate is valid
        bool verify = verify_root_CA();
        if(!verify){
            send_reply(newFD, "invalid");
            continue;
        }
        
        // decode message and session key and saves it in folder
        message_decoded = decode_message(client_name);

        // verify if client's signature is valid
        verify = verify_client_signature(client_name);
        if(!verify){
            send_reply(newFD, "invalid");
            continue;
        }
        // creates the directory that will store the tables
        create_database();
        // executes the decrypted query with homomorphic encrypted values
        query_result = execute_query(message_decoded);

        // encrypt with session key and move to client folder
        encode_message(query_result, client_name);

        send_reply(newFD, "finished");        
    }
    /*********************************** accept messages **********************************/
}


