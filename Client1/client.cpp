#include "../resources.h"

using namespace std;

string load_string(string path)
{
    ifstream f(path);
    string str;
    if (f)
    {
        ostringstream ss;
        ss << f.rdbuf();
        str = ss.str();
    }
    f.close();

    return str;
}

string connect_to_server(string message)
{

    struct sockaddr_in server_addr;
    string reply(10, ' ');

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1)
    {
        perror("socket ");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    int err = inet_aton("127.0.0.1", &server_addr.sin_addr);
    if (err == 0)
    {
        perror("aton ");
        exit(EXIT_FAILURE);
    }
    // setup of server - creation of server connection to server
    err = connect(sock_fd, (const struct sockaddr *)&server_addr,
                  sizeof(server_addr));

    if (err == -1)
    {
        perror("conn ");
        exit(EXIT_FAILURE);
    }
    cout << "\nJust connected to the server" << endl;

    auto bytes_sent = send(sock_fd, &message.front(), message.size(), 0);

    cout << "\nClient sent: " << message << endl;

    auto bytes_received = recv(sock_fd, &reply.front(), reply.size(), 0);

    cout << "\nClient received: " << reply << endl;

    return reply;
}

// function to encode values with Homomorphic Database Key
string encode_values(string message)
{
    string message_values_encoded;

    

    return message_values_encoded;
}

// function to encode message with private and public key
void encode_message(string message)
{
    string message_encoded;

    // create file with message to be encrypted
    ofstream infile("Files/message.txt");

    infile << message << endl;

    infile.close();

    // extract server's public key from certificate
    system("openssl x509 -pubkey -noout -in Files/Server-cert.crt > Files/Server-publ.pem\n");
    // generate random password file
    system("openssl rand -base64 32 > session.key\n");
    // session key encrypted with server's public key
    system("openssl rsautl -encrypt -pubin -inkey Files/Server-publ.pem -in session.key -out Files/Client1-session.key.enc\n");
    // session key signed with client's private key
    system("openssl dgst -sha256 -sign Files/Client1-priv.pem -out Files/Client1-sign.sha256 Files/Client1-session.key.enc");
    // encrypt message with session key
    system("openssl enc -aes-256-cbc -pbkdf2 -salt -in Files/message.txt -out Files/Client1-message.enc -pass file:./session.key\n");

    // remove unnecessary files
    system("rm Files/message.txt\n");

    // moves encoded session-key, encoded message and certificate to server's folder
    system("mv Files/Client1-message.enc ../Server/Files\n");
    system("mv Files/Client1-session.key.enc ../Server/Files\n");
    system("mv Files/Client1-sign.sha256 ../Server/Files\n");
    system("cp Files/Client1-cert.crt ../Server/Files\n");

    // sign message with client's private key
    // system("openssl rsautl -sign -in Files/message.txt -inkey Files/Client1-priv.pem -out Files/message.sign\n");
}

// function to decode message with private and public key
void decode_message()
{
    string reply_decoded;

    // descrypt message with session key
    system("openssl enc -d -aes-256-cbc -pbkdf2 -in Files/query_result.enc -out Files/query_result.txt -pass file:./session.key\n");

    // remove unnecessary files: session key and encrypted query result
    system("rm Files/query_result.enc\n rm session.key");
}

// function to decode values with Homomorphic Database Key
string decode_values(string reply)
{
    string reply_values_decoded;
    return reply_values_decoded;
}

// funciton to make it easy to write the query
string create_query(int input_opt)
{
    int input;
    string tablename, col_name, col_val, col_op, row_num;
    string comm, comm1;

    if(input_opt == 1){
        cout << "Input message: ";
        cin.ignore();
        getline(cin, comm);
        return comm;
    }

    cout << "Choose Query (1 to 6): ";
    cin >> input;

    switch (input){
    case 1:
        cout << "Table Name ('end' to terminate): ";
        cin >> tablename;

        comm = "CREATE TABLE ";
        comm.append(tablename);
        comm.append(" (");

        // construct query
        while (true)
        {
            cout << "Column Name: ";
            cin >> col_name;

            if(col_name.compare("end") == 0) break;

            comm.append(col_name);
            comm.append(" ");
        }
        comm.append(")");

        break;
    case 2:
        cout << "Table Name ('end' to terminate): ";
        cin >> tablename;

        comm = "INSERT INTO TABLE  ";
        comm.append(tablename);
        comm.append(" (");

        comm1 = "VALUES ";

        // construct query
        while(true)
        {
            cout << "Column Name: ";
            cin >> col_name;
            if(col_name.compare("end") == 0) break;

            cout << "Column Value: ";
            cin >> col_val;

            comm.append(col_name);
            comm.append(" ");
            comm1.append(col_val);
            comm1.append(" ");
        }
        comm.append(") ");
        comm.append(comm1);

        cout << comm << endl;

        break;
    case 3:
        cout << "Table Name: ";
        cin >> tablename;

        cout << "Row Number: ";
        cin >> row_num;

        comm = "DELETE ";
        comm.append(row_num);
        comm.append("FROM ");
        comm.append(tablename);
        
        break;
    case 4:
        cout << "Table Name: ";
        cin >> tablename;

        cout << "Row Number: ";
        cin >> row_num;

        comm = "SELECT ROW ";
        comm.append(row_num);
        comm.append("FROM ");
        comm.append(tablename);
        
        break;
    case 5:
        cout << "Table Name('end' to terminate): ";
        cin >> tablename;

        comm = "SELECT ";
        comm.append(row_num);
        while(true)
        {
            cout << "Column Name: ";
            cin >> col_name;
            if(col_name.compare("end") == 0) break;

            comm.append(col_name);
            comm.append(" ");
        }

        comm.append("FROM ");
        comm.append(tablename);
        comm.append(" WHERE ");

        while(true)
        {
            cout << "\nColumn Name: ";
            cin >> col_name;
            if(col_name.compare("end") == 0) break;
            cout << "Operand: ";
            cin >> col_op;
            cout << "Column Value: ";
            cin >> col_val;

            comm.append(col_name);
            comm.append(col_op);
            comm.append(col_val);
            comm.append(" ");
        }
        break;
    case 6:
        cout << "Table Name('end' to terminate): ";
        cin >> tablename;

        cout << "Column Name: ";
        cin >> col_name;

        comm = "SELECT SUM(";
        comm.append(col_name);
        comm.append(") FROM ");      
        comm.append(tablename);
        comm.append(" WHERE ");

        while(true)
        {
            cout << "\nColumn Name: ";
            cin >> col_name;
            if(col_name.compare("end") == 0) break;
            cout << "Operand: ";
            cin >> col_op;
            cout << "Column Value: ";
            cin >> col_val;

            comm.append(col_name);
            comm.append(col_op);
            comm.append(col_val);
            comm.append(" ");
        }
        break;
    }

    cout << "\nCommand: " << comm << endl;
    return comm;
}

void print_commands(){
    cout << "+-------------------------------------------------------------------------------------------------------------------------------------+" << endl;
    cout << "| Commands                   | Syntax                                                                                                 |" << endl;
    cout << "+----------------------------+--------------------------------------------------------------------------------------------------------+" << endl;
    cout << "| 1. Create new table        | CREATE TABLE tablename (col1name, col2name, …, colNname)                                               |" << endl;
    cout << "| 2. Insert row in table     | INSERT INTO TABLE tablename (col1name, … , colNname) VALUES (value1, .., valueN)                       |" << endl;
    cout << "| 3. Delete row from table   | DELETE linenum FROM tablename                                                                          |" << endl;
    cout << "| 4. Select row from table   | SELECT ROW linenum FROM tablename                                                                      |" << endl;
    cout << "| 5. Query table             | SELECT col1name, .., colNname FROM tablename WHERE col1name =|<|> value1 AND|OR col2name =|<|> value2  |" << endl;
    cout << "| 6. Sum column              | SELECT SUM(colname) FROM tablename WHERE col1name =|<|> value AND|OR col2name =|<|> value              |" << endl;
    cout << "| 7. Multiply column(no need)| SELECT MULT(colname) FROM tablename WHERE col1name =|<|> value AND|OR col2name =|<|> value             |" << endl;
    cout << "+----------------------------+--------------------------------------------------------------------------------------------------------+" << endl;
}

void print_query_result(){

}

bool verify_documents(){
    // check if root_ca is valid
    string root_id;

	ifstream root("Files/root_ca.crt");
	if (!root.fail()) {
		system("openssl x509 -in Files/root_ca.crt -noout -pubkey > Files/root-publ.key\n");
		system("openssl x509 -noout -subject -in Files/root_ca.crt | sed -n 's/.*CN = \\([^,]*\\).*/\\1/p' > Files/root_id.txt\n");
		root_id = load_string("Files/root_id.txt");
        
        root.close();
        system("rm Files/root_id.txt\n");

		if(root_id.compare("root\n") != 0){
            cout << "CA inválido: não corresponde à root\n";
            return false;
        } 
    }
    else{
        cout << "Cannot locate root_ca certificate" <<endl;
        return false;
    }

    // check if client certificate is valid
    system("openssl verify -CAfile Files/root_ca.crt Files/Client1-cert.crt > Files/verified.txt");

    // load verified.txt to confirm signature
    string sign_check = load_string("Files/verified.txt");
    system("rm Files/verified.txt\n");
    
    if(sign_check.find("Files/Client1-cert.crt: OK") != 0){
        cout << "\nerror: Signature not valid! Message will not be considered" << endl;
        return false;
    }

    // check if client's private key in coherent with clients certificate
    int crt = system("openssl x509 -noout -modulus -in Files/Client1-cert.crt| openssl md5");
    int key = system("openssl rsa -noout -modulus -in Files/Client1-priv.pem | openssl md5");

    if(crt != key){
        cout << "Client's private key doesn't match certificate" << endl;
        return false;
    }
    return true;
} 

int main(int argc, char *argv[])
{
    cout << "Welcome! To access and change the database choose from the following commands\n"
         << endl;

    bool run = true;

    string message, message_values_encoded, message_encoded;
    string reply, reply_decoded, reply_values_decoded;
    int input_opt;

    bool verify = verify_documents();
    if(!verify) return EXIT_FAILURE; 

    while (run)
    {
        // prints the server's API possible commands
        print_commands();
        
        cout << "Construct Query (0), Input by Hand (1): ";
        cin >> input_opt;

        message = create_query(input_opt);
        
        //message_values_encoded = encode_values(message);
        encode_message(message);

        reply = connect_to_server("Client1");
        if(reply.compare("invalid   ") == 0){
            cout << "Problem authenticating certificates. Message was not considered" << endl;
            continue;
        }

        decode_message();

        // reply_values_unecoded = decode_values(reply_unecoded);

        // print_query_result();
    }
    return EXIT_SUCCESS;
}
