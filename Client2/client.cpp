#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fstream>  

using namespace std;

string connect_to_server(string message){

    struct sockaddr_in server_addr;
    string reply(50, ' ');

    int sock_fd  = socket(AF_INET, SOCK_STREAM, 0);
    if(sock_fd == -1){
        perror("socket ");
        exit(EXIT_FAILURE);
    }
        
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(5000);
    int err = inet_aton("127.0.0.1", &server_addr.sin_addr);
    if(err == 0){
        perror("aton ");
        exit(EXIT_FAILURE);
    }
    // setup of server - creation of server connection to server
    err = connect(sock_fd, (const struct sockaddr *)&server_addr,
                        sizeof(server_addr));

    if(err == -1){
        perror("conn ");
        exit(EXIT_FAILURE);
    }
    cout << "Just connected to the server";

    auto bytes_sent = send(sock_fd, &message.front(), message.size(), 0);

    cout << "\nClient sent: " << message << "\n";

    auto bytes_received = recv(sock_fd, &reply.front(), reply.size(), 0);

    cout << "\nClient received: " << reply << "\n";

    return reply;
}

// function to encode values with Homomorphic Database Key  
string encode_values(string message){
    string message_values_encoded;
    return message_values_encoded;
} 

// function to encode message with private and public key
string encode_message(string message){
    string message_encoded;

    // create file with message to be encrypted
    ofstream infile ("Files/message.txt");

    infile << message << endl;

    infile.close();

    // extract public key of server from certificate
    system("openssl x509 -pubkey -noout -in Files/Server-cert.crt > Files/Server-publ.pem");
    // generate random password file
    system("openssl rand -base64 32 > session.key");
    // session key signed with server's public key
    system("openssl rsautl -encrypt -pubin -inkey Files/Server-publ.pem -in session.key -out Files/session.key.enc"); 
    
    // sign message with client's private key
    system("openssl rsautl -sign -in Files/message.txt -inkey Files/Client1-priv.pem -out Files/message.sign"); 
    // encrypt signed message with session key
    system("openssl enc -aes-256-cbc -pbkdf2 -salt -in Files/message.sign -out Files/message.sign.enc -pass file:./session.key ");
    
    
    ifstream outfile ("session.key.enc");

    outfile >> message_encoded;

    outfile.close();

    return message_encoded;
}

// function to decode message with private and public key  
string decode_message(string reply){
    string reply_decoded;
    return reply_decoded;
}

// function to decode values with Homomorphic Database Key  
string decode_values(string reply){
    string reply_values_decoded;
    return reply_values_decoded;
} 

// funciton to make it easy to write the query
// not important 
string create_command(int input){
    switch (input){
    case 1:
        /* code */
        break;
    case 2:
        /* code */
        break;
    case 3:
        /* code */
        break;
    case 4:
        /* code */
        break;
    case 5:
        /* code */
        break;
    case 6:
        /* code */
        break;
    default:
        break;
    }

    return NULL;
}


int main(int argc, char* argv[]){
    cout << "Welcome! To access and chage the database choose from the following commands:\n" << endl;

    cout << "+------------------------------------------------------------------------------------------------------------------------------------------+" << endl;
    cout << "| Commands                   | Syntax                                                                                                      |" << endl;
    cout << "+----------------------------+-------------------------------------------------------------------------------------------------------------+" << endl;
    cout << "| 1. Create new table        | CREATE TABLE tablename (col1name, col2name, …, colNname)                                                    |" << endl;
    cout << "| 2. Insert row in table     | INSERT INTO TABLE (col1name, … , colNname) VALUES (value1, .., valueN)                                      |" << endl;
    cout << "| 3. Delete row from table   | DELETE FROM tablename WHERE col1name =|<|>value1 AND|OR col2name =|<|> value2                               |" << endl;
    cout << "| 4. Query table             | SELECT col1name, .., colNname FROM tablename WHERE col1name =|<|> value1 AND|OR col2name =|<|> value2       |" << endl;
    cout << "| 5. Sum column              | SELECT SUM(colname) FROM tablename WHERE col1name =|<|> value AND|OR col2name =|<|> value                   |" << endl;
    cout << "| 6. Multiply column         | SELECT MULT(colname) FROM tablename WHERE col1name =|<|> value AND|OR col2name =|<|> value                  |" << endl;
    cout << "+----------------------------+-------------------------------------------------------------------------------------------------------------+" << endl;

    //int input;
    //cin >> input;
    //create_command();

    bool run = true;

    while(run){
        cout << "Input your message" << endl;

        string message, message_values_encoded, message_encoded;
        string reply, reply_unecoded, reply_values_unecoded;

        getline(cin, message);
        if(message.compare("exit") == 0){
            run = false;
            continue;
        }

        //message_values_encoded = encode_values(message);
        message_encoded = encode_message(message);
        cout << "message encoded: " << message_encoded <<endl;

        reply = connect_to_server(message_encoded);

        //reply_unecoded = decode_message(reply);
        //reply_values_unecoded = decode_values(reply_unecoded);

        //cout << "Query result: " << reply_values_unecoded << endl;
    }   
}
