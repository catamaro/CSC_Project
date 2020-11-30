#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

using namespace std;

int main(int argc, char* argv[]){

    struct sockaddr_in server_addr;
    std::string reply(15, ' ');

    int sock_fd  = socket(AF_INET, SOCK_STREAM, 0);
    if(sock_fd == -1){
        perror("socket ");
        cout << "just left 1\n";
        exit(EXIT_FAILURE);
    }
        
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(5000);
    int err = inet_aton("127.0.0.1", &server_addr.sin_addr);
    if(err == 0){
        perror("aton ");
        cout << "just left 2\n";
        exit(EXIT_FAILURE);
    }
    // setup of server - creation of server connection to server
    err = connect(sock_fd, (const struct sockaddr *)&server_addr,
                        sizeof(server_addr));

    if(err == -1){
        cout << "just left 3\n";
        exit(EXIT_FAILURE);
    }
    cout << "Just connected to the server";

    auto bytes_received = recv(sock_fd, &reply.front(), reply.size(), 0);

    cout << "\nClient recieved: " << reply << "\n";
}

