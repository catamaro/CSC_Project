#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>  
#include <string.h>

using namespace std;

int main(int argc, char* argv[]){

    struct sockaddr_in local_addr;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_size = sizeof(client_addr);

    string message(50, ' ');
    string reply(50, 'a');
    
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

    bool run = true;

    while (run) {
        // accept call will give us a new socket descriptor
        int newFD = accept(server_fd, (sockaddr *) &client_addr, &client_addr_size);
        if (newFD == -1) {
            std::cerr << "Error while Accepting on socket\n";
            continue;
        }
        else{
            cout << "Client 1 just connected\n";
        }
            
        // send call sends the data you specify as second param and it's length as 3rd param, also returns how many bytes were actually sent
        auto bytes_received = recv(newFD, &message.front(), message.length(), 0);

        cout << "received message: " << message << endl;

        auto bytes_sent = send(newFD, &reply.front(), reply.length(), 0);

        cout << "sent message: " << reply << endl;

        close(newFD);
    }
}


