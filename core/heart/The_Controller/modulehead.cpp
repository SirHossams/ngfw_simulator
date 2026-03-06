//this module should be in another device, it will be assigned for it its own socket address.
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <nlohmann/json.hpp>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string>
#include <netinet/in.h>

using namespace std;
using nlohmann::json=json;


struct extracted_arguments
{
	int count;
	string argument_values[count];
	extracted_arguments(){count=0;}
	extracted_arguments(int n):count(n){}
};

//the round of receiving the news from the controller
/* !! the module should know its controller for security reasons !! */
string receive_instructions(int port) {
	//preparing the address of this module
	int listen_instructions=socket(PF_INET,SOCK_STREAM,0);
	sockaddr_in listening_addr;
	listening_addr.sin_family=AF_INET;
	listening_addr.port=htons(port);
	listening_addr.sin_addr.s_addr=INADDR_ANY;
	if (bind(listen_instructions,(sockaddr*)&listening_addr,sizeof(listening_addr))<0)
	{
		perror("Could not bind");
		return -1;
	}
	if (listen(listening_addr,2)<0)
	{
		perror("Error during listening");
		return -1;
	}
	u_char listening_buffer[500];
	//now preparing the address of the controller: just prepare the variable of the datatype
	sockaddr_in controller_addr;
	socklen_t addr_size=sizeof(controller_addr);
	int coming_instructions=accept(listen_instructions,(sockaddr*)controller_addr,&addr_size);

	//receiving phase of the instructions
	int size_of_instructions=recv(listen_instructions,listening_buffer,sizeof(listening_buffer)-1,0);
	if (size_of_instructions==0)
	{
		cout << "No instructions received or an error occured\n";
		return -1;
	}
	else
	{
		listening_buffer[size_of_instructions]='\0';
		cout << "Instructions received successfully\n";
	}
	close(listen_instructions);
	close(coming_instructions);
	string str_instructions(listening_buffer,size_of_instructions);
	return str_instructions;
}

//the deployment of the module for the processor and memory to initialise the working of the module
extracted_arguments module_operations(int port_number) {
	string module_instructions=receive_instructions(port_number);
	/* -- Here is the deployment of CPU and memory usage -- */
	json json_module_instructions=json::parse(module_instructions);
	extracted_arguments instance(100);
	extract_keys(json_module_instructions,instance.argument_value,instance.count);
	return instance;
	//the extracted arguments then sent to a distributor that distributes this arguments among the modules functions.
	/* !! Here exists a UNIX socket configuration !! */
}

int main(int argc,char* argv[])
{
	return 0;
}
