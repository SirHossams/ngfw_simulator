#include <iostream>
#include <unistd.h>
#include <fstream>
#include <cstring>
#include <nlohmann/json.hpp>
#include <string>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

using namespace std;
using json=nlohmann::json;

in_addr module_address;

//our planned functions
//the functions are based on the detailed diagram of the pipeline


struct analysed_json {
	//the part of the json file that removed from it the control settings except the socket address.
	json module_settings;
	string ip_address;
	int port_number;
};

//receive the json content from the head including the privilege number of the user
int recv_from_head();

//check whether the user is privileged to do that or not
int check_privileges() {
	recv_from_head();
}

//1- create a new process to start a module, send an instruction to the device carrying the module.
int start_module();

int reboot_module();

int shutdown_module();

int update_module();

//2- analyse the sent JSON file
//it is also responsible for separating the control settings from the module settings.
analysed_json analyse_json(json received_file)
{
	/* -- Validate before the execution (using try..catch) -- */
	analysed_json result;
	json percieved_instructions=received_file["control_settings"];
	string ip_address=percieved_instructions["IP_address"];
	result.ip_address=ip_address;
	int port_address=percieved_instructions["Port_number"];
	result.port_number=port_address;
	if (inet_pton(AF_INET,ip_address.c_str(),&module_address)!=0);
	{
		cerr << "Error: IP address is invalid or something." << endl;
		return -1;
	}
	//remove the socket address part and send the rest of instructions to the module
	if (percieved_instructions.contains("IP_address"))
	percieved_instructions.erase("Socket_address");
	result.module_settings=received_file["module_settings"];
	return result;
}

//3- send the module settings to the module
int send_module_instructions(json received_file) {
	analysed_json module_instructions=analyse_json(received_file);
	int instructions_socket=socket(AF_INET,SOCK_STREAM,0);
	if (instructions_socket<0) {
		perror("Error in creating the socket");
		return -1;
	}
	module_address.sin_family=AF_INET;
	module_address.sin_port=htons(module_instructions.port_number);

	//module connection request
	if (connect(instructions_socket,(sockaddr*) &module_address,sizeof(module_address))<0)
	{
		perror("Could not connect to the module");
		return -1;
	}
	/* !! There must be an encryption phase here !! */
	//the stage of sending the instructions
	string instructions=result.module_settings.dump();
	if (send(instructions_socket,instructions.c_str(),instructions.size(),0)<0)
	{
		perror("Cannot send the message");
		return -1;
	}
	else
		cout << "The instuctions were sent successfully.\n";
	close(instructions_socket);
	return 0;
	//the module next receives this string and may parse it again to JSON format.
	//a module instance will be simulated.
}

//everything is executed here
int main(int argc,char* argv[])
{
	/* !! the json content must be validated first !! */
	json our_json_module; //a convention that we already have the JSON file from the head
	return 0;
}
