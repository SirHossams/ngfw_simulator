#include <iostream>
#include <cstring>
#include <chrono>
#include <string>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <fstream>
#include <ctime>
#include <termios.h>
#include <unistd.h>
#include "../../shared-headers/networking_aux.h"
#include "../../shared-headers/networking_aux.cpp"

#define SOCKET_PATH "/tmp/ngfw-simulator-controller.sock"

int the_body_socket=-1;

using namespace std;
using json=nlohmann::json;

int no_of_modules=3;
string name_mod_database[50]={"stateful_inspection","threat_intelligence","application_awareness"};
json json_manager_database;
int user_index=0;


int number_of_users=3;

string get_password(const string &prompt="Password: ")
{
        cout << prompt;
        termios tnew,told;
        string password;

        tcgetattr(STDIN_FILENO,&told);
        tnew=told;
        tnew.c_lflag&=~ECHO;
        tcsetattr(STDIN_FILENO,TCSANOW,&tnew);

        getline(cin,password);

        tcsetattr(STDIN_FILENO,TCSANOW,&told);
        cout << endl;

        return password;
}

string stringhash(string message)
{
        unsigned char hash[SHA256_DIGEST_LENGTH];

        unsigned char* convmessage=reinterpret_cast<unsigned char*>(const_cast<char*>(message.c_str()));
        SHA256(convmessage,strlen((const char*)convmessage),hash);
        stringstream ss;
        for (int i=0;i<SHA256_DIGEST_LENGTH;i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
        }
        return ss.str();
}


inline int initialise_databases(const char* module_file_path,const char* manager_database_path)
{
	cout << "Head_Controller: Initialising the database...\n";
	fstream modules_database_file(module_file_path);

	if (!modules_database_file.is_open())
	{
		perror("Failed to open file");
		return -1;
	}
	int counter=0;
	while(getline(modules_database_file,name_mod_database[counter])) {
		no_of_modules++;
		counter++;
	}
	modules_database_file.close();
	fstream manager_database_file(manager_database_path);
	if (!manager_database_file.is_open()) {
		cerr << "Controller_Head: Manager database does not exist.\n";
		return -2;
	}
	manager_database_file >> json_manager_database;
	manager_database_file.close();
	cout << "Databases successfully loaded...\n";
	return 0;
}

bool authenticate(const char* manager_database_filepath="manager_database.json")
{
	fstream json_file(manager_database_filepath);
	ofstream login_database("./login.txt",ios::app);
	if (!json_file.is_open())
	{
		cerr << "Head_Controller: Could not open the JSON file\n";
		return false;
	}
	if (!login_database.is_open())
	{
		cerr << "Head_Controller: Could not open the logging file\n";
		return false;
	}
	try {
		json_file >> json_manager_database;
	}
	catch (json::exception &error) {
		cerr << "Head_Controller: Error during loading the managers database: " << error.what() << "\n";
		return -1;
	}

	string validate=get_password();
	time_t current_time=time(NULL);
	char* timestring=ctime(&current_time);
	for (int i=0;i<number_of_users;i++)
	{
		if (stringhash(validate)==json_manager_database[i]["PasswordHash"]) {
			login_database << "Successful login process by " << json_manager_database[i]["Username"] << " at " << timestring << "\n";
			cout << json_manager_database[i]["Username"] << " is now logged on.\n";
			cout << "Privileges: " << json_manager_database[i]["privileges"] << "\n";
			user_index=i;
			return true;
		}
	}
	current_time=time(NULL);
	timestring=ctime(&current_time);
	login_database << "Failed login process at " << timestring << "\n";
	json_file.close();login_database.close();
	return false;
}


inline void print_help()
{
	cout << "The correct form of the command: ./firewall [MODULE] [JSON FILE]\n";
	cout << "The available modules:-\n";
	for (int i=0;i<no_of_modules;i++) {
		cout << name_mod_database[i] << "\n";
	}
}

int send_instructions(string sent_instructions,int user_privileges=0) {
	cout << "Head_Controller: Sending instuctions...\n";
	sent_instructions+="PRI$"+to_string(user_privileges);
	UNIX_Open(the_body_socket,SOCKET_PATH,CLIENT);
	if (the_body_socket<0) {
		cerr << "Head_Controller: SendInstructions: Error during opening the UNIX socket.\n";
		return -1;
	}
	int sending_status=0;
	UNIX_Send(the_body_socket,sent_instructions,sending_status);
	if (sending_status==-1) {
		cerr << "Head_Controller: SendInstructions: Error in sending the message.\n";
		return -2;
	}
	else if (sending_status==1) {
		cerr << "Head_Contoller: SendInstructions: The time of connection with the body is up.\n";
		return -3;
	}
	string recvd_ack;
	UNIX_Receive(the_body_socket,recvd_ack,32); //receive acknowledgement
	if (recvd_ack.empty())
		cout << "Head_Controller: SendInstructions: [WARNING] No acknowledgment message got from the body.\n";
	cout << "Head_Controller: Instructions have been sent.\n";
	return 0;
}

void program_ending() {
	UNIX_Close(the_body_socket);
}

int main(int argc,char* argv[])
{
	if (argc<2) {
		cout << "You must put arguments\n";
		return 0;
	}
	cout << "Starting the controller's head...\n";
	if (strcmp(argv[1],"help")==0)
	{
		print_help();
		return 0;
	}
	if (initialise_databases(argv[2],argv[3])<0)
	{
		cout << "Error during initialising the databases.\n";
		return -2;
	}
	cout << "Authentication is required\n";
	int auth_count=0;
	while (!authenticate() && auth_count<3) {
		auth_count++;
		cout << "Password is incorrect. Try Again.\n";
		if (auth_count==3) {
		cout << "Authentication Failed\n";
		return -1;
		}
	}
	fstream the_json_file(argv[1],ios::in);
	if (!the_json_file.is_open()) {
		cerr << "Head_Controller: The JSON file does not exist.\n";
		return -4;
	}
	stringstream ss;
	ss << the_json_file.rdbuf();
	string json_data=ss.str();
	if (!json::accept(json_data))
	cerr << "Controller_Head: The JSON file given is invalid.\n";
	else {	
	send_instructions(json_data,json_manager_database[user_index]["privileges"]);
	}
	program_ending();
	return 0;
}
