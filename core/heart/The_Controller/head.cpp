//an object to receive updates of a module from the manager in JSON file and gives it to the controller's body
//the controller's head should contain a database of all the available module to compare it with the written inside the JSON file.
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

using namespace std;
using json=nlohmann::json;

//what are the available modules?
//it is updated by "insert" command
int no_of_modules=3;
string name_mod_database[50]={"stateful_inspection","threat_intelligence","application_awareness"};

int number_of_users=3;

string get_password(const string &prompt="Password: ")
{
        cout << prompt;
        termios tnew,told;
        string password;

        //turn echoing off
        tcgetattr(STDIN_FILENO,&told);
        tnew=told;
        tnew.c_lflag&=~ECHO;
        tcsetattr(STDIN_FILENO,TCSANOW,&tnew);

        //read the password
        getline(cin,password);

        //restore echo
        tcsetattr(STDIN_FILENO,TCSANOW,&told);
        cout << endl;

        return password;
}

string stringhash(string message)
{
        unsigned char hash[SHA256_DIGEST_LENGTH];

        //compute the hash
        unsigned char* convmessage=reinterpret_cast<unsigned char*>(const_cast<char*>(message.c_str()));
        SHA256(convmessage,strlen((const char*)convmessage),hash);
        stringstream ss;
        for (int i=0;i<SHA256_DIGEST_LENGTH;i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
        }

        return ss.str();
}


inline int initialise_databases(const char* command_file_path,const char* module_file_path)
{
	cout << "Initialising the database...\n";
	//initialise the modules database
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
	cout << "Databases successfully loaded...\n";
	return 0;
}

bool authenticate(const char* manager_database_filepath="manager_database.json")
{
	//loading the file that contains everything about the manager
	fstream json_file(manager_database_filepath);
	ofstream login_database("./login.txt",ios::app);
	if (!json_file.is_open())
	{
		cerr << "Could not open the JSON file\n";
		return false;
	}
	if (!login_database.is_open())
	{
		cerr << "Could not open the logging file\n";
		return false;
	}
	json json_manager_database;
	try {
		json_file >> json_manager_database;
	}
	catch (json::exception &error) {
		cerr << "Error during loading the managers database: " << error.what() << "\n";
		return -1;
	}

	//get the password
	string validate=get_password();
	time_t current_time=time(NULL);
	char* timestring=ctime(&current_time);
	//comparing passwords
	for (int i=0;i<number_of_users;i++)
	{
		if (stringhash(validate)==json_manager_database[i]["PasswordHash"]) {
			login_database << "Successful login process by " << json_manager_database[i]["Username"] << " at " << timestring << "\n";
			cout << json_manager_database[i]["Username"] << " is now logged on.\n";
			cout << "Privileges: " << json_manager_database[i]["privileges"] << "\n";
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

//needs nlohmann framework here
inline int json_validation(const char* file_path)
{
	fstream file(file_path);
	if (!file.is_open())
	{
		perror("Error opening the file");
		return -1;
	}
	//JSON errors display
	//if it is not a JSON file (syntically incorrect)
	json json_file;
	try {
	file >> json_file;
	}
	catch (const json::exception &e) {
		cerr << "Error occurred: " << e.what() << "\n";
		return -1;
	}
	return 0;
}

//send it in JSON form
inline void send_instructions(json sent_instructions,string user_privileges="0001")
{
	//the body receives this privilege string to know the privileges of the user.
	cout << "Sending instructions...\n";
	//my code
	cout << "Instructions has been sent.\n";
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
	//C arguments validation
	bool is_exist=0;
	for (int i=0;i<no_of_modules;i++)
	{
		if (strcmp(argv[1],name_mod_database[i].c_str())==0)
		{
			is_exist=1;
			break;
		}
	}
	if (!is_exist)
	{
		cerr << "Invalid Module Name\n";
		print_help();
		return -1;
	}
	if (json_validation(const_cast<char*>(argv[2]))!=0) {
		cerr << "An error occurred!\n";
		return -1;
	}
	//send the JSON file
	send_instructions(argv[2]);
	return 0;
}
