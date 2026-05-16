#include <iostream>
#include <unistd.h>
#include <fstream>
#include <cstring>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <unordered_map>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <csignal>
#include <mutex>
#include <atomic>
#include "../../shared-headers/networking_aux.h"
#include "../../shared-headers/crypto_aux.h"
#include "../../shared-headers/data_aux.h"
#include "../../shared-headers/networking_aux.cpp"
#include "../../shared-headers/data_aux.cpp"
#include "../../shared-headers/kdf.h"
#include "../../shared-headers/kdf.cpp"

using namespace std;
using json=nlohmann::json;

json receive_from_head();
json remove_control_settings(json& whole_json_file);
json controller_settings; 
string module_name; 
mutex mtx;
int module_port=2441; 
int module_udp_port=4000;
int stream_port=3252;
int time_delay=0; 
fstream status_terminal;

unordered_map<string,int> modules_sockets_map =
{
	{"policy_engine",-1},
	{"policy_enforcement_point",-1},
	{"threat_intelligence",-1},
	{"interface_handler",-1},
	{"controller_head",-1}
};

unordered_map<string,int> reserved_module_privilege =
{
	{"policy_engine",30},
	{"policy_enforcement_point",20},
	{"threat_intelligence",10},
	{"interface_handler",10},
	{"controller_head",30},
	{"packet_capture",10}
};

int user_privilege_number=0;



unordered_map<string,string> reserved_ip_addresses = 
{
	{"policy_engine","192.168.1.7"},
	{"policy_enforcement_point","192.168.1.9"},
	{"threat_intelligence","192.168.1.10"},
	{"interface_handler","192.168.1.11"},
	{"controller_head","192.168.1.12"},
	{"this_controller","127.0.0.1"}
};

unordered_map<string,string> module_id =
{
	{"policy_engine","2341"},
	{"policy_enforcement_point","2521"},
	{"threat_intelligence","8215"},
	{"interface_handler","1941"},
	{"controller_head","4155"}
};


vector<unsigned char> received_dh_key;
vector<unsigned char> salt={'n','g','f','w'};
vector<unsigned char> info={192,168,1,7};
vector<unsigned char> iv;
vector<unsigned char> tag;
vector<unsigned char> digested_received_dh_key;


struct module_logging
{
	string module_id;
	char state;
	module_logging(string mod_id,char s):module_id(mod_id),state(s){}
	string stringify()
	{
		string copy_module_id=module_id;
		copy_module_id+='(';
		copy_module_id+=state;
		copy_module_id+=')';
		return copy_module_id;
	}
};

vector<module_logging> mod_loggings;

int initialise_body(json& whole_json_file)
{
	cout << "Controller: Initialising...\n";
	UNIX_Open(modules_sockets_map["controller_head"],"/tmp/ngfw-simulator-controller.sock",SERVER);
	if (modules_sockets_map["controller_head"]<0) {
		cerr << "Controller: InitialisingBody: Error in opening the socket.\n";
		return -1;
	}
	json module_settings=json::object();
	try {
		whole_json_file=receive_from_head();
		if (whole_json_file.is_null()) {
		cerr << "Controller: InitialiseBody: Error during receiving from head.\n";
		return -2;
		}
		else if (whole_json_file.empty()) {
			cerr << "Controller: InitialiseBody: The JSON file is empty.\n";
		}
		else {
			cout << "Controller: InitialiseBody: The JSON file is valid.\n";
		}
		module_settings=remove_control_settings(whole_json_file);
		module_name=controller_settings["module_name"];
		module_port=controller_settings["module_port"];
		stream_port=controller_settings["stream_port"];
		time_delay=controller_settings["monitoring_system_update_delay"];
		reserved_ip_addresses["threat_intelligence"]=controller_settings["threat_intelligence_ip"];
		reserved_ip_addresses["interface_handler"]=controller_settings["interface_handler"];
		reserved_ip_addresses["policy_enforcement_point"]=controller_settings["policy_enforcement_point_ip"];
		reserved_ip_addresses["policy_engine"]=controller_settings["policy_engine_ip"];
		reserved_ip_addresses["this_controller"]=controller_settings["Module_IP_Address"];
		salt=controller_settings["encryption_salt"].get<vector<unsigned char>>();
		info=controller_settings["encryption_info"].get<vector<unsigned char>>();
	}
	catch(const std::exception& e) {
		cerr << "Controller: InitialiseBody: Unexpected Behaviour: " << e.what() << "\n";
		return -3;
	}
	catch(...) {
		cerr << "Controller: InitialiseBody: Unknown error.\n";
		return -4;
	}
	fstream export_file("instructions.json",ios::out | ios::in);
	if (!export_file.is_open()) {
		cerr << "Controller: InitialiseBody: The file is not open.\n";
		return -5;
	}	
	export_file << module_settings;
	cout << "Controller: InitialiseBody: Instructions has been exported.\n";
	export_file.close();
	return 0;
}


int check_privilege_number(string str_json,string& appended_pri_number) {
	string marker="PRI$";
	string pri_privilege_no=str_json.substr(str_json.find(marker),str_json.size()-1);
	string privilege_number=pri_privilege_no.substr(marker.size(),pri_privilege_no.size()-1);
	appended_pri_number=marker+privilege_number;
	return stoi(privilege_number);
}

json receive_from_head() {
	cout << "Controller: Receiving the instructions from the head..\n";
	string recvd_instructions,acknowledgement="INSTRUCTIONS_RECEIVED";
	json json_recvd_instructions;
	try {
		UNIX_Receive(modules_sockets_map["controller_head"],recvd_instructions,8192);
		if (recvd_instructions.empty()) {
			cerr << "Controller: ReceiveFromHead: Error during receiving the JSON file.\n";
			return json_recvd_instructions;
		}
		int sending_status=0;
		UNIX_Send(modules_sockets_map["controller_head"],acknowledgement,sending_status);
		if (sending_status==-1) {
			cerr << "Controller: ReceiveFromHead: Error during the sending of the acknowledgement.\n";
			return json_recvd_instructions;
		}
		else if (sending_status==1) {
			cerr << "Controller: ReceiveFromHead: Connection with head timeout.\n";
			return json_recvd_instructions;
		}
		string append_pri_number;
		user_privilege_number=check_privilege_number(recvd_instructions,append_pri_number);
		size_t pos=recvd_instructions.find(append_pri_number);
	if (pos!=string::npos)
	recvd_instructions.erase(pos,append_pri_number.length());
	json_recvd_instructions=json::parse(recvd_instructions);
	}
	catch (const std::exception& e) {
		cerr << "Controller: ReceiveFromHead: Unexpected Behaviour: " << e.what() << "\n";
	}
	cout << "Controller: ReceiveFromHead: Instructions Received.\n";
	return json_recvd_instructions;
}

void end_body()
{
	cout << "Controller: Closing...\n";
	UNIX_Close(modules_sockets_map["controller_head"]);
}

int start_module(string module_name,int port)
{
	cout << "Controller: Starting the module..\n";
	if (user_privilege_number<reserved_module_privilege[module_name])
	{
		cout << "Controller: StartModule: You don't have the enough privileges to start this module.\n";
		return -1;
	}
	cout << "[DEBUGGING] Socket Address: " << reserved_ip_addresses[module_name] << ":" << port << "\n";
	TCP_Open(modules_sockets_map[module_name],reserved_ip_addresses[module_name].c_str(),port,CLIENT);
	module_logging instance_logger(module_id[module_name],'s');
	mod_loggings.push_back(instance_logger);	
	return 0;
}

json remove_control_settings(json& whole_json_file) {
	cout << "Controller: Removing control settings..\n";
	json module_settings;
	try {
	controller_settings=whole_json_file["control_settings"];
	module_settings=whole_json_file["module_settings"];
	}
	catch(const std::exception& e) {
		cerr << "Exception: RemoveControlSettings: " << e.what() << "\n";
		return module_settings;
	}
	return module_settings;
}


int update_module(string module_name,json module_instructions)
{
	cout << "Controller: Updating the module..\n";
	try {
	json module_settings=remove_control_settings(module_instructions);
	string str_module_settings=module_settings.dump();
	int status=0;
	TCP_Send(modules_sockets_map[module_name],str_module_settings,status);
	if (status==1) {
		cerr << "Controller: ModuleUpdate: Connection timeout.\n";
		return -1;
	}
	if (status==-1) {
		cerr << "Controller: ModuleUpdate: Connection Error.\n";
		return -2;
	}
	}
	catch (const std::exception& e) {
		cerr << "Unexpected Behaviour: UpdateModule: " << e.what() << "\n";
		return -3;
	}
	return 0;
}

inline int initialise_UDP_socket(int port) {
	cout << "Controller: Initialising the UDP socket for monitoring...\n";
	if (modules_sockets_map[module_name]==-1) {
		cerr << "Controller: InitialisingUDPSocket: The TCP version is not opened.\n";
		return -1;
	}
	string module_name_udp=module_name+"_udp";
	modules_sockets_map[module_name_udp]=-1;
	cout << "[DEBUGGING] Starting the UDP socket with address: " << reserved_ip_addresses[module_name] << ":" << port << "\n";
	UDP_Open(modules_sockets_map[module_name_udp],reserved_ip_addresses[module_name].c_str(),port);
	if (modules_sockets_map[module_name_udp]<0) {
		cerr << "Controller: InitialisingUDPSocket: An error occured during opening the UDP socket.\n";
		return -2;
	}
	cout << "Controller: InitialisingUDPSocket: UDP socket initialised successfully.\n";
	return 0;
}

json receive_module_updates(string module_name,int port)
{
	json status_json;
	try {
	string update_stat="UPDATE";
	string module_name_udp=module_name+"_udp";
	string recvd_stat;
	UDP_Receive(modules_sockets_map[module_name_udp],recvd_stat,4096);
	if (recvd_stat.empty()) {
		cerr << "Controller: ReceiveModuleUpdates: Error during receiving the message.\n";
		return status_json;
	}
	status_json=json::parse(recvd_stat);
	}
	catch (const std::exception& e) {
		cerr << "Controller: ReceiveModuleUpdates: Unexpected Behaviour: " << e.what() << "\n";
		return status_json;
	}
	return status_json;
}


int start_monitoring_system(string module_name,int status_port,int stream_port,int time_delay)
{
	cout << "Controller: Starting Monitoring System... You should ensure that you are already opening a second terminal for the output of this function.\n";
	if (time_delay<=0) {
		cerr << "Controller: StartMonitoringSystem: Invalid time delay value.\n";
		return -1;
	}
	string module_name_stream=module_name+"_stream";
	modules_sockets_map[module_name_stream]=-1;
	UDP_Open(modules_sockets_map[module_name_stream],reserved_ip_addresses[module_name].c_str(),stream_port);
	if (initialise_UDP_socket(status_port)<0) {
		cerr << "Controller: StartMonitoringSystem: Cannot initialise the UDP socket.\n";
		return -2;
	}
	status_terminal=fstream("/dev/pts/1",ios::out);
	if (!status_terminal.is_open()) {
		cerr << "Controller: MonitoringSystem: Cannot display the status. Maybe you didn't open the second terminal.\n";
		return -3;
	}
	int counter=0;
	srand(time(nullptr));
	while(true) {
		status_terminal << "\033[2J\033[H";
		json instance_module_update=receive_module_updates(module_name,status_port);
		if (instance_module_update.empty()) {
			if (counter==5) {
				cout << "Controller: MonitoringSystem: No news came from the module. Aborting..\n";
				break;
			}
			counter++;
			continue;
		}
		vector<pair<string,string>> displayed_data=json_to_vector(instance_module_update);
		for (auto& [key,value] : displayed_data) {
			status_terminal << key << ": " << value << "\n";
		}
		status_terminal << "-------------------------------------";
		this_thread::sleep_for(chrono::seconds(time_delay));
	}
	status_terminal.close();
	return 0;
}

int save_loggings()
{
	cout << "Controller: Saving loggings..\n";
	fstream saving_file("loggings.log", ios::app | ios::in);
	if (!saving_file.is_open()) {
		cerr << "Controller: SaveLoggings: Error in during opening the file.\n";
		return -1;
	}
	for (int i=0;i<mod_loggings.size();i++) {
		saving_file << mod_loggings[i].stringify() << "\n";
	}
	saving_file.close();
	return 0;
}

void thread1_work(int& function_status) {
	{
	lock_guard<mutex> lock(mtx);
	if (start_monitoring_system(module_name,module_udp_port,stream_port,time_delay)<0) {
		cerr << "Controller: Error during starting the monitoring system.\n";
		function_status=-3;
		return;
	}
	}
}
void thread2_work(int& function_status) {
	json json_instructions=receive_from_head();
	{
	lock_guard<mutex> lock(mtx);
	if (update_module(module_name,json_instructions)<0) {
		cerr << "Controller: Error during updating the module";
		function_status=-4;
		return;
	}
	}
}

void signal_handler(int signal) {
	cout << "Communication Interrupted\n";
	status_terminal.close();
	end_body();
	printf("The controller body is down.\n");
	exit(0);
}

int main(int argc,char* argv[])
{
	signal(SIGINT,signal_handler);
	json whole_object;
	if (initialise_body(whole_object)<0) {
		cerr << "Controller: Error during the initialisation.\n";
		return -1;
	}
	if (start_module(module_name,module_port)<0) {
		cerr << "Controller: Error during starting the module.\n";
		return -2;
	}
	int function_status;
	/*thread t1(thread1_work,std::ref(function_status));
	if (function_status==-3) return -3;
	thread t2(thread2_work,std::ref(function_status));
	if (function_status==-4) return -4; */
	if (save_loggings()<0) {
		cerr << "Controller: Error during saving the loggings.\n";
		return -5;
	}
	/* t1.join();
	t2.join(); */
	end_body();
	return 0;
}
