#include <iostream>
#include <cstring>
#include <sstream>
#include <unistd.h>
#include <nlohmann/json.hpp>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <string>
#include <thread>
#include <unordered_map>
#include <netinet/in.h>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <fstream>
#include <csignal>
#include "../../shared-headers/networking_aux.h"
#include "../../shared-headers/networking_aux.cpp"
#include "current_date_time.h"
#include "get_arguments.cpp"

#define MODULE_SOCKET_PATH "/tmp/module-body.sock"

using namespace std;
using json=nlohmann::json;

const char* error_color="\033[1;31m";
const char* warning_color="\033[1;33m";
const char* success_color="\033[1;32m";
const char* normal_color="\033[0m";
const char* bolded_white_color="\033[1;37m";

int module_status_port=0;
unordered_map<string,string> module_info =
{
	{"Name","Module Name"},
	{"IP address","127.0.0.1"},
	{"Threads","5"},
};

unordered_map<string,int> fund_modules_sockets_map =
{
	{"body",-1},
	{"controller",-1},
	{"controller_news",-1}
};

unordered_map<string,string> modules_ip_map = {
	{"controller","127.0.0.1"}, 
};

vector<unsigned char> received_dh_key;
vector<unsigned char> digested_received_dh_key;
vector<unsigned char> salt={'n','g','f','w'};
vector<unsigned char> info={192,168,1,7};
vector<unsigned char> controller_iv;
vector<unsigned char> controller_ciphertext;
vector<unsigned char> controller_tag;

unordered_map<string,vector<unsigned char>> module_iv_map = {{"controller",controller_iv}};
unordered_map<string,vector<unsigned char>> module_ciphertext_map = {{"controller",controller_ciphertext}};
unordered_map<string,vector<unsigned char>> module_tag_map = {{"controller",controller_tag}};

bool strict_cryptography=true;
mutex mtx;
condition_variable cv_event;
condition_variable cv_signal;
atomic<bool> stop_loop{false};

void send_log(string message,string module_name="Name",int message_type=1) {
	message=module_name+" Module: "+message;
	if (message_type==1) {
		message="[" +get_current_date_time()+ "] "+message;
		cout << error_color << "[ERROR] " << message << normal_color << "\n";
		message=string(error_color)+message+string(normal_color);
	}
	else if (message_type==2) {
		message="[" +get_current_date_time()+ "] "+message;
		cout << warning_color << "[WARNING] " << message << normal_color << "\n";
		message=string(warning_color)+message+string(normal_color);
	}
	else if (message_type==3) {
		message="["+get_current_date_time()+"] "+message;
		cout << success_color << "[COMPLETE] " << message << normal_color << "\n";
		message=string(success_color)+message+string(normal_color);
	}
	else if (message_type==0) cout << message << "\n";
	
	if (fund_modules_sockets_map["controller_news"]<0) return;
	int status=0;
	UDP_Send(fund_modules_sockets_map["controller_news"],message,status);
}

int load_operating_settings(const char* initial_settings_file) {
	cout << "Module Initialise: Loading operating settings...\n";
	fstream settings_file(initial_settings_file, ios::in); 
	if (!settings_file.is_open()) {
		send_log("Cannot load the fundamental configurations and settings.",module_info["Name"],1);
		return -1;
	}
	getline(settings_file,module_info["Name"]);
	getline(settings_file,module_info["IP Address"]);
	getline(settings_file,module_info["Threads"]);
	settings_file.close();
	cout << success_color << "[COMPLETE]: Module: Loading initial operating settings success." << normal_color << "\n";
	return 0;
}

int initialise(int tcp_port,int streaming_port,const char* initial_configuration_file) {
	cout << "Module: Initialising the module...\n";
	if (load_operating_settings(initial_configuration_file)<0) {
		send_log("Initialise: loading operating settings failure.",module_info["Name"],1);
		return -1;
	}
	TCP_Open(fund_modules_sockets_map["controller"],modules_ip_map["controller"].c_str(),tcp_port,SERVER);
	if (fund_modules_sockets_map["controller"]<0) {
		send_log("Initialise: Failed to connect with the controller for receiving the update.",module_info["Name"],2);
	}
	else
	send_log("Initialise: TCP Connection with the controller has been established.",module_info["Name"],3);
	std::this_thread::sleep_for(std::chrono::seconds(1));
	/*UNIX_Open(fund_modules_sockets_map["body"],MODULE_SOCKET_PATH,CLIENT);
	if (fund_modules_sockets_map["body"]<0) {
		send_log("Initialise: Error in the Connection with the body.");
		return -3;
	}*/
	UDP_Open(fund_modules_sockets_map["controller_news"],modules_ip_map["controller"].c_str(),streaming_port);
	
	/*int sending_status=0;
	TCP_Send(fund_modules_sockets_map["controller"],"READY",sending_status);
	if (sending_status==1) return -4;
	else if (sending_status==-1) return -5; */
	return 0;
}

int get_auth_credentials(string recvd_message) {
	send_log("Getting authentication credentials...",module_info["Name"],0);
	stringstream ss(recvd_message);
	string str_controller_iv,str_controller_ciphertext,str_controller_tag;
	getline(ss,str_controller_iv,'|');
	getline(ss,str_controller_ciphertext,'|');
	getline(ss,str_controller_tag);
	controller_iv=vector<unsigned char>(str_controller_iv.begin(),str_controller_iv.end());
	controller_ciphertext=vector<unsigned char>(str_controller_ciphertext.begin(),str_controller_ciphertext.end());
	controller_tag=vector<unsigned char>(str_controller_tag.begin(),str_controller_tag.end());
	return 0;
}

int controller_receive_updates(bool strict_cryptography,json& module_settings) {
    send_log("Waiting for Updates from the controller...",module_info["Name"],0);
    
    string received_instructions; 
    
    while (!stop_loop) {
        try {
            TCP_Receive(fund_modules_sockets_map["controller"], received_instructions, 8192);
            
            if (!received_instructions.empty()) {
                send_log("Controller instructions received! Parsing...",module_info["Name"],3);
                module_settings = json::parse(received_instructions);
                return 0;
            }
            
            
        } catch (const std::exception& e) {
            send_log("Unexpected Behaviour during parse: " + string(e.what()),module_info["Name"],1);
            return -2;
        }
    }
    
    return -1;
}

int extract_details(json instructions_json,json& general_settings,json& module_settings) {
	send_log("Extracting the details..",module_info["Name"],0);
	try {
		general_settings=instructions_json["general_settings"];
		module_settings=instructions_json["module_settings"];
	} catch (const std::exception& e) {
		send_log("Unexpected Behaviour: " + string(e.what()),module_info["Name"],1);
		return -1;
	}
	return 0;
}

inline int set_general_settings(json general_settings) {
	send_log("Setting general settings...",module_info["Name"],0);
	try {
		module_info["Name"]=general_settings["assign_name"]; 
		strict_cryptography=general_settings["general_cryptography"];
	} catch (const std::exception& e) {
		send_log("SetGeneralSettings: Unexpected Behavior: " + string(e.what()),module_info["Name"],1);
		return -1;
	}
	return 0;
}

int send_instructions(json module_ins) {
	send_log("Sending the instructions to the body..",module_info["Name"],0);
	string str_received_ins=module_ins.dump();
	int sending_status=0;
	UNIX_Send(fund_modules_sockets_map["body"],str_received_ins,sending_status);
	if (sending_status<0) {
		send_log("Sending instructions has failed",module_info["Name"],1);
		return -1;
	}
	return 0;
}

int initialise_UDP_socket(string module_name,int port) {
	string udp_module_name=module_name+"_udp";
	fund_modules_sockets_map[udp_module_name]=-1;
	UDP_Open(fund_modules_sockets_map[udp_module_name],modules_ip_map[module_name].c_str(),port);
	if (fund_modules_sockets_map[udp_module_name]<0) return -1;
	return 0;
}

void receive_from_body(string& received_status,int& status) {
	UNIX_Receive(fund_modules_sockets_map["body"],received_status,1024);
	if (received_status.empty()) status=-1;
}

int send_module_status(int port) {
	if (initialise_UDP_socket(module_info["Name"],port)<0) return -1;
	int sending_status=0;
	string str_status;
	receive_from_body(str_status,sending_status);
	if (sending_status == -1) return -2;
	UDP_Send(fund_modules_sockets_map["controller_udp"],str_status,sending_status);
	return 0;
}


void data_plane_proxy() {
    int tcp_server = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(tcp_server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in tcp_addr{};
    tcp_addr.sin_family = AF_INET;
    tcp_addr.sin_port = htons(9000);
    tcp_addr.sin_addr.s_addr = INADDR_ANY;
    bind(tcp_server, (struct sockaddr*)&tcp_addr, sizeof(tcp_addr));
    listen(tcp_server, 5);

    send_log("ModuleHead listening on TCP 9000 for PEP Data Plane...",module_info["Name"], 0);
    int pep_client = accept(tcp_server, nullptr, nullptr);
    if (pep_client < 0) return;
    send_log("PEP Connected to ModuleHead. Bridging to PE UNIX Data Socket...",module_info["Name"] ,3);

    int unix_client = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un unix_addr{};
    unix_addr.sun_family = AF_UNIX;
    strncpy(unix_addr.sun_path, "/tmp/pe-data.sock", sizeof(unix_addr.sun_path)-1);
    
    while(connect(unix_client, (struct sockaddr*)&unix_addr, sizeof(unix_addr)) < 0 && !stop_loop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    send_log("ModuleHead Data Plane connected to PE. Proxying active.",module_info["Name"],3);

    auto proxy_func = [](int src_fd, int dst_fd) {
        char buffer[8192];
        while (!stop_loop) {
            int bytes = recv(src_fd, buffer, sizeof(buffer), 0);
            if (bytes <= 0) break;
            int total_sent = 0;
            while (total_sent < bytes) {
                int sent = send(dst_fd, buffer + total_sent, bytes - total_sent, 0);
                if (sent <= 0) break;
                total_sent += sent;
            }
        }
    };

    std::thread tA(proxy_func, pep_client, unix_client);
    std::thread tB(proxy_func, unix_client, pep_client);

    tA.join();
    tB.join();

    close(unix_client);
    close(pep_client);
    close(tcp_server);
}

void module_end() {
	send_log("Closing the module...",module_info["Name"],0);
	TCP_Close(fund_modules_sockets_map["controller"]);
	UDP_Close(fund_modules_sockets_map["controller_udp"]);
	UDP_Close(fund_modules_sockets_map["controller_news"]);
	UNIX_Close(fund_modules_sockets_map["body"]);
}

void thread1_func(json general_settings) {
	if (set_general_settings(general_settings)<0) return;
	while (!stop_loop) {
		unique_lock<mutex> lock(mtx);
		cv_signal.wait(lock,[]{return stop_loop.load();});
	}
}

void thread2_func(json module_settings) {
	if (send_instructions(module_settings)<0) return;
	while (!stop_loop) {
		unique_lock<mutex> lock(mtx);
		cv_signal.wait(lock,[]{return stop_loop.load();});
	}
}

void signal_handler(int signal) {
	{
		lock_guard<mutex> lock(mtx);
		stop_loop=true;
	}
	cv_signal.notify_all();
}

void print_available_commands() {
	cout << "The real command: ./modulehead [CONTROLLER_PORT] [STREAM_PORT] [CONFIG_FILE].\n";
}

int main(int argc,char* argv[]) {
	signal(SIGINT,signal_handler);
	if (argc<5) {
		print_available_commands();
		return -1;
	}
	//cout << "Operating a function..\n";
	//cout << "Detecting the arguments list file on path: " << argv[4] << "\n";
	string arguments_path=string(argv[4]);
	thread t_data(data_plane_proxy);
    	t_data.detach();

	if (initialise(stoi(string(argv[1])),stoi(string(argv[2])),argv[3])<0) return -2;

	send_log("Starting the arguments initialisation",module_info["Name"],0);
	cout << "Waiting for 3 seconds for starting arguments initialisation..\n";
	this_thread::sleep_for(chrono::seconds(3));
	vector<string> our_arguments=get_arguments(arguments_path,2);
	if (our_arguments.empty()) {
		send_log("Error occured during initialising the arguments.",module_info["Name"],1);
		return -2;
	}
	send_log("Arguments Loaded",module_info["Name"],3);
	for (int i=0;i<our_arguments.size();i++) {
		cout << our_arguments[i] << "\n";
	}
	cout << "PEP IP address: " << our_arguments[0] << "\n";
	cout << "PE IP address: " << our_arguments[0] << "\n";
	json recvd_cont_template; 
	if (controller_receive_updates(true,recvd_cont_template)<0) return -3;
	
	json module_settings, general_settings;
	if (extract_details(recvd_cont_template,general_settings,module_settings)<0) return -4;
	
	//if (initialise_UDP_socket(module_info["Name"],module_status_port)<0) return -5;
	
	thread t1(thread1_func,std::ref(general_settings));
	thread t2(thread2_func,std::ref(module_settings));

	string recvd_ins;
	int stat=0;
	while (!stop_loop) {
		receive_from_body(recvd_ins,stat); 
		if (stat==-1) break;
		send_module_status(module_status_port);
	}
	
	stop_loop = true;
	cv_signal.notify_all();
	t1.join();
	t2.join();
    if (t_data.joinable()) t_data.join();
	//module_end();
	return 0;
}
