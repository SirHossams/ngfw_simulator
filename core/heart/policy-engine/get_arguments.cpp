#pragma once
#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <string>

using namespace std;
namespace fs=std::filesystem;

vector<string> get_arguments(string file_path,int argc) {
	vector<string> result;
	if (fs::exists(file_path) && fs::is_empty(file_path) && argc<=0) {
		cerr << "File does not exist, empty, or invalid arguments number.\n";
		return result;
	}
	ifstream file(file_path.c_str(),ios::in);
	if (!file.is_open()) {
		cerr << "Getting Arguments Failure: The file does not exist or error during opening.\n";
		return result;
	}
	int i=0;
	while (i<argc) {
		string template_string;
		getline(file,template_string);
		result.push_back(template_string);
		i++;
	}
	file.close();
	return result;
}
