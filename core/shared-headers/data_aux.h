#ifndef DATA_AUX_H
#define DATA_AUX_H
#include <iostream>
#include <vector>
#include <nlohmann/json.hpp>

using namespace std;
using json=nlohmann::json;

vector<pair<string,string>> json_to_vector(const json& j);


#endif
