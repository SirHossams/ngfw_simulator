#include "data_aux.h"


vector<pair<string,string>> json_to_vector(const json& j) {
        vector<pair<string,string>> result;
        if (!j.is_object()) {
                cerr << "JSON is not an object.\n";
                return result;
        }
        for (auto& [key, value] : j.items())
                result.push_back({key,value.dump()});
        return result;
}
