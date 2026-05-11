#include <iostream>
#include <string>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>

using namespace std;

string get_current_date_time()
{
        auto now=chrono::system_clock::now();
        time_t now_time=chrono::system_clock::to_time_t(now);

        tm local_tm=*localtime(&now_time);

        stringstream ss;
        ss << put_time(&local_tm,"%Y-%m-%d %H:%M:%S");
        return ss.str();
}
