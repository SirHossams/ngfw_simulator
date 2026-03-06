#include <iostream>
#include <cstring>
#include <ctime>

using namespace std;

int main(int argc,char* argv[])
{
	if (strcmp(argv[1],"suc")==0)
		cout << "Success!\n";
	else
		cout << "Failed!\n";
	return 0;
}
