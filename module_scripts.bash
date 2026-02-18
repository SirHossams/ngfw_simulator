#a function to initiate the modules
initiate_module()
{
        if [[ -z $1 ]]; then
                echo "You should insert the module name";
                return -1;
        fi
        working_directory=$(find /home/$(whoami) -maxdepth 1 -type d -name "ngf>
        if [[ -z $working_directory ]]; then
                echo "The NGFW_Simulator directory does not exist in your home >
                return -1;
        else
                cd "$working_directory/core/modules";
        fi
        mkdir $1;
        #after the insertion, create everything
        #what you want to insert inside the module directory
        touch $1/$1.cpp;
        mkdir $1/headers $1/sos $1/databases;
        return 0;
}
