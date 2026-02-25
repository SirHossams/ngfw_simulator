// Example
pid_t pid = fork();

if(pid == 0)
{
    execv("modules/module1/module1", args);
}
