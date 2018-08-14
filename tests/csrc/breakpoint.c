#include <signal.h>


int main(int argc, char** argv)
{
    raise(SIGINT);
    int a = 3;
    __asm__("int3");
    a++;  
    raise(SIGINT);
	printf("vboxoglfeedbackspu.dll")
    return 0;


}
