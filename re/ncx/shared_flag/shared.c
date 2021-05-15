#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int
main(int argc, char **argv)
{
    void *handle;
    int (*flag)(void);
    char *error;

   handle = dlopen("./shared_flag.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        exit(EXIT_FAILURE);
    }

   dlerror();    /* Clear any existing error */

   flag = (int (*)(void)) dlsym(handle, "printFlagIfIIs56");

   if ((error = dlerror()) != NULL)  {
        fprintf(stderr, "%s\n", error);
        exit(EXIT_FAILURE);
    }

    flag();
    dlclose(handle);
    exit(EXIT_SUCCESS);
}
