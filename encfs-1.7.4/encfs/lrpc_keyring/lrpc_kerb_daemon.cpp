#include "lrpc_kerb_util.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

int
lrpc_run_bg(int nochdir, int noclose)
{
    int status, fd;
    printf("LRPC kerb daemon\n");
    
    status = fork();
    if (status < 0)
        return -1;
    else if (status > 0)
        _exit(0);

    if (setsid() < 0)
        return -1;

    if (!nochdir && chdir("/") < 0)
        return -1;

    if (!noclose) {
        fd = open("/dev/null", O_RDWR, 0);
        if (fd < 0)
            return -1;
        else {
            if (dup2(fd, STDIN_FILENO) < 0)
                return -1;
            if (dup2(fd, STDOUT_FILENO) < 0)
                return -1;
            if (dup2(fd, STDERR_FILENO) < 0)
                return -1;
            if (fd > 2)
                close(fd);
        }
    }
    return 0;
}
