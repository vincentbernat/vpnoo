/*
 *  BASCommon.c
 *  vpnoo
 *
 */

#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "BASCommon.h"

const BASCommandSpec kVpnooCommandSet[] = {
    {   kVpnooGetHashCommand,
        NULL,
        NULL,
        NULL,
        NULL,
    },
    {   kVpnooStartStopRacoonCommand,
        kVpnooStartStopRacoonRightName,
        "allow",
        "You must be authorized to start or stop IPsec daemon.",
        NULL,
    },
    {   NULL,
        NULL,
        NULL,
        NULL,
        NULL,
    }
};

unsigned int hashFile(const char *path) {
    int fd;
    int  err;
    char str;
    unsigned int hash = 0xAAAAAAAA;
    unsigned int i    = 0;
    
    fd = open(path, O_RDONLY);
    if (fd == -1) {
        return 0;
    }
	
    // We use a simple hash algorithm from Arash Partow
    i = 0;
    while (1) {
        err = read(fd, &str, 1);
        if (err == 0) {
            break;
        }
        if ((err == -1) && (errno == EINTR)) {
            continue;
        }
        if (err == -1) {
            return 0;
        }
        i++;
        hash ^= ((i & 1) == 0) ? (  (hash <<  7) ^ str * (hash >> 3)) :
                                 (~((hash << 11) + (str ^ (hash >> 5))));
    }
    close(fd);
    if (hash == 0) {
        hash = 1;
    }
    return hash;
}
