/*
 *  HelperTool.c
 *  vpnoo
 *
 */

#include <mach-o/dyld.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <CoreServices/CoreServices.h>
#include "BetterAuthorizationSampleLib.h"
#include "BASCommon.h"

////////////////////////////////////////////////
#pragma mark ***** Get hash command

static OSStatus DoGetHash(AuthorizationRef auth,
                          const void *userData,
                          CFDictionaryRef request,
                          CFMutableDictionaryRef response,
                          aslclient asl,
                          aslmsg aslMsg) {
    OSStatus retval   = noErr;
    CFNumberRef value;
    unsigned int hash;
    char path[PATH_MAX];
    UInt32 pathlen;
    
    assert(auth != NULL);
    // userData may be NULL
    assert(request != NULL);
    assert(response != NULL);
    // asl may be NULL
    // aslMsg may be NULL
    
    // We need to get our complete path
    pathlen = sizeof(path) - 1;
    if (_NSGetExecutablePath(path, &pathlen) != 0) {
        CFDictionaryAddValue(response, CFSTR(kVpnooErrorString),
                             CFSTR("unable to get helper executable full path"));
        return BASErrnoToOSStatus(ENOENT);
    }
    path[pathlen] = '\0';

    // We open ourselves for reading
    hash = hashFile(path);
    if (hash == 0) {
        CFDictionaryAddValue(response, CFSTR(kVpnooErrorString),
                             CFSTR("unable to hash helper content"));
        return BASErrnoToOSStatus(errno);
    }
    value = CFNumberCreate(NULL, kCFNumberIntType, &hash);
    if (value == NULL) {
        retval = coreFoundationUnknownErr;
    } else {
        CFDictionaryAddValue(response, CFSTR(kVpnooGetHashResponse), value);
    }
    
    if (value != NULL) {
        CFRelease(value);
    }
    
    return retval;
}

////////////////////////////////////////////////
#pragma mark ***** Start/stop Racoon

// Kill racoon
static OSStatus KillRacoon(aslclient asl,
                           aslmsg aslMsg) {
    /* To kill racoon, we don't use any PID, process name, etc. We just
       locate processes listening on UDP using port 500. This black magic
       is done with lsof command :
         lsof -Pan -i udp:500 -Fp
     */
    int      err;
    int      lsof[2];     // Pipes to communicate with lsof
    OSStatus retval;      // Save return value here is needed
    int      devnull;     // File descriptor to /dev/null
    char     process[20]; // PID of racoon process
    pid_t    racoon;      // PID of racoon process
    pid_t    pid;         // PID of lsof
    int      count;       // Number of character read from lsof
    int      status;      // Child status
    char    *conv;        // Used by strtol
    int      iterations = 0; // Number of processes killed
    char *const command[] = { "lsof", "-Pan", "-i", "udp:500", "-Fp" };

    while (1) {
        if (iterations++ > 6) {
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "too many racoon process or racoon not killable");
            assert(err == 0);
            return BASErrnoToOSStatus(ETIME);
        }

        // Create pipe
        if (pipe(lsof)) {
            retval = BASErrnoToOSStatus(errno);
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to get a pair of pipes: %m");
            assert(err == 0);
            return retval;
        }
        // Fork a process
        if ((pid = fork()) < 0) {
            retval = BASErrnoToOSStatus(errno);
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to fork: %m");
            assert(err == 0);
            return retval;
        }
        switch (pid) {
            case 0:
                // In the child, redirect stdout to pipe, close everything else
                close(lsof[0]);
                if ((devnull = open("/dev/null", O_RDWR, 0)) != -1) {
                    dup2(devnull, STDIN_FILENO);
                    dup2(devnull, STDERR_FILENO);
                    dup2(lsof[1], STDOUT_FILENO);
                    if (devnull > 2) close(devnull);
                    if (lsof[1] > 2) close(lsof[1]);
                    // And exec lsof
                    execvp("lsof", command);
                }
                // Exec error
                _exit(127);
                break;
            default:
                // In the parent, read the pipe
                close(lsof[1]);
                count = 0;
                do {
                    status = read(lsof[0], process+count, sizeof(process)-count);
                    if ((status == -1) && (errno == EINTR)) continue;
                    if (status > 0)
                        count += status;
                } while (count < sizeof(process) && (status > 0));
                if (status < 0) {
                    retval = BASErrnoToOSStatus(errno);
                    err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to read from lsof: %m");
                    assert(err == 0);
                    close(lsof[0]);
                    waitpid(pid, NULL, 0);
                    return retval;
                }
                close(lsof[0]);
                if (count >= sizeof(process)) {
                    err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "output of lsof is too large");
                    assert(err == 0);
                    waitpid(pid, NULL, 0);
                    return BASErrnoToOSStatus(E2BIG);
                }
                status = -1;
                if (waitpid(pid, &status, 0) != pid) {
                    return BASErrnoToOSStatus(ECHILD);
                }
                if (!WIFEXITED(status) ||
                    ((WEXITSTATUS(status) != 0) && (WEXITSTATUS(status) != 1))) {
                    err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "lsof not available");
                    assert(err == 0);
                    return BASErrnoToOSStatus(ENOENT);
                }
                if (!count) {
                    err = asl_log(asl, aslMsg, ASL_LEVEL_INFO, "no existing instance of racoon");
                    assert(err == 0);
                    return noErr;
                }
                process[count] = '\0';
                // Keep only first process
                if (strchr(process, '\n')) {
                    *strchr(process, '\n') = '\0';
                }
                // Remove first p
                if (process[0] == 'p') {
                    racoon = strtol(&process[1], &conv, 10);
                } else {
                    racoon = strtol(process, &conv, 10);
                }
                if (*conv != '\0') {
                    err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "got invalid PID %s", process);
                    assert(err == 0);
                    return BASErrnoToOSStatus(EINVAL);
                }
                err = asl_log(asl, aslMsg, ASL_LEVEL_INFO, "racoon PID is %d. Kill it and wait a bit", racoon);
                assert(err == 0);
                kill(racoon, SIGINT);
                usleep(2000000); // Let racoon die properly
                break;
        }
    }
    // We should not be there!
    return BASErrnoToOSStatus(EFAULT);
}

// Start racoon
static OSStatus StartRacoon(const char *confPath,
                            const char *logPath,
                            const char *pidPath,
                            const char *socketPath,
                            aslclient asl, aslmsg aslMsg) {
    /* We start racoon and wait a bit for it to be ready. The PID file
       should exist and the socket should be created. We even try a connection
       to the socket. */
    int     err;
    int     devnull;    // File descriptor to /dev/null
    pid_t   racoon;     // PID of racoon
    int     status;     // Child status
    int     iterations; // Ensure that we don't loop too much
    int     sock;       // Socket descriptor
    OSStatus retval;
    struct sockaddr_un su;
    struct stat statBuf;

    // First, remove the PID, we will rely on its presence later
    if (unlink(pidPath) == -1) {
        if (errno != ENOENT) {
            retval = BASErrnoToOSStatus(errno);
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to delete old PIF file: %m");
            assert(err == 0);
            return retval;
        }
    }

    // Fork a process
    if ((racoon = fork()) < 0) {
        retval = BASErrnoToOSStatus(errno);
        err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to fork: %m");
        assert(err == 0);
        return retval;
    }
    switch (racoon) {
        case 0:
            // In the child, redirect everything to /dev/null, run racoon
            if ((devnull = open("/dev/null", O_RDWR, 0)) != -1) {
                dup2(devnull, STDIN_FILENO);
                dup2(devnull, STDERR_FILENO);
                dup2(devnull, STDOUT_FILENO);
                if (devnull > 2) close(devnull);
                // And exec racoon
                execlp("racoon", "racoon", "-f", confPath, "-l", logPath, NULL);
            }
            // Exec error (cannot do better than the exit code)
            _exit(127);
            break;
        default:
            // In the parent, wait for racoon to "finish" (double fork)
            status = -1;
            if (waitpid(racoon, &status, 0) != racoon) {
                return BASErrnoToOSStatus(ECHILD);
            }
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "racoon did not execute correctly");
                assert(err == 0);
                return BASErrnoToOSStatus(ENOENT);
            }
            break;
    }
    /* From here, racoon has started. We should check if its PID is present */
    iterations = 0;
    while (1) {
        if (iterations++ > 5) {
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "racoon did not start properly (check %s)", logPath);
            assert(err == 0);
            return BASErrnoToOSStatus(ETIME);
        }
        if (iterations > 1) {
            usleep(500000);
        }
        if (stat(pidPath, &statBuf) == -1) {
            if (errno == ENOENT) {
                err = asl_log(asl, aslMsg, ASL_LEVEL_INFO, "racoon PID file is not here yet");
                assert(err == 0);
                continue;
            }
            retval = BASErrnoToOSStatus(errno);
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to check racoon PID file %s: %m", pidPath);
            assert(err == 0);
            return retval;
        }
        break;
    }
    /* Racoon seems to have started properly. We try to connect to his socket */
    iterations = 0;
    while (1) {
        if (iterations++ > 5) {
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "racoon socket %s still not available (check %s)",
                          socketPath, logPath);
            assert(err == 0);
            return BASErrnoToOSStatus(ETIME);
        }
        if (iterations > 1) {
            usleep(500000);
        }
        if (stat(socketPath, &statBuf) == -1) {
            if (errno == ENOENT) {
                err = asl_log(asl, aslMsg, ASL_LEVEL_INFO, "racoon socket is not here yet");
                assert(err == 0);
                continue;
            }
            retval = BASErrnoToOSStatus(errno);
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to check racoon socket file %s: %m",
                          socketPath);
            assert(err == 0);
            return retval;
        }
        // The socket exists, try to connect to it
        sock = socket(PF_UNIX, SOCK_STREAM, 0);
        if (sock == -1) {
            retval = BASErrnoToOSStatus(errno);
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to create a socket: %m");
            assert(err == 0);
            return retval;
        }
        su.sun_family = AF_UNIX;
        strlcpy(su.sun_path, socketPath, sizeof(su.sun_path));
        if (connect(sock, (struct sockaddr *)&su, sizeof(struct sockaddr_un)) == -1) {
            if (errno == ECONNREFUSED) {
                err = asl_log(asl, aslMsg, ASL_LEVEL_INFO, "racoon socket is not ready yet");
                assert(err == 0);
                continue;
            }
            retval = BASErrnoToOSStatus(errno);
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to connect to racoon socket %s: %m",
                          socketPath);
            assert(err == 0);
            return retval;
        }
        close(sock);
        err = asl_log(asl, aslMsg, ASL_LEVEL_INFO, "racoon started successfuly");
        assert(err == 0);
        return noErr;
    }
}

static OSStatus DoStartStopRacoon(AuthorizationRef auth,
                                  const void *userData,
                                  CFDictionaryRef request,
                                  CFMutableDictionaryRef response,
                                  aslclient asl,
                                  aslmsg aslMsg) {
    OSStatus retval = noErr;
    int err;
    CFStringRef path = NULL;
    CFNumberRef command = NULL;
    char tmpPath[PATH_MAX];
    char confPath[PATH_MAX];
    char logPath[PATH_MAX];
    char pidPath[PATH_MAX];
    char socketPath[PATH_MAX];
    int operation;
    
    assert(auth != NULL);
    // userData may be NULL
    assert(request != NULL);
    assert(response != NULL);
    // asl may be NULL
    // aslMsg may be NULL

    // Retrieve configuration path
    path = (CFStringRef) CFDictionaryGetValue(request,
                                              CFSTR(kVpnooStartStopRacoonConfPath));
    if ((path == NULL) || (CFGetTypeID(path) != CFStringGetTypeID())) {
        CFDictionaryAddValue(response, CFSTR(kVpnooErrorString),
                             CFSTR("invalid value for configuration path"));
        return BASErrnoToOSStatus(EBADMSG);
    }
    
    // Build path to log and path to configuration file
    if (!CFStringGetCString(path, tmpPath, sizeof(tmpPath), kCFStringEncodingUTF8)) {
        return coreFoundationUnknownErr;
    }
#define BUILDPATH(name, variable) \
    do { \
    err = snprintf(variable, sizeof(variable), "%s/" name, tmpPath); \
    if (err < 0) { \
        return coreFoundationUnknownErr; \
    } \
    if (err == sizeof(variable)) { \
        CFDictionaryAddValue(response, CFSTR(kVpnooErrorString), \
                CFSTR("unable to build path for " name)); \
        return BASErrnoToOSStatus(ENAMETOOLONG); \
    } \
    } while (0)
    BUILDPATH("racoon.conf", confPath);
    BUILDPATH("racoon.log", logPath);
    BUILDPATH("racoon.pid", pidPath);
    BUILDPATH("racoon.sock", socketPath);
    
    // Get command
    command = (CFNumberRef) CFDictionaryGetValue(request,
                                                 CFSTR(kVpnooStartStopRacoonAction));
    if ((command == NULL) || (CFGetTypeID(command) != CFNumberGetTypeID())) {
        CFDictionaryAddValue(response, CFSTR(kVpnooErrorString),
                             CFSTR("invalid value for command"));
        return BASErrnoToOSStatus(EBADMSG);
    }
    if (!CFNumberGetValue(command, kCFNumberIntType, &operation)) {
        return coreFoundationUnknownErr;
    }

    // First, kill any running racoon
    retval = KillRacoon(asl, aslMsg);
    if (retval != noErr) {
        CFDictionaryAddValue(response, CFSTR(kVpnooErrorString),
                             CFSTR("unable to kill racoon"));
        return retval;
    }
    
    // Execute the wanted operation
    if (operation == kVpnooStartRacoon) {
        retval = StartRacoon(confPath, logPath, pidPath, socketPath,
                             asl, aslMsg);
        if (retval != noErr) {
            CFDictionaryAddValue(response, CFSTR(kVpnooErrorString),
                                 CFSTR("unable to start racoon"));
            return retval;
        }
    }

    return retval;
}


/////////////////////////////////////////////////////////////////
#pragma mark ***** Tool Infrastructure

static const BASCommandProc kVpnooCommandProcs[] = {
    DoGetHash,
    DoStartStopRacoon,
    NULL
};

int main(int argc, char **argv)
{
    return BASHelperToolMain(kVpnooCommandSet, kVpnooCommandProcs);
}
