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
#include <sys/ioctl.h>
#include <util.h>
#include <termios.h>

#include <CoreServices/CoreServices.h>
#include "BetterAuthorizationSampleLib.h"
#include "BASCommon.h"

// Helper function for the next functions
static OSStatus getArg(CFDictionaryRef request,
                       CFMutableDictionaryRef response,
                       CFStringRef argname,
                       const char* error,
                       CFTypeRef *result,
                       CFTypeID (*type)(),
                       aslclient asl,
                       aslmsg aslMsg) {
    OSStatus err;
    CFStringRef cferror;
    *result = CFDictionaryGetValue(request,
                                   argname);
    if ((*result == NULL) || (CFGetTypeID(*result) != type())) {
        cferror = CFStringCreateWithCString(NULL, error, kCFStringEncodingUTF8);
        if (cferror) {
            CFDictionaryAddValue(response, CFSTR(kVpnooErrorString),
                                 cferror);
            CFRelease(cferror);
        }
        err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "%s", error);
        assert(err == 0);
        return BASErrnoToOSStatus(EBADMSG);
    }
    return noErr;
}

// Get a mandatory string from request and turn it into CString
static OSStatus getStringArg(CFDictionaryRef request,
                        CFMutableDictionaryRef response,
                        CFStringRef argname,
                        const char* error,
                        char *result,
                        int len,
                        aslclient asl,
                        aslmsg aslMsg) {
    CFStringRef arg = NULL;
    OSStatus err;
    err = getArg(request, response, argname, error, (CFTypeRef*)&arg, &CFStringGetTypeID,
                 asl, aslMsg);
    if (err) return err;
    
    // Turn arg into a CString
    if (!CFStringGetCString(arg, result, len, kCFStringEncodingUTF8)) {
        return coreFoundationUnknownErr;
    }
    
    return noErr;
}

// Get a mandatory integer from request and turn it into an int
static OSStatus getIntegerArg(CFDictionaryRef request,
                         CFMutableDictionaryRef response,
                         CFStringRef argname,
                         const char* error,
                         int *result,
                         aslclient asl,
                         aslmsg aslMsg) {
    CFNumberRef arg = NULL;
    OSStatus err;
    err = getArg(request, response, argname, error, (CFTypeRef*)&arg, &CFNumberGetTypeID,
                 asl, aslMsg);
    if (err) return err;
    
    // Turn arg into an int
    if (!CFNumberGetValue(arg, kCFNumberIntType, result)) {
        return coreFoundationUnknownErr;
    }
    return noErr;
}

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
    int      iterations = 0; // Number of processes killed * 5 (we try to kill on 1 interaction out of 5)
    char *const command[] = { "lsof", "-Pan", "-i", "udp:500", "-Fp" };

    while (1) {
        if (iterations++ > 30) {
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
                if ((iterations % 5) == 1) {
                    err = asl_log(asl, aslMsg, ASL_LEVEL_INFO, "racoon PID is %d. Kill it and wait a bit", racoon);
                    assert(err == 0);
                    kill(racoon, SIGINT);
                }
                usleep(400000); // Let racoon die properly
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
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to delete old PID file: %m");
            assert(err == 0);
            return retval;
        }
    }
    // We also remove the logfile
    if (unlink(logPath) == -1) {
        if (errno != ENOENT) {
            retval = BASErrnoToOSStatus(errno);
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to remove old racoon log file: %m");
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
        break;
    }
    // racoon is started, we modify the owner of the logs to let the user read them.
    // We use the owner of the socket
    if (stat(socketPath, &statBuf) != -1) {
        chown(logPath, statBuf.st_uid, -1);
    }
    
    return noErr;
}

static OSStatus DoStartStopRacoon(AuthorizationRef auth,
                                  const void *userData,
                                  CFDictionaryRef request,
                                  CFMutableDictionaryRef response,
                                  aslclient asl,
                                  aslmsg aslMsg) {
    OSStatus retval = noErr;
    int err;
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
    err = getStringArg(request, response, CFSTR(kVpnooStartStopRacoonConfPath), 
                       "invalid value for configuration path",
                       tmpPath, sizeof(tmpPath), 
                       asl, aslMsg);
    if (err) {
        return err;
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
    err = getIntegerArg(request, response, CFSTR(kVpnooStartStopRacoonAction),
                        "invalid value for command",
                        &operation, asl, aslMsg);
    if (err) return err;

    // First, kill any running racoon
    retval = KillRacoon(asl, aslMsg);
    if (retval != noErr) {
        CFDictionaryAddValue(response, CFSTR(kVpnooErrorString),
                             CFSTR("unable to kill racoon"));
        return retval;
    }
    
    // Execute the wanted operation
    if (operation == kVpnooStartRacoon) {
        err = asl_log(asl, aslMsg, ASL_LEVEL_INFO, "will start racoon (path: `%s')",
                      tmpPath);
        assert(err == 0);
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
#pragma mark ***** Start racoonctl

// Process to start racoonctl and watch it.
// When the control pipe is closed, kill racoonctl and terminate.
static void WatchRacoonCtl(int tty,
                           int control,
                           const char *socketPath,
                           const char *login,
                           const char *vpn,
                           aslclient asl,
                           aslmsg aslMsg) {
    int err;
    char buf;
    pid_t racoonctl; // PID of racoonctl
    
    racoonctl = fork();
    switch (racoonctl) {
        case -1:
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to fork racoonctl: %m");
            _exit(127);
        case 0:
            // Let's start racoonctl !
            close(control);
            if (login_tty(tty) == -1) {
                err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to set login TTY: %m");
                _exit(127);
            }
            if (login) {
                execlp("racoonctl", "racoonctl", "-s", socketPath, "vc", "-u", login, vpn, NULL);
            } else {
                execlp("racoonctl", "racoonctl", "-s", socketPath, "vd", vpn, NULL);
            }
            _exit(127);
        default:
            close(tty);
            break;
    }
    // We should now wait for a signal to kill racoonctl. This signal
    // is the closing of our control pipe (we have the reading part).
    while (1) {
        err = read(control, &buf, 1);
        switch (err) {
            case -1:
                if (errno == EINTR) continue;
                // Otherwise, like EOF
                err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to get info from control pipe: %m");
            case 0:
                // EOF
                // Check if our child is still here (don't kill a random process)
                if (waitpid(racoonctl, NULL, WNOHANG) == -1) {
                    // Child is not here anymore?
                    if (errno == EINTR) continue;
                    // Well, job done
                }
                err = asl_log(asl, aslMsg, ASL_LEVEL_INFO, "killing racoonctl");
                kill(racoonctl, SIGKILL); // No need to be gentle
                _exit(0);
            default:
                // Someone sent us something, just ignore it
                break;
        }
    }
    _exit(0);
}

// Wait for password prompt and send the password
static OSStatus SendPassword(const char *password,
                             int tty,
                             aslclient asl,
                             aslmsg aslMsg) {
    OSStatus retval = noErr;
    fd_set fdset;
    struct timeval tv;
    int err;
    char buffer[256];
    char *p = buffer;
    int n = 0;
    
    // We wait for at most 1.5 seconds the password prompt
    FD_ZERO(&fdset);
    FD_SET(tty, &fdset);
    tv.tv_sec = 1;
    tv.tv_usec = 500000;
    *p = '\0';
    do {
        err = select(tty + 1, &fdset, NULL, NULL, &tv);
        if ((err == -1) && (errno == EINTR)) continue;
        if (err == -1) {
            retval = BASErrnoToOSStatus(errno);
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "error while waiting for password prompt: %m");
            assert(err == 0);
            return retval;
        }
        if (!FD_ISSET(tty, &fdset)) {
            // Timeout
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR,
                          "did not get the password prompt from racoonctl (got `%s')",
                          buffer);
            assert(err == 0);
            return BASErrnoToOSStatus(ETIME);
        }
        // We have some data to read
        do {
            err = read(tty, p, sizeof(buffer) - 1 - n);
            if ((err == -1) && (errno == EINTR)) continue;
        } while(0);
        if (err == -1) {
            retval = BASErrnoToOSStatus(errno);
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "error while reading password prompt: %m");
            assert(err == 0);
            return retval;
        }
        if (err == 0) {
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR,
                          "racoonctl did terminate without password prompt (got `%s')",
                          buffer);
            assert(err == 0);
            return BASErrnoToOSStatus(EBADMSG);
        }
        n += err;
        p += err;
        *p = '\0';
        // Did we get the password prompt?
        if ((n >= strlen("Password: ")) &&
            (!strcmp(p - strlen("Password: "), "Password: "))) {
            break;
        }
        // No password prompt, continue
    } while (1);

    // We need to send the password
    do {
        err = write(tty, password, strlen(password));
        if ((err == -1) && (errno == EINTR)) continue;
    } while (0);
    if (err != -1) {
        do {
            err = write(tty, "\n", 1);
            if ((err == -1) && (errno == EINTR)) continue;
        } while (0);
    }
    if (err == -1) {
        retval = BASErrnoToOSStatus(errno);
        err = asl_log(asl, aslMsg, ASL_LEVEL_ERR,
                      "error while sending password: %m");
        assert(err == 0);
        return retval;
    }
    return retval;
}

// Run racoonctl
static OSStatus StartRacoonCtl(const char *socketPath,
                               const char *login,
                               const char *password,
                               const char *vpn,
                               CFMutableDictionaryRef response,
                               aslclient asl,
                               aslmsg aslMsg) {
    OSStatus retval = noErr;
    int err;
    pid_t pid;
    int master = -1, slave = -1;    // PTY
    struct termios tty;             // PTY attributes
    int control[2] = {-1, -1};      // Control pipe
    CFMutableArrayRef desc = NULL;  // Array to contain PTY and control pipe
    CFNumberRef desc1 = NULL, desc2 = NULL;

    // Allocate PTY
    if (openpty(&master, &slave, NULL, NULL, NULL) == -1) {
        retval = BASErrnoToOSStatus(errno);
        err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to allocate PTY: %m");
        assert(err == 0);
        return retval;
    }
    if (tcgetattr(master, &tty) == -1) {
        retval = BASErrnoToOSStatus(errno);
        err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to get TTY attributes: %m");
        assert(err == 0);
        goto badracoonctl;
    }
    cfmakeraw(&tty);
    if (tcsetattr(master, TCSANOW, &tty) == -1) {
        retval = BASErrnoToOSStatus(errno);
        err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to set TTY attributes: %m");
        assert(err == 0);
        goto badracoonctl;
    }
    
    // Allocate control pipe that will be used to to interact with racoonctl
    if (pipe(control)) {
        retval = BASErrnoToOSStatus(errno);
        err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to get a control pipe: %m");
        assert(err == 0);
        goto badracoonctl;
    }
    
    // Pseudo daemon
    switch (pid = fork()) {
        case -1:
            retval = BASErrnoToOSStatus(errno);
            err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to fork raconctl: %m");
            assert(err == 0);
            goto badracoonctl;
            break;
        case 0:
            // In the child, we should fork again
            if ((setsid() == -1) ||
                (chdir("/") == -1)) {
                err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to setup env for racoonctl: %m");
                _exit(127);
            }
            close(master);
            switch (fork()) {
                case -1:
                    err = asl_log(asl, aslMsg, ASL_LEVEL_ERR, "unable to fork racoonctl: %m");
                    _exit(127);
                    break;
                case 0:
                    // In the child, we can do our work here
                    close(control[1]);
                    WatchRacoonCtl(slave, control[0], // watcher will read the control pipe
                                   socketPath, login, vpn,
                                   asl, aslMsg);
                    _exit(0);
                    break;
                default:
                    // In the parent. Let's continue. Nothing left to do.
                    _exit(0);
                    break;
            }
        default:
            // In the parent. Let's continue
            while ((err = waitpid(pid, NULL, 0)) == -1) {
                if (errno != EINTR) break;
            } // other children are taken care by init
            break;
    }
    // Close the remote ends to our pipes
    close(slave); slave = -1;
    close(control[0]); control[0] = -1;
    
    if (login) {
        // Our task is now to send the password
        err = asl_log(asl, aslMsg, ASL_LEVEL_INFO, "sending password to racoonctl");
        assert(err == 0);
        retval = SendPassword(password, master, asl, aslMsg);
        if (retval != noErr) goto badracoonctl;
    }
    
    // Transmit file descriptors as an array
    desc = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    if (desc == NULL) {
        retval = coreFoundationUnknownErr;
        goto badracoonctl;
    }
    desc1 = CFNumberCreate(NULL, kCFNumberIntType, &master);
    desc2 = CFNumberCreate(NULL, kCFNumberIntType, &control[1]);
    if ((desc1 == NULL) || (desc2 == NULL)) {
        retval = coreFoundationUnknownErr;
        goto badracoonctl;
    }
    CFArrayAppendValue(desc, desc1);
    CFArrayAppendValue(desc, desc2);
    master = -1; control[1] = -1; // We don't want to close them
    CFDictionaryAddValue(response, CFSTR(kBASDescriptorArrayKey), desc);
    CFRelease(desc); desc = NULL; // We don't want to close them
    
badracoonctl:
    if (master != -1) close(master);
    if (slave != -1) close(slave);
    if (control[0] != -1) close(control[0]);
    if (control[1] != -1) close(control[1]);
    if (desc1 != NULL) CFRelease(desc1);
    if (desc2 != NULL) CFRelease(desc2);
    if (desc != NULL) {
        BASCloseDescriptorArray(desc);
        CFRelease(desc);
    }
    return retval;
}

static OSStatus DoStartRacoonCtl(AuthorizationRef auth,
                                 const void *userData,
                                 CFDictionaryRef request,
                                 CFMutableDictionaryRef response,
                                 aslclient asl,
                                 aslmsg aslMsg) {
    OSStatus retval = noErr;
    int err;
    int operation;
    char socketPath[PATH_MAX];
    char login[128];
    char password[128];
    char vpn[16]; // XXX.XXX.XXX.XXX
    
    assert(auth != NULL);
    // userData may be NULL
    assert(request != NULL);
    assert(response != NULL);
    // asl may be NULL
    // aslMsg may be NULL
    
    // Get command
    err = getIntegerArg(request, response, CFSTR(kVpnooStartRacoonCtlAction),
                        "invalid value for command",  &operation,
                        asl, aslMsg);
    if (err) return err;
    
    // Get socket
    err = getStringArg(request, response, CFSTR(kVpnooStartRacoonCtlSocket),
                       "invalid value for socket path",
                       socketPath, sizeof(socketPath),
                       asl, aslMsg);
    if (err) return err;
    
    if (operation == kVpnooVpnConnect) {
        // Get login
        err = getStringArg(request, response, CFSTR(kVpnooStartRacoonCtlLogin),
                           "invalid value for login",
                           login, sizeof(login),
                           asl, aslMsg);
        if (err) return err;
        
        // Get password
        err = getStringArg(request, response, CFSTR(kVpnooStartRacoonCtlPassword),
                           "invalid value for password",
                           password, sizeof(password),
                           asl, aslMsg);
        if (err) return err;
    }
    
    err = getStringArg(request, response, CFSTR(kVpnooStartRacoonCtlVpn),
                       "invalid value for VPN IP",
                       vpn, sizeof(vpn),
                       asl, aslMsg);
    if (err) return err;
    
    if (operation == kVpnooVpnConnect) {
        err = asl_log(asl, aslMsg, ASL_LEVEL_INFO,
                      "initiate VPN connection (socket: `%s', login: `%s', vpn: `%s')",
                      socketPath, login, vpn);
        assert(err == 0);
        retval = StartRacoonCtl(socketPath,
                                login, password, vpn,
                                response,
                                asl, aslMsg);
    } else {
        err = asl_log(asl, aslMsg, ASL_LEVEL_INFO,
                      "terminate VPN connction (socket: `%s', vpn: `%s')",
                      socketPath, vpn);
        assert(err == 0);
        retval = StartRacoonCtl(socketPath, NULL, NULL, vpn,
                                response,
                                asl, aslMsg);
    }
    if (retval != noErr) {
        CFDictionaryAddValue(response, CFSTR(kVpnooErrorString),
                             CFSTR("unable to start racoonctl"));
        return retval;
    }
        
    return retval;
}


/////////////////////////////////////////////////////////////////
#pragma mark ***** Tool Infrastructure

static const BASCommandProc kVpnooCommandProcs[] = {
    DoGetHash,
    DoStartStopRacoon,
    DoStartRacoonCtl,
    NULL
};

int main(int argc, char **argv)
{
    return BASHelperToolMain(kVpnooCommandSet, kVpnooCommandProcs);
}
