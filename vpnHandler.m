//
//  vpnHandler.m
//  vpnoo
//

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>

#import "vpnHandler.h"
#import "utils.h"

#include "BetterAuthorizationSampleLib.h"
#include "BASCommon.h"

extern AuthorizationRef gAuth;

void VPNLog(NSString *detail) {
    NSNotificationCenter *dc = [NSNotificationCenter defaultCenter];
    [dc postNotificationName: @"vpnInfo"
                      object: detail];
}

@implementation vpnHandler

#pragma mark *** VPN list

- (NSDictionary *)vpnList {
    NSString *plist = [[NSBundle mainBundle] pathForResource: @"vpn" ofType: @"plist"];
    return [NSDictionary dictionaryWithContentsOfFile: plist];
}

// Return a list of available VPN to connect to
- (NSArray *)availableVpn {
    // First, get the list of available VPN
    NSDictionary *plistData;
    plistData = [self vpnList];
    if (!plistData || ([plistData count] == 0)) {
        NSLog(@"no list of VPN found in resources");
        VPNLog(@"No list of VPN found.");
        return nil;
    }
    // Then return the names as an array
    return [plistData allKeys];
}

#pragma mark **** Template building

// Return the IP of a VPN from its name
- (NSString *)vpnIpFrom: (NSString *)name {
    return (NSString *)[[self vpnList] valueForKey: name];
}

// Build racoon.conf template
- (BOOL)buildTemplateFor:(NSString *)name withLogin: (NSString *)login andPassword: (NSString *)password {
    NSError *error = nil;
    NSString *keyword = nil;
    NSDictionary *keywords = [NSDictionary dictionaryWithObjectsAndKeys:
                                [[NSBundle mainBundle] resourcePath], @"RESOURCEPATH",
                                [utils getWorkPath], @"WORKPATH",
                                NSUserName(), @"USER",
                                name, @"NAME",
                                login, @"LOGIN",
                                [self vpnIpFrom: name], @"IP",
                              nil];
    NSEnumerator *keywordsEnum = [keywords keyEnumerator];
    // Grab template content
    NSString *template = [[NSBundle mainBundle] pathForResource: @"racoon" ofType: @"conf"];
    NSString *tc = [NSString stringWithContentsOfFile: template
                                             encoding: NSUTF8StringEncoding
                                                error: &error];
    if (error) {
        NSLog(@"unable to open racoon template `racoon.conf': %@", error);
        VPNLog(@"Unable to prepare configuration. See logs for more details.");
        return NO;
    }
    // Make substitutions
    while ((keyword = (NSString *)[keywordsEnum nextObject])) {
        tc = [tc stringByReplacingOccurrencesOfString: [NSString stringWithFormat: @"%%%%%@%%%%", keyword]
                                           withString: [keywords valueForKey: keyword]];
    }
    [tc writeToFile: [[utils getWorkPath] stringByAppendingPathComponent: @"racoon.conf"]
         atomically: YES
           encoding: NSUTF8StringEncoding
              error: &error];
    if (error) {
        NSLog(@"unable to write racoon template: %@", error);
        VPNLog(@"Unable to prepare configuration. See logs for more details.");
        return NO;
    }
    return YES;
}

#pragma mark **** Dynamic store

// Callbacks when a key has changed
- (void)maybeDisconnected {
    if (state != VPNSTATE_CONNECTED) {
        return;
    }
    // We need to check if our key is still here
    CFPropertyListRef value = SCDynamicStoreCopyValue(dynamicStore,
                                                      (CFStringRef)[NSString stringWithFormat: @"State:/Network/Service/%@",
                                                                    [[NSBundle mainBundle] bundleIdentifier]]);
    if (!value) {
        // The key does not exist anymore
        [self disconnectWithError: @"The connection has been unexpectedly terminated. See logs for more details."];
        return;
    }
    CFRelease(value);
}

static void scCallback(SCDynamicStoreRef store, CFArrayRef changedKeys, void *info) {
    [(vpnHandler *)info maybeDisconnected];
}

#pragma mark **** Helper

// Issue an helper request and return the dictionary if it was successful
- (NSDictionary *)helperRequest: (NSDictionary *)request {
    NSString        *bundleId;
    CFDictionaryRef response = NULL;
    int             alertResult;
    BASFailCode     failCode;
    NSString        *error;
    OSStatus        err;
    
    assert(request != NULL);
    bundleId = [[NSBundle mainBundle] bundleIdentifier];
    assert(bundleId != NULL);

    // Execute the request
    err = BASExecuteRequestInHelperTool(gAuth, kVpnooCommandSet,
                                        (CFStringRef) bundleId, 
                                        (CFDictionaryRef) request, &response);
    if (err == noErr) {
        // No IPC error
        err = BASGetErrorFromResponse(response);
        if (err == noErr) {
            NSLog(@"helper operation successful");
            return [(NSDictionary *)response autorelease];
        }
        error = [(NSDictionary *)response objectForKey: @kVpnooErrorString];
        if (error) {
            NSLog(@"helper was unsuccesful: %@", error);
        } else {
            NSLog(@"helper was unsuccesful: error code %d", err);
        }
        CFRelease(response);
        return NULL;
    }
    if (response != NULL) {
        CFRelease(response);
    }
    failCode = BASDiagnoseFailure(gAuth, (CFStringRef)bundleId);
    switch (failCode) {
        case kBASFailDisabled:
            alertResult = NSRunInformationalAlertPanel(
                @"Helper tool disabled",
                @"The helper tool needed to execute priviledged operations seems to have been disabled.",
                @"Repair the helper tool", @"Do nothing", NULL);
            break;
        case kBASFailPartiallyInstalled:
            alertResult = NSRunInformationalAlertPanel(
                @"Helper tool partially installed",
                @"The helper tool needed to execute priviledged operations seems to have been partially installed.",
                @"Reinstall the helper tool", @"Do nothing", NULL);
            break;
        case kBASFailNotInstalled:
            alertResult = NSRunInformationalAlertPanel(
                @"Helper tool needed",
                @"An helper tool is needed to execute priviledged operations.",
                @"Install the helper tool", @"Do nothing", NULL);
            break;
        default:
            alertResult = NSRunInformationalAlertPanel(
                @"Helper tool failed",
                @"The helper tool needed to execute priviledged operations did not succeed. Please, look at the logs to find possible causes.",
                @"Do nothing", @"Reinstall the helper tool", NULL);
            if (alertResult == NSAlertDefaultReturn) {
                alertResult = NSAlertAlternateReturn;
            } else if (alertResult == NSAlertAlternateReturn) {
                alertResult = NSAlertDefaultReturn;
            }
            break;
    }
    if (alertResult != NSAlertDefaultReturn) {
        return NULL;
    }
    err = BASFixFailure(gAuth,
                        (CFStringRef)bundleId,
                        CFSTR("InstallTool"),
                        CFSTR("HelperTool"),
                        failCode);
    if (err == noErr) {
        return [self helperRequest: request];
    }
    return NULL;
}

// Check that the helper is here and up-to-date
- (BOOL)checkHelper {
    NSDictionary *response;
    NSDictionary *request;
    NSString     *toolpath;
    OSStatus      err;
    int hash;
    int rhash;
    int alertresult;
    
    request = [NSDictionary dictionaryWithObjectsAndKeys:
               @kVpnooGetHashCommand, @kBASCommandKey,
               nil];
    response = [self helperRequest: request];
    if (response == NULL) {
        return NO;
    }
    
    // We need to compute the checksum of our own helper tool
    toolpath = [[NSBundle mainBundle] pathForAuxiliaryExecutable: @"HelperTool"];
    hash = hashFile([toolpath fileSystemRepresentation]);
    if (hash == 0) {
        NSLog(@"unable to compute hash for included helper tool");
        return NO;
    }
    rhash = [(NSNumber *)[response objectForKey: @kVpnooGetHashResponse] intValue];
    NSLog(@"installed helper tool hash: %x ; current helper tool hash: %x",
          rhash, hash);
    if (hash == rhash) {
        return YES;
    }
    alertresult = NSRunInformationalAlertPanel(
            @"Helper tool needs to be updated",
            @"The helper tool needed to execute priviledged operations needs to be updated.",
            @"Update", @"Do nothing", NULL);
    if (alertresult != NSAlertDefaultReturn) {
        NSLog(@"helper tool is not up-to-date");
        return NO;
    }
    err = BASFixFailure(gAuth,
                        (CFStringRef)[[NSBundle mainBundle] bundleIdentifier],
                        CFSTR("InstallTool"),
                        CFSTR("HelperTool"),
                        kBASFailNeedsUpdate);
    if (err == noErr) {
        return [self checkHelper];
    }
    return NO;
}

// Handle racoon Start/Stop (through the helper)
- (BOOL)handleRacoonFor: (NSNumber*) operation {
    NSDictionary *response;
    NSDictionary *request;

    if (![self checkHelper]) {
        return NO;
    }
    request = [NSDictionary dictionaryWithObjectsAndKeys:
                    @kVpnooStartStopRacoonCommand, @kBASCommandKey,
                    operation, @kVpnooStartStopRacoonAction,
                    [utils getWorkPath], @kVpnooStartStopRacoonConfPath,
                    nil];
    response = [self helperRequest: request];
    return (response != NULL);
}

#pragma mark **** Connection

// Kill racoonctl
- (void)killRacoonctl {
    // Let racoonctl die
    if (racoonctlOutput) {
        [racoonctlOutput closeFile];
        [racoonctlOutput release];
        racoonctlOutput = nil;
    }
    if (racoonctlControl) {
        [racoonctlControl closeFile];
        [racoonctlControl release];
        racoonctlControl = nil;
    }
    if (racoonctlTimeout) {
        [racoonctlTimeout invalidate];
        [racoonctlTimeout release];
        racoonctlTimeout = nil;
    }
    if (racoonctlBuffer) {
        [racoonctlBuffer release];
        racoonctlBuffer = nil;
    }
}

// Extract from data recorded by racoonctl the line whose suffix is match
// The suffix is removed from the result
- (NSString*)extractDataBeginningWith: (NSString*)match {
    NSEnumerator *lines;
    NSString *line;
    if (!racoonctlBuffer) {
        return nil;
    }
    lines = [[racoonctlBuffer componentsSeparatedByCharactersInSet: [NSCharacterSet newlineCharacterSet]]
             objectEnumerator];
    while (line = [lines nextObject]) {
        if ([line hasPrefix: match]) {
            return [line substringFromIndex: [match length]];
        }
    }
    // No match
    return nil;
}

// We have received some data from racoonctl
- (void)gotDataFromRacoonctl: (NSNotification *)notification {
    NSDictionary *dic = [notification userInfo];
    NSData *data = [dic objectForKey: NSFileHandleNotificationDataItem];
    NSString *string;
    if (state != VPNSTATE_CONNECTING) {
        return;
    }
    // We buffer data received
    if ([data length] == 0) {
        // Let's check our buffer data to know if this is a success or not. We search for "Bound to address"
        NSLog(@"available data from racoonctl:\n%@", racoonctlBuffer);
        NSString *ip = [self extractDataBeginningWith: @"Bound to address "];
        if (!ip) {
            // We got an error, let's try to find which
            NSString *error = [self extractDataBeginningWith: @"Error: "];
            if (!error) {
                [self disconnectWithError: @"An error occurred while connecting. See logs for more details."];
                return;
            }
            NSDictionary *reasons = [NSDictionary dictionaryWithObjectsAndKeys:
                                     @"Your credentials are incorrect or you don't have right to connect to this system.",
                                     @"Xauth exchange failed",
                                     @"The first phase has failed. This may be a certificate problem.",
                                     @"Peer failed phase 1 authentication (certificate problem?)",
                                     @"The remote end did not agree with the security parameters.",
                                     @"Peer failed phase 1 initiation (proposal problem?)",
                                     @"The remote end did not answer our sollicitations.",
                                     @"Peer not responsing",
                                     nil];
            NSString *reason = [reasons objectForKey: error];
            if (reason) {
                [self disconnectWithError: [NSString stringWithFormat: @"Unable to connect to the VPN. %@", reason]];
                return;
            }
            [self disconnectWithError:
             [NSString stringWithFormat: @"Unable to connect to the VPN. We got this error: %@", error]];
            return;
        }
        state = VPNSTATE_CONNECTED;
        NSLog(@"vpn connected with IP %@", ip);
        VPNLog([NSString stringWithFormat: @"Connected with IP %@.", ip]);
        // racoonctl died
        [self killRacoonctl];
        return;
    }
    // Try to convert to an NSString
    string = [[NSString alloc] initWithData: data encoding: NSUTF8StringEncoding];
    if (string == nil) {
        string = [[NSString alloc] initWithData: data encoding: NSASCIIStringEncoding];
    }
    if (string == nil) {
        string = [[NSString alloc] initWithData: data encoding: NSISOLatin1StringEncoding];
    }
    if (string == nil) {
        NSLog(@"Received the following undecodable data from racoonctl:\n%@", data);
    } else {
        [string autorelease];
        [racoonctlBuffer appendString: string];
    }
    // Reschedule data
    [[notification object] readInBackgroundAndNotify];
}

// Got a timeout from VPN
- (void)vpnTimeout: (NSTimer *)timer {
    if (state != VPNSTATE_CONNECTING) {
        return;
    }
    NSLog(@"got a timeout while connecting. Disconnecting");
    NSLog(@"available data from racoonctl:\n%@", racoonctlBuffer);
    [self killRacoonctl];
    [self disconnectWithError: @"Connection timeout. See logs for more details."];
}

// Initiate the VPN with racoonctl
// vpn is an array [name, login, password]
- (void)startVpnFor: (NSTimer *)timer {
    NSDictionary *response;
    NSDictionary *request;
    NSArray *vpn;
    NSArray *descs;
    int desc;
    
    if (state != VPNSTATE_CONNECTING) {
        return;
    }
    vpn = [timer userInfo];
    request = [NSDictionary dictionaryWithObjectsAndKeys:
               @kVpnooStartRacoonCtlCommand, @kBASCommandKey,
               [NSNumber numberWithInt: kVpnooVpnConnect], @kVpnooStartRacoonCtlAction,
               [self vpnIpFrom: [vpn objectAtIndex: 0]], @kVpnooStartRacoonCtlVpn,
               [vpn objectAtIndex: 1], @kVpnooStartRacoonCtlLogin,
               [vpn objectAtIndex: 2], @kVpnooStartRacoonCtlPassword,
               [[utils getWorkPath] stringByAppendingPathComponent: @"racoon.sock"], @kVpnooStartRacoonCtlSocket,
               nil];
    response = [self helperRequest: request];
    if (response == NULL) {
        [self disconnectWithError: @"Unable to request VPN creation. See logs for more details."];
        return;
    }
    
    // We need to retrive the file descriptors "master" and "control"
    descs = [response objectForKey: @kBASDescriptorArrayKey];
    desc = [(NSNumber*) [descs objectAtIndex: 0] intValue];
    racoonctlOutput = [[NSFileHandle alloc] initWithFileDescriptor: desc];
    desc = [(NSNumber*) [descs objectAtIndex: 1] intValue];
    racoonctlControl = [[NSFileHandle alloc] initWithFileDescriptor: desc];
    
    // Watch racoonctl output
    racoonctlBuffer = [[NSMutableString alloc] initWithCapacity: 1024];
    [racoonctlOutput readInBackgroundAndNotify];
    // And add a timer if it takes too long
    racoonctlTimeout = [[NSTimer scheduledTimerWithTimeInterval: 10
                                                         target: self
                                                       selector: @selector(vpnTimeout:)
                                                       userInfo: nil
                                                        repeats: NO] retain];

}

// Start racoon and schedule the next steps
// vpn is an array [name, login, password]
- (void)startRacoonFor: (NSTimer *)timer {
    if (state != VPNSTATE_CONNECTING) {
        return;
    }
    if (![self handleRacoonFor: [NSNumber numberWithInt: kVpnooStartRacoon]]) {
        state = VPNSTATE_DISCONNECTED;
        VPNLog(@"Unable to start racoon daemon. See logs for more details.");
        return;
    }
    
    VPNLog(@"Connecting to VPN...");
    // Use a timer to let the interface refresh
    [NSTimer scheduledTimerWithTimeInterval: 0.1
                                     target: self
                                   selector: @selector(startVpnFor:)
                                   userInfo: [timer userInfo]
                                    repeats: NO];
}

// Connect to a given VPN using the appropriate login and password
- (void)connectTo:(NSString *)name withLogin: (NSString *)login andPassword: (NSString *)password {
    if (state != VPNSTATE_DISCONNECTED) {
        return;
    }
    if (![self buildTemplateFor: name withLogin: login andPassword: password]) {
        return;
    }
    state = VPNSTATE_CONNECTING;
    NSLog(@"connecting to `%@' using login `%@'", name, login);
    VPNLog(@"Initializing VPN...");
    // Use a timer to let the interface refresh
    [NSTimer scheduledTimerWithTimeInterval: 0.1
                                     target: self
                                   selector: @selector(startRacoonFor:)
                                   userInfo: [NSArray arrayWithObjects: name, login, password, nil]
                                    repeats: NO];
}

#pragma mark **** Deconnection

- (void)stopRacoonFor: (NSTimer*)timer {
    if (state == VPNSTATE_DISCONNECTED) {
        return;
    }

    // We should terminate gracefully the VPN with racoonctl vpn-disconnect.
    // This is not really mandatory since stopping racoon also gracefully stops the VPN
    [self killRacoonctl]; // Maybe we are connecting
    if (![self handleRacoonFor: [NSNumber numberWithInt: kVpnooStopRacoon]]) {
        state = VPNSTATE_DISCONNECTED;
        if (![timer userInfo]) {
            VPNLog(@"Disconnected (but...)");
        } else {
            VPNLog([timer userInfo]);
        }
    } else {
        state = VPNSTATE_DISCONNECTED;
        if (![timer userInfo]) {
            VPNLog(@"Disconnected.");
        } else {
            VPNLog([timer userInfo]);
        }
    }
}

// Disconnect from the running VPN
- (void)disconnectWithError: (NSString*)error {
    if ((state != VPNSTATE_CONNECTING) && (state != VPNSTATE_CONNECTED)) {
        return;
    }
    state = VPNSTATE_DISCONNECTING;
    NSLog(@"disconnect from VPN");
    VPNLog(@"Disconnecting...");
    // Use a timer to let the interface refresh
    [NSTimer scheduledTimerWithTimeInterval: 0.1
                                     target: self
                                   selector: @selector(stopRacoonFor:)
                                   userInfo: error
                                    repeats: NO];
}

- (void)disconnect {
    [self disconnectWithError: nil];
}

// Return the current (external) state
- (enum VpnState)state {
    // state contains both external state and internal state.
    // External state = state % 100
    // Internal state = state DIV 100
    return state % 100;
}

- (id)init {
    self = [super init];
    if (self) {
        state = VPNSTATE_DISCONNECTED;
        // Interface with racoonctl
        racoonctlOutput = nil;
        racoonctlControl = nil;
        racoonctlTimeout = nil;
        racoonctlBuffer = nil;
        [[NSNotificationCenter defaultCenter] addObserver: self
                                                 selector: @selector(gotDataFromRacoonctl:)
                                                     name: NSFileHandleReadCompletionNotification
                                                   object: nil];
        // Interface with system configuration
        SCDynamicStoreContext context = {
            .version         = 0,
            .info            = self,
            .retain          = NULL,
            .release         = NULL,
            .copyDescription = NULL,
        };
        dynamicStore = SCDynamicStoreCreate(NULL,
                                            (CFStringRef)[[NSBundle mainBundle] bundleIdentifier],
                                            scCallback,
                                            &context);
        dynamicStoreRunLoop = SCDynamicStoreCreateRunLoopSource(NULL, dynamicStore, 0);
        CFRunLoopAddSource(CFRunLoopGetCurrent(),
                           dynamicStoreRunLoop,
                           kCFRunLoopCommonModes);
        SCDynamicStoreSetNotificationKeys(dynamicStore,
                                          (CFArrayRef)[NSArray arrayWithObject:
                                                       [NSString stringWithFormat: @"State:/Network/Service/%@",
                                                        [[NSBundle mainBundle] bundleIdentifier]]],
                                          NULL);
    }
    return self;
}

- (void)dealloc {
    CFRunLoopRemoveSource(CFRunLoopGetCurrent(), dynamicStoreRunLoop, kCFRunLoopCommonModes);
    CFRelease(dynamicStoreRunLoop);
    CFRelease(dynamicStore);
    [super dealloc];
}

@end
