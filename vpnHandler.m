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

- (id)init {
    self = [super init];
    if (self) {
        state = VPNSTATE_DISCONNECTED;
    }
    return self;
}

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
                @"The helper tool needed to execute priviledged operations did not succeed.",
                @"Retry", @"Do nothing", @"Reinstall the helper tool", NULL);
            if (alertResult == NSAlertDefaultReturn) {
                return [self helperRequest: request];
            }
            if (alertResult == NSAlertOtherReturn) {
                alertResult = NSAlertDefaultReturn;
            }
            break;
    }
    if (alertResult != NSAlertDefaultReturn) {
        NSLog(@"installation of helper tool has been refused");
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
    hash = hashFile([toolpath cStringUsingEncoding: NSUTF8StringEncoding]);
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

// Initiate the VPN with racoonctl
// vpn is an array [name, login, password]
- (void)startVpnFor: (NSTimer *)timer {
    if (state != VPNSTATE_CONNECTING) {
        return;
    }
    state = VPNSTATE_CONNECTED;
    NSLog(@"vpn connected");
    VPNLog(@"Connected!");
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
    if (![self handleRacoonFor: [NSNumber numberWithInt: kVpnooStopRacoon]]) {
        state = VPNSTATE_DISCONNECTED;
        VPNLog(@"Disconnected (but...)");
    } else {
        state = VPNSTATE_DISCONNECTED;
        VPNLog(@"Disconnected.");
    }
}

// Disconnect from the running VPN
- (void)disconnect {
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
                                   userInfo: nil
                                    repeats: NO];
}

// Return the current (external) state
- (enum VpnState)state {
    // state contains both external state and internal state.
    // External state = state % 100
    // Internal state = state DIV 100
    return state % 100;
}

@end
