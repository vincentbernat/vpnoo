//
//  vpnHandler.m
//  vpnoo
//

#import "vpnHandler.h"
#import "utils.h"

void VPNLog(NSString *detail) {
    NSNotificationCenter *dc = [NSNotificationCenter defaultCenter];
    [dc postNotificationName: @"vpnInfo"
                      object: detail];
}

@implementation vpnHandler

- (NSDictionary *)vpnList {
    NSString *plist = [[NSBundle mainBundle] pathForResource: @"vpn" ofType: @"plist"];
    return [NSDictionary dictionaryWithContentsOfFile: plist];
}

- (id)init {
    self = [super init];
    if (self) {
        connected = NO;
        connecting = NO;
    }
    return self;
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

// Fake method to tell that we connected successfully
- (void)connected:(NSTimer *)timer {
    if (!connecting || connected) {
        return;
    }
    connected = YES;
    connecting = NO;
    NSLog(@"vpn connected");
    VPNLog(@"Connected!");
}

// Connect to a given VPN using the appropriate login and password
- (void)connectTo:(NSString *)name withLogin: (NSString *)login andPassword: (NSString *)password {
    if (connected || connecting) {
        return;
    }
    connecting = YES;
    if (![self buildTemplateFor: name withLogin: login andPassword: password]) {
        return;
    }
    NSLog(@"connecting to `%@' using login `%@'", name, login);
    VPNLog(@"Connecting to VPN...");
    // We emulate a small wait instead of really connecting
    [NSTimer scheduledTimerWithTimeInterval: 1.0
                                     target: self
                                   selector: @selector(connected:)
                                   userInfo: nil
                                    repeats: NO];
}

// Disconnect from the running VPN
- (void)disconnect {
    if (!connected && !connecting) {
        return;
    }
    connected = NO;
    connecting = NO;
    NSLog(@"disconnect from VPN");
    VPNLog(@"Disconnected.");
}

// Tell if we are currently connected
- (BOOL)isConnected {
    return connected;
}

// Tell if we are currently trying to connect
- (BOOL)isConnecting {
    return connecting;
}

@end
