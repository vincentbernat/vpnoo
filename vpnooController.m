//
//  vpnooController.m
//  vpnoo
//

#include <asl.h>

#import "vpnooController.h"
#import "utils.h"


@implementation vpnooController

// Collect logs
- (void)collectLogsFrom: (NSDate *)start {
    NSMutableString *logs = [[[NSMutableString alloc] init] autorelease];
    NSString *sep = @"\n\n8<-------------------------------------\n";
    NSDate *stop = [NSDate date];
    [logs appendFormat: @"Start date: %@\nStop date: %@\n", start, stop];
    [logs appendFormat: @"Current message: %@\n", [statusText stringValue]];
    
    // Logs from racoon
    NSString *racoonPath = [[utils getWorkPath] stringByAppendingPathComponent: @"racoon.log"];
    NSDate *racoonMod = [[[NSFileManager defaultManager] attributesOfItemAtPath: racoonPath
                                                                          error: NULL] fileModificationDate];
    if (racoonMod && ([start compare: racoonMod] != NSOrderedDescending)) {
        [logs appendString: sep];
        [logs appendString: @"Logs from racoon.log:\n"];
        [logs appendString: [NSString stringWithContentsOfFile: racoonPath
                                                      encoding: NSUTF8StringEncoding
                                                         error: NULL]];
    } else {
        [logs appendString: @"No logs from racoon.\n"];
    }
    
    // Logs from ASL
    [logs appendString: sep];
    [logs appendString: @"Logs from system logs:\n"];
    aslclient client = NULL;
    aslmsg query = NULL;
    aslmsg message = NULL;
    aslresponse response = NULL;
    client = asl_open(NULL, [[[NSBundle mainBundle] bundleIdentifier] UTF8String], 0);
    if (!client) goto noasl;
    query = asl_new(ASL_TYPE_QUERY);
    if (!query) goto noasl;
    asl_set_query(query, ASL_KEY_SENDER, "vpnoo", ASL_QUERY_OP_EQUAL | ASL_QUERY_OP_SUFFIX);
    asl_set_query(query, ASL_KEY_TIME, [[NSString stringWithFormat: @"%.0f",
                                         [start timeIntervalSince1970]] UTF8String],
                  ASL_QUERY_OP_GREATER_EQUAL);
    asl_set_query(query, ASL_KEY_TIME, [[NSString stringWithFormat: @"%.0f",
                                         [stop timeIntervalSince1970]] UTF8String],
                  ASL_QUERY_OP_LESS_EQUAL);
    response = asl_search(client, query);
    if (!response) goto noasl;
    while ((message = aslresponse_next(response)) != NULL) {
        [logs appendFormat: @"%s\n",
         asl_get(message, ASL_KEY_MSG)];
    }

noasl:
    if (query) asl_free(query);
    if (response) aslresponse_free(response);
    if (message) asl_free(message);
    if (client) asl_close(client);

    if (failureLog) {
        [failureLog release];
    }
    failureLog = [[NSString alloc] initWithString: logs];
}

// Close interface
- (void)closeInterface: (NSTimer*)timer {
    [[NSApplication sharedApplication] terminate: self];
}

// Enable/disable part of the interfaces depending on the state of various elements
- (void)handleInterfaceChange: (id)nothing {
    BOOL password = ([[passwordField stringValue] length] > 0);
    BOOL login = ([[loginField stringValue] length] > 0);
    BOOL busy = ([vpn state] != VPNSTATE_DISCONNECTED);
    [loginField setEnabled: (!busy)];
    [passwordField setEnabled: (!busy)];
    [savePassword setEnabled: (password && !busy)];
    [vpnName setEnabled: (!busy)];
    [connectButton setEnabled: (password && login && !busy && [vpnName selectedItem])];
    [disconnectButton setEnabled: busy];
    if (([vpn state] == VPNSTATE_CONNECTING) || ([vpn state] == VPNSTATE_DISCONNECTING)) {
        [progressIndicator startAnimation: self];
    } else {
        [progressIndicator stopAnimation: self];
    }
    if (!busy && startDate) {
        [self collectLogsFrom: startDate];
        [startDate release];
        startDate = nil;
    }
    [helpButton setHidden: (failureLog == nil)];
    if (!busy && closeOnDisconnect) {
        [NSTimer scheduledTimerWithTimeInterval: 0.1
                                         target: self
                                       selector: @selector(closeInterface:)
                                       userInfo: nil
                                        repeats: NO];
    }
}

// Receive information to update textual status of the VPN
- (void)handleVpnInformation: (NSNotification *)notification {
    [statusText setStringValue: (NSString *)[notification object]];
    [self handleInterfaceChange: nil];
    // Also save preferences if we are connected
    if ([vpn state] == VPNSTATE_CONNECTED) {
        [prefs setLogin: [loginField stringValue]];
        [prefs setPassword: [passwordField stringValue]];
        [prefs setLastVpn: [[vpnName selectedItem] title]];
        [prefs setSavePassword: ([savePassword state] == NSOnState)];
        [prefs save];
    }
}

// User pushes "Connect" button.
- (IBAction)connect:(id)sender {
    // Connect to VPN
    startDate = [[NSDate date] retain];
    if (failureLog) {
        [failureLog release];
        failureLog = nil;
    }
    [vpn connectTo: [[vpnName selectedItem] title]
         withLogin:[loginField stringValue]
       andPassword:[passwordField stringValue] ];
}

// User pushes "Disconnect" button.
- (IBAction)disconnect:(id)sender {
    if (startDate) {
        [startDate release];
        startDate = nil;
    }
    [vpn disconnect];
}

// Ask to close the application as soon as the connection is terminated
- (void)closeOnDisconnect {
    closeOnDisconnect = YES;
}

- (IBAction)help:(id)sender {
    if (!failureLog) {
        return;
    }
    [logView setString: failureLog];
    [logView setFont: [NSFont userFixedPitchFontOfSize: 0]];
    [logView selectAll: self];
    [logWindow makeKeyAndOrderFront: self];
}

- (void)awakeFromNib {
    NSNotificationCenter *dc = [NSNotificationCenter defaultCenter];
    [dc addObserver: self
           selector: @selector(handleInterfaceChange:)
               name: NSControlTextDidChangeNotification
             object: loginField];
    [dc addObserver: self
           selector: @selector(handleInterfaceChange:)
               name: NSControlTextDidChangeNotification
             object: passwordField];
    [dc addObserver: self
           selector: @selector(handleVpnInformation:)
               name: @"vpnInfo"
             object: nil];
    startDate = nil;
    failureLog = nil;
    [loginField setStringValue: [prefs login]];
    [passwordField setStringValue: [prefs password]];
    [savePassword setState: ([prefs savePassword]?NSOnState:NSOffState)];
    [statusText setStringValue: @"Not connected."];
    [vpnName removeAllItems];
    [vpnName addItemsWithTitles: [vpn availableVpn]];
    [vpnName selectItemWithTitle: [prefs lastVpn]];
    [vpnName setTarget: self]; [vpnName setAction: @selector(handleInterfaceChange:)];
    [self handleInterfaceChange: nil];
    closeOnDisconnect = NO;
}

@end
