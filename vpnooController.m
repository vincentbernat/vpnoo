//
//  vpnooController.m
//  vpnoo
//


#import "vpnooController.h"


@implementation vpnooController

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
    [vpn connectTo: [[vpnName selectedItem] title]
         withLogin:[loginField stringValue]
       andPassword:[passwordField stringValue] ];
}

// User pushes "Disconnect" button.
- (IBAction)disconnect:(id)sender {
    [vpn disconnect];
}

// Ask to close the application as soon as the connection is terminated
- (void)closeOnDisconnect {
    closeOnDisconnect = YES;
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
