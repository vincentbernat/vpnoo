//
//  vpnooController.m
//  vpnoo
//


#import "vpnooController.h"


@implementation vpnooController

// Enable/disable part of the interfaces depending on the state of various elements
- (void)handleInterfaceChange: (NSNotification *)notification {
    BOOL password = ([[passwordField stringValue] length] > 0);
    BOOL login = ([[loginField stringValue] length] > 0);
    BOOL busy = ([vpn isConnected] || [vpn isConnecting]);
    [loginField setEnabled: (!busy)];
    [passwordField setEnabled: (!busy)];
    [savePassword setEnabled: (password && !busy)];
    [vpnName setEnabled: (!busy)];
    [connectButton setEnabled: (password && login && !busy && [vpnName selectedItem])];
    [disconnectButton setEnabled: busy];
    if ([vpn isConnecting]) {
        [progressIndicator startAnimation: self];
    } else {
        [progressIndicator stopAnimation: self];
    }
}

// Receive information to update textual status of the VPN
- (void)handleVpnInformation: (NSNotification *)notification {
    [statusText setStringValue: (NSString *)[notification object]];
    [self handleInterfaceChange: nil];
    // Also save preferences if we are connected
    if ([vpn isConnected]) {
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
    [self handleInterfaceChange: nil];
}

@end
