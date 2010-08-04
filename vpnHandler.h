//
//  vpnHandler.h
//  vpnoo
//

#import <Cocoa/Cocoa.h>

// Here are external vpn states.
enum VpnState {
    VPNSTATE_DISCONNECTED = 1, // Initial state, the VPN is disconnected
    VPNSTATE_CONNECTING,       // Connection is in progress
    VPNSTATE_CONNECTED,        // We are connected
    VPNSTATE_DISCONNECTING     // We are disconnected
};

@interface vpnHandler : NSObject {
    int state; // Internal state
}

- (NSArray *)availableVpn;
- (void)connectTo:(NSString *)name withLogin: (NSString *)login andPassword: (NSString *)password;
- (void)disconnect;
- (enum VpnState)state; // External state

@end
