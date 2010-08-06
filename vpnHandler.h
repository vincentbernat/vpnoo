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
    // Communication with racoonctl
    NSFileHandle *racoonctlOutput;  // Output for racoonctl
    NSFileHandle *racoonctlControl; // Handle to close if racoonctl should be closed
    NSTimer *racoonctlTimeout;      // Timer to ensure that racoonctl is not too long
    NSMutableString *racoonctlBuffer; // Data received by racoonctl
}

- (NSArray *)availableVpn;
- (void)connectTo:(NSString *)name withLogin: (NSString *)login andPassword: (NSString *)password;
- (void)disconnect;
- (void)disconnectWithError: (NSString*) error;
- (enum VpnState)state; // External state

@end
