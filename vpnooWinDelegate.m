//
//  vpnooWinDelegate.m
//  vpnoo
//

#import "vpnooWinDelegate.h"


@implementation vpnooWinDelegate

// Tell if the window can be closed or not
- (BOOL)windowShouldClose:(id)sender {
    NSInteger status;
    if ([vpn state] != VPNSTATE_DISCONNECTED) {
        status = NSRunInformationalAlertPanel(@"VPN is still active",
                                              @"The VPN is still active. Closing the application will disconnect it.",
                                              @"Don't close", @"Disconnect and close", nil);
        if (status == NSAlertDefaultReturn) {
            return NO;
        }
        [controller closeOnDisconnect];
        [vpn disconnect];
        return NO; // We should close once the disconnection is effective
    }
    return YES;
}

@end
