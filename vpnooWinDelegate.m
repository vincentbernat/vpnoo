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
        status = NSRunInformationalAlertPanel(
            NSLocalizedString(@"VPN is still active",
                              @"Dialog title when trying to close while VPN is connected"),
            NSLocalizedString(@"The VPN is still active. Closing the application will disconnect it.",
                              @"Dialog message when trying to close while VPN is connected"),
            NSLocalizedString(@"Don't close",
                              @"Button label to dismiss closing"),
            NSLocalizedString(@"Disconnect and close",
                              @"Button label to acknowledge closing"),
            nil);
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
