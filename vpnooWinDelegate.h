//
//  vpnooWinDelegate.h
//  vpnoo
//

#import <Cocoa/Cocoa.h>
#import "vpnHandler.h"
#import "vpnooController.h"

@interface vpnooWinDelegate : NSObject {
    IBOutlet vpnHandler *vpn;
    IBOutlet vpnooController *controller;
    IBOutlet NSWindow *window;
}

@end
