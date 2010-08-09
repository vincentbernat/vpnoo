//
//  VpnooController.h
//  vpnoo
//

#import <Cocoa/Cocoa.h>
#import "vpnHandler.h"
#import "preferences.h"

@interface vpnooController : NSWindowController {
    IBOutlet NSTextField *loginField;
    IBOutlet NSTextField *passwordField;
    IBOutlet NSTextField *statusText;
    IBOutlet NSPopUpButton *vpnName;
    IBOutlet NSProgressIndicator *progressIndicator;
    IBOutlet NSButton *savePassword;
    IBOutlet NSButton *connectButton;
    IBOutlet NSButton *disconnectButton;
    IBOutlet NSButton *helpButton;
    IBOutlet NSWindow *logWindow;
    IBOutlet NSText *logView;
    IBOutlet vpnHandler *vpn;
    IBOutlet preferences *prefs;
    BOOL closeOnDisconnect;
    NSDate *startDate;
    NSString *failureLog;
}

- (IBAction)connect:(id)sender;
- (IBAction)disconnect:(id)sender;
- (IBAction)help:(id)sender;

- (void)closeOnDisconnect;

@end
