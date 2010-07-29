//
//  preferences.h
//  vpnoo
//

#import <Cocoa/Cocoa.h>


@interface preferences : NSObject {
    NSString *login;
    NSString *password;
    NSString *lastVpn;
    BOOL savePassword;
}

@property(retain) NSString *login;
@property(retain) NSString *password;
@property(retain) NSString *lastVpn;
@property BOOL savePassword;

- (void)save;

@end
