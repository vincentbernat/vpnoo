//
//  vpnHandler.h
//  vpnoo
//

#import <Cocoa/Cocoa.h>


@interface vpnHandler : NSObject {
    BOOL connected;
    BOOL connecting;
}

- (NSArray *)availableVpn;
- (void)connectTo:(NSString *)name withLogin: (NSString *)login andPassword: (NSString *)password;
- (void)disconnect;
- (BOOL)isConnected;
- (BOOL)isConnecting;

@end
