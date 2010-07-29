//
//  preferences.m
//  vpnoo
//

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>

#import "preferences.h"
#import "utils.h"

@implementation preferences

@synthesize login;
@synthesize lastVpn;
@synthesize savePassword;

// Get path to the preference file
- (NSString*)getPreferencePath {
    NSString *path = [utils getWorkPath];
    path = [path stringByAppendingPathComponent: @"preferences.plist"];
    return path;
}

// Save password in key chain
void savePasswordInKeychain(const char *service, const char *user, const char *password) {
    OSStatus status;
    UInt32 oldPasswordLen;
    void *oldPassword;
    SecKeychainItemRef itemRef = NULL;
    // Does the item already exists?
    status = SecKeychainFindGenericPassword(NULL,
                                            strlen(service), service,
                                            strlen(user), user,
                                            &oldPasswordLen, &oldPassword,
                                            &itemRef);
    if (status == errSecItemNotFound) {
        // Save in the keychain
        status = SecKeychainAddGenericPassword(NULL,
                                               strlen(service), service,
                                               strlen(user), user,
                                               strlen(password), password,
                                               NULL);
    } else if (status == noErr) {
        // Update the existing entry if the password changed
        if ((oldPasswordLen != strlen(password)) ||
            (memcmp(oldPassword, password, oldPasswordLen))) {
                status = SecKeychainItemModifyAttributesAndData(itemRef,
                                                                NULL,
                                                                strlen(password), password);
            }
        SecKeychainItemFreeContent(NULL, oldPassword);
        CFRelease(itemRef);
    }
    if (status != noErr) {
        CFStringRef error = SecCopyErrorMessageString(status, NULL);
        NSLog(@"unable to save password: %@", error);
        CFRelease(error);
    }
}

// Get password
NSString *getPasswordFromKeychain(const char *service, const char *user) {
    OSStatus status;
    UInt32 passwordLen;
    void *password;
    NSString *result;
    // Get the password from the keychain
    status = SecKeychainFindGenericPassword(NULL,
                                            strlen(service), service,
                                            strlen(user), user,
                                            &passwordLen, &password,
                                            NULL);
    if (status != noErr) {
        // User did not agree or the password was not in the keychain
        CFStringRef error = SecCopyErrorMessageString(status, NULL);
        NSLog(@"unable to get password: %@", error);
        CFRelease(error);
        return @"";
    }
    // Convert the result to NSString
    result = [[[NSString alloc] initWithBytes: password
                                       length: passwordLen
                                     encoding: NSUTF8StringEncoding] autorelease];
    SecKeychainItemFreeContent(nil, password);
    return result;
}

// Save preferences to disk
- (void)save {
    NSMutableDictionary *prefs;

    // Save non password data
    prefs = [[NSMutableDictionary alloc] init];
    [prefs setObject: login forKey: @"login"];
    [prefs setObject: lastVpn forKey: @"vpn"];
    [prefs setObject: [NSString stringWithFormat:@"%d", (NSInteger)savePassword]
              forKey: @"save"];
    [prefs writeToFile: [self getPreferencePath] atomically: YES];
    [prefs release];
    
    // Save password
    if ([login length] && [password length] && savePassword) {
        savePasswordInKeychain([[[NSBundle mainBundle] bundleIdentifier] UTF8String],
                               [login UTF8String],
                               [password UTF8String]);
    }
}

// Load preferences from disk
- (void)load {
    NSDictionary *prefs;

    prefs = [NSDictionary dictionaryWithContentsOfFile: [self getPreferencePath]];
    if (prefs) {
        [self setLogin: [prefs objectForKey: @"login"]];
        [self setLastVpn: [prefs objectForKey: @"vpn"]];
        [self setSavePassword: [[prefs objectForKey: @"save"] boolValue]];
    }
}

// Standard setter for password
- (void)setPassword:(NSString *) newPassword {
    [password autorelease];
    password = [newPassword retain];
}

// Password getter will use keychain if possible
- (NSString *)password {
    if (password) {
        return password;
    }
    // Password is not available, try to get it from the keychain
    if ([login length] && savePassword) {
        [self setPassword: getPasswordFromKeychain([[[NSBundle mainBundle] bundleIdentifier] UTF8String],
                                                   [login UTF8String])];
    }
    return password;
}
    
- (id)init {
    self = [super init];
    if (self) {
        login = @"";
        password = nil;
        lastVpn = nil;
        savePassword = NO;
        [self load];
    }
    return self;
}

- (void)dealloc {
    [login release];
    [password release];
    [lastVpn release];
    [super dealloc];
}

@end
