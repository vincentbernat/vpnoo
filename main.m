//
//  main.m
//  vpnoo
//

#import <Cocoa/Cocoa.h>
#include "BetterAuthorizationSampleLib.h"
#include "BASCommon.h"

AuthorizationRef gAuth;

int main(int argc, char *argv[])
{
    OSStatus junk;
    junk = AuthorizationCreate(NULL,
                               NULL,
                               kAuthorizationFlagDefaults,
                               &gAuth);
    assert(junk == noErr);
    assert(gAuth != NULL);
    BASSetDefaultRules(gAuth,
                       kVpnooCommandSet,
                       CFBundleGetIdentifier(CFBundleGetMainBundle()),
                       NULL);
    return NSApplicationMain(argc,  (const char **) argv);
}
