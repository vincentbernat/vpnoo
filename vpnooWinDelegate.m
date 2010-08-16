//
//  vpnooWinDelegate.m
//  vpnoo
//

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

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

// Drag'n'Drop
- (void)awakeFromNib {
    SSLeay_add_all_algorithms();
    ERR_load_crypto_strings();
    [window registerForDraggedTypes: [NSArray arrayWithObject: NSFilenamesPboardType]];
}

// Accept filenames
- (NSDragOperation)draggingEntered:(id <NSDraggingInfo>)sender {
    NSPasteboard *pboard;
    NSDragOperation sourceDragMask;
    
    sourceDragMask = [sender draggingSourceOperationMask];
    pboard = [sender draggingPasteboard];
    if ([[pboard types] containsObject: NSFilenamesPboardType] &&
        (sourceDragMask & NSDragOperationCopy)) {
        // We only accept one file
        if ([[pboard propertyListForType: NSFilenamesPboardType] count] == 1) {
            return NSDragOperationCopy;
        }
    }
    return NSDragOperationNone;
}

// Handle PKCS#12 file
- (void)handlePKCS12: (NSString*)file withPassword: (NSString *)password {
    NSString *error = nil;
    
    FILE *fp = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    PKCS12 *p12 = NULL;
    int i;
    
    const char *pass = [password UTF8String];
    NSAlert *alert = nil;
    NSSecureTextField *passwordField = nil;
    
    // Read PKCS12 file
    if (!(fp = fopen([file fileSystemRepresentation], "rb"))) {
        error = [NSString stringWithFormat: NSLocalizedString(@"We are unable to open %@.",
                                                              @"Unable to open certificate file"), file];
        goto endpkcs12;
    }
    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp); fp = NULL;
    if (!p12) {
        error = [NSString stringWithFormat: NSLocalizedString(@"Unable to parse certificate: %s. You need a PKCS#12 certificate.",
                                                              @"Unable to parse P12 certificate"),
                 ERR_reason_error_string(ERR_get_error())];
        goto endpkcs12;
    }
    if (!PKCS12_parse(p12, pass, &pkey, &cert, &ca)) {
        // Maybe we need a password?
        alert = [NSAlert alertWithMessageText: NSLocalizedString(@"Certificate is password portected",
                                                                 @"Title for dialog asking certificate password")
                                defaultButton: NSLocalizedString(@"OK", @"OK button")
                              alternateButton: NSLocalizedString(@"Cancel", @"Cancel button")
                                  otherButton: nil
                    informativeTextWithFormat: NSLocalizedString(@"This certificate is password protected. Please, provide the password:",
                                                                 @"Message for dialog asking certificate password")];
        passwordField = [[NSSecureTextField alloc] initWithFrame: NSMakeRect(0, 0, 200, 24)];
        [alert setAccessoryView: passwordField];
        [[alert window] performSelector: @selector(makeFirstResponder:)
                             withObject: passwordField
                             afterDelay: 0.0];
        [passwordField release];
        [alert beginSheetModalForWindow: window
                          modalDelegate: self
                         didEndSelector: @selector(gotPKCS12Password:returnCode:contextInfo:)
                            contextInfo: [file retain]];
        ca = NULL; // Memory leak, but there is no way to release it correctly
        goto endpkcs12;
    }
    PKCS12_free(p12); p12 = NULL;
    
    // Write the result to files
    if (!ca || !sk_num(ca) || !pkey || !cert) {
        error = NSLocalizedString(@"The certificate is incomplete and is missing certificate, private key or CA certificate.",
                                  @"Incomplete certificate");
        goto endpkcs12;
    }
#define PEM_w(path, call) do { \
    if (!(fp = fopen([[[[NSBundle mainBundle] resourcePath] \
                       stringByAppendingPathComponent: path] fileSystemRepresentation], "w"))) { \
        error = [NSString stringWithFormat: NSLocalizedString(@"Unable to write new certificate: %m.", \
                                                              @"Error message when unable to write certificate")]; \
        goto endpkcs12; \
    } \
    call; \
    fclose(fp); \
    } while(0)
    
    PEM_w(@"user.pem", PEM_write_X509(fp, cert));
    PEM_w(@"user.key",  PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL));
    PEM_w(@"cacert.pem", for (i = 0; i < sk_X509_num(ca); i++) PEM_write_X509(fp, sk_X509_value(ca, i)));
    fclose(fp); sk_free(ca); X509_free(cert); EVP_PKEY_free(pkey);
    
    // Let the user know
    NSRunInformationalAlertPanel(NSLocalizedString(@"New certificate installed",
                                                   @"Title for dialog when the certificate has been installed"),
                                 NSLocalizedString(@"The provided certificate was correctly installed and will be used from now on.",
                                                   @"Message for dialog when the certificate has been installed"),
                                 NSLocalizedString(@"OK", @"OK button"), nil, nil);
    return;
    
endpkcs12:
    if (error) {
        NSRunInformationalAlertPanel(NSLocalizedString(@"Unable to convert certificate",
                                                       @"Title for dialog when we are unable to convert P12 certificate"),
                                     error, NSLocalizedString(@"OK", @"OK button"), nil, nil);
    }
    if (ca) sk_free(ca);
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);
    if (p12) PKCS12_free(p12);
    if (fp) fclose(fp);
}

- (void)gotPKCS12Password: (NSAlert *)alert returnCode: (NSInteger)returnCode contextInfo: (void*)contextInfo {
    NSString *file = [(NSString *)contextInfo autorelease];
    NSSecureTextField *password = (NSSecureTextField *)[alert accessoryView];
    [password validateEditing];
    NSString *pass = [[[password stringValue] retain] autorelease];
    [[alert window] orderOut: nil];
    if ((returnCode != NSAlertDefaultReturn) && (returnCode != NSAlertFirstButtonReturn))  {
        return;
    }
    [self handlePKCS12: file withPassword: pass];
}
- (void)handlePKCS12:(NSTimer *)timer {
    [self handlePKCS12: [timer userInfo]
          withPassword: @""];
}

// Receive p12 file
- (BOOL)performDragOperation:(id <NSDraggingInfo>)sender {
    NSPasteboard *pboard = [sender draggingPasteboard];
    NSArray *files = [pboard propertyListForType: NSFilenamesPboardType];
    NSString *file = [files objectAtIndex: 0];
    
    [NSTimer scheduledTimerWithTimeInterval: 0.1
                                     target: self
                                   selector: @selector(handlePKCS12:)
                                   userInfo: file
                                    repeats: NO];

    return YES;
}

@end
