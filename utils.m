//
//  utils.m
//  vpnoo
//

#import "utils.h"

@implementation utils

+(NSString *)getWorkPath {
    NSString *path;
    NSError *err;
    BOOL dir;
    // Get path to user application support directory
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                         NSUserDomainMask,
                                                         YES);
    if ([paths count] == 0) {
        return nil;
    }
    path = [paths objectAtIndex: 0];
    // Add "vpnoo" as the last component
    path = [path stringByAppendingPathComponent: [[NSBundle mainBundle]
                                                  bundleIdentifier]];
    // Create the directory if it does not exist
    if (![[NSFileManager defaultManager] fileExistsAtPath: path
                                              isDirectory: &dir]) {
        NSLog(@"create user directory `%@'", path);
        [[NSFileManager defaultManager] createDirectoryAtPath: path
                                  withIntermediateDirectories: YES
                                                   attributes: nil
                                                        error: &err];
    } else if (!dir) {
        // The file exists but is not a directory
        NSLog(@"`%@' already exists and is not a directory", path);
        return nil;
    }
    return path;
}

@end
