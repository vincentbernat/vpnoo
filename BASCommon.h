/*
 *  BASCommon.h
 *  vpnoo
 *
 */

#ifndef _BASCOMMON_H
#define _BASCOMMON_H

#include "BetterAuthorizationSampleLib.h"

// Most commands may include a descriptive error string
#define kVpnooErrorString "Error"

// "GetVersion" gets a hash of the helper tool. This never requires
// authorization. This is useful to know if the helper tool is up-to-date
#define kVpnooGetHashCommand "GetHash"
  // authorization right name (none)
  // request keys (none)
  // response keys
#  define kVpnooGetHashResponse  "Hash" // CFNumber

// "StartStopRacoon" starts or stops an instance of racoon.
#define kVpnooStartStopRacoonCommand "StartStopRacoon"
  // authorization right name
#  define kVpnooStartStopRacoonRightName "net.orangeportails.vpnoo.StartStopRacoon"
  // request keys
#  define kVpnooStartStopRacoonAction "Action" // CFNumber
#  define kVpnooStartRacoon 1
#  define kVpnooStopRacoon  2
#  define kVpnooStartStopRacoonConfPath "ConfPath" // CFString (path to configuration, pid, log, ...)
  // response keys (none)

extern const BASCommandSpec kVpnooCommandSet[];
extern unsigned int hashFile(const char *);

#endif
