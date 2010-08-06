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

// "GetHash" gets a hash of the helper tool. This never requires
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

// "StartRacoonCtl" starts an instance of racoonctl.
// We get two descriptors file: 
//    1. the output of racoonctl
//    2. a control channel that will terminate racoonctl when closed
#define kVpnooStartRacoonCtlCommand "StartRacoonCtl"
  // authorization right name
#  define kVpnooStartRacoonCtlRightName "net.orangeportails.vpnoo.StartRacoonCtl"
  // request keys
#  define kVpnooStartRacoonCtlAction "Action" // CFNumber
#  define kVpnooVpnConnect 1
#  define kVpnooVpnDisconnect 2
#  define kVpnooStartRacoonCtlSocket "Socket" // CFString
#  define kVpnooStartRacoonCtlLogin "Login" // CFString
#  define kVpnooStartRacoonCtlPassword "Password" // CFString
#  define kVpnooStartRacoonCtlVpn "Vpn" // CFString
 // response keys (none)

extern const BASCommandSpec kVpnooCommandSet[];
extern unsigned int hashFile(const char *);

#endif
