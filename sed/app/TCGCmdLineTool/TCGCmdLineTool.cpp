//=================================================================================================
//  TCGCmdLineTool.cpp
//  Demonstrates how TCG Enterprise and Opal SSC storage security features 
//  work on a Seagate enterprise or Opal security drive (Hurricane/Firefly 
//  SAS/FC, Julius SATA, eDrive) through the use of Segate TCG Library APIs.
//
//  \legal 
//   All software, source code, and any additional materials contained
//   herein (the "Software") are owned by Seagate Technology LLC and are 
//   protected by law and international treaties.  No rights to the 
//   Software, including any rights to distribute, reproduce, sell, or 
//   use the Software, are granted unless a license agreement has been 
//   mutually agreed to and executed between Seagate Technology LLC and 
//   an authorized licensee. 
//
//   The Software contains SEAGATE CONFIDENTIAL INFORMATION AND SEAGATE 
//   TRADE SECRET INFORMATION that must be protected as such.
//
//   Copyright © 2008-2012.  Seagate Technology LLC  All Rights Reserved.
//
//  The Software is provided under the Agreement No. 134849 between Seagate
//  Technology and Calsoft. All Intellectual Property rights to the Software,
//  as between Calsoft and Seagate, will be governed under the terms of the 
//  Agreement No. 134849; no other rights to the Software are granted.
//    
//=================================================================================================


#include <stdlib.h>

// Some helper functions that may be useful in more than one command-line app.
#include "tcg/Sample_HelperFunc_Wrappers/TCGDrive_Console.hpp"

#if !defined(_WIN32) // nvn20110728
// this is redefinition for gcc compiler
#define _stricmp(s1, s2) strcasecmp(s1, s2)
#define _strnicmp(s1, s2, n) strncasecmp(s1, s2, (n))
#define sprintf_s( a, b, c, d ) sprintf(a, c, d)
#define _strtoui64 strtoul
#define _atoi64 atol
#define _MAX_PATH 255
#endif

// Auto-updated version info file is updated by running bin\UpdateVersion.exe,
// which increments the Build number by default with no arguments. See usage
// info by running bin\UpdateVersion.exe with /? or /help for info on how to
// auto-update other fields. This file is also used to build a version resource
// for this exe.
#include "version.h"

// The following macro is used to create a "version string" from the 
// numeric data and thus avoid having to modify both data types when 
// incrementing version data.

#ifdef   VERSION_TOSTRING
 #undef  VERSION_TOSTRING
 #undef  VERSION_TOSTRING1
 #undef  VERSION_TOSTRING2
#endif
#define VERSION_TOSTRING2(maj, min, rev, bld) #maj "." #min "." #rev "." #bld
//#define VERSION_TOSTRING2(maj, min, c, d) #maj "." #min 
#define VERSION_TOSTRING1(a,b,c,d) VERSION_TOSTRING2(a,b,c,d)
#define VERSION_TOSTRING(a,b,c,d)  VERSION_TOSTRING1(a,b,c,d)

char* _version_ = VERSION_TOSTRING( VERSION_FILE_MAJOR, VERSION_FILE_MINOR, VERSION_FILE_REVISION, VERSION_FILE_BUILD);

#if (__linux__) // nvn
typedef tINT64 INT64;
typedef tUINT64 UINT64;
#endif

// Function prototypes
void  usage( char *exeName, char *taskName="Top", bool bExamples=true, bool bManPage=false );
void  isHelpRqst( char *exeName, int argc, char *argv[], bool bVerbose, bool bManPage=false );
char* getParameter( const char *tag, const int start, const int argc, char* argv[] );
char* extractParameter( char *tag, const bool getAll, int &argc, char* argv[] );
int   getNumberOfRequiredParameters( int argc, char* argv[], char *tag = "-" );
bool  parsePortSettingParameters( IOTable_PortLocking & state, int start, int argc, char* argv[] );
bool  printPortState( IOTable_PortLocking & state );

TCG_BANDNOs * parseParameterOfBandNumbers( char *parmString, TCG_BANDNOs *pSingleUserModeList );
UINT64VALs * parseParameterOfIntegers( char *parmString, UINT64VALs *pUIntegerArrary );


//=====================================================================
int main( int Argc, char* Argv[] )
{
   // Copy the Argv[] pointer vector into a local argv[] vector so 
   // options can be removed from the virtual command line args.

   int argc    = Argc;
   char **argv = new char*[argc];
   for( int ii = 0; ii < argc; ii++ )
      argv[ii] = Argv[ii];

   // Strip path stuff from "command name" string for better readibility

#if defined(_WIN32) // nvn20110728
   char exeName[_MAX_PATH] = {0}; // nvn20110907
   if( _splitpath_s(Argv[0], NULL, 0, NULL, 0, exeName, _MAX_PATH, NULL, 0) == 0 )
   {
      size_t len = strlen( exeName );
      _strupr_s( exeName );
      argv[0] = exeName;
   }
#else
   std::string tmpstr = basename( Argv[0] );
   if( tmpstr.length() > 0 && tmpstr.length() < _MAX_PATH )
      argv[0] = (char*)tmpstr.data();
      // memcpy(&exeName[0], tmpstr.c_str(), tmpstr.length());
#endif

   // Look for embedded options anywhere in the arg list,
   // and remove each one as it is found. Return the entire tag 
   // (getAll) rather than just the value following the tag.

   bool bNoLog    = extractParameter( (char*)"--NoLog", true, argc, argv ) != NULL;
   bool bVerbose  = extractParameter( (char*)"--Verbose", true, argc, argv ) != NULL;
   bool bQuiet    = extractParameter( (char*)"--Quiet", true, argc, argv ) != NULL;
   bool bUseSilo  = extractParameter( (char*)"--Silo", true, argc, argv ) != NULL;
   bool bManPage  = extractParameter( (char*)"--Man", true, argc, argv ) != NULL;

   // See if an 8-char drive serial number preceeded by "=" is specified, and
   // if found, return just the SN param without the leading "=" (getAll=false).

   std::wstring wSerNum( 8, TXT(' ') );    // SerNum is 8 chars.
   if( char *p = extractParameter( (char*)"=", false, argc, argv ) )
   {
      if( strlen( p ) > 8 )
         std::wcout << TXT("Specified Device Serial Number \"") << p << TXT("\" exceeds 8 chars and will be ignored.\n\n");
      else 
         // std::wcout << wSerNum << sizeof(wSerNum)/sizeof(wSerNum[0]) << __T("%S") << p;
         for( unsigned int i = 0; i < strlen(p); i++ )
            wSerNum[i] = p[i];
   }

   // Output App Header at top of screen unless --Quiet option is
   // specified, which is useful for batch file script execution.
   if( !bQuiet )
   {
      std::wcout << std::endl << TXT("Seagate TCG Command-Line Tool (Rev ") << _version_ 
                 << TXT(")     Seagate (C) 2009-2012") << std::endl;

      std::wcout << TXT("   FOR USE ONLY UNDER SEAGATE NDA - NOT FOR PUBLIC DISTRIBUTION!") 
                 << std::endl << std::endl;
   }

   // Under Vista/Win7/Win++, this app needs to run with administrative rights
   // in order to issue the IOCTL_PASSTHROUGH calls. If not run as admin, the
   // app will fail with 'no drives found', which is wrong. Here we test to
   // insure app is running with admin right, and if not, exit with an error.

   if( !IsAdmin() )
   {
      std::wcerr << TXT("This program requires Administrator rights to run properly.") << std::endl
                 << TXT("Invoke from a cmd window started with \"Run as Administrator\".") << std::endl
                 << std::endl;
      return 1;
   }

   // Determine whether to process the command line, or display some menu/usage info

   if( argc < 2 )             // If No args, display top-level usage with manpage if available
   {
      usage( argv[0], (char*)"Top", true, true );
      return 0;
   }

   // Parse the first argument into Cmnd vs Help

   if ( _stricmp( argv[1], "help" ) == 0 || _stricmp( argv[1], "?" ) == 0 ) 
   {
      if( argc == 2 )   // Only 'help' or '?' or ...
      {
         usage( argv[0], (char*)"Top", true, true );
      }
      else              // Help/? has at least 1 argument
      {
         usage( argv[0], argv[2], true, false );
      }
      return 0;
   } 
   else if ( _stricmp( argv[1], "man" ) == 0 || _stricmp( argv[1], "manpage" ) == 0 ) 
   {
      bManPage = true;

      if( argc == 2 )   // Only 'man' which doesn't make sense  ...
      {
         usage( argv[0], (char*)"Top", true, false );
      }
      else              // Man has at least 1 argument, so give detailed output
      {
         usage( argv[0], argv[2], true, true );
      }
      return 0;
   } 
   else if ( _strnicmp( argv[1], "ALL", strlen(argv[1]) ) == 0 ||
             _strnicmp( argv[1], "TCG", strlen(argv[1]) ) == 0 ||
             _strnicmp( argv[1], "OPAL", 3 ) == 0 ||
             _strnicmp( argv[1], "ENT", strlen(argv[1]) ) == 0 ||
             _strnicmp( argv[1], "SEA", strlen(argv[1]) ) == 0 ||
             _strnicmp( argv[1], "ATA", max(3, strlen(argv[1])) ) == 0 ) 
   {
      argv[1][3] = '\0';   // Force only first 3 chars to be significant

      usage( argv[0], argv[1], true, false );
      return 0;
   }


   // ========================= COMMAND PARSING ===========================

   // This is not a HELP request, query for a specific Drive S/N
   // and then Parse Command-line Args

   // Create an instance of the TCG_DRIVE_CONSOLE helper class
   // which provides the general implementation of features needed
   // by various console-style applications. If no drive matching
   // wSerNum, then a drive selection menu will prompt for drive.

#if (__linux__) // nvn
   std::string sSerNum( wSerNum.length(), ' ' );
   std::copy( wSerNum.begin(), wSerNum.end(), sSerNum.begin() );
   CTcgDrive device( ( bNoLog ? TXT("") : TXT("TCGProtocolLog.xml")),
                       ( bNoLog ? TXT("") : TXT("DeviceEnumerationLog.txt")),
                     sSerNum );
#else
   CTcgDrive device( ( bNoLog ? TXT("") : TXT("TCGProtocolLog.xml")),
                     ( bNoLog ? TXT("") : TXT("DeviceEnumerationLog.txt")),
                     _tstring( wSerNum) );
#endif
   {

#ifdef __TCGSILO
         if( bUseSilo )
            device.setUseSilo( true );
#endif //__TCGSILO // nvn20110728
   
#if 0  // Deprecated
      // If device was created successfully, look for obsolete environment variable
      if( device.tcgDriveExist() )
      {
         size_t requiredSize;
         char buf[8];
         getenv_s( &requiredSize, NULL, 0, "TCGCOMCHANNEL" );

         if( requiredSize > 0 )
         {
            getenv_s( &requiredSize, buf, 8, "TCGCOMCHANNEL" );
            int channel = atoi(buf);
            if( channel >= 0 ) // at least one static ComID pre-issued with any SSC, and 2 with Ent-SSC.
            {
               if( !device.selectComChannel( channel, (channel ? true : false) ) ) // switch to the 2nd channel from the default 1st.
                  return 2;
            }
            else if( -1 == channel )
               device.setPreferenceToUseDynamicComID( true );
            else
               std::wcout << TXT("Warning: ComID preference set with environment var \"TCGCOMCHANNEL\" is invalid and ignored.\n\n");
         }
      }
      else
      {
         std::wcout << TXT("Warning: Failed to instantiate TCG Drive Helper Class!\n\n");
         return 2;
      }
#endif // Deprecated

   } // if TCGDrive

   bool result;

   // Must be a command to process, so fall through list of commands.

   // ***************************************************************************
   // ********************** COMMANDS COMMON TO ALL  ****************************
   // ***************************************************************************
   // ShowDriveInfo, Read/Write User-area LBAs,


   // ======================== SD | ShowDrive[Info] ===========================

   if ( _stricmp( argv[1], "SD" ) == 0 ||
        _strnicmp( argv[1], "ShowDrive", sizeof("ShowDrive")-1 ) == 0 )
   {  // " SD | ShowDrive[*] [=<drive-serial-number>] "

      if( !bQuiet )
         std::wcout << TXT("Performing ShowDrive: ") << std::endl << std::endl;
      
      // Retrieve and display basic drive info that ATA or SCSI provide,
      // plus display the detailed IDENTIFY_DEVICE w/Seagate-specific info.
      if( !device.showBasicDriveInfo( true, true ) )
         return 1;   // Unexpected failure in basic discovery

      // Use Protocol-0 Discovery to identify supported TCG protocols,
      // including DriveTrust/SeaCOS drives with protocol 0xF0.
      if( !device.protocol0Discovery( true, true ) )
         return 0;   // Failure in protocol-0 discovery

      // If this drive supports SeaCOS protocol, then for now we don't handle it.   
      if( device.supportsSeaCOSprotocol() )
      {
         std::wcout << std::endl << TXT("SeaCOS DISCOVERY:") << std::endl;
         std::wcout << TXT("  SeaCOSFeatureSet   = [Not supported by this tool]")
                    << std::endl;
      }

      // If this drive supports TCG protocol, display discoverable info
      if ( device.supportsTCGprotocol() )
      {
         // Find TCG SSC security features
         if( !device.performTCGDiscovery( true, bVerbose ) )
            return 0;   // Return if TCG discovery fails

      } // if bTCGprotocol

      // If this drive supports IEEE1667 protocol
      if ( device.supportsIEEE1667protocol() )
      {
         std::wcout << std::endl << TXT("IEEE-1667 DISCOVERY:") << std::endl;


         // for now we don't handle it.   
         std::wcout << TXT("  IEEE1667FeatureSet = [Not yet supported by this tool]")
                    << std::endl;

      } // if IEEE1667 protocol

   } // ShowDriveInfo

   // ========================= RUL | ReadUserLBA ============================

   else if( _stricmp( argv[1], "RUL" ) == 0 ||
            _stricmp( argv[1], "RLBA" ) == 0 ||    // deprecated cmd
            _strnicmp( argv[1], "ReadUserLBA", sizeof("ReadUserLBA")-1 ) == 0 )
   {  
      // " RUL [--NoLog] <StartLBA#> <LengthLBA#> [<FileName>]" 

      if( !bQuiet ) std::wcout << TXT("Performing ReadUserLBA: ");

      if( argc < 4 )
      {
         std::wcerr << TXT(" *** Not enough parameters supplied.") << std::endl << std::endl;
         usage( argv[0], "RUL", true, bManPage );
         return 1;
      }

      tUINT64 startLBA = _atoi64( argv[2] );
      tUINT32 lengthLBA = atoi( argv[3] );
      if( lengthLBA > 128 || lengthLBA == 0 )
      {
         std::wcerr << TXT(" *** Parameter \"LengthLBA\" value \"") << lengthLBA << TXT("\" not valid. Max = 128.")
                    << std::endl << std::endl;
         usage( argv[0], (char*)"RUL", true, bManPage );
         return 1;
      }

      if( startLBA + lengthLBA > device.maxLBA() + 1 )
      {
         std::wcerr << TXT(" *** Parameter \"StartLBA\" or \"LengthLBA\" out of range.") << std::endl << std::endl;
         usage( argv[0], "RUL", true, bManPage );
         return 1;
      }

      char fileName[256] = "UserLba.rd";  // Default file if none specified, or if more than 4 LBAs
      if( argc > 4 )
         sprintf_s( fileName, sizeof(fileName), "%s", argv[4] );
      else if( lengthLBA <= 4 )   // Only output to console for up to 4 LBAs of data
         fileName[0] = '\0';  // if no filename specified or more than 4 LBAs attempted

      // TcgDevice device
      std::wcout << TXT("From LBA ") << startLBA << TXT(" for ") << lengthLBA << TXT(" LBAs.") << std::endl << std::endl;

      result = device.readUserLBA( fileName, startLBA, lengthLBA );
      if( result )
      {
         if( strlen( fileName ) > 0 )      
            std::wcout << TXT("Data was saved to file \"") << fileName << TXT("\".");
         std::wcout << std::endl;
      }
      else
      {
         std::wcout << TXT(" *** Failed to Read User LBA - perhaps sector(s) are locked?") << std::endl;
         return 3;
      }
   } // ReadLBA

   // ========================= WUL | WriteUserLBA ============================

   else if( _stricmp( argv[1], "WUL" ) == 0 ||
            _stricmp( argv[1], "WLBA" ) == 0 ||    // deprecated cmd
            _strnicmp( argv[1], "WriteUserLBA", sizeof("WriteUserLBA")-1 ) == 0 ) 
   {  // " WUL <StartLBA#> <NumberOfLBAs#> [<FileName>]"

      if( !bQuiet ) std::wcout << TXT("Performing WriteUserLBA: ");

      if( argc < 4 )
      {
         std::wcerr << TXT(" *** Not enough parameters supplied.")
                    << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      tUINT64 startLBA = _atoi64( argv[2] );
      tUINT32 lengthLBA = atoi( argv[3] );
      if( lengthLBA > 128 )
      {
         std::wcerr << TXT(" *** Parameter \"LengthLBA\" value \"") << lengthLBA << TXT("\" is too big. Max = 128.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      if( startLBA + lengthLBA > device.maxLBA() + 1 )
      {
         std::wcerr << TXT(" *** Parameter \"StartLBA\" or \"LengthLBA\" falls out of range.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }
      
      std::wcout << TXT("From LBA ") << startLBA << TXT(", length ") << lengthLBA;

      char fileName[256];
      if( argc > 4 )
      {
         sprintf_s( fileName, sizeof(fileName), "%s", argv[4] );
         std::wcout << TXT(" from file \"") << fileName << TXT("\".") << std::endl;
      }
      else
      {
         fileName[0] = '\0';
         std::wcout << TXT(", but no filename supplied. A constant value will be used.") << std::endl;
      }

#if(__linux__) // nvn
      std::string tmpS = device.getDriveSerialNo();
      std::wstring tmpWS( tmpS.length(), L' ' );
      std::copy( tmpS.begin(), tmpS.end(), tmpWS.begin() );
      std::wcout << TXT("\n WARNING: Data on selected drive \"") << tmpWS << TXT("\" WILL BE OVERWRITTEN.");
#else
      std::wcout << TXT("\n WARNING: Data on selected drive \"") << device.getDriveSerialNo() << TXT("\" WILL BE OVERWRITTEN.");
#endif
      // If running from a script, don't perform 
      if( !bQuiet )
      {
         std::wcout << TXT("\nIf the above parameters are correct, continue? (y/n)");
         char c; std::cin >> c;
         if( 'y' != c && 'Y' != c )
            return 1;
      }

      result = device.writeUserLBA( fileName, startLBA, lengthLBA );
      if( result )
      {
         std::wcout << std::endl << TXT("Data has been written to SED.") << std::endl
                    << std::endl;
      }
      else
      {
         std::wcout << std::endl << TXT("Failed to Write User LBA(s) - perhaps sector(s) are locked?") << std::endl
                    << std::endl;
         return 3;
      }
   } // WriteLBA



   // ***************************************************************************
   // **************************** TCG COMMAND GROUP ****************************
   // ***************************************************************************
   // RANGES:  ListRanges, SetRange, EraseRange,
   // TPER:    Enable/Disable Authority, ChangePIN, ResetStack,
   // MISC:    Read/Write DataStore, RanNumGen,
   //


   // ========================= LR | ListRanges ===========================

   else if( _stricmp( argv[1], "LB" ) == 0 ||   // deprecated but kept in cmd parser
            _stricmp( argv[1], "LR" ) == 0 ||
            _strnicmp( argv[1], "ListRanges", sizeof("ListRange")-1 ) == 0)
   {  // " LR[?] | ListRanges [[[-a- <Auth>] [-p- <Passwd>]] | -NoAuth]" 

      if( !bQuiet ) std::wcout << TXT("Performing ListRange: ");

      if( !device.isEnterpriseSSC() && device.isSPInactive( (char*)"Locking" ) )
      {
         std::wcout << TXT(" *** No Ranges found on drive.") << std::endl;
         std::wcerr << TXT(" *** Activate LockingSP first, then try command again.") << std::endl << std::endl;
         return 1;
      }

      int maxRanges;
      if( !device.getMaxBands( &maxRanges ) )
         return 3;

      // Collect Authority and Credential if provided on command line.
      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( "-p-", 2, argc, argv ) );

      // If no Authority provided for Enterprise drive, use default EraseMaster.
      if( device.isEnterpriseSSC() && NULL == authent.AuthorityName )
         authent.AuthorityName = (char*)"EraseMaster";

      // The Opal drives don't need authentication to read Authority table, but GET on Locking table
      // with meaninful returns (more than "UID"/"Name"/"CommonName", ie. "RangeStart", "RangeLength", etc)
      // needs "Admins" authentication.
      if( !device.isEnterpriseSSC() && NULL == authent.AuthorityName )
         authent.AuthorityName = (char*)"Admin1";

      // However, there may still be a reason for -NoAuth, which means don't use default 
      // EraseMaster Authority for Enterprise drivesj or Admin1 Authority for Opal drives.
      if( getParameter( (char*)"-NoAuth", 2, argc, argv ) != NULL ) // indicate no authentication will be done subsequently
         authent.AuthorityName = NULL;

      // Get Single User Mode info, if available
      dta::tBytes singleUserRanges( maxRanges +1 );
      int rangeStartLengthPolicy;

      if( !device.getSingleUserModeInfo( authent, singleUserRanges, rangeStartLengthPolicy ) )
      {
         std::wcout << std::endl << TXT(" *** Failed accessing locking table info.") << std::endl;
         std::wcerr << TXT("Try -NoAuth in command to prevent use of default (Admin1) Authority.") << std::endl << std::endl;
         return 3;
      }

      // List Range Info

      std::wcout << TXT("for Global Range (0) and ") << maxRanges << TXT(" configurable ranges.") << std::endl
                 << std::endl;

      std::wcout << TXT("_____ ") << (device.isSingleUserModeSupported() ? TXT("___ ") : TXT("")) << TXT("___ ___ __ __ _____ ____________ ____________ ____________________") << std::endl;
      std::wcout << TXT("Range ") << (device.isSingleUserModeSupported() ? TXT("SUM ") : TXT("")) << TXT("RLE WLE RL WL  LOR    Start LBA   Length LBAs      Common Name    ") << std::endl;
//    std::wcout << TXT("      ") << (device.isSingleUserModeSupported() ? TXT("ACL ") : TXT("")) << TXT("                                                                  ") << std::endl;
      std::wcout << TXT("_____ ") << (device.isSingleUserModeSupported() ? TXT("___ ") : TXT("")) << TXT("___ ___ __ __ _____ ____________ ____________ ____________________") << std::endl;

      TCGRANGE_INFO rangeInfo;
      for( int range=0; range < maxRanges+1; range++ )
      {
         std::wcout << setw(3) << range;

         // Read the LockingTable row for specified range to get Range Info from table.
         if( !device.getRangeInfo( range, rangeInfo, authent, (range ? false : true), (range == maxRanges ? true : false) ) )
         {
            std::wcerr << TXT("  *** Cannot Access Locking Table Info for this range ***") << std::endl;
            continue;   // Try next range
         }

         if( rangeInfo.rangeEnabled_isValid )
         {
            if( rangeInfo.rangeEnabled )
            {
               // For Julius Opal, one of the ranges can have this LockingTable column enabled.
               if( rangeInfo.lockingRange.AllowATAUnlock_isValid &&
                   rangeInfo.lockingRange.AllowATAUnlock )
                  std::wcout << TXT("*");
               else
                  std::wcout << TXT(" ");    // Range is Enabled/Active
            }
            else
            {
                  std::wcout << TXT("~");    // Range Authority is Disabled
            }
         }

         std::wcout << TXT("  ");   // Separation to next field

#if 0
         // Show Encryption Mode for each Range    (Deprecated 1.6.3.x)
         if( rangeInfo.lockingRange.ActiveKey_isValid )
         {
            if( UID_NULL != rangeInfo.lockingRange.ActiveKey )
            {
               if( rangeInfo.encryptionMode_isValid )
               {
                  if( (UID_K_AES_128_RANGE0 + range) == rangeInfo.lockingRange.ActiveKey || (UID_K_AES_128_RANGE1_OM + range -1) == rangeInfo.lockingRange.ActiveKey )
                     std::wcout << TXT("AES128-");
                  else if( (UID_K_AES_256_RANGE0 + range) == rangeInfo.lockingRange.ActiveKey || (UID_K_AES_256_RANGE1_OM + range -1) == rangeInfo.lockingRange.ActiveKey )
                     std::wcout << TXT("AES256-");
                  else
                     std::wcout << TXT("??????-"); // not recognized

                  switch( rangeInfo.encryptionMode )
                  {
                     case 0:
                        std::wcout << TXT("ECB"); break;
                     case 1:
                        std::wcout << TXT("CBC"); break;
                     case 2:
                        std::wcout << TXT("CFB"); break;
                     case 3:
                        std::wcout << TXT("OFB"); break;
                     case 4:
                        std::wcout << TXT("GCM"); break;
                     case 5:
                        std::wcout << TXT("CTR"); break;
                     case 6:
                        std::wcout << TXT("CCM"); break;
                     case 7:
                        std::wcout << TXT("XTS"); break;
                     case 8:
                        std::wcout << TXT("LRW"); break;
                     case 9:
                        std::wcout << TXT("EME"); break;
                     case 10:
                        std::wcout << TXT("CMC"); break;
                     case 11:
                        std::wcout << TXT("XEX"); break;
                     default:
                        std::wcout << rangeInfo.encryptionMode;
                        break; // nvn20111017
                  }
                  std::wcout << TXT(" ");
               }
               else
                  std::wcout << TXT(" NA        ");
            }
            else
            {
               std::wcout << TXT(" PlainText ");
            }
         }
         else
         {
            std::wcout << TXT(" NA        ");
         }
#endif // 0

         // If singleUserMode is supported on drive, show details from LockingInfo table.

         //   A - Single-user-mode Admin Policy
         //   U - Single-user-mode User Policy
         //   S - Single-user-mode Secret Credential
         //   N - Single-user-mode NULL Credential

         if( device.isSingleUserModeSupported() )
         {
            if( 1 == singleUserRanges[range] )
               std::wcout << TXT(" A");  // Single-User-Mode, Admin Policy
            else if( 0 == singleUserRanges[range] )
               std::wcout << TXT(" U");  // Single-User-Mode, User Policy
            else
               std::wcout << TXT("  "); 

            // See if NULL credential on the range by trying to authenticate with null string
            
            std::wcout << TXT("  ");   // Empty for now
         } // If single user mode


         // Read/Write Lock, Read/Write Lock Enabled
         if( rangeInfo.lockingRange.ReadLockEnabled_isValid )
            std::wcout << (rangeInfo.lockingRange.ReadLockEnabled ? TXT("  T ") : TXT("  F "));
         else
            std::wcout << TXT("  - ");

         if( rangeInfo.lockingRange.WriteLockEnabled_isValid )
            std::wcout << (rangeInfo.lockingRange.WriteLockEnabled ? TXT("  T ") : TXT("  F "));
         else
            std::wcout << TXT("  - ");

         if( rangeInfo.lockingRange.ReadLocked_isValid )
            std::wcout << (rangeInfo.lockingRange.ReadLocked ? TXT(" T ") : TXT(" F "));
         else
            std::wcout << TXT(" - ");

         if( rangeInfo.lockingRange.WriteLocked_isValid )
            std::wcout << (rangeInfo.lockingRange.WriteLocked ? TXT(" T ") : TXT(" F "));
         else
            std::wcout << TXT(" -");

         // Display Lock On Reset Status
         interpretResetType( rangeInfo.lockingRange.LockOnReset_length, &rangeInfo.lockingRange.LockOnReset[0] );

         // Display Range Start and Length LBAs
         if( rangeInfo.lockingRange.RangeStart_isValid )
            std::wcout << setw(11) << tUINT64(rangeInfo.lockingRange.RangeStart) << TXT("  ");
         else
            std::wcout << TXT("           - ");

         if( rangeInfo.lockingRange.RangeLength_isValid )
            if( range == 0 )
               std::wcout << setw(11) <<  tUINT64(device.maxLBA()) << TXT(" ");  // Global Range
            else
               std::wcout << setw(11) <<  tUINT64(rangeInfo.lockingRange.RangeLength) << TXT(" ");
         else
            std::wcout << TXT("           - " );

         // If there is a CommonName for the range, display it.
         if( rangeInfo.lockingRange.CommonName_length > 0 )
         {
            for( int ii=0; ii < rangeInfo.lockingRange.CommonName_length; ii++ )
            {
               std::wcout << TCHAR(rangeInfo.lockingRange.CommonName[ii]); 
            }
         }

         // End Of The Line
         std::wcout << std::endl;
      } // for each range

      // Add appropriate Legend descriptions to avoid a consult with the manual.

      std::wcout << std::endl << TXT("Range Configuration:                Lock On Reset:")
                 << std::endl << TXT("   * - Range AllowATAUnlock Enabled    [ ] - Empty List, All Resets Ignored")
                 << std::endl << TXT("   ~ - Range Authority is Disabled     [P] - Power-Cycle Locks Range")
                 << std::endl << TXT("   ? - Unknown Range State             [T] - TPerReset Locks Range")
                 << std::endl << TXT("   - - Unable to access data                                      ")
                 << std::endl;

      if( device.isSingleUserModeSupported() )
      {
         std::wcout << std::endl << TXT("Single User Mode (Fixed-ACL):")
                    << std::endl << TXT("   A - Admin Policy Mode                N - NULL Credential ")
                    << std::endl << TXT("   U - User Policy Mode                 S - Secret Credential");
      }

      std::wcout << std::endl;

   } // ListBandsInfo


   // ========================= SR | SetRange ============================

   else if( _strnicmp( argv[1], "SR", sizeof("SR")-1 ) == 0 || 
            _strnicmp( argv[1], "SetRange", sizeof("SetRange")-1 ) == 0 ||
            _strnicmp( argv[1], "SB", sizeof("SB")-1 ) == 0 )   // Deprecated but allowed
   {
      // " SR<#> | SetRange<#> [-start <LBA#>] [-len[gth] <LBA#>]"
      // " [-RLE  1|0] [-WLE 1|0] [-RL 1|0] [-WL 1|0]" 
      // " [-LOR  Off | Pwr | TpR | Any] [-name <CommonName>]" 
      // " [-a- <Auth>] [-p- <Passwd>]" 

      std::wcout << TXT("Performing SetRange: ");

      if( !device.isEnterpriseSSC() && device.isSPInactive( (char*)"Locking" ) )
      {
         std::wcout << TXT(" *** No Ranges Exist. Locking SP not Activated yet.")
                    << std::endl << std::endl;
         return 1;
      }

      // Determine target Range for command "SR<#> | SetRange<#>"
      int bandNo = 0;
      if( _strnicmp( argv[1], "SetRange", sizeof("SetRange")-1 ) == 0 )
      {
         bandNo = atoi( argv[1] + sizeof("SetRange") -1 );
      } 
      else if( _strnicmp( argv[1], "SR", sizeof("SR")-1 ) == 0 ||
               _strnicmp( argv[1], "SB", sizeof("SB")-1 ) == 0 )   // Deprecated but allowed
      {
         bandNo = atoi( argv[1] + sizeof("SR") -1 );
      }

      if( !device.isBandNoValid( bandNo ) )
      {
         std::wcout << TXT(" *** Range number ") << bandNo << TXT(" is invalid.")
                    << std::endl << std::endl;
         return 1;
      }

      // Parse command line for optional parameters specifying which Range value to update.
      // Add supplied value to Locking Table row and set value entry "is_valid" true.

      // Create storage for a row in a locking table, setting all valids FALSE.
      IOTableLocking row(false);

      // [-start <LBA#>]
      char* p = getParameter( (char*)"-start", 2, argc, argv );
      if( NULL != p )
      {
         if( bandNo == 0 )
         {
            std::wcout << TXT(" *** Cannot alter Global Range(0) Start LBA.")
                       << std::endl << std::endl;
            return 1;
         }

         row.RangeStart = _atoi64(p);
         row.RangeStart_isValid = true;

         // See if supplied value meets Geometry Alignment requirements, if any
         bool     bRequired = false;
         tINT64   alignment = 1;
         tINT64   lowestLBA = 0;
         int      blockSize = 512;

         if( device.getGeometryAlignment( bRequired, alignment, lowestLBA, blockSize ) )
         {
            if( bRequired && (row.RangeStart % alignment != 0) )
            {
               std::wcout << TXT(" *** BAND ALIGNMENT IS ENFORCED ON THIS DRIVE.") << std::endl;
               std::wcout << TXT("     Alignment granularity: ") << alignment << TXT(" LBAs, LowestAlignedLBA: ")
                          << lowestLBA << TXT(". BlockSize: ") << blockSize << TXT(" bytes.")
                          << std::endl 
                          << TXT("     Suggested Range Start: ") << INT64( row.RangeStart - (row.RangeStart % alignment) )
                          << std::endl << std::endl;
               return 1;
            }
         }
      }

      //  [-len[gth] <LBA#>]
      p = getParameter( (char*)"-len", 2, argc, argv );
      if( NULL == p )
         p = getParameter( (char*)"-length", 2, argc, argv );
      if( NULL != p )
      {
         if( bandNo == 0 )
         {
            std::wcout << TXT(" *** Cannot alter Global Range(0) LBA Length.")
                       << std::endl << std::endl;
            return 1;
         }

         row.RangeLength = _atoi64(p);
         row.RangeLength_isValid = true;

         bool     bRequired = false;
         tINT64   alignment = 1;
         tINT64   lowestLBA = 0;
         int      blockSize = 512;

         if( device.getGeometryAlignment( bRequired, alignment, lowestLBA, blockSize ) )
         {
            if( bRequired && (row.RangeLength % alignment != 0 ) )
            {
               std::wcout << TXT(" *** BAND ALIGNMENT IS ENFORCED ON THIS DRIVE.") << std::endl;
               std::wcout << TXT("     Alignment granularity: ") << alignment << TXT(" LBAs, LowestAlignedLBA: ")
                          << lowestLBA << TXT(". BlockSize: ") << blockSize << TXT(" bytes.")
                          << std::endl 
                          << TXT("     Suggested Range Length: ") << INT64( row.RangeLength - (row.RangeLength % alignment) )
                          << std::endl << std::endl;
               return 1;
            }
         }
      }

      // [-RLE  1|0] [-WLE 1|0] [-RL 1|0] [-WL 1|0]
      p = getParameter( (char*)"-RLE", 2, argc, argv );
      if( NULL != p )
      {
         row.ReadLockEnabled = ( atoi(p) ? true : false );
         row.ReadLockEnabled_isValid = true;
      }

      p = getParameter( (char*)"-WLE", 2, argc, argv );
      if( NULL != p )
      {
         row.WriteLockEnabled = ( atoi(p) ? true : false );
         row.WriteLockEnabled_isValid = true;
      }

      p = getParameter( (char*)"-RL", 2, argc, argv );
      if( NULL != p )
      {
         row.ReadLocked = ( atoi(p) ? true : false );
         row.ReadLocked_isValid = true;
      }

      p = getParameter( (char*)"-WL", 2, argc, argv );
      if( NULL != p )
      {
         row.WriteLocked = ( atoi(p) ? true : false );
         row.WriteLocked_isValid = true;
      }

      //  [-LOR  <Off|None> | Pwr | TpR | Any]
      //  [-LOR  <O|N|0> | P | T | A ]
      p = getParameter( (char*)"-LOR", 2, argc, argv );
      if( NULL != p )
      {
         if( _strnicmp( p, "Off", sizeof("O")-1 ) == 0 ||
             _strnicmp( p, "None", sizeof("N")-1 ) == 0 ||
             _stricmp( p, "0" ) == 0 || strlen(p) == 0 )
         {
            row.LockOnReset_length = 0; // Turn off Lock-on-Reset
         }
         else if( _strnicmp( p, "PWR", sizeof("P")-1 ) == 0 )
         {
            row.LockOnReset_length = 1;
            row.LockOnReset[0] = 0;  // Lock-on-Power-Reset
         }
         else if( _strnicmp( p, "TPR", sizeof("T")-1 ) == 0 )
         {
            row.LockOnReset_length = 1;
            row.LockOnReset[0] = 3;  // Programatic (TprReset)
         }
         else if( _strnicmp( p, "Any", sizeof("A")-1 ) == 0 )
         {
            row.LockOnReset_length = 2;
            row.LockOnReset[0] = 0;  // Lock-on-Power-Reset
            row.LockOnReset[1] = 3;  // Programatic (TprReset)
         }
         else
         {
            std::wcout << TXT(" *** -LOR parameter \"") << p << TXT("\" not recognized.")
                       << std::endl << std::endl;
            return 1;
         }
      }

      // [-name <CommonName>]
      p = getParameter( (char*)"-name", 2, argc, argv );
      if( NULL != p )
      {
         row.CommonName_length = (tINT8) strlen(p);
         if( row.CommonName_length >= sizeof(row.CommonName) )
         {
            std::wcerr << TXT(" *** -name truncated to ") << sizeof(row.CommonName)-1 << TXT(" byte maximim length.")
                       << std::endl << std::endl;
            row.CommonName_length = sizeof(row.CommonName)-1;
         }
         else if ( row.CommonName_length == 0 )    // Setting name to empty string
         {
            row.CommonName[row.CommonName_length] = 0;
            row.CommonName_length++;
         }

         memcpy( row.CommonName, p, row.CommonName_length );
         row.CommonName[row.CommonName_length] = 0;   // Insure string is null-terminated.
      }

      // Was at least one valid Range parameter found?ndNo
      if( row.isEmpty() )
      {
         std::wcerr << TXT(" *** At least one Range parameter must be supplied.")
                    << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      if( !bQuiet )
      {
         std::wcout << TXT("Updating Range using:") << std::endl;

         if( row.RangeStart_isValid )
            std::wcout << TXT("    RangeStart       = ") << row.RangeStart << std::endl;
         if( row.RangeLength_isValid )
            std::wcout << TXT("    RangeLength      = ") << row.RangeLength << std::endl;
         if( row.ReadLockEnabled_isValid )
            std::wcout << TXT("    ReadLockEnabled  = ") << row.ReadLockEnabled << std::endl;
         if( row.WriteLockEnabled_isValid )
            std::wcout << TXT("    WriteLockEnabled = ") << row.WriteLockEnabled << std::endl;
         if( row.ReadLocked_isValid )
            std::wcout << TXT("    ReadLocked       = ") << row.ReadLocked << std::endl;
         if( row.WriteLocked_isValid )
            std::wcout << TXT("    WriteLocked      = ") << row.WriteLocked << std::endl;
         if( row.LockOnReset_length >= 0 )
         {
            std::wcout << TXT("    LockOnReset      =");
            interpretResetType( row.LockOnReset_length, &row.LockOnReset[0] );
            std::wcout << std::endl;
         }
         if( row.CommonName_length > 0 )
            std::wcout << TXT("    CommonName       = ") << (char*)row.CommonName << std::endl;

      } // if !bQuiet

      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );

      result = device.setLockingRange( bandNo, row, authent );

      if( result )
         std::wcout << TXT("Range ") << bandNo << TXT(" has been set accordingly.") << std::endl;
      else
         return 3;

   } // SetRange


   // ========================= ER | EraseRange ============================

   else if( _strnicmp( argv[1], "ER", sizeof("ER")-1 ) == 0 ||
            _strnicmp( argv[1], "EraseRange", sizeof("EraseRange")-1 ) == 0 )
   {  
      // " ER[<#>[-<#>]]|[All] [-reset <1/0>] [-a- <Auth>] [-p- <Passwd>]"

      std::wcout << TXT("Performing EraseRange: ");

      if( !device.isEnterpriseSSC() && device.isSPInactive( (char*)"Locking" ) )
      {
         std::wcout << TXT(" *** No Ranges Exist. (Locking SP not Activated yet.)")
                    << std::endl << std::endl;
         return 1;
      }

      int bandNo = 0;
      int lastBandNo = 0;

      /*if( _stricmp( argv[1] + sizeof("EraseRange") -1, "All" ) == 0 ||
          _stricmp( argv[1] + sizeof("ER") -1, "All" ) == 0)
      {
         if( !device.getMaxBands( &lastBandNo ) )
            return 3;
      }
      else */
      {
         if( _strnicmp( argv[1], "ER", sizeof("ER")-1 ) == 0 )
            bandNo = atoi( argv[1] + sizeof("ER") -1 );
         else
            bandNo = atoi( argv[1] + sizeof("EraseRange") -1 );

         if( NULL != strchr( argv[1], '-' ) )
            lastBandNo = atoi( strchr( argv[1], '-' ) +1 );
      }

      if( !device.isBandNoValid( bandNo ) || !device.isBandNoValid( lastBandNo ) )
      {
         if( lastBandNo > 0 )
            std::wcout << TXT(" *** Requested Range from ") << bandNo << TXT(" to ") << lastBandNo << TXT(" is invalid.") << std::endl << std::endl;
         else
            std::wcout << TXT(" *** Requested Range number ") << bandNo << TXT(" is invalid.")  << std::endl << std::endl;
         return 1;
      }

      char *ps;
      bool resetACL = ( device.isEnterpriseSSC() ) ? true : false;

      if( NULL != ( ps = getParameter( (char*)"-reset", 2, argc, argv ) ) )
         resetACL = atoi( ps ) ? true : false;

      if( !resetACL && device.isEnterpriseSSC() )
      {
         std::wcerr << TXT(" *** Must always \"-resetACL\" for current Enterprise-SSC drives.")  << std::endl << std::endl;
         return 1;
      }

      std::wcout << std::endl << TXT(" *** WARNING: All Data on Range ") << bandNo;
      if( bandNo < lastBandNo )
         std::wcout << TXT(" to ") << lastBandNo;
      std::wcout << TXT(" on selected SED will be lost.") << std::endl << TXT("Continue? (y/n)");
      char c; 
      cin >> c;
      if( 'y' != c && 'Y' != c )
         return 1;

      std::wcout << std::endl << TXT("Erase Range ") << bandNo;
      if( bandNo < lastBandNo )
         std::wcout << TXT(" to ") << lastBandNo;
      std::wcout << TXT(": ");

      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );

      result = device.eraseBand( bandNo, ((lastBandNo < bandNo)? bandNo : lastBandNo), authent, resetACL );

      if( result )
      {
         if( bandNo < lastBandNo )
            std::wcout << TXT(" have been cryptographically erased.") << std::endl;
         else
            std::wcout << TXT(" has been cryptographically erased.") << std::endl;
      }
      else
         return 3;
   } // EraseRange


//#if 0 // deprecate sub-commands for Ranges
/*
            _strnicmp( argv[1], "RB", sizeof("RB")-1 ) == 0 || 
            _strnicmp( argv[1], "ResizeBand", sizeof("ResizeBand")-1 ) == 0 ||
            _strnicmp( argv[1], "LK", sizeof("LK")-1 ) == 0 || 
            _strnicmp( argv[1], "LockBand", sizeof("LockBand")-1 ) == 0 || 
            _strnicmp( argv[1], "UL", sizeof("UL")-1 ) == 0 || 
            _strnicmp( argv[1], "UnlockBand", sizeof("UnlockBand")-1 ) == 0 || 
            _strnicmp( argv[1], "LOR", sizeof("LOR")-1 ) == 0 || 
            _strnicmp( argv[1], "LR", sizeof("LR")-1 ) == 0 ||  // Deprecated in v1.6
            _strnicmp( argv[1], "LockOnReset", sizeof("LockOnReset")-1 ) == 0 
*/
      // ========================= RB | ResetBand ============================

     else if( _strnicmp( argv[1], "RB", sizeof("RB")-1 ) == 0 ||
          _strnicmp( argv[1], "ResizeBand", sizeof("ResizeBand")-1 ) == 0 )
      {
        int bandNo = 0;
        IOTableLocking row(false);
         if( getNumberOfRequiredParameters( argc, argv ) < 4 )
         {
            std::wcerr << TXT("Not enough parameters given to proceed with.") << std::endl << std::endl;
            usage( argv[0], argv[1], true, bManPage );
            return 1;
         }
         if( _strnicmp( argv[1], "RB", sizeof("RB")-1 ) == 0 )
            bandNo = atoi( argv[1] + sizeof("RB") -1 );
         else
            bandNo = atoi( argv[1] + sizeof("ResizeBand") -1 );

         if( bandNo == 0 )
         {
            std::wcerr << TXT("  Cannot alter starting LBA or Length of Global Band/Range 0.") << std::endl << std::endl;
            return 1;
         }

         // Verify alignment if Opal SSC 2.0 and alignment feature descriptor was found
         row.RangeStart = _atoi64( argv[2] );
         row.RangeStart_isValid = true;

         row.RangeLength = _atoi64( argv[3] );
         row.RangeLength_isValid = true;

         bool     bRequired = false;
         tINT64   alignment = 1;
         tINT64   lowestLBA = 0;
         int      blockSize = 512;

         if( device.getGeometryAlignment( bRequired, alignment, lowestLBA, blockSize ) )
         {
            if( bRequired )
            {
               std::cout << TXT(" NOTE: BAND ALIGNMENT IS ENFORCED ON THIS DRIVE.") << std::endl;
            }
            std::cout << TXT("     Alignment granularity: ") << alignment << TXT(" LBAs, LowestAlignedLBA: ")
                      << lowestLBA << TXT(". BlockSize: ") << blockSize << TXT(" bytes.")
                      << std::endl << std::endl;
         }
      } // ResizeBand

      // ========================= LK | LockBand ============================

      else if( _strnicmp( argv[1], "LockBand", sizeof("LockBand")-1 ) == 0 ||
               _strnicmp( argv[1], "LK", sizeof("LK")-1 ) == 0 )
      {
        int bandNo = 0;
        IOTableLocking row(false);
         if( _strnicmp( argv[1], "LK", sizeof("LK")-1 ) == 0 )
            bandNo = atoi( argv[1] + sizeof("LK") -1 );
         else
            bandNo = atoi( argv[1] + sizeof("LockBand") -1 );

         row.ReadLockEnabled = true;
         row.ReadLockEnabled_isValid = true;

         row.WriteLockEnabled = true;
         row.WriteLockEnabled_isValid = true;

         row.ReadLocked = true;
         row.ReadLocked_isValid = true;

         row.WriteLocked = true;
         row.WriteLocked_isValid = true;
      
      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );

      result = device.setLockingRange( bandNo, row, authent );
      } // LckBand

      // ========================= UL | UnlockBand ============================

      else if( _strnicmp( argv[1], "UnlockBand", sizeof("UnlockBand")-1 ) == 0 ||
               _strnicmp( argv[1], "UL", sizeof("UL")-1 ) == 0 )
      {
        int bandNo = 0;
        IOTableLocking row(false);
         if( _strnicmp( argv[1], "UL", sizeof("UL")-1 ) == 0 )
            bandNo = atoi( argv[1] + sizeof("UL") -1 );
         else
            bandNo = atoi( argv[1] + sizeof("UnlockBand") -1 );

         row.ReadLocked = false;
         row.ReadLocked_isValid = true;

         row.WriteLocked = false;
         row.WriteLocked_isValid = true;
      
      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );

      result = device.setLockingRange( bandNo, row, authent );
      }  // UnlockBand

      // ========================= LOR | LockOnReset ============================

      else if( _strnicmp( argv[1], "LOR", sizeof("LOR")-1 ) == 0 ||
               _strnicmp( argv[1], "LR", sizeof("LR")-1 ) == 0 ||  // Deprecated in v1.6
               _strnicmp( argv[1], "LockOnReset", sizeof("LockOnReset")-1 ) == 0  )
      {
        int bandNo = 0;
        IOTableLocking row(false);
         if( getNumberOfRequiredParameters( argc, argv ) < 3 )
         {
            std::wcerr << TXT("Not enough parameters given to proceed with.") << std::endl << std::endl;
            usage( argv[0], argv[1], true, bManPage );
            return 1;
         }

         if( _strnicmp( argv[1], "LOR", sizeof("LOR")-1 ) == 0 )
            bandNo = atoi( argv[1] + sizeof("LOR")-1 );
         else if( _strnicmp( argv[1], "LR", sizeof("LR")-1 ) == 0 )
            bandNo = atoi( argv[1] + sizeof("LR")-1 );
         else
            bandNo = atoi( argv[1] + sizeof("LockOnReset")-1 );

         if( _stricmp( argv[2], "On" ) == 0 || _stricmp( argv[2], "1" ) == 0 )
         {
            row.LockOnReset_length = 1;
            row.LockOnReset[0] = 0;  // Lock-on-Power-Reset
         }
         else if( _stricmp( argv[2], "Off" ) == 0 || _stricmp( argv[2], "0" ) == 0 )
         {
            row.LockOnReset_length = 0; // Turn off Lock-on-Reset
         }
         else
         {
            std::wcerr << TXT("Specified On or Off value \"") << argv[2] << TXT("\" not understood.") << std::endl << std::endl;
            return 1;
         }
      
      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );

      result = device.setLockingRange( bandNo, row, authent );
    } // LockOnReset

//#endif 0 // deprecate sub-commands for Ranges



   // *******************************************************************
   // *************  BUG BUG   TODO  TODO   BUG BUG *********************
   // *******************************************************************
   
   // The Enable/Disable/Show authority commands need to add a paramter for
   // the SP to use since Opal2/edrive drives have authorities in both AdminSP
   // and LockingSP. 

   // *******************************************************************
   // *************  BUG BUG   TODO  TODO   BUG BUG *********************
   // *******************************************************************

   // ========================= SA | ShowAuthorities ============================

   else if( _strnicmp( argv[1], "ShowAuthorities", sizeof("ShowAuthorit")-1 ) == 0 ||
            _strnicmp( argv[1], "SA", sizeof("SA")-1 ) == 0 )
   {
      std::wcout << TXT("Performing ShowAuthorities: ");

#if 1 // Implemented
      if( argc < 3 )
      {
         std::wcout << TXT(" *** Not enough parameters given.")  << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );

      if( _strnicmp( argv[2], "Locking", sizeof("Locking")-1 ) == 0 )
      {
         if( !device.isEnterpriseSSC() && device.isSPInactive( (char*)"Locking" ) )
         {
            std::wcout << TXT(" *** LockingSP not Activated yet.") << std::endl;
            return 1;
         }

         device.showAuthorities( "LockingSP", authent );
      }
      else if( _strnicmp( argv[2], "Admin", sizeof("Admin")-1 ) == 0 )
      {

         device.showAuthorities( "AdminSP", authent );
      }
      else
      {
         std::wcout << TXT("Parameter \"") << argv[2] << TXT("\' not understood.")  << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }


      if( device.isEnterpriseSSC() )
      {
         // UID_SP_LOCKING_E  0x0000020500010001   // defined in Enterprise-SSC

      }
      else
      {



         // GET on Authority table doesn't require authentication, 
//       m_device->_startSession( UID_SP_LOCKING_OM, authent );
//         device.showAuthorities( "Admin" );


      }
#else
      std::wcout << TXT("NOT IMPLEMENTED YET") << std::endl;
#endif
      std::wcout << std::endl;

   } // ShowAuthorities


   // ========================= EA | EnableAuthority ============================
   // ========================= DA | DisableAuthority ============================

   else if( _stricmp( argv[1], "EnableAuthority" ) == 0 || _stricmp( argv[1], "EA" ) == 0 
          ||_stricmp( argv[1], "DisableAuthority" ) == 0 || _stricmp( argv[1], "DA" ) == 0 )
   {  // " EA <TargetAuthority> [-a- <Auth>] [-p- <Passwd>]"
      // " DA <TargetAuthority> [-a- <Auth>] [-p- <Passwd>]"

      bool toEnable;
      if(  _stricmp( argv[1], "EnableAuthority" ) == 0 || _stricmp( argv[1], "EA" ) == 0 )
      {
         if( !bQuiet ) std::wcout << TXT("Performing EnableAuthority: ");
         toEnable = true;
      }
      else
      {
         if( !bQuiet ) std::wcout << TXT("Performing DisableAuthority: ");
         toEnable = false;
      }

      //if( !device.isEnterpriseSSC() && device.isSPInactive( "Locking" ) )
      //{
      //   std::wcout << TXT("Locking SP has not been activated yet. Activate LockingSP first, then try again.") << std::endl;
      //   return 1;
      //}

      if( getNumberOfRequiredParameters( argc, argv ) < 3 )
      {
         std::wcerr << TXT("Not enough parameters supplied.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 3, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 3, argc, argv ) );
      result = device.enableDisableAuthority( toEnable, argv[2], authent );      
      if( result )
          std::wcout << TXT("Authority \"") << argv[2] << TXT("\" has been ") << (toEnable ? TXT("enabled.") : TXT("disabled.")) << std::endl;
      else
         return 3;
   } // EnableAuthority/DisableAuthority


   // ========================= CP | ChangePin ============================

   else if( _stricmp( argv[1], "ChangePin" ) == 0 || _stricmp( argv[1], "CP" ) == 0 )
   {
      // " CP <Authority> [-name <CommonName>] [-pin <Passwd>] [-TryLimit <#>]"
      // "   [-Tries <#>] [-Persist <1/0>] [-a- <Auth>] [-p- <Passwd>]"

      std::wcout << TXT("Performing ChangePin: ");

      if( argc < 3 )
      {
         std::wcerr << TXT("At least one parameter must be supplied.")  << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      if( !(_stricmp( argv[2], "SID" ) == 0 || _stricmp( argv[2], "MSID" ) == 0 || _stricmp( argv[2], "PSID" ) == 0 )
          && !device.isEnterpriseSSC() && device.isSPInactive( (char*)"Locking" ) )
      {
         std::wcout << TXT(" *** Locking SP not activated yet. Cannot change this PIN.")
                    << std::endl;
         return 1;
      }

      IOTableC_PIN pin(false);

      // [-name <CommonName>]
      char *p = getParameter( (char*)"-name", 2, argc, argv );
      if( NULL != p )
      {
         pin.CommonName_length = (tINT8) strlen(p);
         if( pin.CommonName_length >= sizeof(pin.CommonName) )
         {
            std::wcerr << TXT(" *** CommonName \"") << p << TXT("\" truncated to ") << sizeof(pin.CommonName)-1 << TXT(" bytes max.")
                       << std::endl << std::endl;
            pin.CommonName_length = sizeof(pin.CommonName)-1;
         }
         else if ( pin.CommonName_length == 0 )    // Setting name to empty string
         {
            pin.CommonName[pin.CommonName_length] = 0;
            pin.CommonName_length++;   // have to fake a non-zero length
         }

         memcpy( pin.CommonName, p, pin.CommonName_length );
         pin.CommonName[pin.CommonName_length] = 0;   // Insure string is null-terminated.
      }

      p = getParameter( (char*)"-pin", 3, argc, argv );
      if( NULL != p )
      {
         pin.PIN_length = (tINT8) strlen(p);
         if( pin.PIN_length >= sizeof(pin.PIN) )
         {
            std::wcerr << TXT(" *** -pin value exceeds maximum length of ") << sizeof(pin.PIN) - 1 << TXT(" bytes.")  << std::endl << std::endl;
            return 1;
         }

         memcpy( pin.PIN, p, pin.PIN_length );
         pin.PIN[pin.PIN_length] = 0;
      }

      p = getParameter( (char*)"-TryLimit", 3, argc, argv );
      if( NULL != p )
      {
         pin.TryLimit = atoi(p);
         pin.TryLimit_isValid = true;
      }

      p = getParameter( (char*)"-Tries", 3, argc, argv );
      if( NULL != p )
      {
         pin.Tries = atoi(p);
         pin.Tries_isValid = true;
      }

      p = getParameter( (char*)"-Persist", 3, argc, argv );
      if( NULL != p )
      {
         pin.Persistence = ( atoi(p) ? true : false );
         pin.Persistence_isValid = true;
      }

      if( pin.isEmpty() )
      {
         std::wcerr << TXT(" *** At least one parameter must be supplied.")  << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 3, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 3, argc, argv ) );

      result = device.setCredential( argv[2], pin, authent );
      if( result )
         std::wcout << TXT("Authority \"") << argv[2] << TXT("\" has been updated.") << std::endl
                    << std::endl;
      else
         return 3;
   } // ChangePin


   // ========================= RS | ResetStack ============================

   else if( _stricmp( argv[1], "ResetStack" ) == 0 || _stricmp( argv[1], "RS" ) == 0 )
   {  // " RS [<#>]"
      int channel = 0;
      if( argc > 2 )
         channel = atoi( argv[2] );

      if( channel < 0 || channel > 1 )
      {
         std::wcout << TXT(" *** COM channel number is invalid. Must be 0 or 1.")  << std::endl
                    << std::endl;
         return 1;
      }

      std::wcout << TXT("Performing ResetStack for COM Channel ") << channel << ": ";

      if( device.protocolStackReset( channel, false ) )
         std::wcout << TXT("Stack has been reset.") << std::endl;
      else
         return 3;
   } // ResetStack


   // ========================= GR | GenerateRandom ============================

   else if( _stricmp( argv[1], "GenerateRandom" ) == 0 || _stricmp( argv[1], "GR" ) == 0 )
   {  // " GR <SPName> [<NumberOfBytes>] (1-32, def=32)"
      std::wcout << TXT("Performing GenerateRandom: ");

      if( getNumberOfRequiredParameters( argc, argv ) < 3 )
      {
         std::wcout << TXT(" *** Not enough parameters supplied.") << std::endl
                    << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      if( (_stricmp( argv[2], "Locking" ) == 0 || _stricmp( argv[2], "LockingSP" ) == 0 )
          && !device.isEnterpriseSSC() && device.isSPInactive( (char*)"Locking" ) )
      {
         std::wcout << TXT(" *** Locking SP has not been activated.") << std::endl
                    << std::endl;
         return 1;
      }

      int count = 32; // default
      if( argc > 3 )
      {
         count = atoi( argv[3] );
         if (count < 1 || count > 32)
         {
            std::wcerr << TXT("Size must be between 1 and 32.") << std::endl << std::endl;
            return 1;
         }
      }

      dta::tBytes randomData( count );
      result = device.generateRandom( argv[2], randomData );

      if( result )
      {
         std::wcout << count << TXT(" bytes generated by ") << argv[2] << TXT("SP:") << std::endl
                    << std::endl;
         for( unsigned int ii = 0; ii < randomData.size(); ii++ )
         {  
            std::wcout << TXT(" 0x") << setfill(L'0') << setw(2) << hex << randomData[ii] << dec;
            if( (ii % 8) == 7 ) 
               std::wcout << std::endl;
         }
      }
      else
      {
         std::wcerr << TXT(" *** Failed to generate random number.") << std::endl;
         return 3;
      }
   } // GenerateRandom


   // ========================= RDS | ReadDataStore ============================

   else if( _strnicmp( argv[1], "ReadDataStore", sizeof("ReadDataStore")-1 ) == 0 ||
            _strnicmp( argv[1], "RDS", sizeof("RDS")-1 ) == 0 )
   {  // " RDS[<#>] <FileName> [-start <#>] [-len[gth] <#>] [-a- <Auth>] [-p- <Passwd>]"

      std::wcout << TXT("Performing ReadDataStore: ");

      if( !device.isEnterpriseSSC() && device.isSPInactive( (char*)"Locking" ) )
      {
         std::wcout << TXT(" *** Locking SP not activated yet.") << std::endl;
         return 1;
      }

      // Need at least the FileName 
      if( getNumberOfRequiredParameters( argc, argv ) < 3 )
      {
         std::wcout << TXT(" *** Not enough parameters supplied.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      // For Opal SSC 1.0, there is one standard DataStore Table available. Seagate's size is
      // 10mbytes, other OEMs smaller. Seagate also provides 4 additional DSTs, each 10mbytes.
      // For Opal SSC 2.0, the DSTs are dynamic and are allocated during Activate or Reactivate,
      // by dividing up the 50mb of MaxDSTStorage among the "Additional_DataStore_Tables" (16 
      // for Seagate Opal 2.0). For Enterprise SSC 1.0, there is one standard DataStore Table
      // of length 1024 bytes.

      // The primary Opal SSC 1.0 DST is accessed using the default DST, which is the base DST
      // and arbitrarily assigned as DST 1. The additional 4 DSTs are accessed as DST 2 thru 5.
      // For Opal SSC 2.0, the DSTs are accessed starting at DST 1 thru DST 16 (or whatever max
      // number of DSTs is reported by Level 0 Feature Descriptor).
      // For Enterprise SSC, the DST is accessed using default DST = 1.

      if( !device.isDataStoreTableFeatureSupported() )
      {
         std::wcout << TXT(" *** DataStoreTables not supported on this device.") << std::endl;
         return 1;
      }
      else if( device.getMaxNumDataStoreTables() <= 0 )
      {
         std::wcout << TXT(" *** No DataStore Tables exist on this device.") << std::endl;
         return 1;
      }

      // DataStore Tables are accessed starting arbitrarily from DST 1.
      int dsTableNameNo = -1; 
      if( _strnicmp( argv[1], "ReadDataStore", sizeof("ReadDataStore")-1 ) == 0 )
         dsTableNameNo = atoi( argv[1] + sizeof("ReadDataStore") -1 );
      else
         dsTableNameNo = atoi( argv[1] + sizeof("RDS") -1 );

      if( dsTableNameNo < 1 )
         dsTableNameNo = 1;  // Force minimum table number to be 1

      if( dsTableNameNo > device.getMaxNumDataStoreTables() )
      {
         std::wcout << TXT(" *** DataStore Table ") << dsTableNameNo << TXT(" does not exist.")  << std::endl
                    << TXT(" Device reports Maximum number of DataStore Tables is ") << (tUINT16)device.getMaxNumDataStoreTables() << TXT(".") << std::endl;
         return 1;
      }

      char fileName[256];
#if defined(_WIN32) // nvn20110728
      if( NULL != strstr( argv[2], ".ds" ) || NULL != strstr( argv[2], ".DS" ) )
         sprintf_s( fileName, sizeof(fileName), "%s", argv[2] );
      else
         sprintf_s( fileName, sizeof(fileName), "%s.DS", argv[2] );
#else
      //int nprint = 0;
      if( NULL != strstr( argv[2], ".ds" ) || NULL != strstr( argv[2], ".DS" ) )
         sprintf( fileName, "%s", argv[2] );
      else
         sprintf( fileName, "%s.DS", argv[2] );
#endif

      char *ps;
      tINT64 start =-1, end =-1, len =-1;
      if( NULL != ( ps = getParameter( (char*)"-start", 3, argc, argv ) ) )
         start = atoi( ps );

      if( NULL != ( ps = getParameter( (char*)"-len", 3, argc, argv ) ) ||
          NULL != ( ps = getParameter( (char*)"-length", 3, argc, argv ) ) )
      {
         len = atoi( ps );
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 3, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 3, argc, argv ) );

      tUINT32 execTimeMS;
      result = device.readDataStore( fileName, authent, dsTableNameNo -1, start, len, &execTimeMS );

      if( !result )
         return 3;

   } // ReadDataStore

   // ========================= WDS | WriteDataStore ============================

   else if( _strnicmp( argv[1], "WriteDataStore", sizeof("WriteDataStore")-1 ) == 0 ||
            _strnicmp( argv[1], "WDS", sizeof("WDS")-1 ) == 0 )
   {  // " WDS[<#>] <FileName> [-start <#>] [-len[gth] <#>] [-a- <Auth>] [-p- <Passwd>]"
      std::wcout << TXT("Performing WriteDataStore: ");

      if( !device.isEnterpriseSSC() && device.isSPInactive( (char*)"Locking" ) )
      {
         std::wcout << TXT(" *** Locking SP not activated yet.") << std::endl;
         return 1;
      }

      // Need at least the FileName 
      if( getNumberOfRequiredParameters( argc, argv ) < 3 )
      {
         std::wcout << TXT(" *** Not enough parameters supplied.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      // For Opal SSC 1.0, there is one standard DataStore Table available. Seagate's size is
      // 10mbytes, other OEMs smaller. Seagate also provides 4 additional DSTs, each 10mbytes.
      // For Opal SSC 2.0, the DSTs are dynamic and are allocated during Activate or Reactivate,
      // by dividing up the 50mb of MaxDSTStorage among the "Additional_DataStore_Tables" (16 
      // for Seagate Opal 2.0). For Enterprise SSC 1.0, there is one standard DataStore Table
      // of length 1024 bytes.

      // The primary Opal SSC 1.0 DST is accessed using the default DST, which is the base DST
      // and arbitrarily assigned as DST 1. The additional 4 DSTs are accessed as DST 2 thru 5.
      // For Opal SSC 2.0, the DSTs are accessed starting at DST 1 thru DST 16 (or whatever max
      // number of DSTs is reported by Level 0 Feature Descriptor).
      // For Enterprise SSC, the DST is accessed using default DST = 1.

      if( !device.isDataStoreTableFeatureSupported() )
      {
         std::wcout << TXT(" *** DataStoreTables not supported on this device.") << std::endl;
         return 1;
      }
      else if( device.getMaxNumDataStoreTables() <= 0 )
      {
         std::wcout << TXT(" *** No DataStore Tables exist on this device.") << std::endl;
         return 1;
      }

      int dsTableNameNo = -1;    // Default starting DST number.
      if( _strnicmp( argv[1], "WriteDataStore", sizeof("WriteDataStore")-1 ) == 0 )
         dsTableNameNo = atoi( argv[1] + sizeof("WriteDataStore") -1 );
      else
         dsTableNameNo = atoi( argv[1] + sizeof("WDS") -1 );

      if( dsTableNameNo < 1 )
         dsTableNameNo = 1;

      if( dsTableNameNo > device.getMaxNumDataStoreTables() )
      {
            std::wcout << TXT(" *** DataStore Table ") << dsTableNameNo << TXT(" does not exist.")  << std::endl
                       << TXT(" Maximum DataStore Tables is ") << (tUINT16)device.getMaxNumDataStoreTables() << TXT(".") << std::endl;
         return 1;
      }

      char fileName[256];
      if( NULL != strstr( argv[2], ".ds" ) || NULL != strstr( argv[2], ".DS" ) )
         sprintf_s( fileName, sizeof(fileName), "%s", argv[2] );
      else
         sprintf_s( fileName, sizeof(fileName), "%s.DS", argv[2] );



      char *ps;
      tINT64 start =-1, end =-1, len =-1;
      if( NULL != ( ps = getParameter( (char*)"-start", 3, argc, argv ) ) )
         start = atoi( ps );

      if( NULL != ( ps = getParameter( (char*)"-len", 3, argc, argv ) ) ||
          NULL != ( ps = getParameter( (char*)"-length", 3, argc, argv ) ) )
      {
         len = atoi( ps );
      }

      if( len > 0 && start >= 0 )
         end = start + len - 1;

      AuthenticationParameter authent( getParameter( (char*)"-a-", 3, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 3, argc, argv ) );

      tUINT32 execTimeMS;
      result = device.writeDataStore( fileName, authent, dsTableNameNo -1, start, end, &execTimeMS );

      if( result )
      {
         std::wcout << TXT("File \"") << fileName << TXT("\" written to DS") << dsTableNameNo << TXT(" in ") << execTimeMS << TXT(" ms") << std::endl; 
      }
      else
         return 3;
   } // WriteDataStore

// ========================= SDS | ShowDataStore ============================

   else if( _stricmp( argv[1], "ShowDataStore" ) == 0 ||
            _stricmp( argv[1], "SDS" ) == 0 )
   {  // " SDS [-a- <Auth>] [-p- <Passwd>]"

      std::wcout << TXT("Performing ShowDataStore: NOT IMPLEMENTED YET") << std::endl << std::endl;
#if 0
      if( !device.isEnterpriseSSC() && device.isSPInactive( (char*)"Locking" ) )
      {
         std::wcout << TXT(" *** Locking SP not activated yet.") << std::endl;
         return 1;
      }

      // Need at least the FileName 
      if( getNumberOfRequiredParameters( argc, argv ) < 3 )
      {
         std::wcout << TXT(" *** Not enough parameters supplied.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      // For Opal SSC 1.0, there is one standard DataStore Table available. Seagate's size is
      // 10mbytes, other OEMs smaller. Seagate also provides 4 additional DSTs, each 10mbytes.
      // For Opal SSC 2.0, the DSTs are dynamic and are allocated during Activate or Reactivate,
      // by dividing up the 50mb of MaxDSTStorage among the "Additional_DataStore_Tables" (16 
      // for Seagate Opal 2.0). For Enterprise SSC 1.0, there is one standard DataStore Table
      // of length 1024 bytes.

      // The primary Opal SSC 1.0 DST is accessed using the default DST, which is the base DST
      // and arbitrarily assigned as DST 1. The additional 4 DSTs are accessed as DST 2 thru 5.
      // For Opal SSC 2.0, the DSTs are accessed starting at DST 1 thru DST 16 (or whatever max
      // number of DSTs is reported by Level 0 Feature Descriptor).
      // For Enterprise SSC, the DST is accessed using default DST = 1.

      if( !device.isDataStoreTableFeatureSupported() )
      {
         std::wcout << TXT(" *** DataStoreTables not supported on this device.") << std::endl;
         return 1;
      }
      else if( device.getMaxNumDataStoreTables() <= 0 )
      {
         std::wcout << TXT(" *** No DataStore Tables exist on this device.") << std::endl;
         return 1;
      }

      // DataStore Tables are accessed starting arbitrarily from DST 1.
      int dsTableNameNo = -1; 
      if( _strnicmp( argv[1], "ReadDataStore", sizeof("ReadDataStore")-1 ) == 0 )
         dsTableNameNo = atoi( argv[1] + sizeof("ReadDataStore") -1 );
      else
         dsTableNameNo = atoi( argv[1] + sizeof("RDS") -1 );

      if( dsTableNameNo < 1 )
         dsTableNameNo = 1;  // Force minimum table number to be 1

      if( dsTableNameNo > device.getMaxNumDataStoreTables() )
      {
         std::wcout << TXT(" *** DataStore Table ") << dsTableNameNo << TXT(" does not exist.")  << std::endl
                    << TXT(" Device reports Maximum number of DataStore Tables is ") << (tUINT16)device.getMaxNumDataStoreTables() << TXT(".") << std::endl;
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 3, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 3, argc, argv ) );

      tUINT32 execTimeMS;
      result = device.ShowDataStore( fileName, authent, dsTableNameNo -1, start, len, &execTimeMS );

      if( !result )
         return 3;
#endif // 0
      return 1;
   } // ShowDataStore



   // *************************************************************************
   // *************************** OPAL COMMAND GROUP **************************
   // *************************************************************************
   //
   // Activate, Reactivate, TPerReset, RevertSP, GrantAccess,
   // Read/Write ShadowMBR, Get/Set ShadowMBRCtrl
   //


   // ========================= AT | Activate ============================

   else if( _stricmp( argv[1], "Activate" ) == 0 ||
            _stricmp( argv[1], "AT" ) == 0 )
   {  // " AT | Activate <SPName> [-sur All | \"<Range# list>\"] [-sup <0/1>] [-dst "<DSTable size list>"] [-a- <Auth>] [-p- <Passwd>]"
    
      std::wcout << TXT("Performing Activate: ");

      if( device.isEnterpriseSSC() )
      {
         std::wcerr << TXT(" *** Enterprise SSC devices do not support this feature.")  << std::endl << std::endl;
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );

      char *sp = (char*)"Locking"; // default LockingSP
      if( getNumberOfRequiredParameters( argc, argv ) >= 3 )
      {
         if( _stricmp( argv[2], "Admin" ) == 0 || _stricmp( argv[2], "AdminSP" ) == 0 )
         {
            std::wcerr << TXT(" *** Not allowed to activate AdminSP (It's already active).") << std::endl << std::endl;
            return 1;
         }
         else if( !( _stricmp( argv[2], "Locking" ) == 0 || _stricmp( argv[2], "LockingSP" ) == 0 ) )
         {
            std::wcerr << TXT(" *** Only SP that can be activated is LockingSP if in Manufactured-Inactive state.") << std::endl << std::endl;
            return 1;
         }
      }

      // Check to see if the SP is already in active state
      if( device.isSPManufactured( sp ) )
      {
         std::wcout << sp << TXT(" *** SP is already Activated (in Manufactured state).") << std::endl;
         return 1;
      }
 
      if( getParameter( (char*)"-sur", 2, argc, argv ) != NULL ||
          getParameter( (char*)"-sup", 2, argc, argv ) != NULL )
      {
         // Check if device supports Opal "Single User Mode Fixed ACL"
         if( !device.isSingleUserModeSupported() )
         {
            std::wcout << TXT("Your device does not support Opal Single User Mode feature.") << std::endl;
            return 1;
         }
      }

      TCG_BANDNOs singleUserRanges;
      TCG_BANDNOs *pSingleUserModeList = parseParameterOfBandNumbers( getParameter( "-sur", 2, argc, argv ), &singleUserRanges );

      int rangeStartLengthPolicy =-1;
      char *p = getParameter( (char*)"-sup", 2, argc, argv );
      if( NULL != p )
         rangeStartLengthPolicy = atoi( p );

      UINT64VALs dsTableSizes( device.getMaxNumDataStoreTables() );
      result = device.activateSP( sp, authent, pSingleUserModeList, rangeStartLengthPolicy, parseParameterOfIntegers( getParameter( "-dst", 2, argc, argv ), &dsTableSizes ) );

      if( result )
         std::wcout << TXT("Successfully activated ") << sp << TXT("SP to the Manufactured state.") << std::endl;
      else
         return 3;
   } // Activate


   // ========================= RA | Reactivate ============================

   else if( _stricmp( argv[1], "Reactivate" ) == 0 ||
            _stricmp( argv[1], "RA" ) == 0 )
   {  // " RA | Reactivate [-sul All | \"<Band# list>\"] [-slp <0/1>] [-pin <Admin1Passwd>] [-tbs "<DS table size list>"] [-a- <Auth>] [-p- <Passwd>]"
      std::wcout << TXT("Performing Reactivate: ");

      // Check if device supports Opal "Single User Mode Fixed ACL"
      if( !device.isSingleUserModeSupported() )
      {
         std::wcout << TXT("Your device does not support Opal Single User Mode feature.") << std::endl;
         return 1;
      }

      // Check to see if the Locking SP is in active state
      if( !device.isSPManufactured( (char*)"Locking" ) )
      {
         std::wcout << TXT(" *** Locking SP should be activated first.") << std::endl;
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );

      TCG_BANDNOs singleUserRanges;
      TCG_BANDNOs *pSingleUserModeList = parseParameterOfBandNumbers( getParameter( (char*)"-sur", 2, argc, argv ), &singleUserRanges );

      int rangeStartLengthPolicy =-1;
      char *p = getParameter( (char*)"-sup", 2, argc, argv );
      if( NULL != p )
         rangeStartLengthPolicy = atoi( p );

      UINT64VALs dsTableSizes( device.getMaxNumDataStoreTables() );

      dta::tBytes admin1PIN;
      p = getParameter( (char*)"-pin", 2, argc, argv );
      if( NULL != p )
      {
         admin1PIN.resize( strlen(p) );
         if( admin1PIN.size() > 32 )
         {
            std::wcerr << TXT("-pin parameter for Admin1PIN is too long, exceeding 32 bytes.")  << std::endl << std::endl;
            return 1;
         }

         if( admin1PIN.size() > 0 )
            memcpy( &admin1PIN[0], p, admin1PIN.size() );

         result = device.reactivateSP( authent, pSingleUserModeList, rangeStartLengthPolicy, &admin1PIN, parseParameterOfIntegers( getParameter( "-tbs", 2, argc, argv ), &dsTableSizes ) );
      }
      else
      {
         result = device.reactivateSP( authent, pSingleUserModeList, rangeStartLengthPolicy, NULL, parseParameterOfIntegers( getParameter( "-tbs", 2, argc, argv ), &dsTableSizes ) );
      }

      if( result )
         std::wcout << TXT("Successfully reactivated Locking-SP in Manufactured state.") << std::endl;
      else
         return 3;
   } // Reactivate


   // ========================= GA | GrantAccess ============================

   else if( _stricmp( argv[1], "GrantAccess" ) == 0 || _stricmp( argv[1], "GA" ) == 0 )
   {  // " GA SRL/SWL Range[<#>[-<#>]]|[All] {<Authority>} [-a- <Auth>] [-p- <Passwd>]"   (Set ReadLocked/WriteLocked)
      // " GA SMBRCDone/SDS[<#>]/GDS[<#>] {<Authority>} [-a- <Auth>] [-p- <Passwd>]"      (Set MBRControlDone/DataStore, Get DataStore)
      // " GA <LockingSP_ACE_UID> {<Authority>} [-a- <Auth>] [-p- <Passwd>]"              (Set a given ACE in LockingSP by its UID)

      std::wcout << TXT("Performing GrantAccess: ");

      if( device.isEnterpriseSSC() )
      {
         std::wcout << TXT(" *** Not supported on Enterprise SSC.") << std::endl << std::endl;
         return 1;
      }

      if( !device.isEnterpriseSSC() && device.isSPInactive( (char*)"Locking" ) )
      {
         std::wcout << TXT(" *** Locking SP has not been activated yet.") << std::endl << std::endl;
         return 1;
      }

      if( getNumberOfRequiredParameters( argc, argv ) < 4 )
      {
         std::wcout << TXT(" *** Not enough parameters supplied.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 4, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 4, argc, argv ) );

      if( _stricmp( argv[2], "SRL" ) == 0 || _stricmp( argv[2], "SWL" ) == 0 ) // SET RdLocked/WrtLocked of a range
      {
         if( getNumberOfRequiredParameters( argc, argv ) < 5 )
         {
            std::wcerr << TXT("Not enough parameters supplied.") << std::endl << std::endl;
            usage( argv[0], argv[1], true, bManPage );
            return 1;
         }

         int bandNo = 0;
         int lastBandNo = 0;

         if( _stricmp( argv[3] + sizeof("Range") -1, "All" ) == 0 )
         {
            if( !device.getMaxBands( &lastBandNo ) )
               return 3;
         }
         else
         {
            bandNo = atoi( argv[3] + sizeof("Range") -1 );
            if( NULL != strchr( argv[3], '-' ) )
               lastBandNo = atoi( strchr( argv[3], '-' ) +1 );
         }

         if( !device.isBandNoValid( bandNo ) || !device.isBandNoValid( lastBandNo ) )
         {
            if( lastBandNo > 0 )
               std::wcerr << TXT("Range number requested ") << bandNo << TXT(" to ") << lastBandNo << TXT(" is invalid.") << std::endl << std::endl;
            else
               std::wcerr << TXT("Range number requested ") << bandNo << TXT(" is invalid.")  << std::endl << std::endl;
            return 1;
         }

         do
         {
            std::wcout << TXT("\rPerforming GrantAccess to Range") << bandNo << TXT(": ");
            //if( bandNo < 10 && lastBandNo != 0 && bandNo < lastBandNo )
            //   std::wcout << TXT(" ");

            result = device.setAuthorityAccess( argv[2], bandNo, argc -4, argv +4, authent );

            if( result )
               std::wcout << TXT("Successfully.") << std::endl;
            else
               return 3;

            if( lastBandNo == 0 || bandNo >= lastBandNo )
               break;
            else
               bandNo++;

         } while( bandNo <= lastBandNo );
      }
      else if( _stricmp( argv[2], "SMBRCDone" ) == 0 )
      {
         result = device.setAuthorityAccess( argv[2], 0, argc -3, argv +3, authent );

         if( result )
            std::wcout << TXT("Successfully, granted access ") << argv[2] << TXT(".") << std::endl;
         else
            return 3;
      }
      else if( _strnicmp( argv[2], "SDS", sizeof("SDS") -1 ) == 0 || _strnicmp( argv[2], "GDS", sizeof("GDS") -1 ) == 0 )
      {
         int dsTableNameNo = 1; // The "Additional_DataStore_Tables" spec defines DS table names starting from 1.
         if( _strnicmp( argv[2], "SDS", sizeof("SDS") -1 ) == 0 )
            dsTableNameNo = atoi( argv[2] + sizeof("SDS") -1 );
         else if( _strnicmp( argv[2], "GDS", sizeof("GDS") -1 ) == 0 )
            dsTableNameNo = atoi( argv[2] + sizeof("GDS") -1 );

         if( dsTableNameNo < 1 )
            dsTableNameNo = 1;

         if( 0 != device.getMaxNumDataStoreTables() && dsTableNameNo > device.getMaxNumDataStoreTables() )
         {
            std::wcerr << TXT("Requested DataStore Table") << dsTableNameNo << TXT(" does not exist (out of range).")  << std::endl;
            return 1;
         }

         result = device.setAuthorityAccess( argv[2], dsTableNameNo -1, argc -3, argv +3, authent );

         if( result )
            std::wcout << TXT("Successfully, granted access ") << argv[2] << TXT(".") << std::endl;
         else
            return 3;
      }
      else
      {
         TCG_UID ace = (TCG_UID) _strtoui64( argv[2], NULL, 16 );
         if( ace )
         {
            result = device.setAuthorityAccess( ace, argc -3, argv +3, authent );
            if( result )
               std::wcout << TXT("Successfully, granted access ACE (0x") << hex << UINT64(ace) << TXT(".") << dec << std::endl;
            else
               return 3;
          }
         else
         {
            std::wcerr << TXT("GrantAccess parameters are not recognized, try again.")  << std::endl << std::endl;
            usage( argv[0], argv[1], true, bManPage );
            return 1;
         }
      }
   } // GrantAccess

   // ========================= RMT | ReadMBR ============================

   else if( _strnicmp( argv[1], "ReadMBR", sizeof("ReadMBR")-1 ) == 0 ||
            _stricmp( argv[1], "RMBR" ) == 0 ||    // deprecated command name
            _stricmp( argv[1], "RMT" ) == 0 )
   {  // " ReadMBR/RMT <FileName> [-s <Start>] [-e <End>] [-a- <Auth>] [-p- <Passwd>]"
      std::wcout << TXT("Performing ReadMbrTable: ");

      if( device.isEnterpriseSSC() )
      {
         std::wcerr << TXT("Your device (Ent-SSC) does not support this feature.")  << std::endl << std::endl;
         return 1;
      }

      if( !device.isEnterpriseSSC() && device.isSPInactive( (char*)"Locking" ) )
      {
         std::wcerr << TXT("Locking SP has not been activated yet. No ShadowMBR Table exists.") << std::endl << std::endl;
         return 1;
      }

      if( getNumberOfRequiredParameters( argc, argv ) < 3 )
      {
         std::wcerr << TXT("Not enough parameters supplied.")  << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      char fileName[256];
      if( NULL != strstr( argv[2], ".mbr" ) || NULL != strstr( argv[2], ".MBR" ) )
         sprintf_s( fileName, sizeof(fileName), "%s", argv[2] );
      else
         sprintf_s( fileName, sizeof(fileName), "%s.MBR", argv[2] );

      char *ps;
      tINT64 start =-1, end =-1;
      if( NULL != ( ps = getParameter( (char*)"-s", 3, argc, argv ) ) )
         start = _atoi64( ps );

      if( NULL != ( ps = getParameter( (char*)"-e", 3, argc, argv ) ) )
         end = _atoi64( ps );

      AuthenticationParameter authent( getParameter( (char*)"-a-", 3, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 3, argc, argv ) );

      tUINT32 execTimeMS;
      result = device.readMBR( fileName, authent, start, end, &execTimeMS );

      if( result )
         std::wcout << TXT("Successfully in ") << execTimeMS << TXT(" ms, MBR has been saved to file \"") << fileName << TXT("\".") << std::endl;
      else
         return 3;
   } // ReadMBR

   // ========================= WMT | WriteMBR ============================

   else if(_strnicmp( argv[1], "WriteMBR", sizeof("WriteMBR")-1 ) == 0 ||
            _stricmp( argv[1], "WMT" ) == 0)
   {  // " WriteMBR/WMT <FileName> [-s <Start>] [-e <End>] [-a- <Auth>] [-p- <Passwd>]"
      std::wcout << TXT("Performing WriteMBRTable: ");

      if( device.isEnterpriseSSC() )
      {
         std::wcerr << TXT("Your device (Ent-SSC) does not support this feature.")  << std::endl << std::endl;
         return 1;
      }

      if( !device.isEnterpriseSSC() && device.isSPInactive( (char*)"Locking" ) )
      {
         std::wcout << TXT("Locking SP has not been activated yet. No Shadow MBR Table exists.") << std::endl;
         return 1;
      }

      if( getNumberOfRequiredParameters( argc, argv ) < 3 )
      {
         std::wcerr << TXT("Not enough parameters supplied.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      char fileName[256];
      if( NULL != strstr( argv[2], ".mbr" ) || NULL != strstr( argv[2], ".MBR" ) )
         sprintf_s( fileName, sizeof(fileName), "%s", argv[2] );
      else
         sprintf_s( fileName, sizeof(fileName), "%s.MBR", argv[2] );

      char *ps;
      tINT64 start =-1, end =-1;
      if( NULL != ( ps = getParameter( (char*)"-s", 3, argc, argv ) ) )
         start = _atoi64( ps );

      if( NULL != ( ps = getParameter( (char*)"-e", 3, argc, argv ) ) )
         end = _atoi64( ps );

      AuthenticationParameter authent( getParameter( (char*)"-a-", 3, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 3, argc, argv ) );

      tUINT32 execTimeMS;
      result = device.writeMBR( fileName, authent, start, end, &execTimeMS );

      if( result )
         std::wcout << TXT("Successfully in ") << execTimeMS << TXT(" ms, MBR has been written from file \"") << fileName << TXT("\".") << std::endl;
      else
         return 3;
   } // WriteMBR

   // ========================= GMC | GetMBRControl ============================

   else if( _stricmp( argv[1], "GetMBRControl" ) == 0 ||
            _stricmp( argv[1], "GMBRC" ) == 0 ||   // deprecated command name
            _stricmp( argv[1], "GMC" ) == 0 )
   {  // " GetMBRControl/GMC [-a- <Auth>] [-p- <Passwd>]"
      std::wcout << TXT("Performing GetMBRControl: ");

      if( device.isEnterpriseSSC() )
      {
         std::wcerr << TXT("Your device (Ent-SSC) does not support this feature.") << std::endl << std::endl;
         return 1;
      }

      if( !device.isEnterpriseSSC() && device.isSPInactive( (char*)"Locking" ) )
      {
         std::wcout << ("Locking SP has not been activated yet. Activate LockingSP first, then try again.") << std::endl;
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );

      IOTableMBRControl row(true);

      result = device.getMBRControl( row, authent );
      if( result )
      {
         std::wcout << TXT("Successfully, MBRControl has been read as") << std::endl;
         std::wcout << TXT("\tEnable=") << row.Enable << TXT(", Done=") << row.Done << TXT(", MBRDoneOnReset=");
            interpretResetType( row.MBRDoneOnReset_length, &row.MBRDoneOnReset[0] );
         std::wcout << TXT(".") << std::endl;
      }
      else
         return 3;
   } // GetMBRControl


   // ========================= SMC | SetMBRControl ============================

   else if( _stricmp( argv[1], "SetMBRControl" ) == 0 ||
            _stricmp( argv[1], "SMBRC" ) == 0 ||  // deprecated command name
            _stricmp( argv[1], "SMC" ) == 0 )
   {  // " SetMBRControl/SMBRC [-e <Enable>] [-d <Done>] [-r <Reset>] [-a- <Auth>] [-p- <Passwd>]"
      std::wcout << TXT("Performing SetMBRControl: ");

      if( device.isEnterpriseSSC() )
      {
         std::wcerr << TXT("Your device (Ent-SSC) does not support this feature.") << std::endl << std::endl;
         return 1;
      }

      if( !device.isEnterpriseSSC() && device.isSPInactive( (char*)"Locking" ) )
      {
         std::wcout << TXT("Locking SP has not been activated yet. Activate LockingSP first, then try again.") << std::endl;
         return 1;
      }

      if( argc < 3 )
      {
         std::wcerr << TXT("Not enough parameters supplied.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      IOTableMBRControl row(false);

      char *ps;
      if( NULL != ( ps = getParameter( (char*)"-e", 2, argc, argv ) ) )
      {
          row.Enable = atoi( ps ) ? true : false;
          row.Enable_isValid = true;
      }

      if( NULL != ( ps = getParameter( (char*)"-d", 2, argc, argv ) ) )
      {
          row.Done = atoi( ps ) ? true : false;
          row.Done_isValid = true;
      }

      if( NULL != ( ps = getParameter( (char*)"-r", 2, argc, argv ) ) )
      {
         if( _stricmp( ps, "On" ) == 0 || _stricmp( ps, "0" ) == 0 )
         {
            row.MBRDoneOnReset_length = 1;
            row.MBRDoneOnReset[0] = 0;  // Done set to False upon Power-Reset
         }
         else if( _stricmp( ps, "Off" ) == 0 || strlen(ps) == 0 )
         {
            row.MBRDoneOnReset_length = 0; // No change to Done upon any reset
         }
         else
         {
            std::wcerr << TXT("-r parameter On or Off? State clearly, and try again.")  << std::endl << std::endl;
            return 1;
         }
      }

      if( row.isEmpty() )
      {
         std::wcerr << TXT("No parameters given required to set the MBRControl, please try again.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );

      result = device.setMBRControl( row, authent );
      if( result )
      {
         std::wcout << TXT("Successfully, MBRControl has been set to") << std::endl << TXT("\t");
         if( row.Enable_isValid )
            std::wcout << TXT("Enable=") << (row.Enable ? 1:0);

         if( row.Done_isValid )
            std::wcout << TXT(", Done=") << (row.Done ? 1:0);

         if( row.MBRDoneOnReset_length >= 0 )
         {
            std::wcout << TXT(", MBRDoneOnReset=");
            interpretResetType( row.MBRDoneOnReset_length, &row.MBRDoneOnReset[0] );
            std::wcout << std::endl;
         }
         std::wcout << std::endl;
      }
      else
         return 3;
   } // SetMBRControl



   // ========================= RP | RevertSP ============================

   else if( _stricmp( argv[1], "RevertSP" ) == 0 || _stricmp( argv[1], "RP" ) == 0 )
   {  // " RP <SPName> [-a- <Auth>] [-p- <Passwd>]"
      std::wcout << TXT("Performing RevertSP: ");

      if( getNumberOfRequiredParameters( argc, argv ) < 3 )
      {
         std::wcerr << TXT("Not enough parameters supplied.")  << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      if( (_stricmp( argv[2], "Locking" ) == 0 || _stricmp( argv[2], "LockingSP" ) == 0 )
          && !device.isEnterpriseSSC() && device.isSPInactive( (char*)"Locking" ) )
      {
         std::wcout << TXT("Locking SP has not been activated yet. Activate LockingSP first, then try again.") << std::endl;
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 3, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 3, argc, argv ) );

      if( _stricmp( argv[2], "Admin" ) == 0 || _stricmp( argv[2], "AdminSP" ) == 0 )
      {
         std::wcout << TXT("AdminSP ");
         if( device.isEnterpriseSSC() )
            std::wcout << TXT(" (Proprietary Seagate Enterprise SSC feature.) ") << std::endl;

         result = device.revertSP( (char*)"Admin", authent );
      }
      else if( _stricmp( argv[2], "Locking" ) == 0 || _stricmp( argv[2], "LockingSP" ) == 0 )
      {
         std::wcout << TXT("LockingSP ");
         if( device.isEnterpriseSSC() )
         {
            std::wcerr << TXT("Enterprise SSC cannot do RevertSP on LockingSP.")  << std::endl << std::endl;
            return 1;
         }

         result = device.revertSP( (char*)"Locking", authent );
      }
      else
      {
         std::wcerr << TXT("Incorrect SP name. Use Admin or Locking, and try again.")  << std::endl << std::endl;
         return 1;
      }

      if( result )
         std::wcout << TXT("has been successfully reverted to factory-state.") << std::endl;
      else
         return 3;
   } // RevertSP


   // ========================= TR | TPerReset ============================
   // ========================= RT | ResetTPer ============================

   else if( _stricmp( argv[1], "TPerReset" ) == 0 || _stricmp( argv[1], "TR" ) == 0 ||
            _stricmp( argv[1], "ResetTPer" ) == 0 || _stricmp( argv[1], "RT" ) == 0 )
   {  // " TPerReset/TR"
      std::wcout << TXT("Performing TPerReset: ");
#if 0 // deprecated jls20120405
      if ( device.isEnterpriseSSC() || device.isOpalSSC() )
      {
         std::wcerr << TXT(" *** TPerReset method applicable to Opal SSC 2 only.") << std::endl << std::endl;
         return 1;
      }
#endif
      if( device.tperReset( false ) )
         std::wcout << TXT("TPer has been reset.") << std::endl;
      else
         return 3;
   } // TPerReset

   // ========================= ETR | EnableTPerReset ============================

   else if( _stricmp( argv[1], "EnableTPerReset" ) == 0 ||
            _stricmp( argv[1], "ETR" ) == 0 )
   {  // " EnableTPerReset | ETR"
      std::wcout << TXT("Performing EnableTPerReset: ");
#if 0 // deprecated jls20120405
      if ( !device.isOpalSSCVersion2() ) // earlier than Opal SSC 2.
      {
         std::wcerr << TXT("*** TPerReset method only supported by Opal SSC 2") << std::endl << std::endl;
         return 1;
      }
#endif
      // See if user provided alternate authentication for TPerInfoTable Enabled column
      AuthenticationParameter authent( getParameter( (char*)"-a-", 3, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 3, argc, argv ) );

      // For now, force it Enabled with no way to disable.
      if( device.setTperResetEnable( authent, true ) )
         std::wcout << TXT("TPerReset has been enabled.") << std::endl;
      else
         return 3;
   } // EnableTPerReset

   // ========================= DTR | DisableTPerReset ============================

   else if( _stricmp( argv[1], "DisableTPerReset" ) == 0 ||
            _stricmp( argv[1], "DTR" ) == 0 )
   {  // " DisableTPerReset | DTR"
      std::wcout << TXT("Performing DisableTPerReset: ");
#if 0 // deprecated jls20120405
      if (  device.isEnterpriseSSC() || device.isOpalSSC() ) // equal or greater than Opal SSC 2.
      {
         std::wcerr << TXT("*** TPerReset method only supported by Opal SSC 2") << std::endl << std::endl;
         return 1;
      }
#endif
      // See if user provided alternate authentication for TPerInfoTable Enabled column
      AuthenticationParameter authent( getParameter( (char*)"-a-", 3, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 3, argc, argv ) );

      // For now, force it Enabled with no way to disable.
      if( device.setTperResetEnable( authent, false ) )
         std::wcout << TXT("TPerReset has been disabled.") << std::endl;
      else
         return 3;
   } // DisableTPerReset

    // ========================= GUP | GetUDSPort ============================

   else if( _stricmp( argv[1], "GetUdsPort" ) == 0 || 
            _stricmp( argv[1], "GUP" ) == 0 )
   {  // " GetUDSPort [-a- <Auth>] [-p- <Passwd>] [-any]"
      std::wcout << TXT("Performing GetUdsPort: ");

      if( getParameter( (char*)"-any", 2, argc, argv ) == NULL && !device.isSeagateDrive() )
      {
         std::wcerr << TXT("This feature is only available with a Seagate TCG drive.") << std::endl << std::endl;
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );
      IOTable_PortLocking portState(true);
      result = device.getUDSPort( portState, authent );

      if( result )
      {
         if( !portState.PortLocked_isValid && portState.LockOnReset_length < 0 )
         {
            std::wcerr << TXT("No data available (Due to lack of proper authentication).") << std::endl << std::endl;
            return 3;
         }
         else
         {
            std::wcout << TXT("Port is: ");
            printPortState( portState );
         }
      }
      else
         return 3;
   } // GetUDSPort

   // ========================= SUP | SetUDSPort ============================

   else if( _stricmp( argv[1], "SetUdsPort" ) == 0 ||
            _stricmp( argv[1], "SUP" ) == 0 )
   {  // " SetFWDownload/SF [-Locked <1/0>] [-LReset <On/Off>] [-a- <Auth>] [-p- <Passwd>] [-any]"
      std::wcout << TXT("Performing SetUdsPort: ");

      if( getParameter( (char*)"-any", 2, argc, argv ) == NULL && !device.isSeagateDrive() )
      {
         std::wcerr << TXT("This feature is only available with a Seagate TCG drive.")  << std::endl << std::endl;
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );
      IOTable_PortLocking portState;
      if( !parsePortSettingParameters( portState, 2, argc, argv ) )
      {
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      result = device.setUDSPort( portState, authent );

      if( result )
      {
         std::wcout << TXT("Port set:");
         printPortState( portState );
      }
      else
         return 3;
   } // SetFWDownload


   // ========================= GF | GetFirmwareDownload ============================

   else if( _stricmp( argv[1], "GetFWDownload" ) == 0 || 
            _stricmp( argv[1], "GFD" ) == 0 || 
            _stricmp( argv[1], "GF" ) == 0 )
   {  // " GetFWDownload/GF [-a- <Auth>] [-p- <Passwd>] [-any]"
      std::wcout << TXT("Performing GetFWDownload: ");

      if( getParameter( (char*)"-any", 2, argc, argv ) == NULL && !device.isSeagateDrive() )
      {
         std::wcerr << TXT("This feature is only available with a Seagate TCG drive.") << std::endl << std::endl;
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );
      IOTable_PortLocking portState(true);
      result = device.getFWDownload( portState, authent );

      if( result )
      {
         if( !portState.PortLocked_isValid && portState.LockOnReset_length < 0 )
         {
            std::wcerr << TXT("No data available (Due to lack of proper authentication).") << std::endl << std::endl;
            return 3;
         }
         else
         {
            std::wcout << TXT("Successfully, FWDownload port state is: ");
            printPortState( portState );
         }
      }
      else
         return 3;
   } // GetFWDownload

   // ========================= SFD | SetFirmwareDownload ============================

   else if( _stricmp( argv[1], "SetFWDownload" ) == 0 ||
            _stricmp( argv[1], "SFD" ) == 0 ||
            _stricmp( argv[1], "SF" ) == 0 )
   {  // " SetFWDownload/SF [-Locked <1/0>] [-LReset <On/Off>] [-a- <Auth>] [-p- <Passwd>] [-any]"
      std::wcout << TXT("Performing SetFWDownload: ");

      if( getParameter( (char*)"-any", 2, argc, argv ) == NULL && !device.isSeagateDrive() )
      {
         std::wcerr << TXT("This feature is only available with a Seagate TCG drive.")  << std::endl << std::endl;
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );
      IOTable_PortLocking portState;
      if( !parsePortSettingParameters( portState, 2, argc, argv ) )
      {
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      result = device.setFWDownload( portState, authent );

      if( result )
      {
         std::wcout << TXT("Successfully, FWDownload port has been set as\n\t");
         printPortState( portState );
      }
      else
         return 3;
   } // SetFWDownload

   // ========================= FD | FWDownload ============================

#if 1 //#ifdef FIRMWARE_DOWNLOAD_OPTION
   else if( _stricmp( argv[1], "FWDownload" ) == 0 ||
            _stricmp( argv[1], "FD" ) == 0 )
   {  // " FWDownload/FD <pathname_of_signed_firmware_file.lod> [-any]"
      std::wcout << TXT("Performing Signed Firmware Download ") << std::endl; 

      if( getParameter( (char*)"-any", 3, argc, argv ) == NULL && !device.isSeagateDrive() )
      {
         std::wcerr << TXT("This feature is only available with a Seagate TCG drive.")  << std::endl << std::endl;
         return 1;
      }

      if( getNumberOfRequiredParameters( argc, argv ) < 3 )
      {
         std::wcerr << TXT("Not enough parameters supplied.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      char fileName[256];
      if( NULL != strstr( argv[2], ".lod" ) || NULL != strstr( argv[2], ".LOD" ) )
      {
         sprintf_s( fileName, sizeof(fileName), "%s", argv[2] );
      }
      else
      {
         sprintf_s( fileName, sizeof(fileName), "%s.lod", argv[2] );
      }

      bool result = device.firmwareDownload( fileName );

      if ( result )
      {
         std::wcout << TXT("Firmware Download finished. The drive must be POWER-CYCLED!") << std::endl;
      }
      else
      {
         std::wcout << TXT("Firmware download failed: ") /*<< statusToString((tUINT16)err.Info.Detail)*/ << std::endl;
         return 3;
      }
   }
#endif
   
   // ***************************************************************************
   // ********************** ENTERPRISE SSC COMMAND GROUP ***********************
   // ***************************************************************************
   // RANGE:  
   // FIPS      SetATAFIPS                       
   // 

   // ========================= EAR | EnableAuthorityForRange ============================

   else if( _strnicmp( argv[1], "EnableAuthorityForRange", sizeof("EnableAuthorityForRange")-1 ) == 0 ||
            _strnicmp( argv[1], "EAR", sizeof("EAR")-1 ) == 0 )
   {  // " EAR[<#>[-<#>]]|[All] [-a- <Auth>] [-p- <Passwd>]"

      std::wcout << TXT("Performing EnableAuthorityForRange: "); 

      if( !device.isEnterpriseSSC() )
      {
         std::wcout << TXT(" *** not supported by this device.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      int bandNo = 0;
      int lastBandNo = 0;

      if( _stricmp( argv[1] + sizeof("EnableAuthorityForRange") -1, "All" ) == 0 ||
          _stricmp( argv[1] + sizeof("EAR") -1, "All" ) == 0 )
      {
         if( !device.getMaxBands( &lastBandNo ) )
            return 3;
      }
      else
      {
         if( _strnicmp( argv[1], "EAR", sizeof("EAR")-1 ) == 0 )
            bandNo = atoi( argv[1] + sizeof("EAR") -1 );
         else
            bandNo = atoi( argv[1] + sizeof("EnableAuthorityForRange") -1 );

         if( NULL != strchr( argv[1], '-' ) )
            lastBandNo = atoi( strchr( argv[1], '-' ) +1 );
      }

      if( !device.isBandNoValid( bandNo ) || !device.isBandNoValid( lastBandNo ) )
      {
         if( lastBandNo > 0 )
            std::wcerr << TXT(" *** Range ") << bandNo << TXT(" to ") << lastBandNo << TXT(" is invalid.") << std::endl << std::endl;
         else
            std::wcerr << TXT(" *** Range ") << bandNo << TXT(" is invalid.") << std::endl << std::endl;
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );

      do
      {
         //if( bandNo < 10 && lastBandNo != 0 && bandNo < lastBandNo )
         std::wcout << std::endl << std::setw(3) << bandNo << TXT(": ");

         result = device.enableDisableBand( true, bandNo, authent );
         if( result )
            std::wcout << TXT(" Authority has been enabled");
         else
         {
            std::wcout << TXT(" Authority enable FAILED");
            return 3;
         }

         if( lastBandNo == 0 || bandNo >= lastBandNo )
            break;
         else
            bandNo++;

      } while( bandNo <= lastBandNo );

      std::wcout << std::endl; 
   } // EnableAuthorityForRange


   // ======================= DAR | DisableAuthorityForRange ========================

   else if( _strnicmp( argv[1], "DisableAuthorityForRange", sizeof("DisableAuthorityForRange")-1 ) == 0 ||
            _strnicmp( argv[1], "DAR", sizeof("DAR")-1 ) == 0 )
   {  // " DAR[<#>[-<#>]]|[All] [-a- <Auth>] [-p- <Passwd>]"

      std::wcout << TXT("Performing DisableAuthorityForRange: "); 

      if( !device.isEnterpriseSSC() )
      {
         std::wcout << TXT(" *** not supported by this device.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }       
      int bandNo = 0;
      int lastBandNo = 0;

      if( _stricmp( argv[1] + sizeof("DisableAuthorityForRange") -1, "All" ) == 0 ||
          _stricmp( argv[1] + sizeof("DAR") -1, "All" ) == 0 )
      {
         if( !device.getMaxBands( &lastBandNo ) )
            return 3;
      }
      else
      {
         if( _strnicmp( argv[1], "DAR", sizeof("DAR")-1 ) == 0 )
            bandNo = atoi( argv[1] + sizeof("DAR") -1 );
         else
            bandNo = atoi( argv[1] + sizeof("DisableAuthorityForRange") -1 );

         if( NULL != strchr( argv[1], '-' ) )
            lastBandNo = atoi( strchr( argv[1], '-' ) +1 );
      }

      if( !device.isBandNoValid( bandNo ) || !device.isBandNoValid( lastBandNo ) )
      {
         if( lastBandNo > 0 )
            std::wcerr << TXT(" *** Range ") << bandNo << TXT(" to ") << lastBandNo << TXT(" is invalid.") << std::endl << std::endl;
         else
            std::wcerr << TXT(" *** Range ") << bandNo << TXT(" is invalid.") << std::endl << std::endl;
         return 1;
      }

      AuthenticationParameter authent( getParameter( (char*)"-a-", 2, argc, argv ), (tUINT8*) getParameter( (char*)"-p-", 2, argc, argv ) );

      do
      {
         std::wcout << std::endl << std::setw(3) << bandNo << TXT(": ");

         result = device.enableDisableBand( false, bandNo, authent );
         if( result )
            std::wcout << TXT(" Authority has been disabled");
         else
         {
            std::wcout << TXT(" Authority disable FAILED");
            return 3;
         }

         if( lastBandNo == 0 || bandNo >= lastBandNo )
            break;
         else
            bandNo++;

      } while( bandNo <= lastBandNo );

      std::wcout << std::endl; 
   } // DisableAuthorityForRange


   // ***************************************************************************
   // **************************** ATA COMMAND GROUP ****************************
   // ***************************************************************************
   // SECURITY: ATASetUserPW, ATASetMasterPW, ATAUnlock, ATAFreezeLock
   //           ATADisablePassword, ATAErase               
   // FIPS      SetATAFIPS                       
   //
   
   // ========================= ASU | ATASetUser ============================

   else if( _stricmp( argv[1], "ATASetPasswordUser" ) == 0 ||   // deprecated command
            _stricmp( argv[1], "ATASetUser" ) == 0 ||
            _stricmp( argv[1], "ASPU" ) == 0 ||    // deprecated command
            _stricmp( argv[1], "ASU" ) == 0 )
   {  // " ATASetPasswordUser/ASU <Password> [MasterHigh|MH] | [MasterMaximum|MM]"
      std::wcout << TXT("Performing ATASetUser Password: ");

      if( !device.isATADevice() )
      {
         std::wcerr << TXT("This feature is only applicable to a ATA drive.") << std::endl << std::endl;
         return 1;
      }

      if( argc < 3 )
      {
         std::wcerr << TXT("Not enough parameters supplied.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      bool masterPwdCapabilityHigh = true;
      dta::tBytes password;
      int length = (int) strlen( argv[2] );

      if( length == 0 || length > 32 )
      {
         std::wcerr << TXT("ATA password is too ")
            << (length == 0 ? TXT("short, minimum is 1 byte.") : TXT("long, maximum is 32 bytes."))
            << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      password.resize(length);
      memcpy( &password[0], argv[2], length );

      if( argc > 3 )
      {
         if( _stricmp( argv[3], "MasterMaximum" ) == 0 || _stricmp( argv[3], "MM" ) == 0 )
            masterPwdCapabilityHigh = false;
      }

      result = device.ataSecuritySetPasswordUser( password, masterPwdCapabilityHigh );

      if( result )
         std::wcout << TXT("Successfully, ATASetPasswordUser has been set with ") 
                    << (masterPwdCapabilityHigh? TXT("MasterHigh") : TXT("MasterMaximum")) << TXT(".") 
                    << std::endl;
      else
         return 3;
   } // ATASetPasswordUser

   // ========================= ASM | ATASetMaster ============================

   else if( _stricmp( argv[1], "ATASetPasswordMaster" ) == 0 || // deprecated command
            _stricmp( argv[1], "ATASetMaster" ) == 0 ||
            _stricmp( argv[1], "ASPM" ) == 0 ||   // deprecated command
            _stricmp( argv[1], "ASM" ) == 0 )
   {  // " ATASetPasswordMaster/ASPM <Password> [<MasterIdentifier>]"
      std::wcout << TXT("Performing ATASetMaster Password: ");

      if( !device.isATADevice() )
      {
         std::wcerr << TXT("This feature is only applicable to a ATA drive.")  << std::endl << std::endl;
         return 1;
      }

      if( argc < 3 )
      {
         std::wcerr << TXT("Not enough parameters supplied.")  << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      dta::tBytes password;
      int length = (int) strlen( argv[2] );

      if( length == 0 || length > 32 )
      {
         std::wcerr << TXT("ATA password is too ")
            << (length == 0 ? TXT("short, minimum is 1 byte.") : TXT("long, maximum is 32 bytes."))
            << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      password.resize(length);
      memcpy( &password[0], argv[2], length );

      tUINT16 masterPwdIdentifier = 0;
      if( argc > 3 )
         masterPwdIdentifier = atoi( argv[3] );

      result = device.ataSecuritySetPasswordMaster( password, masterPwdIdentifier );

      if( result )
         std::wcout << TXT("Successfully, ATASetPasswordMaster has been set with MasterPwdIdentifier ") 
                    << masterPwdIdentifier << TXT(".") << std::endl;
      else
         return 3;
   } // ATASetPasswordMaster

   // ========================= AU | ATAUnlock ============================

   else if( _stricmp( argv[1], "ATAUnlock" ) == 0 ||
            _stricmp( argv[1], "AU" ) == 0 )
   {  // " ATAUnlock/AU <Password> [User/Master]"
      std::wcout << TXT("Performing ATAUnlock: ");

      if( !device.isATADevice() )
      {
         std::wcerr << TXT("This feature is only applicable to a ATA drive.")  << std::endl << std::endl;
         return 1;
      }

      if( argc < 3 )
      {
         std::wcerr << TXT("Not enough parameters supplied.")  << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      bool userPassword = true;
      dta::tBytes password;
      int length = (int) strlen( argv[2] );

      if( length == 0 || length > 32 )
      {
         std::wcerr << TXT("ATA password is too ")
            << (length == 0 ? TXT("short, minimum is 1 byte.") : TXT("long, maximum is 32 bytes."))
            << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      password.resize(length);
      memcpy( &password[0], argv[2], length );

      if( argc > 3 )
      {
         if( _stricmp( argv[3], "Master" ) == 0 )
            userPassword = false;
      }

      result = device.ataSecurityUnlock( password, userPassword );

      if( result )
         std::wcout << TXT("Successfully, ATAUnlock has been done with ") 
                    << (userPassword? TXT("User") : TXT("Master")) << TXT("Password.") << std::endl;
      else
         return 3;
   } // ATAUnlock

   // ========================= AFL | ATAFreezeLock ============================

   else if( _stricmp( argv[1], "ATAFreezeLock" ) == 0 ||
            _stricmp( argv[1], "AFL" ) == 0 )
   {  // " ATAFreezeLock/AFL"
      std::wcout << TXT("Performing ATAFreezeLock: ");

      if( !device.isATADevice() )
      {
         std::wcerr << TXT("This feature is only applicable to a ATA drive.") << std::endl << std::endl;
         return 1;
      }

      result = device.ataSecurityFreezeLock();

      if( result )
         std::wcout << TXT("Successfully, ATAFreezeLock has been done.") << std::endl;
      else
         return 3;
   } // ATAFreezeLock

   // ========================= ADP | ATADisablePassword ============================

   else if( _stricmp( argv[1], "ATADisablePassword" ) == 0 ||
            _stricmp( argv[1], "ADP" ) == 0 )
   {  // " ATADisablePassword/ADP <Password> [User/Master]"
      std::wcout << TXT("Performing ATADisablePassword: ");

      if( !device.isATADevice() )
      {
         std::wcerr << TXT("This feature is only applicable to a ATA drive.")  << std::endl << std::endl;
         return 1;
      }

      if( argc < 3 )
      {
         std::wcerr << TXT("Not enough parameters supplied.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      bool userPassword = true;
      dta::tBytes password;
      int length = (int) strlen( argv[2] );

      if( length == 0 || length > 32 )
      {
         std::wcerr << TXT("ATA password is too ")
            << (length == 0 ? TXT("short, minimum is 1 byte.") : TXT("long, maximum is 32 bytes."))
            << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      password.resize(length);
      memcpy( &password[0], argv[2], length );

      if( argc > 3 )
      {
         if( _stricmp( argv[3], "Master" ) == 0 )
            userPassword = false;
      }

      result = device.ataSecurityDisablePassword( password, userPassword );

      if( result )
         std::wcout << TXT("Successfully, ATADisablePassword has been done via ") 
                    << (userPassword ? TXT("User") : TXT("Master")) << TXT("Password.") << std::endl;
      else
         return 3;
   } // ATADisablePassword

   // ========================= AED | ATAEraseDevice ============================

   else if( _stricmp( argv[1], "ATAEraseDevice" ) == 0 ||
            _stricmp( argv[1], "AED" ) == 0 )
   {  // " ATAEraseDevice/AE <Password> [User/Master] [Enhanced/EH/Normal/NM]"
      std::wcout << TXT("Performing ATAEraseDevice: ");

      if( !device.isATADevice() )
      {
         std::wcerr << TXT("This feature is only applicable to a ATA drive.")  << std::endl << std::endl;
         return 1;
      }

      if( argc < 3 )
      {
         std::wcerr << TXT("Not enough parameters supplied.")  << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      bool userPassword = true;     // Set Default
      bool enhancedErase = true;    // Set Default
      dta::tBytes password;
      int length = (int) strlen( argv[2] );

      if( length == 0 || length > 32 )
      {
         std::wcerr << TXT("ATA password is too ")
            << (length == 0 ? TXT("short, minimum is 1 byte.") : TXT("long, maximum is 32 bytes."))
            << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      password.resize(length);
      memcpy( &password[0], argv[2], length );

      if( argc > 3 )
      {
         if( _stricmp( argv[3], "Master" ) == 0 )
            userPassword = false;
      }

      if( argc > 4 )
      {
         if( _stricmp( argv[4], "Normal" ) == 0 || _stricmp( argv[4], "NM" ) == 0 )
            enhancedErase = false;
      }

      result = device.ataSecurityEraseDevice( password, userPassword, enhancedErase );

      if( result )
         std::wcout << TXT("Successfully, ATAEraseDevice has been done with ") 
                    << (userPassword ? TXT("User") : TXT("Master")) << TXT("Password in ") 
                    << (enhancedErase? TXT("Enhanced") : TXT("Normal")) << TXT("-Erase mode.") << std::endl;
      else
         return 3;
   } // ATAEraseDevice

   // ========================= SAFP | SetATAFips ============================

   //
   // FIPS compliance mode configurations for ATA and TCG security
   // Setting a new or out-of-factory SED to ATA-FIPS compliance mode or TCG-FIPS compliance mode
   //
   else if (  _stricmp( argv[1], "SAFP" ) == 0 ||
             _strnicmp( argv[1], "SetAtaFIPS", sizeof("SetAtaFIPS")-1 ) == 0 )
   {  // " SAF <MasterPassword> <UserPassword> [MasterHigh/MH/MasterMaximum/MM]"
      std::wcout << "Performing SetAtaFIPS: ";

      if( !device.isATADevice() )
      {
         std::wcerr << TXT("This feature is only applicable to a ATA drive.") << std::endl << std::endl;
         return 1;
      }

      if( argc < 4 )
      {
         std::wcerr << TXT("Not enough parameters supplied.") << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      bool masterPwdCapabilityHigh = true;
      dta::tBytes masterPwd, userPwd;
      int length1 = (int) strlen( argv[2] );
      int length2 = (int) strlen( argv[3] );
      
      if( length1 > 32 || length2 > 32 )
      {
         std::wcerr << TXT("ATA password is too long, maximum is 32 bytes.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      if( length1 < 4 || length2 < 4 )
      {
         std::wcerr << TXT("ATA password is too short, minimum is 4 bytes.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      masterPwd.resize(length1);
      memcpy( &masterPwd[0], argv[2], length1 );

      userPwd.resize(length2);
      memcpy( &userPwd[0], argv[3], length2 );

      if( argc > 4 )
      {
         if( _stricmp( argv[4], "MasterMaximum" ) == 0 || _stricmp( argv[4], "MM" ) == 0 )
            masterPwdCapabilityHigh = false;
      }

      result = device.setATAFIPS( masterPwd, userPwd, masterPwdCapabilityHigh );

      if( result )
         std::wcout << TXT("TXT(Successfully, ATAFIPS has been set.") << std::endl;
      else
         return 3;
   } // ATAFIPS

   // ***************************************************************************
   // ************************** TCG FIPS COMMAND GROUP *************************
   // ***************************************************************************
   // FIPS      GetFipsPolicy, SetFipsPolicy,                        
 
   // ========================= GFP | GetFipsPolicy ============================

   else if (  _stricmp( argv[1], "GFP" ) == 0  ||
             _strnicmp( argv[1], "GetFipsPolicy", sizeof("GetFipsPolicy")-1 ) == 0 )

   {  // " GFP "
      std::wcout << TXT("Performing GetFipsPolicy: ");

      if( argc != 2 )
      {
         std::wcerr << TXT("Incorrect parameters given.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      // Perform FIPS queries on drive
      result = device.getFIPSPolicy();

      std::wcout << std::endl << TXT("  This drive appears to ") << (result ? TXT("BE") : TXT("NOT BE"))
         << TXT(" operating in a typical FIPS Security Policy mode.") << std::endl;

      if( ! result )
         return 3;

   } // GetFIPS

   // ========================= SFP | SetFIPSPolicy ============================

   else if (  _stricmp( argv[1], "SFP" ) == 0 ||
             _strnicmp( argv[1], "SetFipsPolicy", sizeof("SetFipsPolicy")-1 ) == 0 )

   {  // " SFP <SIDPIN> <Admin1Passwd>"
      std::wcout << TXT("Performing SetFipsPolicy: ");

      if( argc < 4 )
      {
         std::wcerr << TXT("Not enough parameters supplied.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      dta::tBytes sidPIN, admin1PIN;
      int length1 = (int) strlen( argv[2] );
      int length2 = (int) strlen( argv[3] );
      if( length1 > 32 || length2 > 32 )
      {
         std::wcerr << TXT("Too long PIN, maximum is 32 bytes.") << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      if( length1 < 4 || length2 < 4 )
      {
         std::wcerr << TXT("Too short PIN, minimum is 4 bytes.")  << std::endl << std::endl;
         usage( argv[0], argv[1], true, bManPage );
         return 1;
      }

      sidPIN.resize(length1);
      memcpy( &sidPIN[0], argv[2], length1 );

      admin1PIN.resize(length2);
      memcpy( &admin1PIN[0], argv[3], length2 );

      result = device.setFIPSPolicy( sidPIN, admin1PIN );

      if( result )
      {
         std::wcout << TXT("\n NOTE: Drive state was successfully set using a generic FIPS 140-2 Module") << std::endl
         << TXT("      Security Policy document. User must still confirm requirements using") << std::endl
         << TXT("      the specific FIPS MSP Document for each FIPS140-capable Drive!")<< std::endl;
      }
      else
      {
         std::wcerr << TXT("\n *** FAILED setting FIPS 140-2 Module Security Policy requirements!") << std::endl;
         return 3;
      }
   } // SetFips


// The following commands are deprecated in Version 1.6, but left for backward compatibility

   else if( _strnicmp( argv[1], "OpalSSC", sizeof("OpalSSC")-1 ) == 0 || _strnicmp( argv[1], "OS", sizeof("OS")-1 ) == 0 )
   {  // " OpalSSC [NOT | INVERT]"
      int   success = 0;   // If is OpalSSC, return 0
      int   failure = 1;   // If is NOT OpalSSC, return 1

      if( argc > 2  && (_stricmp( argv[2], "NOT" ) == 0 || _stricmp( argv[2], "INVERT" ) == 0 ) )
      {
         success = 1;      // If is NOT OpalSSC, return 0
         failure = 0;
      }

      if ( device.isOpalSSC() )
      {
         std::wcout << TXT("Device is Opal SSC" << std::endl);
         return success;
      }
      else
      {
         std::wcout << TXT("Device is NOT Opal SSC") << std::endl;
         return failure;
      }
   } // OpalSSC

   else if( _strnicmp( argv[1], "EnterpriseSSC", sizeof("EnterpriseSSC")-1 ) == 0 || _strnicmp( argv[1], "ES", sizeof("ES")-1 ) == 0 )
   {  // " EnterpriseSSC [NOT | INVERT]"
      int   success = 0;   // If is EnterpriseSSC, return 0
      int   failure = 1;   // If is NOT EnterpriseSSC, return 1

      if( argc > 2  && (_stricmp( argv[2], "NOT" ) == 0 || _stricmp( argv[2], "INVERT" ) == 0 ) )
      {
         success = 1;      // Swap return values
         failure = 0;
      }

      if ( device.isEnterpriseSSC() )
      {
         std::wcout << TXT("Device is Enterprise SSC") << std::endl;
         return success;
      }
      else
      {
         std::wcout << TXT("Device is NOT Enterprise SSC") << std::endl;
         return failure;
      }
   } // EnterpriseSSC

   else if( _strnicmp( argv[1], "SpActive", sizeof("SpActive")-1 ) == 0 || _strnicmp( argv[1], "SA", sizeof("SA")-1 ) == 0 )
   {  // " SpActive [NOT] "

      int   success = 0;      // If is Active, return 0
      int   failure = 1;      // If is NOT Active, return 1
      char* sp = "Locking";   // Default SP to test

      for ( int ii = 2; ii < argc ; ii++ )
      {
         if( _stricmp( argv[ii], "NOT" ) == 0 ) 
         {
            success = 1;      // Swap return values
            failure = 0;
            break;
         }
      }

      for ( int ii = 2; ii < argc ; ii++ )
      {
         if( _stricmp( argv[ii], "NOT" ) == 0 ) 
            continue;

         if( _stricmp( argv[ii], "Locking" ) == 0 || _stricmp( argv[ii], "LockingSP" ) == 0 ) 
            continue;

         std::wcout << TXT("Unrecognized SP: \"") << argv[ii] << TXT("\"") << std::endl;
      }

      if ( device.isSPInactive( sp ) )
      {
         std::wcout << sp << TXT(" is INACTIVE") << std::endl;
         return failure;
      }
      else
      {
         std::wcout << sp << TXT(" is ACTIVE") << std::endl;
         return success;
      }
   } // SpInactive

   else if( _strnicmp( argv[1], "SecurityState", sizeof("SecurityState")-1 ) == 0 || _strnicmp( argv[1], "SS", sizeof("SS")-1 ) == 0 )
   {  // " SecurityState "

      device.securityState(false);

      if( !device.isEnterpriseSSC() )
      {
         std::wcout << TXT("  AdminSP State      = ");
         device.reportSPState( "Admin" );

         std::wcout << TXT("  LockingSP State    = ");
         device.reportSPState( "Locking" );
      }
   } // SecurityState

   else
   {
      std::wcerr << TXT("Command \"") << argv[1] << TXT("\" not recognized, please re-issue the command or use help:") << std::endl << std::endl;
      usage( argv[0] );
      return 1;
   }

   return 0;
} // main



//=======================================================================================
// getParameter searchs the arg list, beginning at index 'start', returning
// remainder of a parameter that begins with the specified tag string. The
// tag can either prefix the parameter, or it can have a space char before 
// the name of the parameter.

char* getParameter( const char *tag, const int start, const int argc, char* argv[] )
{
   if( start < 0 || start >= argc ) // 'start' is counted from 0.
      return NULL;

   char *p = NULL;
   for( int ii = start; ii < argc; ii++ )
   {
      if( _strnicmp( argv[ii], tag, strlen( tag ) ) == 0 )
      {
         // first chars of argv match the tag string 
         p = argv[ii] + strlen( tag );  // p is the next char following tag string

         // if separated by spaces, the next argv is the parm value.
         if( ( 0 == *p ) && ( ii +1 < argc ) ) 
            p = argv[ii+1];

         break;
      }
   }

   return p;
} // getParameter


//=======================================================================================
// extractParameter searchs the arg list, beginning at argv[1], looking
// for a parameter that begins with the specified tag string. The tag can 
// either prefix the parameter, or it can have a space char before the 
// parameter name. If found, return either the entire argv[] value or
// just the tail of the parameter name following the tag. If an argv[]
// containing the tag is not found, return a NULL pointer. Because this
// function extracts parameters, remove returned value from argv[] list
// and decrement the argc count.  

char* extractParameter( char *tag, const bool getAll, int &argc, char* argv[] )
{
   size_t taglen  = strlen( tag );
   char *p     = NULL;         // Param value to return
   
   for( int ii = 1; ii < argc; ii++ )
   {
      if( _strnicmp( argv[ii], tag, taglen ) == 0 )
      {
         // First chars of argv match the tag string, so see if a
         // param string starts at next char following the tag.

         if( strlen( argv[ii] ) == taglen )    // tag is same length as argv[] 
         {
            // This argv[] is the same as the tag, so if getAll, fall
            // through and return the argv containing the tag, ignoring
            // the next argv value. Otherwise, return the parameter
            // value that is in the next argv by first decrementing the
            // argc and moving argv[] values down.

            if( !getAll )
            {
               // Return just the parameter value that is in the next 
               // argv by decrementing the argc and moving the argv[]
               // values down first, and then falling thru.

               taglen = 0;
               argc -= 1;
               for( int jj = ii; jj < argc; jj++ )
                  argv[jj] = argv[jj + 1];
            }
         }

         // The argv[] was longer than the tag, so don't worry about 
         // the next argv[] contents. Stash away either the entire argv 
         // or just the remaining tail after the tag, depending on 
         // getAll value.

         p = argv[ii] + ( getAll ? 0 : taglen );

         // Decrement the arg count and move all argv[] values down one.
         argc -= 1;
         for( int jj = ii; jj < argc; jj++ )
            argv[jj] = argv[jj + 1];

         break;
      } // if tag found
   } //for

   return p;
} // extractParameter


//=======================================================================================
// Given a "tag" string that marks the end of the arg search, return the
// number of args remaining in the command line before the tagged arg. 
// NOTE: The returned arg count is one greater than the arg index, so caller
// will have to subtract 1 to get the arg index.

int getNumberOfRequiredParameters( int argc, char* argv[], char *tag )
{
   if( NULL == tag ) // If no tag, then all args can be parameters
      return argc;

   int ii;
   for( ii = 1; ii < argc; ii++ )
   {
      if( _strnicmp( argv[ii], tag, strlen( tag ) ) == 0 )
         return ii;
   }

   return argc;
} // getNumberOfRequiredParameters

//=======================================================================================
TCG_BANDNOs * parseParameterOfBandNumbers( char *parmString, TCG_BANDNOs *pSingleUserModeList )
{ // "All" or "Band# list" (e.g., "0,1,7,9,15")

   if( NULL != parmString )
   {
      if( _stricmp( parmString, "All" ) == 0 )
      {
         (*pSingleUserModeList).resize( 1 );
         (*pSingleUserModeList)[0] = -1;
      }
      else
      {
         unsigned int ranges = 0;
         char *p = parmString;

         (*pSingleUserModeList).resize( ( strlen(p) + 1 ) / 2 );
         if( strlen( p ) )
         {
            while( 0 != *p && ranges < (*pSingleUserModeList).size() )
            {
               while( 0 != *p && ( *p < '0' || *p > '9' ) ) p++;  // trim non-digit chars, and look for next number
               if( 0 == *p )
                  break;

               (*pSingleUserModeList)[ranges++] = atoi( p );
               while( 0 != *p && *p >= '0' && *p <= '9' ) p++;  // skip the current no
            }
         }

         (*pSingleUserModeList).resize( ranges );
      }

      return pSingleUserModeList;
   }
   else
   {
      return NULL;
   }
} // parseParameterOfBandNumbers

//=======================================================================================
UINT64VALs * parseParameterOfIntegers( char *parmString, UINT64VALs *pUIntegerArrary )
{ // "100,1177,7,9,15" or "100 1177 7 9 15" or "200x16" (16 same value of 200)

   if( NULL == pUIntegerArrary )
      return NULL;

   if( NULL == parmString )
   {
      (*pUIntegerArrary).resize( 0 );
      return NULL;
   }

   if( 0 == *parmString )
   {
      (*pUIntegerArrary).resize( 0 );
      return pUIntegerArrary;
   }

   unsigned int count = 0;
   char *p = parmString;

   while( 0 != *p && count < (*pUIntegerArrary).size() )
   {
      while( 0 != *p && ( *p < '0' || *p > '9' ) ) p++;  // trim non-digit chars, and look for next number
      if( 0 == *p )
         break;

      (*pUIntegerArrary)[count++] = _atoi64( p );

      while( 0 != *p && *p >= '0' && *p <= '9' ) p++;  // skip the current no
      while( 0 != *p && ' ' == *p ) p++;  // skip spaces

      if( ( 'x' == *p || 'X' == *p || '*' == *p ) &&  1 == count )
      {
         while( 0 != *p && ( *p < '0' || *p > '9' ) ) p++;  // trim non-digit chars, and look for next number

         if( 0 != *p )
            count = atoi( p );

         if( 0 == *p || count > (*pUIntegerArrary).size() ) // set for all same value
            count = (unsigned int) (*pUIntegerArrary).size();

         for( unsigned int ii=1; ii<count; ii++ )
            (*pUIntegerArrary)[ii] = (*pUIntegerArrary)[0];

         break;
      }
   }

   (*pUIntegerArrary).resize( count );
   return pUIntegerArrary;
} // parseParameterOfIntegers

//=======================================================================================
bool parsePortSettingParameters( IOTable_PortLocking & portState, int start, int argc, char* argv[] )
{
   char *p = getParameter( (char*)"-Locked", start, argc, argv );
   if( NULL != p )
   {
      portState.PortLocked = ( atoi(p) ? true : false );
      portState.PortLocked_isValid = true;
   }
   else
      portState.PortLocked_isValid = false;

   p = getParameter( (char*)"-LReset", start, argc, argv );
   if( NULL != p )
   {
      if( _stricmp( p, "On" ) == 0 || _stricmp( p, "0" ) == 0 )
      {
         portState.LockOnReset_length = 1;
         portState.LockOnReset[0] = 0;  // Lock-on-Power-Reset
      }
      else if( _stricmp( p, "Off" ) == 0 || strlen(p) == 0 )
      {
         portState.LockOnReset_length = 0; // Turn off Lock-on-Reset
      }
      else
      {
         std::wcerr << TXT("-Reset On or Off? State clearly, and try again.")  << std::endl << std::endl;
         return false;
      }
   }
   else
      portState.LockOnReset_length = -1;

   if( !portState.PortLocked_isValid && portState.LockOnReset_length < 0 )
   {
      std::wcerr << TXT("No parameters given to set the port state, please try again.")  << std::endl << std::endl;
      usage( argv[0], argv[1], true, false );
      return false;
   }
   else
   {
      printPortState( portState );

      std::wcout << TXT("\nCorrect parameter(s) to proceed? (y/n)");
#if defined(_WIN32) // nvn20110728
      char c = _getche();
#else
      char c = getchar();
#endif

      std::wcout << std::endl;
      if( 'y' != c && 'Y' != c )
         return false;
      else
         return true;
   }
} // parsePortSettingParameters

//=======================================================================================
bool printPortState( IOTable_PortLocking & portState )
{
   bool result = true;

   if( !portState.PortLocked_isValid && portState.LockOnReset_length < 0 )
   {
      result = false;
      return result;
   }

   if( portState.PortLocked_isValid )
      std::wcout << TXT("Locked=") << (portState.PortLocked ? 1 : 0);

   if( -1 != portState.LockOnReset_length )
   {
      if( portState.PortLocked_isValid )
         std::wcout << TXT(", ");

      std::wcout << TXT("LockOnReset=");
      result = interpretResetType( portState.LockOnReset_length, &portState.LockOnReset[0] );
   }

   std::wcout << TXT(".") << std::endl;
   return result;
} // printPortState


//============================== End of File =============================================
