//=================================================================================================
//  TCG-Usage.cpp
//  Provides user information on usage of the TCG CommandLine Toolkit.
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

#include <iostream>
using namespace std;

#if (__linux__) // nvn
int _stricmp( const char * s1, const char * s2 )
{
   for (;;)
   {
      if (*s1 != *s2) {
         int c1 = toupper((unsigned char)*s1);
         int c2 = toupper((unsigned char)*s2);

         if (c2 != c1) {
            return c2 > c1 ? -1 : 1;
         }
         } else {
            if (*s1 == '\0') {
               return 0;
         }
      }
      ++s1;
      ++s2;
   }
   return 0;
}

int _strnicmp(const char *s1, const char *s2, size_t n)
{
   for (;;) {
      if (n-- == 0) {
         return 0;
      }
      if (*s1 != *s2) {
         int c1 = toupper((unsigned char)*s1);
         int c2 = toupper((unsigned char)*s2);

         if (c2 != c1) {
            return c2 > c1 ? -1 : 1;
         }
      } else {
         if (*s1 == '\0') {
            return 0;
         }
      }
   ++s1;
   ++s2;
   }
   return 0;
}
#endif

// =================================================================================
// To minimize the complexity of the command options, a tiered command 
// structure is used. This breaks the possible commands into groups of 
// associated functionality:
//    COMMON:    Usage, help, Options (--NoLog, --Verbose, --Quiet, --All
//               --Silo), ShowCommandGroups (SEA/TCG/Opal/Ent/ATA,eDrive,FIPS,User), 
//               ShowDrives, Read/WriteUserLBA, Show MBR Partition Table, etc
//    TCG:       ListBands, Set/Resize/Lock/Unlock/LockOnReset/Erase Bands,
//               Enable/Disable Authority, Read/Write DataStore, RevertSP, 
//               RNG, ResetStack, TPerReset, 
//               ChangePIN, OptionalFeatureSets, 
//    OPAL:      ActivateSP, ReactivateSP, GrantAccess, Read/Write SMBR,
//               Get/Set ShadowMBRCtrl,
//    ENTERPRISE: Enable/Disable Range Authority
//    EDRIVE:    ?any specific cmds such as probe silo, pw silo, tcg silo?
//    SEAGATE:   Get/SetFW, FW Download,
//               ATA: User/Master SetPW, DisablePW, Unlock, Freeze, Erase,
//               FIPS: Configure/Verify SOM1/SOM2  
//
// Commands could also be grouped according to target drive features:
// 
//    GLOBAL:    Usage, Help, Options (--NoLog, --Verbose, --Quiet, --All ),
//               ShowCommandGroups (TPER, SP, BAND, AUTH, DST, SMBR, ATA,
//               FIPS, USER), ShowDrives, 
//    TPER:      ResetStack, TPerReset, Get/Set FW, FW Download,
//               List FeatureSets, GetTCG-SSC, IDENTIFY-DEVICE Data,
//    SP:        ActivateSP, ReactivateSP, RevertSP, GenRandomSP, IsActiveSP
//    RANGE:     List/Set/Resize/Lock/Unlock/LockOnReset/Enable/Disable/Erase Bands
//    AUTHORITY: List/Enable/Disable Authority, ChangePIN, GrantAccess, 
//    DATASTORE: Read/Write DataStorTable, 
//    SHADOWMBR: Read/Write SMBR, Get/Set SMBR Ctrl, 
//    SEAGATE:   Get/Set FWDownload, SOM0, SOM1, SOM2
//    ATA(SOM1): User/Master SetPW, DisablePW, Unlock, Freeze, Erase, FW Download, 
//    FIPS:      Configure/Verify SOM1/SOM2 
//    USER-DATA: Read/Write LBA, MBR Partition Table, 
// =================================================================================

// Usage functions for each possible tool command are provided here and should support
// a non-verbose mode suitable for listing multiple commands concisely, one per line.
// For help on a specific command, the usage functions must also support a verbose mode
// where the syntax and semantics of the command and it's options are displayed.


// ***************************************************************************
// ********************** COMMANDS COMMON TO ALL  ****************************
// ***************************************************************************
// Help, Options, ShowDriveInfo, Read/Write User-area LBAs,


// ========================= ? | Help ============================

void UsageHelp( char *exeName, char *taskName, bool verbose, bool manpage )
{
   std::cout << "?   | help - Usage help for specific Command, Command Group, or Options" << std::endl;

   if( verbose )
   {
      std::cout << "\nUsage:\n   " << exeName << " ? | help | <CmndGrp> [ <Command> | Options ]\n      where:\n" << std::endl
                << "        <CmndGrp> is one of [ALL | TCG | OPAL | ENT | SEA | ATA | EDRV]" << std::endl
                << "            ALL   - Summarizes ALL toolkit commands for Seagate SEDs" << std::endl
                << "            TCG   - Summarizes TCG commands for Seagate SEDs" << std::endl
                << "            OPAL  - Summarizes OPAL-only commands for Seagate SEDs" << std::endl
                << "            ENT   - Summarizes ENTerprise-only commands for Seagate SEDs" << std::endl
                << "            SEA   - Summarizes other commands for SEAgate SEDs" << std::endl
                << "            ATA   - Summarizes ATA commands for Seagate SEDs" << std::endl
// TODO:        << "            EDRV  - Summarizes EDRV commands for Seagate eDrives" << std::endl
                << "          or " << std::endl
                << "        <Command> is any " << exeName << " Command for which Usage is needed." << std::endl
                << "          or " << std::endl
                << "        \"Options\" requests help about " << exeName << " command-line options." << std::endl
                << std::endl;

      std::cout << "      Eg. " << exeName << " ? SD " << std::endl
                << "      Eg. " << exeName << " help SD " << std::endl
                << "      Eg. " << exeName << " help ALL " << std::endl
                << "      Eg. " << exeName << " ALL   (this form doesn't need \"help\" command)" << std::endl
                << "      Eg. " << exeName << " ? Options " << std::endl
                << std::endl;

      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   The " << exeName << " '?' or 'help' command provides more information about using a\n"
                   << "   specific command. You can also use one of the pre-defined Command Group \n"
                   << "   names to get a summary of the commands in that group. For information about \n"
                   << "   command-line options, use the string \"Options\" as the help argument.\n\n"

                   << "   With very few exceptions, upper/lower case letters are treated as equivalent\n"
                   << "   in both command names and option values.\n\n"
                   << std::endl;
      else
         std::cout << "   For additional details about a command, run \"" << exeName << " man <Command>\".\n" << std::endl;

   } // if verbose
} // UsageHelp

void UsageMan( char *exeName, char *taskName, bool verbose, bool manpage )
{
   std::cout << "MAN | ManPage - Detailed help for specific Command or Options" << std::endl;

   if( verbose )
   {
      std::cout << "\nUsage:\n   " << exeName << " man | manpage [ <Command> | Options ]\n      where:\n" << std::endl
                << "        <Command> is any " << exeName << " Command for which Usage is needed." << std::endl
                << "          or " << std::endl
                << "        \"Options\" requests detaled help about " << exeName << " command-line options." << std::endl
                << std::endl;

      std::cout << "      Eg. " << exeName << " man" << std::endl
                << "      Eg. " << exeName << " man SD" << std::endl
                << "      Eg. " << exeName << " man Options " << std::endl
                << std::endl;

      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   The " << exeName << " 'man' or 'manpage' command provides more detailed help\n"
                   << "   information about using the command specified on the command line. For information about\n"
                   << "   command-line options, use Options as the command-line argument.\n\n" 
                   << "   With very few exceptions, upper/lower case letters are treated as equivalent\n"
                   << "   in both command names and option values.\n\n"
                   << std::endl;
      else
         std::cout << "   For additional help on a command, run \"" << exeName << " man <Command>\".\n" << std::endl;

   } // if verbose
} // UsageHelp



// ========================= Usage for Options ============================

void UsageOptions( char *exeName, char *taskName, bool verbose, bool manpage )
{
   std::cout << "Options   - Modify default behavior of accompanying <Command>" << std::endl;

   if( verbose )
   {
      std::cout << "\nUsage:\n   " << exeName << " [--NoLog] [--Verbose | --Quiet] [=<sernum>] <Command>" << std::endl
                << std::endl;

      std::cout << "      where Option is one or more of the following:" << std::endl
                << "          --NoLog   - disable logfile of <Command>'s TCG operations." << std::endl
                << "          --Verbose - maximum output while running <Command>." << std::endl
                << "          --Quiet   - minimum output while running <Command>." << std::endl
#ifdef __TCGSILO
                << "          --Silo    - use IEEE1667 Silos to perform <Command>" << std::endl 
#endif //__TCGSILO
                << "          =<SerNum> - Attempts command only on drive with this serial number." << std::endl
                << std::endl 
                << "      NOTE: Options can appear anywhere on the command line."
                << std::endl;

      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " commands support various command-line options for regulating\n"
                   << "   the amount of output generated by the command, and for providing special\n"
                   << "   directions to a command.\n\n"
                   << "   Because every command creates an XML logfile containing the TCG commands\n"
                   << "   and associated data sent to and from the SED. This option is on by default,\n"
                   << "   so in some cases, the command may generate a very large logfile that may\n"
                   << "   not be useful. Use the --NoLog Option to disable logfile generation for\n"
                   << "   the command.\n\n"
                   << "   If the system has more than 1 Self-Encrypting Drive, each " << exeName << "command\n"
                   << "   will require the user to select the desired drive. Using the =<sernum> \n"
                   << "   command-line option with the Serial Number of the desired drive will avoid\n"
                   << "   the need to repeatedly select the drive.\n\n"
                   << "   In general, command-line options can be used for all of the toolkit commands.\n"
                   << std::endl;
      else
         std::cout << "   For additional detail about Options, run \"" << exeName << " man Options\".\n" << std::endl;

   } // verbose
} // UsageOptions()

// ========================= SD | ShowDrive* ============================

void UsageShowDriveInfo( char *exeName, char *taskName, bool verbose, bool manpage )
{
   std::cout << "SD  | ShowDrive        - Display SED Security Configuration and State" << std::endl;

   if( verbose )
   {
      std::cout << "\nUsage:\n   " << exeName << " SD | ShowDrive [=<SerNum>]" << std::endl << std::endl 
                << "      where \"=<SerNum>\" shows drive info just for specifed drive." 
                << std::endl;

      if( manpage )
         std::cout << "\nDetails:\n"
                   << "    Depending on the features of a self-encrypting drive, this command will\n"
                   << "    display basic information obtained from the drive (IDENTIFY-DEVICE or SCSI\n"
                   << "    Query). If the drive supports TCG Protocol 0, the command provides a list\n"
                   << "    of the supported TCG protocols. If TCG Protocol 1 is supported, a TCG \n"
                   << "    Level-0 discovery command returns information present in the discovery\n"
                   << "    header, along with additional TCG drive state.\n\n"
                   << "    For this Seagate toolkit release, there is incomplete support for drives\n"
                   << "    implementing the ieee1667 protocol and for Seagate DriveTrust/SeaCOS SEDs.\n"
                   << std::endl;
      else
         std::cout << "   For additional details, run \"" << exeName << " man SD\".\n" << std::endl;

   } // verbose
} // UsageShowDriveInfo

// ========================= RUL | ReadUserLBA ============================

void UsageReadUserLBA( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "RUL | ReadUserLBA      - Read User-area LBAs to console or file" << std::endl;

   if( verbose )
   {
      std::cout << "\nUsage:\n   " << exeName << " RUL <Start#> <Length#> [<FileName>] [--NoLog]" << std::endl
                << std::endl;

      std::cout << "        where:" << std::endl
                << "          <Start#>   - Begin reading at LBA #" << std::endl
                << "          <Length#>  - Number of LBAs to read (max 128)" << std::endl
                << "          <FileName> - Data will be written to filename, if supplied" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " ReadUserLBA 1000 36 MyLbaData.bin" << std::endl
                << "        Eg. " << exeName << " RUL 1000 3       (outputs up to 4 LBAs to console)" << std::endl
                << "        Eg. " << exeName << " RUL 123456 128   (output file defaults to \"UserLBA.rd\")" << std::endl
                << std::endl;

      std::cout << "   NOTE: Unless you need to see the raw packet information, use the --NoLog\n"
                << "         command-line option to avoid generating a large log file.\n"
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageReadUserLBA

// ========================= WUL | WriteUserLBA ============================

void UsageWriteUserLBA ( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "WUL | WriteUserLBA     - Write User-area LBAs from specified file" << std::endl;   

   if( verbose )
   {
      std::cout << "\nUsage:\n  " << exeName << " WUL <Start#> <Length#> [<FileName>] [--NoLog]" << std::endl
                << std::endl;

      std::cout << "        where:" << std::endl
                << "          <Start#>   - Begin writing at LBA #" << std::endl
                << "          <Length#>  - Number of LBAs to write (max 128)" << std::endl
                << "          <FileName> - Filename supplies data to be written" << std::endl
                << std::endl;

      std::cout << "    WARNING: YOU CAN OVERWRITE IMPORTANT DATA IF YOU ADDRESS THE WRONG DEVICE!\n" << std::endl
                << "        Eg. " << exeName << " WriteUserLBA 1000 36 MyWriteFile" << std::endl
                << "        Eg. " << exeName << " WUL 1234 128 UserLBA.wr   (default filename)" << std::endl
                << "        Eg. " << exeName << " WUL 1000 2      (asks for byte value if no file)" << std::endl

                << std::endl;
      
      std::cout << "   NOTE: Unless you need to see the raw packet information, use the --NoLog\n"
                << "         command-line option to avoid generating a large log file.\n"
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageWriteUserLba


// ***************************************************************************
// **************************** TCG COMMAND GROUP ****************************
// ***************************************************************************
// RANGE: ListRangess, Set/Resize/Lock/Unlock/LockOnReset/Erase Ranges,
// TPER:  Enable/Disable Authority, ChangePIN,RevertSP, ResetStack, TPerReset,
// MISC:  Read/Write DataStore, RanNumGen, Base Feature Sets.
//

// ========================= LR | ListRanges ============================

void UsageListRange( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "LR  | ListRanges       - Display status of TCG Ranges" << std::endl;
   
   if( verbose )
   {
      std::cout << "\nUsage:\n   " << exeName << " LR | ListRanges [[[-a- <Auth>] [-p- <Passwd>]] | -NoAuth]" << std::endl
                << std::endl;

      std::cout << "        where:" << std::endl
                << "          -a-     - Authority (default is Admin1 or EraseMaster)" << std::endl
                << "          -p-     - Password of Authority (default is MSID)" << std::endl
                << "          -NoAuth - Do not authenticate using default Authority" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " ListRanges" << std::endl
                << "        Eg. " << exeName << " LR -a-Admin1 -p-MyAdmin1Passwd   (Opal SSC)" << std::endl
                << "        Eg. " << exeName << " LR -a-EraseMaster -p-MyEMPasswd  (Enterprise SSC)" << std::endl
                << "        Eg. " << exeName << " LR -NoAuth    (use -NoAuth for provisioned eDrives)" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // verbose
} // UsageListRange


// ========================= SR | SetRange ============================

void UsageSetRange( char* exeName, char* taskName, bool verbose, bool manpage )
{
// std::cout << "SB# | SetBand# - Create/update band/range, including LockOnReset state" << std::endl;
   std::cout << "SR# | SetRange#        - Create/update Range Start/Length/Lock/LockOnReset/Name" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " SR<#> | SetRange<#> [-start <LBA#>] [-len[gth] <LBA#>]" << std::endl
                << "          [-RLE  1|0] [-WLE 1|0] [-RL 1|0] [-WL 1|0]" << std::endl
                << "          [-LOR  Off | Pwr | TpR | Any] [-name <CommonName>]" << std::endl
                << "          [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "      where:" << std::endl
                << "          SR<#>       - <#> is the Range number targeted by the command" << std::endl
                << "          -Start <#>  - Starting LBA of Range (may need geometry alignment)" << std::endl
                << "          -Len   <#>  - Number of LBAs in Range (may need geometry alignment)" << std::endl
                << "          -RLE   1|0  - Set ReadLockEnabled (1=True, 0=False)" << std::endl
                << "          -WLE   1|0  - Set WriteLockEnabled (1=True, 0=False)" << std::endl
                << "          -RL    1|0  - Set ReadLocked (1=True, 0=False)" << std::endl
                << "          -WL    1|0  - Set WriteLocked (1=True, 0=False)" << std::endl
                << "          -LOR <mode> - Set LockOnReset mode to Off, PwrCycle, TPerReset or Any" << std::endl
                << "          -Name <str> - 32-char-max Common Name string assigned to Range" << std::endl
                << "          -a- <Auth>  - Authority (default is Admin1)" << std::endl
                << "          -p- <Pwd>   - Password of Authority (default is MSID)" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " SetRange1 -start 1000 -len 200    (Create/update Range 1)" << std::endl
                << "        Eg. " << exeName << " SetRange5 -length 100             (Update Range 5 Length" << std::endl
                << "        Eg. " << exeName << " SetRange1 -Start 0 -Length 0      (Disable Range 1)" << std::endl
                << "        Eg. " << exeName << " SR  -RLE1 -WLE1 -WL1 -RL1 -LORAny (Lock Global Range, Any LOR" << std::endl
                << "        Eg. " << exeName << " SR0 -RLE0 -WLE0 -RL0 -WL0         (Perm. Unlock Range 0 R/W" << std::endl
                << "        Eg. " << exeName << " SR3 -RLE1 -RL0 -WLE1 -WL0         (Temp. Unlock Range 3 R/W)" << std::endl
                << "        Eg. " << exeName << " SR2 -RL 0 -WL 1                   (Lock Range 2 for write)" << std::endl
                << "        Eg. " << exeName << " SR7 -LOR Off -a-User8 -p-\"\"       (no LOR, SUM NULL passwd)" << std::endl
                << "        Eg. " << exeName << " SR5 -name \"My Name For Range 4\"   (update CommonName)" << std::endl
                << std::endl
                << "    At least one Range parameter must be provided, and only the Range value(s)" << std::endl
                << "    provided will be updated. All other Range values remain unmodified." << std::endl
                << std::endl
                << "    Note: If no range number specified, default is Global Range (0)," << std::endl
                << "    but remember that start and length of Global Range cannot be set." << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageSetRange

#if 0 // Deprecate other Band commands
// ========================= RB | ResizeBand ============================

void UsageResizeBand( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "RB# | ResizeBand#  - Change Band/Range starting LBA and length" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " RB<#> | ResizeBand<#> <StartLBA#> <Len#> [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " RB1 1000 200  (resizes band 1 to start 1000 & len 200)" << std::endl
                << "        Eg. " << exeName << " RB2 1000 200 -a-User3 -p-\"\"    (Resize Single-User Mode band)" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageResizeBand

// ========================= LK | LockBand ============================

void UsageLockBand( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "LK# | LockBand# - Enable locking for a band/range" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " LK<#> | LockBand<#> [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " LK3                  (Lock Band 3 as Admin1)" << std::endl
                << "        Eg. " << exeName << " LK5 -a-User6 -p-\"\"   (Lock Single-User Mode band)" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageLockBand

// ========================= UL | UnlockBand ============================

void UsageUnlockBand( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "UL# | UnlockBand# - Unlock the specified band/range" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " UL<#> | UnlockBand<#> [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << "UnlockBand6                 (Unlock Band 6 as Admin1)" << std::endl
                << "        Eg. " << exeName << "UL6 -a-Admin2 -p-MyAdmin2Pin" << std::endl
                << "        Eg. " << exeName << "UL8 -a-User9 -p-\"\"          (Unlock SingleUserBand)" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageUnlockBand

// ========================= LOR | LockOnReset ============================

void UsageLockOnResetBand( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "LOR#| LockOnReset# - Set LockOnReset for specified band/range" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " LOR<range#> | LockOnReset<range#> <Pwr|Rst|All|Off> | <1|0> [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << "LockOnReset2-5 Pwr     (LOR bands 2,3,4,5 for PowerCycle)" << std::endl
                << "        Eg. " << exeName << "LOR0  0,3              (LOR band 0 for PowerCycle,TprReset)" << std::endl
                << "        Eg. " << exeName << "LOR3 Off               (LOR band 3 disabled for any event" << std::endl
                << "        Eg. " << exeName << "LOR6 TR -User7 -p-\"\"   (LOR SingleUserMode band 6 for TprReset)" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageLockOnReset
#endif 0 // Deprecate other Band commands


// ========================= ER | EraseRange ============================

void UsageEraseRange( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "ER# | EraseRange#      - Crypto-Erase Range contents, Unlock Range" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " ER<#>[-<#>]|All | EraseRange<#>[-<#>]|All [-reset <1/0>]" << std::endl
                << "          [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;
 
      std::cout << "        where:" << std::endl
                << "          -reset 1|0 - Erase should reset ACLs (1=True, 0=False)?" << std::endl
                << "          -a- <Auth> - Authority (default is Admin1)" << std::endl
                << "          -p- <Pwd>  - Password of Authority (default is MSID)" << std::endl
                << std::endl;

// For Opal SSC1, GenKey method performs crypto-erase on range by creating new DEK for range.
// For Opal SSC2 with SingleUserMode, "erase" method crypto-erases range and clears Locking control.
// For Enterprise SSC1, GenKey is used but must authenticate to EraseMaster.

      std::cout << "        Eg. " << exeName << " EraseRange                    (Erase Range 0)" << std::endl
                << "        Eg. " << exeName << " EraseRangeAll -p- MyEraseMasterPW" << std::endl
                << "        Eg. " << exeName << " ER5-12 -reset 0 -a- Admin2 -p- Admin2Passwd" << std::endl
                << "        Eg. " << exeName << " ERB6 -User7 -p-\"\"   (Erase SingleUserMode Band" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageEraseRange

// ========================= SA | ShowAuthorities ============================

void UsageShowAuthorities( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "SA  | ShowAuthorities  - Display SP Table of Authorities" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " SA | ShowAuthorities  <SPName>" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " SA Locking" << std::endl
                << "        Eg. " << exeName << " ShowAuthorities AdminSP" << std::endl
                << std::endl
                << "    Note: Opal SSC 2.0 supports Admin1-4 Authorities in both the AdminSP and" << std::endl
                << "    LockingSP, but there is currently no way to specify the desired SP." << std::endl
                << std::endl;



/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageShowAuthorities




// ========================= EA | EnableAuthority ============================

void UsageEnableAuthority( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "EA  | EnableAuthority  - Enable an Authority" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " EA <Authority> [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        where:" << std::endl
                << "          <Authority> - Authority Name (Admin1, etc.)" << std::endl
                << "          -a- <Auth>  - Authority (default is Admin1)" << std::endl
                << "          -p- <Pwd>   - Password of Authority (default is MSID)" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " EA User1                        (defaults to LockingSP)" << std::endl
                << "        Eg. " << exeName << " EA Admin2 -a-Admin1 -p-Admin1Passwd " << std::endl
                << "        Eg. " << exeName << " EA Admin1 -a-SID  (defaults to LockingSP in Opal SSC 2)" << std::endl
                << "        Eg. " << exeName << " EA SID  -a-SID      (defaults to AdminSP, Seagate only)" << std::endl
                << "        Eg. " << exeName << " EA BandMaster2 -a-EraseMaster          (Enterprise SSC)" << std::endl
                << std::endl

                << "    Note: Opal SSC 2.0 supports Admin1-4 Authorities in both the AdminSP and" << std::endl
                << "    LockingSP, but there is currently no way to specify the desired SP." << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageEnableAuthority

// ========================= DA | DisableAuthority ============================

void UsageDisableAuthority( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "DA  | DisableAuthority - Disable an Authority" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " DA <Authority> [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        where:" << std::endl
                << "          <Authority> - Authority Name (Admin1, etc.)" << std::endl
                << "          -a- <Auth>  - Authority (default is Admin1)" << std::endl
                << "          -p- <Pwd>   - Password of Authority (default is MSID)" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " DA User1                        (defaults to LockingSP)" << std::endl
                << "        Eg. " << exeName << " DA Admin2 -a-Admin1 -p-Admin1Passwd " << std::endl
                << "        Eg. " << exeName << " DA Admin1 -a-SID  (defaults to LockingSP in Opal SSC 2)" << std::endl
                << "        Eg. " << exeName << " DA SID  -a-SID      (defaults to AdminSP, Seagate only)" << std::endl
                << "        Eg. " << exeName << " DA BandMaster2 -a-EraseMaster          (Enterprise SSC)" << std::endl
                << std::endl

                << "    Note: Opal SSC 2.0 supports Admin1-4 Authorities in both the AdminSP and" << std::endl
                << "    LockingSP, but there is currently no way to specify the desired SP." << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageDisableAuthority


// ========================= CP | ChangePin ============================

void UsageChangePin( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "CP  | ChangePin        - Update an Authority's configuration" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " CP | ChangePin <Authority> [-name <CommonName>] [-pin <NewPasswd>]" << std::endl
                << "      [-TryLimit <#>] [-Tries <#>] [-Persist <1/0>] [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        where:" << std::endl
                << "          <Authority>   - Specify Authority whose PIN is to be changed" << std::endl
                << "          -name <str>   - New 32-char Common Name string for Authority" << std::endl
                << "          -pin <Passwd> - Password to be set as new Authority PIN" << std::endl
                << "          -TryLimit <#> - Max failed attempts to authenticate Authority" << std::endl
                << "          -Tries <#>    - Number of failed Authentication attempts" << std::endl
                << "          -Persist 1|0  - Persist Tries across power cycles(1=True, 0=False)" << std::endl
                << "          -a- <Auth>    - Authority to authenticate to" << std::endl
                << "          -p- <Passwd>  - Password of Authority being authenticated" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " ChangePin SID -pin NewSIDPasswd" << std::endl
                << "        Eg. " << exeName << " CP Admin1 -pin \"\"                    (sets NULL pin)" << std::endl
                << "        Eg. " << exeName << " CP Admin1 -TryLimit5 -Tries0 -Persist1" << std::endl
                << "        Eg. " << exeName << " CP Admin2 -pin NewAdm2Passwd -a-Admin1 -p-CurAdm1Pin" << std::endl
                << "        Eg. " << exeName << " CP User1 -name \"User1 Common Name\" -a-Admin1" << std::endl
                << "        Eg. " << exeName << " CP EraseMaster -pin NewEMPasswd  (Enterprise SSC)" << std::endl
                << "        Eg. " << exeName << " CP BandMaster0 -pin NewBMPasswd  (Enterprise SSC)" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageChangePin


// ========================= RS | ResetStack ============================

void UsageResetStack( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "RS  | ResetStack       - Reset TCG Command Parsing stack to default" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " RS | ResetStack" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " ResetStack" << std::endl
                << "        Eg. " << exeName << " RS" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageResetStack

// ========================= RDS | ReadDataStore ============================

void UsageReadDataStore( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "RDS#| ReadDataStore#   - Read bytes from DataStore Table <#> into file" << std::endl;
   
   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " RDS[<#>] | ReadDataStore[<#>] <FileName> [-start <#>] [-len[gth] <#>]" << std::endl
                << "           [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        where:" << std::endl
                << "          RDS[<#>]   - Selects DataStore Table <#>, (default is first DST)" << std::endl
                << "          <Filename> - Read DataStore contents into file <Filename>" << std::endl
                << "          -start <#> - Beginning byte offset in DataStore to read from" << std::endl
                << "          -len <#>   - Number of bytes in DataStore Table to read" << std::endl
                << "          -a- <Auth> - Authority (default is Admin1)" << std::endl
                << "          -p- <Pwd>  - Password of Authority (default is MSID)" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " ReadDataStore1 MyFile.ds    (entire DS1 read into file)" << std::endl
                << "        Eg. " << exeName << " RDS16 MyFile.ds -start10 -len20 --NoLog" << std::endl
                << "        Eg. " << exeName << " RDS1 MyFile.ds -a-BandMaster0 -p-MyBmPin" << std::endl
                << "        Eg. " << exeName << " RDS MyFile.ds -start 0 -len 1000 (default first DST)" << std::endl
                << "        Eg. " << exeName << " RDS3 MyFile.ds -length128 (start defaults to 0)" << std::endl
                << std::endl;

      std::cout << "    Note: The maximum number and size of DataStore Tables is fixed in Seagate" << std::endl
                << "    Opal SSC 1.0 and Enterprise SSC drives. Opal SSC 2.0 drives report max number" << std::endl
                << "    and max size of DataStore Tables during Level 0 Discovery, but any desired" << std::endl
                << "    DataStore Tables must be created during Activate or Reactivate operations." << std::endl
                << std::endl;

/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageReadDataStore

// ========================= WDS | WriteDataStore ============================

void UsageWriteDataStore( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "WDS#| WriteDataStore#  - Write bytes from file into DataStore Table <#>" << std::endl;
   
   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " WDS[<#>] | WriteDataStore[<#>] <FileName> [-start <#>] [-len[gth] <#>]" << std::endl
                << "          [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        where:" << std::endl
                << "          WDS[<#>]   - Selects DataStore Table <#> (default is first DST)" << std::endl
                << "          <Filename> - Write DataStore with data from file <Filename>" << std::endl
                << "          -start <#> - Beginning byte offset to write to (default 0)" << std::endl
                << "          -len <#>   - Number of bytes to write (default is size of DST)" << std::endl
                << "          -a- <Auth> - Authority (default is Admin1)" << std::endl
                << "          -p- <Pwd>  - Password of Authority (default is MSID)" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " WriteDataStore MyFile.ds     (writes entire file to DST" << std::endl
                << "        Eg. " << exeName << " WDS1 MyFile.ds -start10 -length20   (small write in DST)" << std::endl
                << "        Eg. " << exeName << " WDS8 MyFile.ds -a-BandMaster0 -p-MyBmPin -NoLog" << std::endl
                << "        Eg. " << exeName << " WDS  MyFile.ds -start 0 -len 1000   (default is first DST)" << std::endl
                << "        Eg. " << exeName << " WDS16 MyFile.ds -len 128  (start defaults to byte 0 in DST)" << std::endl
                << std::endl;

      std::cout << "    Note: The maximum number and size of DataStore Tables is fixed in Seagate" << std::endl
                << "    Opal SSC 1.0 and Enterprise SSC drives. Opal SSC 2.0 drives report max number" << std::endl
                << "    and max size of DataStore Tables during Level 0 Discovery, but any desired" << std::endl
                << "    DataStore Tables must be created during Activate or Reactivate operations." << std::endl
                << std::endl;

/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageWriteDataStore

// ========================= SDS | ShowDataStore ============================

void UsageShowDataStore( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "SDS | ShowDataStore    - Show information about DataStore Table(s)" << std::endl;
   
   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " SDS | ShowDataStore [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        where:" << std::endl
                << "          -a- <Auth> - Authority (default is Admin1)" << std::endl
                << "          -p- <Pwd>  - Password of Authority (default is MSID)" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " ShowDataStore" << std::endl
                << "        Eg. " << exeName << " SDS" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageShowDataStore



// ========================= GR | GenerateRandom ============================

void UsageGenerateRandom( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "GR  | GenerateRandom   - Generate Random Number using the Security Provider" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " GR | GenerateRandom <SPName> [<NumberOfBytes>]" << std::endl
                << std::endl;

      std::cout << "      Eg. " << exeName << " GenerateRandom Admin       (default is 32 bytes)" << std::endl
                << "      Eg. " << exeName << " GR Locking 16" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageGenerateRandom


// *************************************************************************
// *************************** OPAL COMMAND GROUP **************************
// *************************************************************************
//
// ActivateSP, Reactivate, GrantAccess, Read/Write ShadowMBR,
// Get/Set ShadowMBRCtrl
//

// ========================= AT | Activate ============================

void UsageActivate( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "AT  | Activate         - Activate an Opal Security Provider" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " AT | Activate [<SP>]  [-SUR All | \"<Range# list>\"] [-SUP <0/1>]" << std::endl 
                << "          [-DST \"<DataStore Table size(s)>\"] [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        where:" << std::endl
                << "          <SP> - Which SP to Activate (LockingSP is the default SP)"  << std::endl
                << "          -SUR - Sets All or \"<range# list>\" into Single User Mode" << std::endl
                << "          -SUP - Sets Single-User Policy to 0 (User) or 1 (Admin)" << std::endl
                << "          -DST - DataStore Table size list \"t0size t1size ... t15size\"" << std::endl
                << "                 or DataStore Table size \"nn x 16\" (nn bytes for each DST)" << std::endl
                << "          -a-  - Authority to use (default is Admin1)" << std::endl
                << "          -p-  - Password of Authority (default is MSID)" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " AT       (defaults to LockingSP and no single-user-mode)" << std::endl
                << "        Eg. " << exeName << " AT -sur \"0,2,7,15\" -sup0 -dst \"1024, 1024, 20480\"" << std::endl
                << "        Eg. " << exeName << " AT -SURAll -SUP0 -DST \"3276800x16\" -a- Admin1 -p- MyPassWd" << std::endl
                << std::endl;

      std::cout << "    Note: The maximum number and size of DataStore Tables is fixed in Seagate" << std::endl
                << "    Opal SSC 1.0 and Enterprise SSC drives. Opal SSC 2.0 drives report max number" << std::endl
                << "    and max size of DataStore Tables during Level 0 Discovery, but any desired" << std::endl
                << "    DataStore Tables must be created during Activate or Reactivate operations." << std::endl
                << std::endl;

/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageActivate

// ========================= RA | Reactivate ============================

void UsageReactivate( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "RA  | Reactivate       - Reactivate Locking SP (Single-User Mode Only)" << std::endl;   
   
   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " RA | Reactivate [-SUR All | \"<Range# list>\"] [-SUP <0/1>]"  << std::endl 
                << "          [-DST \"<DataStore Table size(s)>\"] [-pin <NewAdmin1PIN>]" << std::endl
                << "          [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        where:" << std::endl
                << "          <SP> - Which SP to Activate (LockingSP is the default SP)"  << std::endl
                << "          -SUR - Sets All or \"<range# list>\" into Single User Mode" << std::endl
                << "          -SUP - Sets Single-User Policy to 0 (User) or 1 (Admin)" << std::endl
                << "          -DST - DataStore Table size list \"t0size t1size ... t15size\"" << std::endl
                << "                 or DataStore Table size \"nn x 16\" (nn bytes for each DST)" << std::endl
                << "          -pin - Sets new Admin PIN to user's supplied Password" << std::endl
                << "          -a-  - Authority to use (default is Admin1)" << std::endl
                << "          -p-  - Password of Authority (default is MSID)" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " Reactivate -pin MyNewPasswd" << std::endl
                << "        Eg. " << exeName << " RA -sub \"0,2,7,15\" -sup0 -tbs \"2048x16\"" << std::endl
                << "        Eg. " << exeName << " RA -sub All -sup 1 -pin NewAdm1Pin -a- Admin1 -p- MyPin" << std::endl
                << std::endl;

      std::cout << "    Note: The maximum number and size of DataStore Tables is fixed in Seagate" << std::endl
                << "    Opal SSC 1.0 and Enterprise SSC drives. Opal SSC 2.0 drives report max number" << std::endl
                << "    and max size of DataStore Tables during Level 0 Discovery, but any desired" << std::endl
                << "    DataStore Tables must be created during Activate or Reactivate operations." << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageReactivate


// ========================= TR | TPerReset ============================
// ========================= RT | ResetTPer ============================

void UsageTPerReset( char* exeName, char* taskName, bool verbose, bool manpage )

{
   std::cout << "RT  | ResetTPer        - Reset objects having \'TPerReset\' in LockOnReset mode" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " TR | RT | TPerReset | ResetTPer" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " ResetTPer" << std::endl
                << "        Eg. " << exeName << " TR" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageTPerReset


// ========================= ETR | EnableTPerReset ============================

void UsageEnableTPerReset( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "ETR | EnableTPerReset  - Enable TPerReset (Opal SSC 2 only)" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " ETR | EnableTPerReset" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " EnableTPerReset      (Enables TR)" << std::endl
                << "        Eg. " << exeName << " ETR                  (Enables TR)" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageEnableTPerReset


// ========================= DTR | DisableTPerReset ============================

void UsageDisableTPerReset( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "DTR | DisableTPerReset - Disable TPerReset (Opal SSC 2 only)" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " DTR | DisableTPerReset" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " DisableTPerReset     (Disables TR)" << std::endl
                << "        Eg. " << exeName << " DTR                  (Disables TR)" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageDisableTPerReset



// ========================= RP | RevertSP ============================

void UsageRevertSP( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "RP  | RevertSP         - Revert drive to manufactured/factory default state" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " RP | RevertSP <SPName> [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " RevertSP Admin" << std::endl
                << "        Eg. " << exeName << " RP Admin -a-PSID -p-MyPSID" << std::endl
                << "        Eg. " << exeName << " RP Locking -a-Admin1 -p-Admin1Passwd\n" << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageRevertSP

// ========================= GA | GrantAccess ============================

void UsageGrantAccess( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "GA  | GrantAccess      - Grant access to one or more authorities" << std::endl;   
   
   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " GA SRL Range[<#>[-<#>]]|[All] {<Authority>} [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << "   " << exeName << " GA SWL Range[<#>[-<#>]]|[All] {<Authority>} [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << "   " << exeName << " GA SMBRCDone {<Authority>} [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << "   " << exeName << " GA SDS[<#>] {<Authority>} [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << "   " << exeName << " GA GDS[<#>] {<Authority>} [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << "   " << exeName << " GA <ACE_UID> {<Authority>} [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        where:" << std::endl
                << "          SRL       - Set Authority for range(List or All) ReadLock" << std::endl
                << "          SWL       - Set Authority for range(List or All) WriteLock" << std::endl
                << "          SMBRCDone - Set Authority for ShadowMBR Control \"Done\"" << std::endl
                << "          SDS<#>    - Set Authority for DataStoreTable(List or All)" << std::endl
                << "          GDS<#>    - Get Authority for DataStoreTable(List or All)" << std::endl
                << "          <ACE_UID> - Set Authority for <ACE_UID>" << std::endl
                << "          -a-       - Authority to use (default is Admin1)" << std::endl
                << "          -p-       - Password of Authority (default is MSID)" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " GA SRL Range1 User1 User2" << std::endl
                << "        Eg. " << exeName << " GA SWL Ranges0-15 User1 -a-Admin1 -p-Admin1Passwd" << std::endl
                << "        Eg. " << exeName << " GA SMBRCDone User1 User2 -a-Admin2 -p-Admin2Passwd" << std::endl
                << "        Eg. " << exeName << " GA SDS User1 -p- Admin1Passwd" << std::endl
                << "        Eg. " << exeName << " GA GDS2 User2" << std::endl
                << "        Eg. " << exeName << " GA 0x0000000900010001 Admin2 -a-Admin2 -p-Admin2Passwd" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageGrantAccess

// ========================= RMT | ReadMBRTable ============================

void UsageReadMBR( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "RMT | ReadMBRTable     - Read from the Shadow MBR Table" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n  " << exeName << " RMT | ReadMBRTable <FileName> [-s <Start>] [-e <End>] [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        where:" << std::endl
                << "          <FileName> - Filename to receive data from ShadowMBR Table" << std::endl
                << "          -s <Start> - Byte offset for start of data to be read" << std::endl
                << "          -e <End>   - Byte offset for end of data to be read" << std::endl
                << "          -a-        - Authority to use (default is Admin1)" << std::endl
                << "          -p-        - Password of Authority (default is MSID)" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " ReadMBRTable MyMBR.mbr" << std::endl
                << "        Eg. " << exeName << " RMT MyMBR.mbr -s0 -e102400 --NoLog" << std::endl
                << "        Eg. " << exeName << " RMT MyMBR.mbr -a-Admin1 -p-Admin1Passwd --NoLog" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageReadMBR

// ========================= WMT | WriteMBRTable ============================

void UsageWriteMBR( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "WMT | WriteMBRTable    - Write to the Shadow MBR Table" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " <<exeName << " WMT | WriteMBRTable <FileName> [-s <Start>] [-e <End>] [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        where:" << std::endl
                << "          <FileName> - Filename containing data written to ShadowMBR Table" << std::endl
                << "          -s <Start> - Byte offset for start of data to be written" << std::endl
                << "          -e <End>   - Byte offset for end of data to be written" << std::endl
                << "          -a-        - Authority to use (default is Admin1)" << std::endl
                << "          -p-        - Password of Authority (default is MSID)" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " WriteMBRTable MyMBR.mbr" << std::endl
                << "        Eg. " << exeName << " WMT MyMBR.mbr -s0 -e102400 --NoLog" << std::endl
                << "        Eg. " << exeName << " WMT MyMBR.mbr -a-Admin1 -p-Admin1Passwd --NoLog\n" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageWriteMBR

// ========================= GMC | GetMBRControl ============================

void UsageGetMBRControl( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "GMC | GetMBRControl    - Get the current state of the MBR control" << std::endl;   
   
   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " GMC | GetMBRControl [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " GMC" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageGetMBRControl

// ========================= SMC | SetMBRControl ============================

void UsageSetMBRControl( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "SMC | SetMBRControl    - Set the state of the MBR control" << std::endl;   
   
   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " SMC | SetMBRControl [-e <Enable>] [-d <Done>] [-r <Reset>]" << std::endl
                << "          [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " SMC -e1 -r Off -a-Admin1 -p-Admin1Passwd" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageSetMBRControl


// ***************************************************************************
// ************************ ENTERPRISE COMMAND GROUP *************************
// ***************************************************************************
//
// Enable/Disable Band Authority (not enable/disable band itself).
//

// ========================= EAR | EnableAuthorityForRange ============================

void UsageEnableAuthorityForRange( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "EAR#| EnableAuthorityForRange#  - Enable Authority for one or more Ranges" << std::endl;   
   
   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " EAR[<#>[-<#>]]|[All] | EnableAuthorityForRange[<#>[-<#>]]|[All]" << std::endl
                << "          [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " EnableAuthorityForRange2" << std::endl
                << "        Eg. " << exeName << " EAR2-15 -a-EraseMaster" << std::endl
                << "        Eg. " << exeName << " EARAll" << std::endl
                << "        Eg. " << exeName << " EAR15 -p-MyEraseMasterPW" << std::endl
                << std::endl;

      std::cout << "    Note: This command applies only to Enterprise SSC Drives." << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageEnableAuthorityForRange

// ========================= DAR | DisableAuthorityForRange ============================

void UsageDisableAuthorityForRange( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "DAR#| DisableAuthorityForRange# - Disable Authority for one or more Ranges" << std::endl;   
   
   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " DAR[<#>[-<#>]]|[All] | DisableAuthorityForRange[<#>[-<#>]]|[All]" << std::endl
                << "          [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " DisableAuthorityForRange2" << std::endl
                << "        Eg. " << exeName << " DAR2-15 -a-EraseMaster" << std::endl
                << "        Eg. " << exeName << " DARAll" << std::endl
                << "        Eg. " << exeName << " DAR15 -p-MyEraseMasterPW" << std::endl
                << std::endl;

      std::cout << "    Note: This command applies only to Enterprise SSC Drives." << std::endl
                << std::endl;

      /*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageDisableBand


// ***************************************************************************
// ************************* EDRIVE-SPECIFIC COMMANDS ************************
// ***************************************************************************
// At this time, the Toolkit does not provide specific support for eDrive
// devices other than what is provided by the TCG Opal 2 capabilities. There
// is a --Silo command-line option that can be used in the future to use the
// Probe and TCG Silos on an eDrive rather than sending TCG commands directly
// to the drive.  
//
// REMEMBER:  THIS SECTION IS TO-BE-DONE!
// 



// ***************************************************************************
// ************************* SEAGATE-SPECIFIC COMMANDS ***********************
// ***************************************************************************
// Seagate SEDs have public but proprietary features that can be used to
// obtain behaviors not specified in the standard TCG specifications. This
// section will contain the Usage info for these commands.  They are broken
// into the following command groups:
// 
// * ATA SECURITY GROUP: SetUserPW, SetMasterPW, DisablePW, Unlock, Freeze, Erase,
// * FIPS-RELATED COMMANDS: EnterATA-FIPSMode, EnterFIPSMode, VerifyFIPSMode
// * FIRMWARE/SerialPort Commands: Enable/Disable FirmwareDownloadPort, etc.


// ========================= ASU | ATASetUser ============================

void UsageATASetUserPW( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "ASU | ATASetUser       - Set UserPW needed to unlock drive after power cycle" << std::endl;   
   
   if (verbose)
   {
      std::cout << "\nUsage:\n  " << exeName << " ASU | ATASetUser <Passwd> [MasterHigh|MH] | [MaxterMaximum|MM]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " ASU MyUserPw MH      (also sets MasterHigh mode)" << std::endl
                << "        Eg. " << exeName << " ASU MyUserPw MM      (also sets MasterMax mode)" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageATASetUserPW

// ========================= ASM | ATASetMaster ============================

void UsageATASetMasterPW( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "ASM | ATASetMaster     - Set or update Master Password" << std::endl;   
   
   if (verbose)
   {
      std::cout << "\nUsage:\n  " << exeName << " ASM | ATASetMaster <Passwd> [<MasterIdentifier>]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " ASM  MasterPassword  1234    (sets optional MID = 1234" << std::endl
                << "        Eg. " << exeName << " ATASetMaster MyMstrPw        (no MID specified)" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageATASetMasterPW

// ========================= ADP | ATADisablePW ============================

void UsageATADisablePW( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "ADP | ATADisablePW     - Permanently unlock drive and clear password" << std::endl;   
   
   if (verbose)
   {
      std::cout << "\nUsage:\n  " << exeName << " ADP | ATADisablePW <Passwd> [User/Master]" << std::endl
                      << std::endl;

      std::cout << "        Eg. " << exeName << " ADP  MyUserPassword User    (User disables)" << std::endl
                << "        Eg. " << exeName << " ADP  MyMasterPW  Master     (Disable only if MasterHigh)" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageATADisablePW

// ========================= AU | ATAUnlock ============================

void UsageATAUnlock( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "AU  | ATAUnlock        - Unlock drive with UserPW (or MasterPW if mode is HIGH)" << std::endl;   
   
   if (verbose)
   {
      std::cout << "\nUsage:\n  " << exeName << " AU | ATAUnlock <Passwd> [User/Master]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " AU  MyUserPassword User   (unlocks drive)" << std::endl
                << "        Eg. " << exeName << " AU  MyMasterPw Master     (unlocks only if MasterHigh)" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageATAUnlock

// ========================= AFL | ATAFreezelock ============================

void UsageATAFreezelock( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "AFL | ATAFreezelock    - Ignore subsequent ATA Security Cmnds until powercycle" << std::endl;   
   
   if (verbose)
   {
      std::cout << "\nUsage:\n  " << exeName << " AFL | ATAFreezelock" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " ATAFreezelock" << std::endl
                << "        Eg. " << exeName << " AFL" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageATAFreezelock

// ========================= AED | ATAEraseDevice ============================

void UsageATAEraseDevice( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "AED | ATAEraseDevice   - Perform ATA SecureErase on Device" << std::endl;   
   
   if (verbose)
   {
      std::cout << "\nUsage:\n  " << exeName << " AED | ATAEraseDevice <Passwd> [User|Master] [Enhanced/EH]|[Normal/NM]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " ATAEraseDevice MyUserPW User EH" << std::endl
                << "        Eg. " << exeName << " AED MyMasterPW Master Enhanced" << std::endl
                << "        Eg. " << exeName << " AED \"x*2d88ml\"     (defaults to UserPW and Enhanced Erase)" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageATAEraseDevice


// ========================= SUP | SetUdsPort ============================

void UsageSetUdsPort( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "SUP | SetUdsPort       - Set enable/disable state for Logical UDS Port" << std::endl;   

   if (verbose)
   {
      std::cout << "\nUsage:\n  " << exeName << " SUP | SetUdsPort [-Locked <1/0>] [-LReset <On/Off>] [-a-<Auth>] [-p-<Passwd>]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " SetUdsPort -Locked 1 -p- MySIDPin" << std::endl
                << "        Eg. " << exeName << " SUP -Locked 0 -LReset On    (Temporary Unlock)" << std::endl
                << "        Eg. " << exeName << " SUP -Locked 0 -LReset Off   (Permanent Unlock)" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageSetUDSPort

// ========================= GUP | GetUdsPort ============================

void UsageGetUdsPort( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "GUP | GetUdsPort       - Get enable/disable state for Logical UDS Port" << std::endl;   

   if (verbose)
   {
      std::cout << "\nUsage:\n  " << exeName << " GUP | GetUdsPort [-a-<Auth>] [-p-<Passwd>]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " GUP -p- MySIDPin" << std::endl
                << "        Eg. " << exeName << " GUP" << std::endl
                << std::endl;
 /*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageGetUDSPort


// ========================= SFD | SetFWDownload ============================

void UsageSetFWDownload( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "SFD | SetFWDownload    - Set enable/disable state for Logical FWDownload Port" << std::endl;   

   if (verbose)
   {
      std::cout << "\nUsage:\n  " << exeName << " SFD | SetFWDownload [-Locked <1/0>] [-LReset <On/Off>] [-a-<Auth>] [-p-<Passwd>]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " SFD -Locked 0 -LReset Off -p- MySIDPin" << std::endl
                << "        Eg. " << exeName << " SFD -LReset On" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageSetFWDownload

// ========================= GFD | GetFWDownload ============================

void UsageGetFWDownload( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "GFD | GetFWDownload    - Get enable/disable state for Logical FWDownload Port" << std::endl;   

   if (verbose)
   {
      std::cout << "\nUsage:\n  " << exeName << " GFD | GetFWDownload [-a-<Auth>] [-p-<Passwd>]" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " GFD -p- MySIDPin" << std::endl
                << "        Eg. " << exeName << " GFD" << std::endl
                << std::endl;
 /*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageGetFWDownload


// ========================= FD | FWDownload ============================

void UsageFWDownload( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "FD  | FWDownload       - Download a signed firmware file to drive" << std::endl;   

   if (verbose)
   {
      std::cout << "\nUsage:\n  " << exeName << " FD | FWDownload <pathname_of_signed_firmware_file.lod>" << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " FD Seagate_Opal_R7_signed.lod" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageFWDownload


// ========================= SAF | SetAtaFIP (ATA) ============================

void UsageSAFP( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "SAF | SetAtaFIPS       - Place new/reverted SED in ATA-FIPS Compliance Mode" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " SAF | SetAtaFIPS <MasterPassword> <UserPassword> [MasterHigh/MH | MasterMaximum/MM]" << std::endl
                << std::endl;   
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageATAFIPS

// ========================= GFP | GetFipsPolicy (TCG) ============================

void UsageGTFP( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "GFP | GetFipsPolicy    - Compare Drive state to FIPS 140 Module Security Policy" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " GFP | GetFipsPolicy" << std::endl
                << std::endl;   
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageFIPS

// ========================= SFP | SetFipsPolicy (TCG) ============================

void UsageSTFP( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << "SFP | SetFipsPolicy    - Configure Drive using FIPS 140 Module Security Policy" << std::endl;

   if (verbose)
   {
      std::cout << "\nUsage:\n   " << exeName << " SFP | SetFipsPolicy <NewSIDPassword> <NewAdmin1Password> " << std::endl
                << std::endl;   
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageFIPS



#if 0
// ========================= XX |  ============================

void UsageXX ( char* exeName, char* taskName, bool verbose, bool manpage )
{
   std::cout << " |  - " << std::endl;   

   if( verbose )
   {
      std::cout << "\n  " << exeName << "  | " << std::endl
                << std::endl;

      std::cout << "        Eg. " << exeName << " XXX" << std::endl
                << "        Eg. " << exeName << " XXX" << std::endl
                << std::endl;
/*
      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " man XXX\".\n" << std::endl;
*/
   } // if verbose
} // UsageXX

#endif



#if 0
// Optional commands that allow a script to determine programatically various states of
// a device. These were added for the BatchFile generator's use, and have not been
// maintained.  They are preserved here until we decide to permanently deprecate them.

if( _stricmp( taskName, "All" ) == 0 || _stricmp( taskName, "OS" ) == 0 || _stricmp( taskName, "OpalSSC" ) == 0 )
{
   std::cout << "\n" << std::endl;

   std::cout << "   " << "- To determine if device is Opal SSC drive" << std::endl;
   std::cout << "   " << exeName << " <OpalSSC | OS>  [NOT]" << std::endl
             << "   Eg. " << exeName << " OpalSSC" << std::endl
             << "   Eg. " << exeName << " OS NOT  (Error return is 0 if NOT Opal SSC)\n" << std::endl;
}

if( _stricmp( taskName, "All" ) == 0 || _stricmp( taskName, "ES" ) == 0 || _stricmp( taskName, "EnterpriseSSC" ) == 0 )
{
   std::cout << "\n" << std::endl;

   std::cout << "   " << "- To determine if device Is Enterprise SSC drive" << std::endl;
   std::cout << "   " << exeName << " <EnterpriseSSC | ES> [NOT]" << std::endl
             << "   Eg. " << exeName << " EnterpriseSSC" << std::endl
             << "   Eg. " << exeName << " ES NOT   (Error return is 0 if NOT Enterprise SSC)\n" << std::endl;
}

if( _stricmp( taskName, "All" ) == 0 || _stricmp( taskName, "SA" ) == 0 || _stricmp( taskName, "SpActive" ) == 0 )
{
   std::cout << "\n" << std::endl;      
   
   std::cout << "   " << "- To determine if SP is Active (default LockingSP)" << std::endl;
   std::cout << "   " << exeName << " SpActive | SA [<sp>] [NOT]" << std::endl
             << "   Eg. " << exeName << " SpActive" << std::endl
             << "   Eg. " << exeName << " SpActive Locking" << std::endl
             << "   Eg. " << exeName << " SA NOT   (Error return is 0 if SP is NOT Active)\n" << std::endl;
}

if( _stricmp( taskName, "All" ) == 0 || _stricmp( taskName, "SS" ) == 0 || _stricmp( taskName, "SecurityState" ) == 0 )
{
std::cout << "\n" << std::endl;   
   
   std::cout << "   " << "- shows Security State information" << std::endl;
   std::cout << "   " << exeName << " SS or SecurityState\n" << std::endl;
}

// Any command that generates lots of logging output can be listed here to caution user about disabling logging.
   if( _stricmp( taskName, "All" ) == 0 
 || _stricmp( taskName, "RMBR" ) == 0 || _stricmp( taskName, "ReadMBR" ) == 0
 || _stricmp( taskName, "WMBR" ) == 0 || _stricmp( taskName, "WriteMBR" ) == 0
 || _stricmp( taskName, "RDS" ) == 0 || _stricmp( taskName, "ReadDataStore" ) == 0
 || _stricmp( taskName, "WDS" ) == 0 || _stricmp( taskName, "ShowDataStore" ) == 0 )
   std::cout << " Note: A TCG protocol log (\"TCGProtocolLog.xml\") is usually generated with each\n run of the tool. To ignore the log, attach a switch  --NoLog.\n"  << std::endl;
#endif //if 0

/*
#ifdef __TCGSILO
if( _stricmp( taskName, "All" ) == 0 )
   std::cout << " Note: If your device supports TCG Silo, and you prefer it to native TCG, attach a switch  --UseTCGSilo.\n"  << std::endl;
#endif // __TCGSILO
*/

// ***************************************************************************
// ****************  USAGE( Path, Task, Verbose, Details ) *******************
// ***************************************************************************


bool isHelpRqst( char *exeName, int argc, char *argv[], bool bVerbose, bool manpage=false )
{
   // Assume this is a blank cmnd or is only a top-level help rqst
   char *taskName = "TOP";

   if( _stricmp( argv[1], "help" ) == 0 || _stricmp( argv[1], "?" ) == 0 ) 
   {
      if( argc > 2 )       // Help/? has at least 1 argument
         taskName = argv[2];
   } 

   bool showTop   = (_stricmp( taskName, "HELP" ) == 0 || _stricmp( taskName, "?" ) == 0 ); 
   return false;
}

void  usage( char *exeName, char *taskName="Top", bool bExamples=true, bool manpage=false )
{
   bool verbose   = bExamples;
   bool showAll   = (_stricmp( taskName, "All" ) == 0);
   bool showTCG   = (_stricmp( taskName, "TCG" ) == 0);
   bool showOPAL  = (_stricmp( taskName, "OPA" ) == 0);
   bool showENT   = (_stricmp( taskName, "ENT" ) == 0);
   bool showSEA   = (_stricmp( taskName, "SEA" ) == 0);
   bool showATA   = (_stricmp( taskName, "ATA" ) == 0);
   bool showEDRV  = (_stricmp( taskName, "EDR" ) == 0);  // Not implemented yet

   bool metacmd   = showAll | showSEA | showTCG | showOPAL | showENT | showEDRV | showATA ;

   if( metacmd )
   {
      verbose = false;     // minimize usage output to one line
      manpage = false;
   }

   if ( showAll )          // Show limited usage for ALL commands
   {
      showSEA = showTCG = showOPAL = showENT = showEDRV = showATA = true;
   }

   // The taskName string can specify an individual command to show usage, or can
   // be meta tasks such as "All", "Options", "Top", a CmndGrp, etc.  Here we see
   // if taskName is one of the Meta tasks.

   if( _stricmp( taskName, "Top" ) == 0 ) // Top-level usage info
   {
      UsageHelp( exeName, "", true, manpage );
      return;
   }
   else if( _stricmp( taskName, "Options" ) == 0 )   // Help on Optional args on command line
   {
      UsageOptions( exeName, "", true, manpage );
      return;
   }
   else if( _stricmp( taskName, "Man" ) == 0 )   // Help on ManPages usage to show details
   {
      UsageOptions( exeName, "Man", true, manpage );
      return;
   }

   // ============ SHOW META_COMMAND SUMMARIES ============

   if( metacmd )  // Show the "COMMON" Meta-Command Group
   {
      std::cout << "\nCOMMON COMMANDS:\n" << std::endl;

      UsageShowDriveInfo ( exeName, "", false, false );  // ShowDrives
      UsageReadUserLBA ( exeName, "", false, false );
      UsageWriteUserLBA ( exeName, "", false, false );
   }

   if( showTCG )      // Show the "TCG" Command Group
   {
      std::cout << "\nSEAGATE TCG COMMANDS:\n" << std::endl;

      UsageListRange( exeName, taskName, false, false );
      UsageSetRange( exeName, taskName, false, false );      
//    UsageResizeBand( exeName, taskName, false, false );
//    UsageLockBand( exeName, taskName, false, false );
//    UsageUnlockBand( exeName, taskName, false, false );
//    UsageLockOnResetBand( exeName, taskName, false, false );
      UsageEraseRange( exeName, taskName, false, false );

      UsageShowAuthorities ( exeName, "", false, false );
      UsageEnableAuthority( exeName, taskName, false, false );
      UsageDisableAuthority( exeName, taskName, false, false );
      UsageChangePin( exeName, taskName, false, false );
      UsageResetStack( exeName, taskName, false, false );

      UsageGenerateRandom( exeName, taskName, false, false );
      UsageReadDataStore( exeName, taskName, false, false );
      UsageWriteDataStore( exeName, taskName, false, false );
      UsageShowDataStore( exeName, taskName, false, false );
   }

   if( showOPAL )      // Show the "OPAL" Command Group
   {
      std::cout << "\nSEAGATE OPAL SSC COMMANDS:\n" << std::endl;

      UsageActivate( exeName, taskName, false, false );
      UsageReactivate( exeName, taskName, false, false );
      UsageEnableTPerReset( exeName, taskName, verbose, manpage );
      UsageDisableTPerReset( exeName, taskName, verbose, manpage );
      UsageTPerReset( exeName, taskName, false, false );
      UsageRevertSP( exeName, taskName, false, false );
      UsageGrantAccess( exeName, taskName, false, false );
      UsageReadMBR( exeName, taskName, false, false );
      UsageWriteMBR( exeName, taskName, false, false );
      UsageGetMBRControl( exeName, taskName, false, false );
      UsageSetMBRControl( exeName, taskName, false, false );
   }

   if( showENT )      // Show the "ENT" Enterprise Command Group
   {
      std::cout << "\nSEAGATE ENTERPRISE SSC COMMANDS:\n" << std::endl;

      UsageRevertSP( exeName, taskName, false, false );
      UsageEnableAuthorityForRange( exeName, taskName, false, false );
      UsageDisableAuthorityForRange( exeName, taskName, false, false );
   }

 /*
   if( showEDRV )      // Show the "EDRV" Command Group
   {
      std::cout << "\nEDRIVE-ONLY COMMANDS:\n" << std::endl;
   }
*/
   if( showSEA )      // Show the "SEAGATE" Command Group
   {
      std::cout << "\nOTHER SEAGATE COMMANDS:\n" << std::endl;

      UsageATASetUserPW( exeName, taskName, false, false );
      UsageATASetMasterPW( exeName, taskName, false, false );
      UsageATADisablePW( exeName, taskName, false, false );
      UsageATAUnlock( exeName, taskName, false, false );
      UsageATAFreezelock( exeName, taskName, false, false );
      UsageATAEraseDevice( exeName, taskName, false, false );
//    UsageATAFIPS( exeName, taskName, false, false );  // Don't display this option!

      UsageGetUdsPort( exeName, taskName, false, false );
      UsageSetUdsPort( exeName, taskName, false, false );

      UsageGetFWDownload( exeName, taskName, false, false );
      UsageSetFWDownload( exeName, taskName, false, false );
      UsageFWDownload( exeName, taskName, false, false );

      UsageGTFP( exeName, taskName, false, false );
      UsageSTFP( exeName, taskName, false, false );
   }

   if( showATA & !showSEA )      // Show the "ATA" Command Group
   {
      std::cout << "\nSEAGATE ATA SECURITY COMMANDS:\n" << std::endl;

      UsageATASetUserPW( exeName, taskName, false, false );
      UsageATASetMasterPW( exeName, taskName, false, false );
      UsageATADisablePW( exeName, taskName, false, false );
      UsageATAUnlock( exeName, taskName, false, false);
      UsageATAFreezelock( exeName, taskName, false, false );
      UsageATAEraseDevice( exeName, taskName, false, false );
//    UsageATAFIPS( exeName, taskName, false );  // Don't display this capability
   }

   // If we found a meta cmnd, then don't fall thru to individual cmnds

   if( metacmd )
      return;


   // If it's not a META taskName, then must be one of the actual commands:

   // COMMANDS FOUND ON ALL SEAGATE SEDs:

   if( _stricmp( taskName, "SD" ) == 0 ||
       _strnicmp( taskName, "ShowDrive", sizeof("ShowDrive")-1 ) == 0 )
   {
      UsageShowDriveInfo( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "RUL" ) == 0 ||
            _strnicmp( taskName, "ReadUserLBA", sizeof("ReadUserLBA")-1 ) == 0 )
   {
      UsageReadUserLBA( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "WUL" ) == 0 ||
            _strnicmp( taskName, "WriteUserLBA", sizeof("WriteUserLBA")-1 ) == 0 )
   {
      UsageWriteUserLBA( exeName, taskName, verbose, manpage );
   }

   // COMMANDS FOUND ON ALL SEAGATE TCG DEVICES

   else if( _stricmp( taskName, "LB" ) == 0 ||
            _strnicmp( taskName, "ListBands", sizeof("ListBand")-1 ) == 0 ||
            _stricmp( taskName, "LR" ) == 0 ||
            _strnicmp( taskName, "ListRanges", sizeof("ListRange")-1 ) == 0 )
   {
      UsageListRange( exeName, taskName, verbose, manpage );
   }
   else if( _strnicmp( taskName, "SR", sizeof("SR")-1 ) == 0 ||
            _strnicmp( taskName, "SetRange", sizeof("SetRange")-1 ) == 0 ||
            _strnicmp( taskName, "SB", sizeof("SB")-1 ) == 0 ||
            _strnicmp( taskName, "SetBand", sizeof("SetBand")-1 ) == 0 )
   {
      UsageSetRange( exeName, taskName, verbose, manpage );
   }
#if 0
   else if( _strnicmp( taskName, "RB", sizeof("RB")-1 ) == 0 ||
            _strnicmp( taskName, "ResizeBand", sizeof("ResizeBand")-1 ) == 0 )
   {
      UsageResizeBand( exeName, taskName, verbose, manpage );
   }
   else if( _strnicmp( taskName, "LK", sizeof("LK")-1 ) == 0 ||
            _strnicmp( taskName, "LockBand", sizeof("LockBand")-1 ) == 0 )
   {
      UsageLockBand( exeName, taskName, verbose, manpage );
   }
   else if( _strnicmp( taskName, "UL", sizeof("UL")-1 ) == 0 ||
            _strnicmp( taskName, "UnlockBand", sizeof("UnlockBand")-1 ) == 0 )
   {
      UsageUnlockBand( exeName, taskName, verbose, manpage );
   }
   else if( _strnicmp( taskName, "LOR", sizeof("LOR")-1 ) == 0 ||
            _strnicmp( taskName, "LR", sizeof("LR")-1 ) == 0 ||  // Deprecated Ver1.6.3
             _strnicmp( taskName, "LockOnReset", sizeof("LockOnReset")-1 ) == 0 )
   {
      UsageLockOnResetBand( exeName, taskName, verbose, manpage );
   }
#endif // disable other band/range commands
   else if( _strnicmp( taskName, "ER", sizeof("ER")-1 ) == 0 ||
            _strnicmp( taskName, "EraseRange", sizeof("EraseRange")-1 ) == 0 )
   {
      UsageEraseRange( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "SA" ) == 0 ||
        _strnicmp( taskName, "ShowAuthorities", sizeof("ShowAuth")-1 ) == 0 )
   {
      UsageShowAuthorities( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "EA" ) == 0  ||
             _stricmp( taskName, "EnableAuthority" ) == 0 )
   {
      UsageEnableAuthority( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "DA" ) == 0  ||
            _stricmp( taskName, "DisableAuthority" ) == 0 )
   {
      UsageDisableAuthority( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "CP" ) == 0 ||
            _stricmp( taskName, "ChangePin" ) == 0 )
   {
      UsageChangePin( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "RS" ) == 0 ||
            _stricmp( taskName, "ResetStack" ) == 0 )
   {
      UsageResetStack( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "GR" ) == 0 ||
            _stricmp( taskName, "GenerateRandom" ) == 0 )
   {
      UsageGenerateRandom( exeName, taskName, verbose, manpage );
   }
   else if( _strnicmp( taskName, "RDS", sizeof("RDS")-1 ) == 0 ||
             _strnicmp( taskName, "ReadDataStore", sizeof("ReadDataStore")-1 ) == 0 )
   {
      UsageReadDataStore( exeName, taskName, verbose, manpage );
   }
   else if( _strnicmp( taskName, "WDS", sizeof("WDS")-1 ) == 0 ||
             _strnicmp( taskName, "WriteDataStore", sizeof("WriteDataStore")-1 ) == 0 )
   {
      UsageWriteDataStore( exeName, taskName, verbose, manpage );
   }
   else if( _strnicmp( taskName, "SDS", sizeof("SDS")-1 ) == 0 ||
             _strnicmp( taskName, "ShowDataStore", sizeof("ShowDataStore")-1 ) == 0 )
   {
      UsageShowDataStore( exeName, taskName, verbose, manpage );
   }

   // COMMANDS ONLY FOUND ON SEAGATE OPAL SSC DEVICES

   else if( _stricmp( taskName, "AT" ) == 0 ||
            _stricmp( taskName, "Activate" ) == 0 )
   {
      UsageActivate( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "RA" ) == 0 ||
            _stricmp( taskName, "Reactivate" ) == 0 )
   {
      UsageReactivate( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "ETR" ) == 0 ||
            _stricmp( taskName, "EnableTPerReset" ) == 0 )
   {
      UsageEnableTPerReset( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "DTR" ) == 0 ||
            _stricmp( taskName, "DisableTPerReset" ) == 0 )
   {
      UsageDisableTPerReset( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "TR" ) == 0 || _stricmp( taskName, "RT" ) == 0 ||
            _stricmp( taskName, "TPerReset" ) == 0 || _stricmp( taskName, "ResetTPer" ) == 0 )
   {
      UsageTPerReset( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "RP" ) == 0 ||
            _stricmp( taskName, "RevertSP" ) == 0 )
   {
      UsageRevertSP( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "GA" ) == 0 ||
            _stricmp( taskName, "GrantAccess" ) == 0 )
   {
      UsageGrantAccess( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "RMT" ) == 0 ||
            _stricmp( taskName, "ReadMBRTable" ) == 0 )
   {
      UsageReadMBR( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "WMT" ) == 0 ||
            _stricmp( taskName, "WriteMBRTable" ) == 0 )
   {
      UsageWriteMBR( exeName, taskName, verbose, manpage );
   }
   else if(  _stricmp( taskName, "GMC" ) == 0 ||
             _stricmp( taskName, "GetMBRControl" ) == 0 )
   {
      UsageGetMBRControl( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "SMC" ) == 0 ||
            _stricmp( taskName, "SetMBRControl" ) == 0 )
   {
      UsageSetMBRControl( exeName, taskName, verbose, manpage );
   }

   // COMMANDS ONLY FOUND ON SEAGATE ENTERPRISE SSC DEVICES

   else if( _strnicmp( taskName, "EAR", sizeof("EAR")-1 ) == 0 ||
           _strnicmp( taskName, "EnableAuthorityForRange", sizeof("EnableAuthorityForRange")-1 ) == 0 )
   {
      UsageEnableAuthorityForRange( exeName, taskName, verbose, manpage );
   }
   else if( _strnicmp( taskName, "DAR", sizeof("DAR")-1 ) == 0 ||
            _strnicmp( taskName, "DisableAuthorityForRange", sizeof("DisableAuthorityForRange")-1 ) == 0 )
   {
      UsageDisableAuthorityForRange( exeName, taskName, verbose, manpage );
   }

   // ATA COMMANDS FOUND ON SEAGATE SED DEVICES

   else if( _strnicmp( taskName, "ASU", sizeof("ASU")-1 ) == 0 ||
            _strnicmp( taskName, "ATASetUser", sizeof("ATASetUser")-1 ) == 0 )
   {
      UsageATASetUserPW( exeName, taskName, verbose, manpage );
   }
   else if( _strnicmp( taskName, "ASM", sizeof("ASM")-1 ) == 0 ||
            _strnicmp( taskName, "ATASetMaster", sizeof("ATASetMaster")-1 ) == 0 )
   {
      UsageATASetMasterPW( exeName, taskName, verbose, manpage );
   }
   else if( _strnicmp( taskName, "ADP", sizeof("ADP")-1 ) == 0 ||
            _strnicmp( taskName, "ATADisablePW", sizeof("ATADisablePW")-1 ) == 0 )
   {
      UsageATADisablePW( exeName, taskName, verbose, manpage );
   }
   else if( _strnicmp( taskName, "AU", sizeof("AU")-1 ) == 0 ||
            _strnicmp( taskName, "ATAUnlock", sizeof("ATAUnlock")-1 ) == 0 )
   {
      UsageATAUnlock( exeName, taskName, verbose, manpage );
   }
   else if( _strnicmp( taskName, "AFL", sizeof("AFL")-1 ) == 0 ||
            _strnicmp( taskName, "ATAFreezelock", sizeof("ATAFreezelock")-1 ) == 0 )
   {
      UsageATAFreezelock( exeName, taskName, verbose, manpage );
   }
   else if( _strnicmp( taskName, "AED", sizeof("AED")-1 ) == 0 ||
            _strnicmp( taskName, "ATAEraseDevice", sizeof("ATAEraseDevice")-1 ) == 0 )
   {
      UsageATAEraseDevice( exeName, taskName, verbose, manpage );
   }

   // OTHER COMMANDS FOUND ON SEAGATE SED DEVICES:

   else if( _stricmp( taskName, "SUP" ) == 0 ||
            _stricmp( taskName, "SetUdsPort" ) == 0 )
   {
      UsageSetUdsPort( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "GUP" ) == 0 ||
            _stricmp( taskName, "GetUdsPort" ) == 0 )
   {
      UsageGetUdsPort( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "SFD" ) == 0 ||
            _stricmp( taskName, "SetFWDownload" ) == 0 )
   {
      UsageSetFWDownload( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "GFD" ) == 0 ||
            _stricmp( taskName, "GetFWDownload" ) == 0 )
   {
      UsageGetFWDownload( exeName, taskName, verbose, manpage );
   }

   else if( _stricmp( taskName, "FD" ) == 0 ||
            _stricmp( taskName, "FWDownload" ) == 0 )
   {
      UsageFWDownload( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "SAFP" ) == 0 ||
            _strnicmp( taskName, "SetAtaFIPS", sizeof("SetAtaFIPS")-1 ) == 0 )
   {
      UsageSAFP( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "GFP" ) == 0 ||
            _strnicmp( taskName, "GetFipsPolicy", sizeof("GetFipsPolicy")-1 ) == 0 )
   {
      UsageGTFP( exeName, taskName, verbose, manpage );
   }
   else if( _stricmp( taskName, "SFP" ) == 0 ||
            _strnicmp( taskName, "SetFipsPolicy", sizeof("SetFipsPolicy")-1 ) == 0 )
   {
      UsageSTFP( exeName, taskName, verbose, manpage );
   }

#if 0  // Room for expansion of commands
   else if(
   {
      UsageXX( exeName, taskName, verbose, manpage );
   }
   else if(
   {
      UsageXX( exeName, taskName, verbose, manpage );
   }
   else if(
   {
      UsageXX( exeName, taskName, verbose, manpage );
   }
   else if(
   {
      UsageXX( exeName, taskName, verbose, manpage );
   }
   else if(
   {
      UsageXX( exeName, taskName, verbose, manpage );
   }
   else if(
   {
      UsageXX( exeName, taskName, verbose, manpage );
   }
#endif // if 0
   else
   {
      std::wcerr << std::endl << "Command \"" << taskName << "\" not recognized, please use help:" << std::endl
                 << std::endl;
      UsageHelp( exeName, "top", true, true );
   }
} // usage


#if 0 // Save copy of usage templates here
   std::cout << "XYZ | XxxxYyyyZzzz    - <Short description of command here>  " << std::endl;

   if( verbose )
   {
      std::cout << "\nUsage:\n   " << exeName << " XZY | XxxxYyyyZzzz -RqdParam1<#> [-OptParam2<#> [<FileName>] [--NoLog]" << std::endl
                << "          [-a- <Auth>] [-p- <Passwd>]" << std::endl
                << std::endl;

      std::cout << "        where:" << std::endl
                << "          -RqdParam<#> - Describe Required Param with numberic suffix <#>" << std::endl
                << "          -OptParam<#> - Describe Optional Param with numberic suffix <#>" << std::endl
                << "          <FileName>   - Data will be written to filename, if supplied" << std::endl
                << "          -a- <Auth>   - Authority to use (default is Admin1)" << std::endl
                << "          -p- <Passwd> - Password of Authority (default is MSID)" << std::endl
                << std::endl;


      std::cout << "      Eg. " << exeName << " <show examples of command use> " << std::endl
                << "      Eg. " << exeName << "    " << std::endl
                << "      Eg. " << exeName << "    " << std::endl
                << std::endl;

      if( manpage )
         std::cout << "\nDetails:\n"
                   << "   " << exeName << " command XXX is ...\n"
                   << "   \n"
                   << std::endl;
      else
         std::cout << "   For additional help, run \"" << exeName << " MAN XYZ\"." << std::endl << std::endl;

#endif
