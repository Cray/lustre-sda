//=================================================================================================
////  TCGDaemon.hpp
////  This is separate header file for the TCGDaemon utility.
////
////  \legal
////   All software, source code, and any additional materials contained
////   herein (the "Software") are owned by Seagate Technology LLC and are
////   protected by law and international treaties.  No rights to the
////   Software, including any rights to distribute, reproduce, sell, or
////   use the Software, are granted unless a license agreement has been
////   mutually agreed to and executed between Seagate Technology LLC and
////   an authorized licensee. 
////
////   The Software contains SEAGATE CONFIDENTIAL INFORMATION AND SEAGATE
////   TRADE SECRET INFORMATION that must be protected as such.
////
////   Copyright © 2009-2012.  Seagate Technology LLC  All Rights Reserved.
////
////  The Software is provided under the Agreement No. 134849 between Seagate
////  Technology and Calsoft. All Intellectual Property rights to the Software,
////  as between Calsoft and Seagate, will be governed under the terms of the
////  Agreement No. 134849; no other rights to the Software are granted.
////
////=================================================================================================

#define SED_INIT 0x00000000
#define SED_GET_PASSWORD_FROM_AD 0x00000001
#define SED_UNLOCK 0x00000002
#define SED_LOCK 0x00000003
#define SED_ADD_DRIVE 0x00000004
#define SED_BANDMASTER 0x00000005
#define SED_ERASEMASTER 0x00000006
#define SED_ADMIN 0x00000007
#define SED_END 0x00000008

#define MAX_DEV 256

#define VERSION_TOSTRING2(maj, min, rev, bld) #maj "." #min "." #rev "." #bld
#define VERSION_TOSTRING1(a,b,c,d) VERSION_TOSTRING2(a,b,c,d)
#define VERSION_TOSTRING(a,b,c,d)  VERSION_TOSTRING1(a,b,c,d)

char* add_entryinAD( std::string sserNum, int sSuNum );
struct str getParameter_fromAD( std::string sserNum, int sSuNum );
void SED_operation( string sserNum, int no_dev, CTcgDrive &device, int sSuNum );
char* extractParameter( char *tag, const bool getAll, int &argc, char* argv[] );
char* getParameter( const char *tag, const int start, const int argc, char* argv[] );
char* _version_ = VERSION_TOSTRING( VERSION_FILE_MAJOR, VERSION_FILE_MINOR, VERSION_FILE_REVISION, VERSION_FILE_BUILD );
bool SED_locking_operation( std::string sserNum, int sSuNum, CTcgDrive &device, bool lock_decision );

struct str{
	int lock;
	char *pin;
	bool entry_flag;
	char *diskId;
	char *msid;
	char *suid;
};
