#ifndef __COMMON_H__
#define __COMMON_H__

#include "LinuxIncludes.h"

using namespace std;

// Constant definitions
#define BIT0		0x0001
#define BIT1		0x0002
#define BIT2		0x0004
#define BIT3		0x0008
#define BIT4		0x0010
#define BIT5		0x0020
#define BIT6		0x0040
#define BIT7		0x0080
#define BIT8		0x0100
#define BIT9		0x0200
#define BIT10		0x0400
#define BIT11		0x0800
#define BIT12		0x1000
#define BIT13		0x2000
#define BIT14		0x4000
#define BIT15		0x8000

#define LOW_NIBBLE	0x000000000000000F
#define BYTE0		0x00000000000000FF
#define BYTE1		0x000000000000FF00
#define BYTE2		0x0000000000FF0000
#define BYTE3		0x00000000FF000000
#define BYTE4		0x000000FF00000000
#define BYTE5		0x0000FF0000000000
#define BYTE6		0x00FF000000000000
#define BYTE7		0xFF00000000000000

#define BITS_1_TO_0_SET		3
#define BITS_2_TO_0_SET		7
#define BITS_3_TO_0_SET		15
#define BITS_4_TO_0_SET		31
#define BITS_5_TO_0_SET		63
#define BITS_6_TO_0_SET		127

// nvn20110624 - already defined in Xcommon & Pcommon
/*
// Structures and type definitions
typedef unsigned char       	tUINT8;
typedef unsigned short      	tUINT16;
typedef unsigned int      	tUINT32;
typedef unsigned long long      tUINT64;

#ifndef _WIN32
	typedef u_int64_t    UINT64, *PUINT64;
	typedef unsigned short      	UINT16, *PUINT16;
#endif

typedef unsigned char 		BYTE;

typedef char                	tINT8;
typedef short               	tINT16;
typedef int               	tINT32;
typedef long long               tINT64;
*/

typedef int 			HANDLE;

#if defined(__cplusplus)

   typedef bool               tBOOL;

#else // !defined(__cplusplus)

   typedef int                tBOOL;

#endif // !defined(__cplusplus)

#define PATH_SLASH "\\"


// Code
string ConvertDataToASCIIString( tUINT8* source_buffer, tUINT32 length );

void dStrHex(const char* str, int len, int no_ascii);


	


#endif
