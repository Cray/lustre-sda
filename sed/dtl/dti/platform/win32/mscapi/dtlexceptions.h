/*! \file dtlExceptions.h 
    \brief Seagate CExceptionChainObject Types file.

    This file must be defined per project to enumerate 
    what exception types are used by the project.

    \legal 
    All software, source code, and any additional materials contained
    herein (the "Software") are owned by Seagate Technology LLC and are 
    protected by law and international treaties.  No rights to the 
    Software, including any rights to distribute, reproduce, sell, or 
    use the Software, are granted unless a license agreement has been 
    mutually agreed to and executed between Seagate Technology LLC and 
    an authorized licensee. 

    The Software contains SEAGATE CONFIDENTIAL INFORMATION AND SEAGATE 
    TRADE SECRET INFORMATION that must be protected as such.

    Copyright © 2008.  Seagate Technology LLC  All Rights Reserved.

    The Software is provided under the Agreement No. 134849 between Seagate
    Technology and Calsoft. All Intellectual Property rights to the Software,
    as between Calsoft and Seagate, will be governed under the terms of the 
    Agreement No. 134849; no other rights to the Software are granted.
*/

#if !defined(_DTLExceptions_DOT_H)
#define      _DTLExceptions_DOT_H

//=========================================================
// enums (Typed constants)
//=========================================================
enum eExceptionType
{
   EXCEPTION_TYPE_UNHANDLED   = 0,      // Do not remove, used by Exception.h
   EXCEPTION_TYPE_PARAMETER   = 1,      // maps to eParameterException
   EXCEPTION_TYPE_APDU_STATUS = 2,      // maps to ENUM_STATUS_WORDS
   EXCEPTION_TYPE_DEVICE_INTERFACE = 3, // maps to eDeviceInterfaceResults
   EXCEPTION_TYPE_WIN32_ERROR = 4,      // maps to an OS error
   EXCEPTION_TYPE_ATA_ERROR   = 5,      // maps to ATA output registers.
   EXCEPTION_TYPE_TFR_ERROR   = 6,      // maps to ATA output TFRs.
   // TODO : Add your project's exception types here.
};

enum eParameterException
{
   PARAMETER_INVALID_INDEX         = 0, // an invalid array/device index
   PARAMETER_UNKNOWN_ERROR         = 1, // An unspecified error.
   PARAMETER_INVALID_POINTER       = 2, // pointer had invalid value
   PARAMETER_INVALID_DATA          = 3, // parameter failed data validation
};

enum eDeviceInterfaceResults
{
   eDIR_Success=0,
   eDIR_InvalidParameter,
   eDIR_Transport,
   eDIR_DeviceAbortError,
   eDIR_DeviceUnspecifiedError,
   eDIR_InvalidLBA,
   eDIR_NotSupported,
   eDIR_Timeout,
   eDIR_FatalError
};

//=========================================================
// Include files
//=========================================================
// Now that the eExceptionType is provided, we can
// include the base classes for implementations.

#include "Exception.h"
#include <dta/common.h>

//=========================================================
// Typedefs
//=========================================================
// Lastly, we can then typedef based on the above for
// some easy class definitions.

typedef tException< eParameterException, EXCEPTION_TYPE_PARAMETER > 
   CParameterException;
typedef tException< eDeviceInterfaceResults, EXCEPTION_TYPE_DEVICE_INTERFACE > 
   CDeviceInterfaceException;
typedef tException< int, EXCEPTION_TYPE_WIN32_ERROR >
   CWin32Exception;

#endif    // _DTDExceptions_DOT_H