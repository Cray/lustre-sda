/*! \file errors.h
    \brief Header file for dta error categories, codes, and structures.
    
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
///////////////////////////////////////////////////////////////////////////////
#ifndef DTA_ERRORS_DOT_H
#define DTA_ERRORS_DOT_H
//=================================
// Include files
//=================================
#include "dta/common.h"

#if defined __cplusplus
namespace dta {
#endif // if defined __cplusplus

//=================================
// Macro definitions
//=================================
/// Simple macro to determine if a DTA_ERROR
/// is reporting a success value.
#define M_DtaSuccess( x ) ( 0 == x.Error )
/// Simple macro to determine if a DTA_ERROR
/// is reporting a failure value.
#define M_DtaFail( x )    ( 0 != x.Error )

//=================================
// Enumerations
//=================================

/// eDtaErrorCategory is a list of known valid values for
/// the Category member of the DTA_ERROR structure.
typedef enum
{
   eDtaCategoryGeneric   = 0,  //!< Error detail maps to eDtaGenericError
   eDtaCategoryOS        = 1,  //!< Error detail is an OS error code (e.g. GetLastError()).
   eDtaCategoryDirect    = 2,  //!< Error detail maps to eDtaDirectError
   eDtaCategoryClient    = 3,  //!< Error detail maps to eDtaClientError
   eDtaCategoryService   = 4,  //!< Error detail maps to eDtaServiceError
   eDtaCategoryProtocol  = 5,  //!< Error detail maps to eDtaProtocolError
   // Additional error enumerations TBD.
} eDtaErrorCategory;

/// eDtaGenericError is a list of known valid values for
/// the Detail member of the DTA_ERROR_DETAIL structure when
/// the Category member is eDtaGenericError.
typedef enum
{
   eGenericNoError           = 0, //!< Success value
   eGenericWarning           = 1, //!< Operation completed with warning
   eGenericFatalError        = 2, //!< Catch-all for unclassifiable error
   eGenericTimeoutError      = 3, //!< Time-out value exceeded.
   eGenericDeviceUnavailable = 4, //!< Specified device cannot be used
   eGenericInvalidParameter  = 5, //!< User-provided parameter not valid
   eGenericNotImplemented    = 6, //!< Functionality not implemented
   eGenericInvalidIdentifier = 7, //!< Invalid identifier value
   eGenericAttributeReadOnly = 8, //!< Device attribute cannot be set.
   eGenericMemoryError       = 9, //!< Memory allocation/deallocation error.
   // Additional enumerations TBD.
} eDtaGenericError;

/// eDtaDirectError is a list of known valid values for
/// the Detail member of the DTA_ERROR_DETAIL structure when
/// the Category member is eDtaCategoryDirect.
typedef enum
{
   eDirectNoError       = 0, //!< Success value
   eDirectDeviceAbort   = 1, //!< Device aborted the command
   eDirectDeviceAddressNotFound = 2,   //!< Device could not find requed address/LBA
   eDirectFatalError    = 3, //!< Catch-all for unclassifiable error
   // Additional enumerations TBD.
} eDtaDirectError;

/// eDtaClientError is a list of known valid values for
/// the Detail member of the DTA_ERROR_DETAIL structure when
/// the Category member is eDtaCategoryClient.
typedef enum
{
   eClientNoError       = 0, //!< Success value
   eClientFatalError    = 1, //!< Catch-all for unclassifiable error
   // Additional enumerations TBD.
} eDtaClientError;

/// eDtaServiceError is a list of known valid values for
/// the Detail member of the DTA_ERROR_DETAIL structure when
/// the Category member is eDtaCategoryService.
typedef enum
{
   eServiceNoError       = 0, //!< Success value
   eServiceFatalError    = 1, //!< Catch-all for unclassifiable error
   // Additional enumerations TBD.
} eDtaServiceError;

/// eDtaProtocolError is a list of known valid values for
/// the Detail member of the DTA_ERROR_DETAIL structure when
/// the Category member is eDtaCategoryProtocol.
typedef enum
{
   eProtocolNoError       = 0, //!< Success value
   eProtocolFatalError    = 1, //!< Catch-all for unclassifiable error
   // Additional enumerations TBD.
} eDtaProtocolError;

//=================================
// typedefs and structures
//=================================
#pragma pack( push, 1 )

/// DTA_ERROR_DETAIL consists of an error category which 
/// shows the source of the error, and a Detail code 
/// explaining the problem found.
typedef struct _DTA_ERROR_DETAIL
{
   /// \brief Type of error.  Provides context to Detail.
   ///
   /// Category holds a value that tells an error handler how
   /// to interpret the error code held in Detail.  A list of
   /// categories used by DTA can be found in the 
   /// eDtaErrorCategory enumeration.
   tUINT64  Category;
   /// \brief Error number.  Relies on Category for context.
   ///
   /// Detail holds an error code that can be interpreted
   /// based on the associated Category.  For example, if
   /// Category is eDtaCategoryGeneric, the caller can then
   /// use the eDtaGenericError enumeration to interpret
   /// the error code found in Detail.
   tOSError Detail;
} DTA_ERROR_DETAIL;

/// The standard return value for DTA API functions.  If
/// an error is not found, Error should be equal to zero (no error)
typedef union _DTA_ERROR
{
   /// Unified error code for convenience.  A value of zero can
   /// safely be interpreted as success.
   tUINT64          Error;
   /// Information about the source (Category) and type (Detail)
   /// of error that occurred.
   DTA_ERROR_DETAIL Info; 
} DTA_ERROR;

#pragma pack( pop )

//=================================
// Inline functions
//=================================

/// Returns a DTA_ERROR from a eDtaGenericError
inline dta::DTA_ERROR Error( eDtaGenericError detail )
{
   dta::DTA_ERROR result;
   result.Info.Category = eDtaCategoryGeneric;
   result.Info.Detail   = detail;
   return result;
}

/// Returns a DTA_ERROR from a eDtaDirectError
inline dta::DTA_ERROR Error( eDtaDirectError detail )
{
   dta::DTA_ERROR result;
   result.Info.Category = eDtaCategoryDirect;
   result.Info.Detail   = detail;
   return result;
}

/// Returns a DTA_ERROR from a eDtaClientError
inline dta::DTA_ERROR Error( eDtaClientError detail )
{
   dta::DTA_ERROR result;
   result.Info.Category = eDtaCategoryClient;
   result.Info.Detail   = detail;
   return result;
}

/// Returns a DTA_ERROR from a eDtaServiceError
inline dta::DTA_ERROR Error( eDtaServiceError detail )
{
   dta::DTA_ERROR result;
   result.Info.Category = eDtaCategoryService;
   result.Info.Detail   = detail;
   return result;
}

/// Returns a DTA_ERROR from a eDtaProtocolError
inline dta::DTA_ERROR Error( eDtaProtocolError detail )
{
   dta::DTA_ERROR result;
   result.Info.Category = eDtaCategoryProtocol;
   result.Info.Detail   = detail;
   return result;
}

/// Returns a DTA_ERROR from a tOSError (Os-specific error code)
inline dta::DTA_ERROR Error( tOSError detail )
{
   dta::DTA_ERROR result;
   result.Info.Category = eDtaCategoryOS;
   result.Info.Detail   = detail;
   return result;
}

#if defined __cplusplus
} // namespace dta
#endif // if defined __cplusplus
#endif // DTA_ERRORS_DOT_H
