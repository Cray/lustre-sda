/*! \file osLogObject.cpp
    \brief Implementation of COSLogObject

    \legal 
    All software, source code, and any additional materials contained
    herein (the "Software") are owned by Seagate Technology LLC and are 
    protected by law and international treaties.� No rights to the 
    Software, including any rights to distribute, reproduce, sell, or 
    use the Software, are granted unless a license agreement has been 
    mutually agreed to and executed between Seagate Technology LLC and 
    an authorized licensee.�

    The Software contains SEAGATE CONFIDENTIAL INFORMATION AND SEAGATE 
    TRADE SECRET INFORMATION that must be protected as such.

    Copyright � 2008.� Seagate Technology LLC �All Rights Reserved.

    The Software is provided under the Agreement No. 134849 between Seagate
    Technology and Calsoft. All Intellectual Property rights to the Software,
    as between Calsoft and Seagate, will be governed under the terms of the 
    Agreement No. 134849; no other rights to the Software are granted.
*/

//=================================
// Include files
//=================================
#include <sstream>
#include "osLogObject.hpp"
#include <time.h>
//#include <iostream>
//#include <windows.h>

//=================================
// macro/constant definitions
//=================================

//=================================
// typedefs and structures
//=================================

//=================================
// function implementations
//=================================

//=================================
// class implementations
//=================================

//================================================================
dta::COSLogObject::COSLogObject()
{
   // Set time zone from TZ environment variable. If TZ is not set,
   // the operating system is queried to obtain the default value 
   // for the variable. 
   //
   tzset(); // nvn20110624
}

//================================================================
dta::COSLogObject::~COSLogObject()
{
   Close();
}

//================================================================
bool dta::COSLogObject::IsOpen() const
{
   return m_file.is_open();
}

//================================================================
void dta::COSLogObject::Close()
{
   if ( IsOpen() )
   {
      m_file.close();
   }
}

//================================================================
bool dta::COSLogObject::Open( const _tstring& fileName,
                              const _tstring& title )
{
   Close();

   m_file.open( fileName.c_str(),
      std::ios_base::out | std::ios_base::app
      );

   if ( IsOpen() && title.size() )
   {
      _tstring hashes( 40, '-');
      AddLogEntry( dta::Success, hashes );
      AddLogEntry( dta::Success, title );
      AddLogEntry( dta::Success, hashes );
   }
   return IsOpen();
}

//================================================================
const dta::DTA_ERROR& dta::COSLogObject::AddLogEntry( 
      const dta::DTA_ERROR &error,
      const _tstring& text 
      )
{
   if ( IsOpen() && ( M_DtaSuccess(error) || text.size() ) )
   {
      // There is a log file, it's open, and I have something to log.
      _tostringstream sstr;

      // Begin the log entry with current date/time.
      sstr << CreateHeader();

      if ( !M_DtaSuccess( error ) )
      {
         sstr << CreateDtaErrorText( error );
         if ( text.size() )
         {
            sstr << ' ' << text;
         }
      }
      else if ( text.size() )
      {
         sstr << text;
      }
      sstr << std::endl;

      // sstr now contains the log entry.  Write it!
      m_file << sstr.str();
      m_file.flush();
   }

   return error;
}

//================================================================
_tstring dta::COSLogObject::CreateHeader() const
{
   // nvn20110624
   TCHAR tmpbuf[24];
   time_t rawtime;
   struct tm * timeinfo;
   _tostringstream result;

   time ( &rawtime );
   timeinfo = localtime ( &rawtime );

   strftime (tmpbuf,24,"%c",timeinfo);
   result << tmpbuf;
   result << ' ';

   return result.str();
}

//================================================================
_tstring dta::COSLogObject::CreateDtaErrorText(
   const dta::DTA_ERROR &error
   ) const
{
   _tstring str;
   bool unknownDetail = false;

   switch ( error.Info.Category )
   {
   case eDtaCategoryGeneric: // Error detail maps to eDtaGenericError
      switch( error.Info.Detail )
      {
      case eGenericNoError:
         str = TXT("Success");
         break;
      case eGenericWarning:
         str = TXT("Warning (Gen)");
         break;
      case eGenericFatalError:
         str = TXT("Fatal error (Gen)");
         break;
      case eGenericTimeoutError:
         str = TXT("Timeout exceeded (Gen)");
         break;
      case eGenericDeviceUnavailable:
         str = TXT("Device unavailable (Gen)");
         break;
      case eGenericInvalidParameter:
         str = TXT("User-provided parameter invalid (Gen)");
         break;
      case eGenericNotImplemented:
         str = TXT("Functionality not implemented (Gen)");
         break;
      case eGenericInvalidIdentifier:
         str = TXT("Invalid identifier name (Gen)");
         break;
      case eGenericAttributeReadOnly:
         str = TXT("Attribute is read only, cannot be changed (Gen)");
         break;
      case eGenericMemoryError:
         str = TXT("Memory error (Gen)");
         break;
      default:
         unknownDetail = true;
         str = TXT("Unknown eDtaCategoryGeneric error ");
         break;
      }
      break;
   case eDtaCategoryOS:      // Error detail maps to Win32 GetLastError()
      str = GetWin32ErrorString( error.Info.Detail );
      break;
   case eDtaCategoryDirect:  // Error detail maps to eDtaDirectError
      switch ( error.Info.Detail )
      {
      case eDirectNoError:
         str = TXT("Success (Direct)");
         break;
      case eDirectDeviceAbort:
         str = TXT("Device aborted operation (Direct)");
         break;
      case eDirectFatalError:
         str = TXT("Fatal error (Direct)");
         break;
      default:
         unknownDetail = true;
         str = TXT("Unknown eDtaCategoryDirect error ");
         break;
      }
      break;
   case eDtaCategoryClient:  // Error detail maps to eDtaClientError
      switch ( error.Info.Detail )
      {
      case eClientNoError:
         str = TXT("Success (Client)");
         break;
      case eClientFatalError:
         str = TXT("Fatal error (Client)");
         break;
      default:
         unknownDetail = true;
         str = TXT("Unknown eDtaCategoryClient error ");
         break;
      }
      break;
   case eDtaCategoryService: // Error detail maps to eDtaServiceError
      switch ( error.Info.Detail )
      {
      case eServiceNoError:
         str = TXT("Success (Service)");
         break;
      case eServiceFatalError:
         str = TXT("Fatal error (Service)");
         break;
      default:
         unknownDetail = true;
         str = TXT("Unknown eDtaCategoryService error ");
         break;
      }
      break;
   }

   if ( !str.size() )
   {
   }
   return str;
}

//================================================================
_tstring dta::COSLogObject::GetWin32ErrorString( tOSError error ) const
{
   _tstring result = "error";
   // nvn20110624 - TODO: empty function
   return result;
}
