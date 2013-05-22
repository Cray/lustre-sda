/*! \file OSLocalSystemObject.hpp
    \brief COSLocalSystemObject class definition.

    Provide the definition of an O/S-specific class that implements
    dta::CLocalSystem.  The implementation of this class will include
    details appropriate to the O/S (e.g. Win32 ).
    
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
///////////////////////////////////////////////////////////////////////////////

#ifndef OS_LOCAL_SYSTEM_OBJECT_DOT_HPP
#define OS_LOCAL_SYSTEM_OBJECT_DOT_HPP

#if !defined(__cplusplus)
#error C++ compiler required.
#endif
// !defined __cplusplus
//=================================
// Include files
//=================================
#include "dta/platform/linux32/osLogObject.hpp" // nvn20110624
#include <dta/dta.hpp>

namespace dtad {
//=================================
// macro definitions
//=================================

//=================================
// typedefs and structures
//=================================

//=================================
// class definitions
//=================================

/// \brief OS-specific implementation of CLocalSystem interface.
///
/// COSLocalSystem overrides and implements the pure virtual
/// functions from dta::CLocalSystem to provide a compilable
/// and useful implementation.
///
class COSLocalSystem : public dta::CLocalSystem
{
public:
   /// Constructor.
   COSLocalSystem();
   /// Destructor.
   virtual ~COSLocalSystem();

   // dta::CLocalSystem overrides
   virtual dta::DTA_ERROR GetDriveTrustIdentifiers(
      dta::DTIdentifierCollection &identifiers,
      const _tstring& = TXT(""),
      const _tstring& = TXT("")
      );
   virtual dta::DTA_ERROR GetDeviceAttribute(
      const dta::DTIdentifier& identifier,
      const _tstring& attribute,
      _tstring& value
      );
   virtual dta::DTA_ERROR CreateSession(
      const dta::DTIdentifier  &identifier,
      const tUINT8             protocol,
      const      _tstring      &options,
      dta::CDriveTrustSession* &session
      );

   // dta::DriveTrustBase overrides
   virtual dta::DTA_ERROR AddLogEntry( 
      const dta::DTA_ERROR &error,
      const _tstring& text 
      );
protected:
   dta::COSLogObject m_log;   //!< output log file object.
};

//=================================
// function definitions
//=================================

}  // end namespace dtad
#endif // OS_LOCAL_SYSTEM_OBJECT_DOT_HPP
