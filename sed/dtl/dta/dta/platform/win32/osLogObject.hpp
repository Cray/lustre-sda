/*! \file osLogObject.hpp
    \brief COSLogObject class definition.

    Provide the definition of an O/S-specific class that will log
    requested messages and errors to a log file.
    
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

#ifndef OS_LOG_OBJECT_DOT_HPP
#define OS_LOG_OBJECT_DOT_HPP

#if !defined(__cplusplus)
#error C++ compiler required.
#endif
// !defined __cplusplus
//=================================
// Include files
//=================================
#include <dta/dta.hpp>
#include <fstream>

namespace dta{
//=================================
// macro definitions
//=================================

//=================================
// typedefs and structures
//=================================

//=================================
// class definitions
//=================================

/// \brief Simple Windows logging class for DTA objects.
///
/// COSLogObject implements a simple logging object.  It
/// is used by other COS* objects within the DTA
/// hierarchy.
///
class COSLogObject
{
public:
   /// Constructor.
   COSLogObject();
   /// Destructor.
   virtual ~COSLogObject();

   //================================================================
   //
   /// Returns whether the log file is currently open (true) or closed (false).
   ///
   /// \return Boolean value denoting if the file is open (true)
   ///      or currently closed (false).
   ///
   /// @pre  None
   ///
   /// @post None
   //
   //================================================================
   virtual bool IsOpen() const;

   //================================================================
   //
   /// Open a log file by name and prepare to append output.
   ///
   /// \param fileName - (IN)
   ///      A filename to be opened for logging.  Data will 
   ///      always be appended to the file.
   ///
   /// \param title - (IN)
   ///      The title to be placed in the intial record in the file.
   ///
   /// \return Boolean value denoting if the file was opened (true)
   ///      or an error occurred (false).
   ///
   /// @pre  None
   ///
   /// @post None
   //
   //================================================================
   virtual bool Open( const _tstring& fileName, const _tstring& title );

   //================================================================
   //
   /// Close the log file if it is currently open.
   ///
   /// \return None
   ///
   /// @pre  None
   ///
   /// @post None
   //
   //================================================================
   virtual void Close();

   //================================================================
   //
   /// Add an entry to the log file, if it is open.
   ///
   /// \param error - (IN)
   ///      A DTA_ERROR enumeration, or success if no error is
   ///      to be reported to the log.
   ///
   /// \param text - (IN)
   ///      The text to be placed in the log file, or an empty
   ///      string if no extra text is requested.
   ///
   /// \return The error provided to the method.
   ///
   /// @pre  None
   ///
   /// @post None
   //
   //================================================================
   virtual const dta::DTA_ERROR& AddLogEntry( 
      const dta::DTA_ERROR &error,
      const _tstring& text 
      );

protected:
   //================================================================
   //
   /// Create a log entry header, including time stamp.
   ///
   /// \return The header string for the log entry.
   ///
   /// @pre  None
   ///
   /// @post None
   //
   //================================================================
   virtual _tstring CreateHeader() const;

   //================================================================
   //
   /// Convert a DTA_ERROR into an English text error string.
   ///
   /// \return The converted error text.
   ///
   /// \param error - (IN)
   ///      The error to be translated into text.
   ///
   /// @pre  None
   ///
   /// @post None
   //
   //================================================================
   virtual _tstring CreateDtaErrorText( const dta::DTA_ERROR &error ) const;

   //================================================================
   //
   /// Convert a Win32 GetLastError() code into an English text error string.
   ///
   /// \return The converted error text.
   ///
   /// \param error - (IN)
   ///      The error to be translated into text.
   ///
   /// @pre  None
   ///
   /// @post None
   //
   //================================================================
   virtual _tstring GetWin32ErrorString( tOSError error ) const;

   _tofstream m_file; //!< Output log file object.
};

//=================================
// function definitions
//=================================

}  // end namespace dta
#endif // OS_LOG_OBJECT_DOT_HPP
