/*! \file osCreateLocalSystemObject.cpp
    \brief Windows-specific implementation of CreateLocalSystemObject().

    This implementation is specific to the Windows O/S.  It may include
    Windows-specific headers and definitions as necessary.
    
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

//=================================
// Include files
//=================================
#include "osLocalSystemObject.hpp"
using namespace dta;

//=================================
// macro definitions
//=================================

//=================================
// typedefs and structures
//=================================

//=================================
// function implementations
//=================================
//========================================================================
/**
* Create a COSLocalSystemObject.
*
*
* \param localSystemObject - (OUT) 
*     pointer that will be filled in with a pointer to a 
*     CLocalSystem interface.  Any previous value in 
*     localSystemObject is discarded.
*
* \return DTA_ERROR - Return success (0) or error code.  This method
*     will not throw a C++ DTA_ERROR exception.
*
* @pre None.
*
* @post None.
*/
//========================================================================
DTA_ERROR dta::CreateLocalSystemObject( CLocalSystem* &localSystemObject )
{
   DTA_ERROR result = { 0 };
   localSystemObject = new dtad::COSLocalSystem();
   return result;
}

//=================================
// class implementations
//=================================
