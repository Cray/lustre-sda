/*! \file atatasks.cpp
    \brief Definition of ATA interactive tasks.

    TODO : Detailed description
    
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

    Copyright © 2009.  Seagate Technology LLC  All Rights Reserved.

    The Software is provided under the Agreement No. 134849 between Seagate
    Technology and Calsoft. All Intellectual Property rights to the Software,
    as between Calsoft and Seagate, will be governed under the terms of the 
    Agreement No. 134849; no other rights to the Software are granted.
*/

#ifndef ATATASKS_DOT_HPP
#define ATATASKS_DOT_HPP

//=================================
// Include files
//=================================
#include "Ata.hpp" // nvn20110614

namespace ata {

//=================================
// class definitions
//=================================

class CAtaTasks : public CAta
{
public:
   //================================================================
   /// Constructor
   //================================================================
   CAtaTasks();

   //================================================================
   /// Download a microcode file to the device..
   ///
   /// \return None.
   //================================================================
   void DownloadMicrocode();


}; // CAtaTasks

}; // namespace ata

#endif // ATATASKS_DOT_HPP
