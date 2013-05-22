/*! \file TokenProcessor.hpp
    \brief Class declaration for TCG Tokens.

    This file contains the class structures for handling TCG token types.
    It is a C++ specific interface. For a 'C' interface, include 
    TokenProcessor.h instead of this file.
    
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

#ifndef TOKENPROCESSOR_DOT_HPP
#define TOKENPROCESSOR_DOT_HPP

#if !defined(__cplusplus)
#error C++ compiler required.  Include .h for 'C' compilers.
#endif
// !defined __cplusplus
//=================================
// Include files
//=================================
#include <math.h>
#include "dta/dta.hpp"
#include "../byteorder.hpp"
#include "TCGValues.h"

namespace dti
{
   //=================================
   // defines
   //=================================

   //=================================
   // structures and type definitions
   //=================================

   //=================================
   // class definitions
   //=================================

   //====================================================================================
   /// \brief Class that defines and handles TCG Tokens.
   ///
   /// CTcgTokens is a class the implements the TCG Tokens
   //====================================================================================
   class CTcgTokenProcessor
   {
   public:
      // Handles a generic Atom token
      dta::tByte* buildAtom( dta::tByte *pBuffer, dta::tByte *pData, tUINT32 length, bool flagByte=true, bool flagSign=false );
      dta::tByte* buildAtom( dta::tByte *pBuffer, tINT64 data, tUINT32 length=sizeof(tINT64), bool flagByte=false );
      dta::tByte* buildAtom( dta::tByte *pBuffer, tUINT64 data, tUINT32 length=sizeof(tUINT64), bool flagByte=false );
      dta::tByte* buildIntAtom( dta::tByte *pBuffer, tINT64 data );
      dta::tByte* buildIntAtom( dta::tByte *pBuffer, tUINT64 data );
      bool isAtom( dta::tByte tag );
      bool isAtomSigned( dta::tByte tag );
      bool isAtomBytes( dta::tByte tag );
      tUINT32 sizeofAtomData( dta::tByte *pAtom );
      tUINT32 sizeofAtom( dta::tByte *pAtom );
      dta::tByte* getAtomDataPointer( dta::tByte *pAtom, tUINT8 **pDataPointer, tUINT64 *pDataLength );
      dta::tByte* getAtomData( dta::tByte *pAtom, dta::tBytes &data );
      tUINT64 getAtomData( dta::tByte *pAtom );
      dta::tByte* getAtomData( dta::tByte *pAtom, tUINT64 *pData );

      // Tiny Atom
      dta::tByte* buildTinyAtom( dta::tByte *pBuffer, tINT8 value );
      dta::tByte* buildTinyAtom( dta::tByte *pBuffer, tUINT8 value );
      bool isTinyAtom( dta::tByte tag ) { return (TOKEN_MASK_TINY_TYPE & tag) == TOKEN_TYPE_TINY; }
      bool isTinyAtomSigned( dta::tByte tag ) { return (TOKEN_MASK_TINY_SIGN & tag) == TOKEN_MASK_TINY_SIGN; }
      tINT8 getTinyAtomData( dta::tByte *pTinyAtom );
      dta::tByte* getTinyAtomData( dta::tByte *pTinyAtom, tINT8 *pData );

      // Short Atom
      dta::tByte* buildShortAtom( dta::tByte *pBuffer, dta::tByte *pData, tUINT8 length, bool flagByte=true, bool flagSign=false );
      dta::tByte* buildShortAtom( dta::tByte *pBuffer, tINT64 data, tUINT8 length=sizeof(tINT64), bool flagByte=false );
      dta::tByte* buildShortAtom( dta::tByte *pBuffer, tUINT64 data, tUINT8 length=sizeof(tUINT64), bool flagByte=false );
      dta::tByte* buildUID( dta::tByte *pBuffer, tUINT64 uid ) { return buildShortAtom( pBuffer, uid, 8, true ); }
      dta::tByte* buildHalfUID( dta::tByte *pBuffer, tUINT64 uid ) { return buildShortAtom( pBuffer, uid, 4, true ); }
      bool isShortAtom( dta::tByte tag ) { return (TOKEN_MASK_SHORT_TYPE & tag) == TOKEN_TYPE_SHORT; }
      bool isShortAtomSigned( dta::tByte tag ) { return (TOKEN_MASK_SHORT_SIGN & tag) == TOKEN_MASK_SHORT_SIGN; }
      bool isShortAtomBytes( dta::tByte tag ) { return (TOKEN_MASK_SHORT_BYTE & tag) == TOKEN_MASK_SHORT_BYTE; }
      tUINT8 sizeofShortAtomData( dta::tByte *pShortAtom ) { return *pShortAtom & TOKEN_MASK_SHORT_SIZE; }
      tUINT8 sizeofShortAtom( dta::tByte *pShortAtom ) { return 1 + (*pShortAtom & TOKEN_MASK_SHORT_SIZE); }
      dta::tByte* getShortAtomData( dta::tByte *pShortAtom, dta::tBytes &data );
      tUINT64 getShortAtomData( dta::tByte *pShortAtom );
      dta::tByte* getShortAtomData( dta::tByte *pShortAtom, tUINT64* pData );

      // Medium Atom
      dta::tByte* buildMediumAtom( dta::tByte *pBuffer, dta::tByte *pData, tUINT16 length, bool flagByte=true, bool flagSign=false );
      dta::tByte* buildMediumAtom( dta::tByte *pBuffer, tINT64 data, tUINT16 length=sizeof(tINT64), bool flagByte=false );
      dta::tByte* buildMediumAtom( dta::tByte *pBuffer, tUINT64 data, tUINT16 length=sizeof(tUINT64), bool flagByte=false );
      bool isMediumAtom( dta::tByte tag ) { return (TOKEN_MASK_MEDIUM_TYPE & tag) == TOKEN_TYPE_MEDIUM; }
      bool isMediumAtomSigned( dta::tByte tag ) { return (TOKEN_MASK_MEDIUM_SIGN & tag) == TOKEN_MASK_MEDIUM_SIGN; }
      bool isMediumAtomBytes( dta::tByte tag ) { return (TOKEN_MASK_MEDIUM_BYTE & tag) == TOKEN_MASK_MEDIUM_BYTE; }
      tUINT16 sizeofMediumAtomData( dta::tByte *pMediumAtom )
      { 
         return m_swapper.NetToHost(*((tUINT16*)pMediumAtom)) & TOKEN_MASK_MEDIUM_SIZE;
      }
      tUINT16 sizeofMediumAtom( dta::tByte *pMediumAtom )
      { 
         return 2 + sizeofMediumAtomData( pMediumAtom );
      }
      dta::tByte* getMediumAtomData( dta::tByte *pMediumAtom, dta::tBytes &data );
      tUINT64 getMediumAtomData( dta::tByte *pMediumAtom );
      dta::tByte* getMediumAtomData( dta::tByte *pMediumAtom, tUINT64 *pData );

      // Long Atom
      dta::tByte* buildLongAtom( dta::tByte *pBuffer, dta::tByte *pData, tUINT32 length, bool flagByte=true, bool flagSign=false );
      dta::tByte* buildLongAtom( dta::tByte *pBuffer, tINT64 data, tUINT32 length=sizeof(tINT64), bool flagByte=false );
      dta::tByte* buildLongAtom( dta::tByte *pBuffer, tUINT64 data, tUINT32 length=sizeof(tUINT64), bool flagByte=false );
      bool isLongAtom( dta::tByte tag ) { return (TOKEN_MASK_LONG_TYPE & tag) == TOKEN_TYPE_LONG; }
      bool isLongAtomSigned( dta::tByte tag ) { return (TOKEN_MASK_LONG_SIGN & tag) == TOKEN_MASK_LONG_SIGN; }
      bool isLongAtomBytes( dta::tByte tag ) { return (TOKEN_MASK_LONG_BYTE & tag) == TOKEN_MASK_LONG_BYTE; }
      tUINT32 sizeofLongAtomData( dta::tByte *pLongAtom )
      { 
         return m_swapper.NetToHost(*((tUINT32*)pLongAtom)) & TOKEN_MASK_LONG_SIZE;
      }
      tUINT32 sizeofLongAtom( dta::tByte *pLongAtom )
      { 
         return 4 + sizeofLongAtomData( pLongAtom );
      }
      dta::tByte* getLongAtomData( dta::tByte *pLongAtom, dta::tBytes &data );
      tUINT64 getLongAtomData( dta::tByte *pLongAtom );
      dta::tByte* getLongAtomData( dta::tByte *pLongAtom, tUINT64 *pData );

      // List Token
      dta::tByte* buildListToken( dta::tByte *pBuffer, dta::tByte *pElements, tUINT32 length );
      dta::tByte* buildStartList( dta::tByte *pBuffer ) { *pBuffer++ = TOKEN_TYPE_START_LIST; return pBuffer; }
      dta::tByte* addListElement( dta::tByte *pBuffer, dta::tByte *pElement, tUINT32 length ) { memcpy(pBuffer, pElement, length); return pBuffer + length; }
      dta::tByte* buildEndList( dta::tByte *pBuffer ) { *pBuffer++ = TOKEN_TYPE_END_LIST; return pBuffer; }
      bool isList( dta::tBytes & data );
      bool isListToken( dta::tByte tag ) { return TOKEN_TYPE_START_LIST == tag; }
      bool isStartList( dta::tByte tag ) { return TOKEN_TYPE_START_LIST == tag; }
      bool isEndList( dta::tByte tag ) { return TOKEN_TYPE_END_LIST == tag; }
      bool isEmptyList( dta::tByte *pListToken ) { return sizeofListTokenData( pListToken ) == 0; }
      tUINT32 sizeofListTokenData( dta::tByte *pListToken );
      tUINT32 sizeofListToken( dta::tByte *pListToken ) { return 2 + sizeofListTokenData( pListToken ); }
      tUINT32 numberOfListItems( dta::tByte *pListToken );
      dta::tByte* getListTokenData( dta::tByte *pListToken, dta::tBytes &data );

      // NamedValue Token
      dta::tByte* buildNamedValueToken( dta::tByte *pBuffer, dta::tByte *pName, tUINT32 nameLen, dta::tByte *pData, tUINT32 dataLen, bool tokenFormat = false );
      dta::tByte* buildNamedValueToken( dta::tByte *pBuffer, dta::tByte *pName, tUINT32 nameLen, tINT64 data, int size =-1 );
      dta::tByte* buildNamedValueToken( dta::tByte *pBuffer, dta::tByte *pName, tUINT32 nameLen, tUINT64 data, int size =-1, bool flagByte=false );
      dta::tByte* buildNamedValueToken( dta::tByte *pBuffer, tUINT64 name, dta::tByte *pData, tUINT32 dataLen, bool tokenFormat = false );
      dta::tByte* buildNamedValueToken( dta::tByte *pBuffer, tUINT64 name, tINT64 data, int size =-1 );
      dta::tByte* buildNamedValueToken( dta::tByte *pBuffer, tUINT64 name, tUINT64 data, int size =-1, bool flagByte=false );
      dta::tByte* buildNamedValueToken( dta::tByte *pBuffer, tUINT64 uid, int uidSize, dta::tByte *pData, tUINT32 dataLen, bool tokenFormat = false );
      dta::tByte* buildNamedValueToken( dta::tByte *pBuffer, tUINT64 uid, int uidSize, tINT64 data, int size =-1 );
      dta::tByte* buildNamedValueToken( dta::tByte *pBuffer, tUINT64 uid, int uidSize, tUINT64 data, int size =-1, bool flagByte=false );
      dta::tByte* buildStartName( dta::tByte *pBuffer ) { *pBuffer++ = TOKEN_TYPE_START_NAME; return pBuffer; }
      dta::tByte* buildNamedValueTokenName( dta::tByte *pBuffer, dta::tByte *pName, tUINT32 length );
      dta::tByte* buildNamedValueTokenName( dta::tByte *pBuffer, tUINT64 name ) { return buildIntAtom( pBuffer, name ); }
      dta::tByte* buildNamedValueTokenDataObject( dta::tByte *pBuffer, dta::tByte *pData, tUINT32 length );
      dta::tByte* buildNamedValueTokenDataRaw( dta::tByte *pBuffer, dta::tByte *pData, tUINT32 length );
      dta::tByte* buildEndName( dta::tByte *pBuffer ) { *pBuffer++ = TOKEN_TYPE_END_NAME; return pBuffer; }
      bool isNamedValueToken( dta::tByte tag ) { return TOKEN_TYPE_START_NAME == tag; }
      bool isStartName( dta::tByte tag ) { return TOKEN_TYPE_START_NAME == tag; }
      bool isEndName( dta::tByte tag ) { return TOKEN_TYPE_END_NAME == tag; }
      tUINT32 sizeofNamedValueTokenName( dta::tByte *pNamedValueToken );
      tUINT32 sizeofNamedValueTokenValue( dta::tByte *pNamedValueToken );
      tUINT32 sizeofNamedValueToken( dta::tByte *pNamedValueToken ) 
      { return 2 + sizeofNamedValueTokenName( pNamedValueToken ) + sizeofNamedValueTokenValue( pNamedValueToken ); }
      dta::tByte* getNamedValueTokenName( dta::tByte *pNamedValueToken, dta::tBytes &name );
      dta::tByte* getNamedValueTokenName( dta::tByte *pNamedValueToken, tUINT64 &name );
      dta::tByte* getNamedValueTokenValue( dta::tByte *pNamedValueToken, dta::tBytes &data );
      dta::tByte* getNamedValueTokenValue( dta::tByte *pNamedValueToken, tUINT64 &data );

      // Call Token
      dta::tByte* buildCallToken( dta::tByte *pBuffer, tUINT64 targetUID, tUINT64 methodUID, dta::tByte *pParameters=NULL, tUINT32 paramLen=0, tUINT8 expectedStatus=TS_SUCCESS );
      dta::tByte* buildCallToken( dta::tByte *pBuffer, tUINT64 targetUID, tUINT64 methodUID, dta::tBytes &parameters, tUINT8 expectedStatus=TS_SUCCESS );
      dta::tByte* buildCallTokenHeader( dta::tByte *pBuffer, tUINT64 targetUID, tUINT64 methodUID );
      dta::tByte* buildCallTokenFooter( dta::tByte *pBuffer, tUINT8 expectedStatus=0 );
      bool isCallToken( dta::tByte tag ) { return TOKEN_TYPE_CALL == tag; }
      dta::tByte* getCallReturnedListData( dta::tByte *pReturnedData, dta::tBytes &data );
      tUINT8 getCallReturnedStatus( dta::tByte *pReturnedData );

      // End-of-Data Token
      dta::tByte* buildEOD( dta::tByte *pBuffer ) { *pBuffer++ = TOKEN_TYPE_END_OF_DATA; return pBuffer; }
      bool isEOD( dta::tByte tag ) { return TOKEN_TYPE_END_OF_DATA == tag; }

      // End-of-Session
      dta::tByte* buildEOS( dta::tByte *pBuffer ) { *pBuffer++ = TOKEN_TYPE_END_OF_SESSION; return pBuffer; }
      bool isEOS( dta::tByte tag ) { return TOKEN_TYPE_END_OF_SESSION == tag; }

      // Start Transaction
      dta::tByte* buildStartTransactionToken( dta::tByte *pBuffer ) { *pBuffer++ = TOKEN_TYPE_START_TRANSACTION; return pBuffer; }
      dta::tByte* buildStartTransaction( dta::tByte *pBuffer, tUINT8 status ) { return buildTinyAtom( buildStartTransactionToken( pBuffer ), status ); }
      bool isStartTransactionToken( dta::tByte tag ) { return TOKEN_TYPE_START_TRANSACTION == tag; }
      tUINT8 getStartTransactionStatus( dta::tByte *pStartTransactionToken ) { return getTinyAtomData( ++pStartTransactionToken ); }

      // End Transaction
      dta::tByte* buildEndTransactionToken( dta::tByte *pBuffer ) { *pBuffer++ = TOKEN_TYPE_END_TRANSACTION; return pBuffer; }
      dta::tByte* buildEndTransaction( dta::tByte *pBuffer, tUINT8 status ) { return buildTinyAtom( buildEndTransactionToken( pBuffer ), status ); }
      bool isEndTransactionToken( dta::tByte tag ) { return TOKEN_TYPE_END_TRANSACTION == tag; }
      tUINT8 getEndTransactionStatus( dta::tByte *pEndTransactionToken ) { return getTinyAtomData( ++pEndTransactionToken ); }

      // Empty Token
      dta::tByte* buildEmptyTokens( dta::tByte *pBuffer, int count );
      dta::tByte* skipEmptyTokens( dta::tByte *pBuffer, int *pCount=NULL );
      bool isEmptyToken( dta::tByte tag ) { return TOKEN_TYPE_EMPTY == tag; }

      // Utilities
      dta::tByte* skipSimpleToken( dta::tByte *pSimpleToken );
      dta::tByte* retrieveNamedDataFromList( dta::tBytes & list, tUINT8 *pName, tUINT32 nameLength );
      dta::tByte* retrieveNamedDataFromList( dta::tBytes & list, tUINT64 name );
      dta::tByte* retrieveNamedDataFromStream( dta::tByte* pNVStream, tUINT32 streamLength, tUINT8 *pName, tUINT32 nameLength );
      dta::tByte* retrieveNamedDataFromStream( dta::tByte* pNVStream, tUINT32 streamLength, tUINT64 name );

   protected:
      CByteOrder m_swapper;     /// Used for converting data stored between system and big endian format.

   }; // class CTcgTokenProcessor

} // namespace dti


#endif // TOKENPROCESSOR_DOT_HPP