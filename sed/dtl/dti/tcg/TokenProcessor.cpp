/*! \file TokenProcessor.cpp
    \brief Class definition and handle for TCG Tokens.

    This file contains the class definition for handling TCG token types.
    It's designed to work as a service provider to user/caller, generally
    expecting the caller to have allocated and pass in a buffer if needed.

    It is a C++ specific interface.
    
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

//=================================
// Include files
//=================================
#include "TokenProcessor.hpp"

using namespace dta;
using namespace dti;

//=================================================================================
/// \brief Build a size-fit atom from a data buffer, and save it to a given location.
///
/// \param pBuffer  [OUT] Destination buffer to keep the built atom.
/// \param pData    [IN]  Raw data bytes (device byte order) to be converted to an atom format.
/// \param length   [IN]  Length of the input data.
/// \param flagByte [IN]  Bool value for the "B" (Byte) bit in the atom.
/// \param flagSign [IN]  Bool value for the "S" (Sign) bit in the atom.
///
/// \pre Caller provides storage to save the result, pData must be in Device-format(Big-Endian).
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildAtom( dta::tByte *pBuffer, dta::tByte *pData, tUINT32 length, bool flagByte, bool flagSign )
{
   if( length > TOKEN_MASK_LONG_SIZE )
      throw (TCG_STATUS)TS_INVALID_PARAMETER;

   // Try to match the data size from the smallest(TinyAtom) to the largest(LongAtom)
   if( 1 == length )
   {
      if( !flagByte ) // an integer
      {
         if( flagSign )
         {
            if( *((tINT8*)pData) >= -32 || *((tINT8*)pData) <= 31 )
               return buildTinyAtom( pBuffer, *((tINT8*)pData) );
            else
               return buildShortAtom( pBuffer, pData, length, flagByte, flagSign );
         }
         else
         {
            if( *((tUINT8*)pData) <= TOKEN_MASK_TINY_DATA )
               return buildTinyAtom( pBuffer, *((tUINT8*)pData) );
            else
               return buildShortAtom( pBuffer, pData, length, flagByte, flagSign );
         }
      }
      else
      {
         // Tiny atom can only represent an integer. Bytes (with the 'B' bit set) has to appeal to larger atoms (ShortAtom, for instance).
         return buildShortAtom( pBuffer, pData, length, flagByte, flagSign );
      }
   }

   if( length <= TOKEN_MASK_SHORT_SIZE )
   {
      if( 0 == length && !(flagByte && !flagSign) ) // Zero is allowed only for non-continued Bytes token (B=1,S=0)
         throw (TCG_STATUS)TS_INVALID_PARAMETER;

      return buildShortAtom( pBuffer, pData, length, flagByte, flagSign );
   }

   if( length <= TOKEN_MASK_MEDIUM_SIZE )
   {
      return buildMediumAtom( pBuffer, pData, length, flagByte, flagSign );
   }

   return buildLongAtom( pBuffer, pData, length, flagByte, flagSign );

} // buildAtom

//=================================================================================
/// \brief Build a size-fit atom from a signed integer, and save it to a given location.
///
/// \param pBuffer  [OUT] Destination buffer to keep the built atom.
/// \param data     [IN]  Signed 64-bit integer to be converted to a size-fit atom format.
/// \param length   [IN]  Length of the converted data.
/// \param flagByte [IN]  Whether to set Byte flag.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildAtom( dta::tByte *pBuffer, tINT64 data, tUINT32 length, bool flagByte )
{
   if( 0 == length || length > TOKEN_MASK_LONG_SIZE )
      throw (TCG_STATUS)TS_INVALID_PARAMETER;

   if( 1 == length )
   {
      if( !flagByte ) // an integer
      {
         if( data >= -32 || data <= 31 )
            return buildTinyAtom( pBuffer, (tINT8)data );
      }
   }

   if( length <= TOKEN_MASK_SHORT_SIZE )
   {
      return buildShortAtom( pBuffer, data, length, flagByte );
   }

   if( length <= TOKEN_MASK_MEDIUM_SIZE )
   {
      return buildMediumAtom( pBuffer, data, length, flagByte );
   }

   return buildLongAtom( pBuffer, data, length, flagByte );

} // buildAtom

//=================================================================================
/// \brief Build a size-fit atom from an unsigned integer, and save it to a given location.
///
/// \param pBuffer  [OUT] Destination buffer to keep the built atom.
/// \param data     [IN]  Unsigned 64-bit integer to be converted to a size-fit atom format.
/// \param length   [IN]  Length of the converted data.
/// \param flagByte [IN]  Whether to set Byte flag.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildAtom( dta::tByte *pBuffer, tUINT64 data, tUINT32 length, bool flagByte )
{
   if( 0 == length || length > TOKEN_MASK_LONG_SIZE )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");

   if( 1 == length )
   {
      if( !flagByte ) // an integer
      {
         if( data <= TOKEN_MASK_TINY_DATA )
            return buildTinyAtom( pBuffer, (tUINT8)data );
      }
   }

   if( length <= TOKEN_MASK_SHORT_SIZE )
   {
      return buildShortAtom( pBuffer, data, length, flagByte );
   }

   if( length <= TOKEN_MASK_MEDIUM_SIZE )
   {
      return buildMediumAtom( pBuffer, data, length, flagByte );
   }

   return buildLongAtom( pBuffer, data, length, flagByte );

} // buildAtom

//=================================================================================
/// \brief Build a size-fit integer atom from a signed integer, and save it to a given location.
///
/// \param pBuffer  [OUT] Destination buffer to keep the built atom.
/// \param data     [IN]  Signed 64-bit integer to be converted to a size-fit atom format.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildIntAtom( dta::tByte *pBuffer, tINT64 data )
{
   if( data >= -32 && data <= 31 )
      return buildTinyAtom( pBuffer, (tINT8) data );

   int length;
   tUINT64 d = (data < 0) ? (-data) : data;
   for( length=63; length>=0; length-- )
   {
      if( d >> length )
         break;
   }
   length++; length++; // plus the sign-bit
   length = ( length + 7 ) / 8;

   return buildShortAtom( pBuffer, data, length );

} // buildIntAtom

//=================================================================================
/// \brief Build a size-fit integer atom from an unsigned integer, and save it to a given location.
///
/// \param pBuffer  [OUT] Destination buffer to keep the built atom.
/// \param data     [IN]  Unsigned 64-bit integer to be converted to a size-fit atom format.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildIntAtom( dta::tByte *pBuffer, tUINT64 data )
{
   if( data <= 63 )
      return buildTinyAtom( pBuffer, (tUINT8) data );

   int length;
   for( length=63; length>=0; length-- )
   {
      if( data >> length )
         break;
   }
   length++;
   length = ( length + 7 ) / 8;

   return buildShortAtom( pBuffer, data, length );

} // buildIntAtom

//=================================================================================
/// \brief Check if the given token tag is a type of Atom token.
///
/// \param tag [IN]  A token tag.
///
/// \return bool The result of the check whether the tag is an Atom token tag.
//=================================================================================
bool CTcgTokenProcessor::isAtom( dta::tByte tag )
{
   if( isTinyAtom( tag )   ||
       isShortAtom( tag )  ||
       isMediumAtom( tag ) ||
       isLongAtom( tag )   ||
       isEmptyToken( tag ) )
   {
      return true;
   }

   return false;

} // isAtom

//=================================================================================
/// \brief Check if the given token tag is a Signed Atom token.
///
/// \param tag [IN]  A token tag.
///
/// \pre Caller ensures the tag is an Atom token.
///
/// \exception throwing TCG_STATUS
///
/// \return bool The result of the check whether the tag is a Signed Atom token tag.
//=================================================================================
bool CTcgTokenProcessor::isAtomSigned( dta::tByte tag )
{
   if( !isAtom( tag ) )
   {
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Not an Atom token tag");
   }

   if( isTinyAtomSigned( tag )   ||
       isShortAtomSigned( tag )  ||
       isMediumAtomSigned( tag ) ||
       isLongAtomSigned( tag ) )
       //isEmptyTokenSigned( tag ) )
   {
      return true;
   }

   return false;

} // isAtomSigned

//=================================================================================
/// \brief Check if the given token tag is a Bytes Atom token.
///
/// \param tag [IN]  A token tag.
///
/// \pre Caller ensures the tag is an Atom token.
///
/// \exception throwing TCG_STATUS
///
/// \return bool The result of the check whether the tag is a Bytes Atom token tag.
//=================================================================================
bool CTcgTokenProcessor::isAtomBytes( dta::tByte tag )
{
   if( !isAtom( tag ) )
   {
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Not an Atom token tag");
   }

   if( //isTinyAtomBytes( tag )
       isShortAtomBytes( tag )  ||
       isMediumAtomBytes( tag ) ||
       isLongAtomBytes( tag ) )
       //isEmptyTokenBytes( tag ) )
   {
      return true;
   }

   return false;

} // isAtomBytes

//=================================================================================
/// \brief Report the length of the Atom token data.
///
/// \param pAtom [IN]  Pointer to a buffer holding an atom object.
///
/// \return tUINT32 The length (number of bytes) of the Atom token data.
//=================================================================================
tUINT32 CTcgTokenProcessor::sizeofAtomData( dta::tByte *pAtom )
{
   if( isTinyAtom(*pAtom) )
      return 1; // 6 bits(5..0) of a byte actually

   else if( isShortAtom(*pAtom) )
      return sizeofShortAtomData( pAtom );

   else if( isMediumAtom(*pAtom) )
      return sizeofMediumAtomData( pAtom );

   else if( isLongAtom(*pAtom) )
      return sizeofLongAtomData( pAtom );

   else if( isEmptyToken(*pAtom) )
      return 0;

   else // not Atom token
      return 0;

} // sizeofAtomData

//=================================================================================
/// \brief Report the length of the Atom token object.
///
/// \param pAtom [IN]  Pointer to a buffer holding an atom object.
///
/// \return tUINT32 The length (number of bytes) of the Atom token object.
//=================================================================================
tUINT32 CTcgTokenProcessor::sizeofAtom( dta::tByte *pAtom )
{
   if( isTinyAtom(*pAtom) )
      return 1;

   else if( isShortAtom(*pAtom) )
      return sizeofShortAtom( pAtom );

   else if( isMediumAtom(*pAtom) )
      return sizeofMediumAtom( pAtom );

   else if( isLongAtom(*pAtom) )
      return sizeofLongAtom( pAtom );

   else if( isEmptyToken(*pAtom) )
      return 1;

   else // not Atom token
      return 0;

} // sizeofAtom

//=================================================================================
/// \brief Retrieve the pointer to the atom data of bytes stream within an atom object buffer.
///
/// \param pAtom         [IN]  Pointer to a buffer holding an atom object.
/// \param pDataPointer  [OUT] A caller passed-in storage to keep the pointer of the atom data (in device format, byte stream).
/// \param pDataLength   [OUT] Pointer to the size of the the data section of the atom object. NULL means not interested.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getAtomDataPointer( dta::tByte *pAtom, tUINT8 **pDataPointer, tUINT64 * pDataLength )
{
   pAtom = skipEmptyTokens( pAtom );
   if( NULL == pAtom )
      throw (TCG_STATUS)TS_INVALID_PARAMETER;

   tUINT64 len = sizeofAtomData( pAtom );
   *pDataPointer = pAtom + ( sizeofAtom( pAtom ) - len );

   if( NULL != pDataLength )
      *pDataLength = len;

   return pAtom + sizeofAtom( pAtom );
} // getAtomDataPointer

//=================================================================================
/// \brief Retrieve atom data in byte stream from an atom object buffer.
///
/// \param pAtom [IN]  Pointer to a buffer holding an atom object.
/// \param data  [OUT] A caller passed-in buffer to keep the atom value (in device format).
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getAtomData( dta::tByte *pAtom, dta::tBytes &data )
{
   pAtom = skipEmptyTokens( pAtom );
   if( NULL == pAtom )
      throw (TCG_STATUS)TS_INVALID_PARAMETER;

   if( isTinyAtom(*pAtom) )
   {
      data.resize( 1 );
      return getTinyAtomData( pAtom, (tINT8*) &data[0] );
   }
   else if( isShortAtom(*pAtom) )
   {
      data.resize( sizeofShortAtomData( pAtom ) );
      return getShortAtomData( pAtom, data );
   }
   else if( isMediumAtom(*pAtom) )
   {
      data.resize( sizeofMediumAtomData( pAtom ) );
      return getMediumAtomData( pAtom, data );
   }
   else if( isLongAtom(*pAtom) )
   {
      data.resize( sizeofLongAtomData( pAtom ) );
      return getLongAtomData( pAtom, data );
   }
   else
   {
      data.resize( 0 );
      return pAtom;
      //throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Not Atom token");
   }
} // getAtomData

//=================================================================================
/// \brief Retrieve Atom data of an integer from an atom object buffer.
///
/// \param pAtom [IN]  Pointer to a buffer holding an atom object.
///
/// \pre Caller ensures it's an integer atom object, and has up to 64-bit data.
///
/// \exception throwing TCG_STATUS
///
/// \return tUINT64 the parsed integer value of the atom object (Directly casting to signed for a signed value).
//=================================================================================
tUINT64 CTcgTokenProcessor::getAtomData( dta::tByte *pAtom )
{
   pAtom = skipEmptyTokens( pAtom );

   if( NULL == pAtom )
      throw (TCG_STATUS)TS_INVALID_PARAMETER;

   if( isTinyAtom(*pAtom) )
   {
      return getTinyAtomData( pAtom );
   }
   else if( isShortAtom(*pAtom) )
   {
      return getShortAtomData( pAtom );
   }
   else if( isMediumAtom(*pAtom) )
   {
      return getMediumAtomData( pAtom );
   }
   else if( isLongAtom(*pAtom) )
   {
      return getLongAtomData( pAtom );
   }
   else
   {
      //return 0;
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Not Atom token");
   }
} // getAtomData

//=================================================================================
/// \brief Retrieve Atom data of an integer from an atom object buffer.
///
/// \param pAtom [IN]  Pointer to a buffer holding an atom object.
/// \param pData [OUT] A caller passed-in buffer to keep the atom value.
///
/// \pre Caller ensures it's an integer atom object, and has upto 64-bit data.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getAtomData( dta::tByte *pAtom, tUINT64 *pData )
{
   pAtom = skipEmptyTokens( pAtom );
   if( NULL == pAtom )
      throw (TCG_STATUS)TS_INVALID_PARAMETER;

   if( isTinyAtom(*pAtom) )
   {
      *pData = getTinyAtomData( pAtom );
      return ++pAtom;
   }
   else if( isShortAtom(*pAtom) )
   {
      return getShortAtomData( pAtom, pData );
   }
   else if( isMediumAtom(*pAtom) )
   {
      return getMediumAtomData( pAtom, pData );
   }
   else if( isLongAtom(*pAtom) )
   {
      return getLongAtomData( pAtom, pData );
   }
   else
   {
      //return pAtom;
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Not Atom token");
   }
} // getAtomData

//=================================================================================
/// \brief Build a tiny atom from a small signed integer and save it to a buffer.
///
/// \param pBuffer [OUT] Destination buffer to keep the built Tiny atom.
/// \param value   [IN]  A small signed integer to be converted to a Tiny atom.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildTinyAtom( dta::tByte *pBuffer, tINT8 value )
{
   if( value < -32 || value > 31 )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");
        
   *pBuffer++ = (TOKEN_MASK_TINY_DATA & value) | TOKEN_MASK_TINY_SIGN;
   return pBuffer;

} // buildTinyAtom

//=================================================================================
/// \brief Build a tiny atom from a small unsigned integer and save it to a buffer.
///
/// \param pBuffer [OUT] Destination buffer to keep the built Tiny atom.
/// \param value   [IN]  A small unsigned integer to be converted to a Tiny atom.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildTinyAtom( dta::tByte *pBuffer, tUINT8 value )
{
   if( value > 63 )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");
        
   *pBuffer++ = TOKEN_MASK_TINY_DATA & value;
   return pBuffer;

} // buildTinyAtom

//=================================================================================
/// \brief Retrieve a tiny atom value from a buffer holding a Tiny atom.
///
/// \param pTinyAtom [IN] Buffer containing a Tiny atom.
///
/// \pre Caller makes usre that the input points to a Tiny atom object.
///
/// \return tINT8, the parsed tiny atom value.
//=================================================================================
tINT8 CTcgTokenProcessor::getTinyAtomData( dta::tByte *pTinyAtom )
{
   tINT8 data = TOKEN_MASK_TINY_DATA & (*pTinyAtom);

   if( TOKEN_MASK_TINY_SIGN & (*pTinyAtom) )
   {
      if( TOKEN_MASK_TINY_DATA_MSB & (*pTinyAtom) )
         data |= TOKEN_MASK_TINY_DATA_NEG; // Make up the negative sign bits occupied by token tags
   }

   return data;

} // getTinyAtomData

//=================================================================================
/// \brief Retrieve a tiny atom value from a buffer holding a Tiny atom.
///
/// \param pTinyAtom [IN] Buffer containing a Tiny atom.
/// \param pData     [IN] Buffer to hold the return data of the token.
///
/// \pre Caller makes usre that the input points to a Tiny atom object.
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getTinyAtomData( dta::tByte *pTinyAtom, tINT8 *pData )
{
   *pData = getTinyAtomData( pTinyAtom );
   return ++pTinyAtom;

} // getTinyAtomData

//=================================================================================
/// \brief Build a Short atom from a data buffer, and save it to a given location.
///
/// \param pBuffer  [OUT] Destination buffer to keep the built Short atom.
/// \param pData    [IN]  Raw data bytes (device format) to be converted to a Short atom format.
/// \param length   [IN]  Length of the input data (Zero is allowed only for non-continued Bytes token).
/// \param flagByte [IN]  Bool value for the "B" (Byte) bit in the Short atom.
/// \param flagSign [IN]  Bool value for the "S" (Sign) bit in the Short atom.
///
/// \pre Caller provides storage to save the result, pData must be in Device-format.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildShortAtom( dta::tByte *pBuffer, dta::tByte *pData, tUINT8 length, bool flagByte, bool flagSign )
{
   if( length > TOKEN_MASK_SHORT_SIZE )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");

   if( 0 == length && !(flagByte && !flagSign) ) // Zero is allowed only for non-continued Bytes token (B=1,S=0)
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");

   // Set up header/tag byte
   *pBuffer = TOKEN_TYPE_SHORT | length;

   if( flagByte )
      *pBuffer |= TOKEN_MASK_SHORT_BYTE;

   if( flagSign )
      *pBuffer |= TOKEN_MASK_SHORT_SIGN;

   // Save data
   if( length > 0 )
      memcpy( pBuffer+1, pData, length );

   return pBuffer + length +1;

} // buildShortAtom

//=================================================================================
/// \brief Build a Short atom from a unsigned integer, and save it to a given location.
///
/// \param pBuffer  [OUT] Destination buffer to keep the built Short atom.
/// \param data     [IN]  Unsigned 64-bit integer to be converted to a Short atom format.
/// \param length   [IN]  Length of the converted data.
/// \param flagByte [IN]  Whether to set Byte flag.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildShortAtom( dta::tByte *pBuffer, tUINT64 data, tUINT8 length, bool flagByte )
{
   if( 0 == length || length > 8 || length > TOKEN_MASK_SHORT_SIZE )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");

   tUINT64 d = m_swapper.HostToNet( data );
   return buildShortAtom( pBuffer, ((dta::tByte*)&d ) + 8-length, length, flagByte, false );

} // buildShortAtom

//=================================================================================
/// \brief Build a Short atom from a signed integer, and save it to a given location.
///
/// \param pBuffer  [OUT] Destination buffer to keep the built Short atom.
/// \param data     [IN]  Signed 64-bit integer to be converted to a Short atom format.
/// \param length   [IN]  Length of the converted data.
/// \param flagByte [IN]  Whether to set Byte flag.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildShortAtom( dta::tByte *pBuffer, tINT64 data, tUINT8 length, bool flagByte )
{
   if( 0 == length || length > 8 || length > TOKEN_MASK_SHORT_SIZE )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");

   tINT64 d = m_swapper.HostToNet( (tUINT64)data );
   return buildShortAtom( pBuffer, ((dta::tByte*)&d ) + 8-length, length, flagByte, true );

} // buildShortAtom

//=================================================================================
/// \brief Retrieve Short atom data of a byte stream from a Short atom buffer.
///
/// \param pShortAtom [IN]  Pointer to a buffer holding a Short atom object.
/// \param data       [OUT] A caller passed-in buffer to keep the Short atom value (Device format).
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getShortAtomData( dta::tByte *pShortAtom, dta::tBytes &data )
{
   if( !isShortAtom( *pShortAtom ) )
   {
      data.resize( 0 );
      return pShortAtom;
   }

   tUINT8 length = *pShortAtom & TOKEN_MASK_SHORT_SIZE;
   if( length > TOKEN_MASK_SHORT_SIZE )
   {
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");
   }

   if( 0 == length && !(isShortAtomBytes( *pShortAtom ) && !isShortAtomSigned( *pShortAtom )) ) // Zero is allowed only for non-continued Bytes token (B=1,S=0)
   {
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");
   }

   data.resize( length );
   if( length > 0 )
      memcpy( &data[0], pShortAtom+1, length );

   return pShortAtom + length +1;

} // getShortAtomData

//=================================================================================
/// \brief Retrieve Short atom data of an integer or UID bytes from a Short atom buffer.
///
/// \param pShortAtom [IN]  Pointer to a buffer holding a Short atom object.
///
/// \pre Caller ensures it's a Short atom object, and has upto 64-bit data.
///
/// \exception throwing TCG_STATUS
///
/// \return tUINT64 the parsed integer value of the Short atom object (Directly casting to signed for a signed value).
//=================================================================================
tUINT64 CTcgTokenProcessor::getShortAtomData( dta::tByte *pShortAtom )
{
   if( !isShortAtom( *pShortAtom ) )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data type");

   tUINT8 length = *pShortAtom & TOKEN_MASK_SHORT_SIZE;
   if( 0 == length || length > TOKEN_MASK_SHORT_SIZE )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");

   if( length > 8 )
      length = 8; // It's caller's responsibility to ensure fetching the correct size of data.

   tUINT64 data = 0;

   if( isShortAtomSigned(*pShortAtom) && ( *(pShortAtom+1) & 0x80 ) == 0x80 )
      data = 0xFFFFFFFFFFFFFFFF; // Make up for negetive value

   for( int ii=1; ii<=length; ii++ )
   {
      *((tUINT8 *)&data + length -ii) = *(pShortAtom + ii);
   }

   return data;

} // getShortAtomData

//=================================================================================
/// \brief Retrieve Short atom data of an integer or bytes (UID) from a Short atom buffer.
///
/// \param pShortAtom [IN]  Pointer to a buffer holding a Short atom object.
/// \param pData      [IN]  Buffer to hold the return data of the token.
///
/// \pre Caller ensures it's a Short atom object, and has upto 64-bit data.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getShortAtomData( dta::tByte *pShortAtom, tUINT64* pData )
{
   *pData = getShortAtomData( pShortAtom );

   tUINT8 length = *pShortAtom & TOKEN_MASK_SHORT_SIZE;
   if( length > 8 )
      length = 8; // It's caller's responsibility to ensure fetching the correct size of data.

   return pShortAtom + length +1;

} // getShortAtomData

//=================================================================================
/// \brief Build a Medium atom from a data buffer, and save it to a given location.
///
/// \param pBuffer  [OUT] Destination buffer to keep the built Medium atom.
/// \param pData    [IN]  Raw data bytes (Device-format) to be converted to a Medium atom format.
/// \param length   [IN]  Length of the input data.
/// \param flagByte [IN]  Bool value for the "B" (Byte) bit in the Medium atom.
/// \param flagSign [IN]  Bool value for the "S" (Sign) bit in the Medium atom.
///
/// \pre Caller provides storage to save the result, pData must be in device format.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildMediumAtom( dta::tByte *pBuffer, dta::tByte *pData, tUINT16 length, bool flagByte, bool flagSign )
{
   if( 0 == length || length > TOKEN_MASK_MEDIUM_SIZE )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");

   // Setup header/tag byte
   *pBuffer = TOKEN_TYPE_MEDIUM | ((tUINT8)(length >> 8));
   *(pBuffer +1)= (tUINT8)length;

   if( flagByte )
      *pBuffer |= TOKEN_MASK_MEDIUM_BYTE;

   if( flagSign )
      *pBuffer |= TOKEN_MASK_MEDIUM_SIGN;

   // Save data
   memcpy( pBuffer+2, pData, length );

   return pBuffer + length +2;

} // buildMediumAtom

//=================================================================================
/// \brief Build a Medium atom from a unsigned integer, and save it to a given location.
///
/// \param pBuffer  [OUT] Destination buffer to keep the built Medium atom.
/// \param data     [IN]  Unsigned 64-bit integer to be converted to a Medium atom format.
/// \param length   [IN]  Length of the converted data.
/// \param flagByte [IN]  Whether to set Byte flag.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildMediumAtom( dta::tByte *pBuffer, tUINT64 data, tUINT16 length, bool flagByte )
{
   if( 0 == length || length > 8 || length > TOKEN_MASK_MEDIUM_SIZE )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");

   tUINT64 d = m_swapper.HostToNet( data );
   return buildMediumAtom( pBuffer, ((dta::tByte*)&d ) +8-length, length, flagByte, false );

} // buildMediumAtom

//=================================================================================
/// \brief Build a Medium atom from a signed integer, and save it to a given location.
///
/// \param pBuffer  [OUT] Destination buffer to keep the built Medium atom.
/// \param data     [IN]  Signed 64-bit integer to be converted to a Medium atom format.
/// \param length   [IN]  Length of the converted data.
/// \param flagByte [IN]  Whether to set Byte flag.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildMediumAtom( dta::tByte *pBuffer, tINT64 data, tUINT16 length, bool flagByte )
{
   if( 0 == length || length > 8 || length > TOKEN_MASK_MEDIUM_SIZE )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");

   tINT64 d = m_swapper.HostToNet( (tUINT64)data );
   return buildMediumAtom( pBuffer, ((dta::tByte*)&d ) +8-length, length, flagByte, true );

} // buildMediumAtom

//=================================================================================
/// \brief Retrieve Medium atom data of a byte stream from a Medium atom buffer.
///
/// \param pMediumAtom [IN]  Pointer to a buffer holding a Medium atom object.
/// \param data        [OUT] A caller passed-in buffer to keep the Medium atom value in device format.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getMediumAtomData( dta::tByte *pMediumAtom, dta::tBytes &data )
{
   if( !isMediumAtom( *pMediumAtom ) )
   {
      data.resize( 0 );
      return pMediumAtom;
   }

   tUINT16 length = sizeofMediumAtomData( pMediumAtom );
   if( 0 == length || length > TOKEN_MASK_MEDIUM_SIZE )
   {
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");
   }

   data.resize( length );
   memcpy( &data[0], pMediumAtom+2, length );
   return pMediumAtom + length +2;

} // getMediumAtomData

//=================================================================================
/// \brief Retrieve Medium atom data of an integer from a Medium atom buffer.
///
/// \param pMediumAtom [IN]  Pointer to a buffer holding a Medium atom object.
///
/// \pre Caller ensures it's a Medium atom object, and has upto 64-bit data.
///
/// \exception throwing TCG_STATUS
///
/// \return tUINT64 the parsed integer value of the Medium atom object (Directly casting to signed for a signed value).
//=================================================================================
tUINT64 CTcgTokenProcessor::getMediumAtomData( dta::tByte *pMediumAtom )
{
   if( !isMediumAtom( *pMediumAtom ) )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data type");

   tUINT16 length = sizeofMediumAtomData( pMediumAtom );
   if( 0 == length || length > TOKEN_MASK_MEDIUM_SIZE )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");

   if( length > 8 )
      length = 8; // It's caller's responsibility to ensure fetching the correct size of data.

   tUINT64 data = 0;

   if( isMediumAtomSigned(*pMediumAtom) && ( *(pMediumAtom+2) & 0x80 ) == 0x80 )
      data = 0xFFFFFFFFFFFFFFFF; // Make up for negetive value

   for( int ii=1; ii<=length; ii++ )
   {
      *((tUINT8 *)&data + length -ii) = *(pMediumAtom + 1 + ii);
   }

   return data;

} // getMediumAtomData

//=================================================================================
/// \brief Retrieve Medium atom data of an integer from a Medium atom buffer.
///
/// \param pMediumAtom [IN]  Pointer to a buffer holding a Medium atom object.
///
/// \param pData [IN]
///
/// \pre Caller ensures it's a Medium atom object, and has upto 64-bit data.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getMediumAtomData( dta::tByte *pMediumAtom, tUINT64 *pData )
{
   *pData = getMediumAtomData( pMediumAtom );

   tUINT16 length = sizeofMediumAtomData( pMediumAtom );
   if( length > 8 )
      length = 8; // It's caller's responsibility to ensure fetching the correct size of data.

   return pMediumAtom + length +2;

} // getMediumAtomData

//=================================================================================
/// \brief Build a Long atom from a data buffer, and save it to a given location.
///
/// \param pBuffer  [OUT] Destination buffer to keep the built Long atom.
/// \param pData    [IN]  Raw data bytes (device format) to be converted to a Long atom format.
/// \param length   [IN]  Length of the input data.
/// \param flagByte [IN]  Bool value for the "B" (Byte) bit in the Long atom.
/// \param flagSign [IN]  Bool value for the "S" (Sign) bit in the Long atom.
///
/// \pre Caller provides storage to save the result, pData must be in device format.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildLongAtom( dta::tByte *pBuffer, dta::tByte *pData, tUINT32 length, bool flagByte, bool flagSign )
{
   if( 0 == length || length > TOKEN_MASK_LONG_SIZE )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");

   // Setup header/tag byte
   *pBuffer = TOKEN_TYPE_LONG;
       
   if( flagByte )
      *pBuffer |= TOKEN_MASK_LONG_BYTE;

   if( flagSign )
      *pBuffer |= TOKEN_MASK_LONG_SIGN;

   *(pBuffer +1)= (tUINT8)( length >> 16 );
   *(pBuffer +2)= (tUINT8)( length >> 8 );
   *(pBuffer +3)= (tUINT8)length;

   // Save data
   memcpy( pBuffer+4, pData, length );

   return pBuffer + length +4;

} // buildLongAtom

//=================================================================================
/// \brief Build a Long atom from a signed integer, and save it to a given location.
///
/// \param pBuffer  [OUT] Destination buffer to keep the built Long atom.
/// \param data     [IN]  Signed 64-bit integer to be converted to a Long atom format.
/// \param length   [IN]  Length of the converted data.
/// \param flagByte [IN]  Whether to set Byte flag.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildLongAtom( dta::tByte *pBuffer, tINT64 data, tUINT32 length, bool flagByte )
{
   if( 0 == length || length > 8 || length > TOKEN_MASK_LONG_SIZE )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");

   tINT64 d = m_swapper.HostToNet( (tUINT64)data );
   return buildLongAtom( pBuffer, ((dta::tByte*)&d ) +8-length, length, flagByte, false );

} // buildLongAtom

//=================================================================================
/// \brief Build a Long atom from an unsigned integer, and save it to a given location.
///
/// \param pBuffer  [OUT] Destination buffer to keep the built Long atom.
/// \param data     [IN]  Unsigned 64-bit integer to be converted to a Long atom format.
/// \param length   [IN]  Length of the converted data.
/// \param flagByte [IN]  Whether to set Byte flag.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildLongAtom( dta::tByte *pBuffer, tUINT64 data, tUINT32 length, bool flagByte )
{
   if( 0 == length || length > 8 || length > TOKEN_MASK_LONG_SIZE )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");

   tUINT64 d = m_swapper.HostToNet( data );
   return buildLongAtom( pBuffer, ((dta::tByte*)&d ) +8-length, length, flagByte, true );

} // buildLongAtom

//=================================================================================
/// \brief Retrieve Long atom data of a byte stream from a Long atom buffer.
///
/// \param pLongAtom [IN]  Pointer to a buffer holding a Long atom object.
/// \param data      [OUT] A caller passed-in buffer to keep the Long atom value in device format.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getLongAtomData( dta::tByte *pLongAtom, dta::tBytes &data )
{
   if( !isLongAtom( *pLongAtom ) )
   {
      data.resize( 0 );
      return pLongAtom;
   }

   tUINT32 length = sizeofLongAtomData( pLongAtom );
   if( 0 == length || length > TOKEN_MASK_LONG_SIZE )
   {
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");
   }

   data.resize( length );
   memcpy( &data[0], pLongAtom+4, length );
   return pLongAtom + length +4;

} // getLongAtomData

//=================================================================================
/// \brief Retrieve Long atom data of an integer from a Long atom buffer.
///
/// \param pLongAtom [IN]  Pointer to a buffer holding a Long atom object.
///
/// \pre Caller ensures it's a Long atom object, and has upto 64-bit data.
///
/// \exception throwing TCG_STATUS
///
/// \return tUINT64 the parsed integer value of the Long atom object (Directly casting to signed for a signed value).
//=================================================================================
tUINT64 CTcgTokenProcessor::getLongAtomData( dta::tByte *pLongAtom )
{
   if( !isLongAtom( *pLongAtom ) )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data type");

   tUINT32 length = sizeofLongAtomData( pLongAtom );
   if( 0 == length || length > TOKEN_MASK_LONG_SIZE )
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");

   if( length > 8 )
      length = 8; // It's caller's responsibility to ensure fetching the correct size of data.

   tUINT64 data = 0;

   if( isLongAtomSigned(*pLongAtom) && ( *(pLongAtom+4) & 0x80 ) == 0x80 )
      data = 0xFFFFFFFFFFFFFFFF; // Make up for negetive value

   for( tUINT32 ii=1; ii<=length; ii++ )
   {
      *((tUINT8 *)&data + length -ii) = *(pLongAtom + 3 + ii);
   }

   return data;

} // getLongAtomData

//=================================================================================
/// \brief Retrieve Long atom data of an integer from a Long atom buffer.
///
/// \param pLongAtom [IN]  Pointer to a buffer holding a Long atom object.
///
/// \param pData [IN] Pointer to Long (int64) data for atom
///
/// \pre Caller ensures it's a Long atom object, and has upto 64-bit data.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getLongAtomData( dta::tByte *pLongAtom, tUINT64 *pData )
{
   *pData = getLongAtomData( pLongAtom );

   tUINT32 length = sizeofLongAtomData( pLongAtom );
   if( length > 8 )
      length = 8; // It's caller's responsibility to ensure fetching the correct size of data.

   return pLongAtom + length +4;

} // getLongAtomData

//=================================================================================
/// \brief Build a List token from a byte stream of elements, and save it to a given location.
///
/// \param pBuffer   [OUT] Destination buffer to keep the built List token.
/// \param pElements [IN]  Byte stream of list elements to be converted to a List token format.
/// \param length    [IN]  Length of the elements.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildListToken( dta::tByte *pBuffer, dta::tByte *pElements, tUINT32 length )
{
   *pBuffer++ = TOKEN_TYPE_START_LIST;

   if( NULL != pElements && length > 0 )
   {
      memcpy( pBuffer, pElements, length );
      pBuffer += length;
   }

   *pBuffer++ = TOKEN_TYPE_END_LIST;

   return pBuffer;

} // buildListToken

//=================================================================================
/// \brief Check the given buffer contains a list, regardless empty list.
///
/// \param data  [IN]  Passed-in buffer holding the List.
///
/// \return bool True if it has a list, False otherwise.
//=================================================================================
bool CTcgTokenProcessor::isList( dta::tBytes & data )
{
   if( data.size() < 2 ) // At least []
      return false;

   if( isStartList( data[0] ) && isEndList( data[data.size() -1] ) )
      return true;
   else
      return false;
} // isList

//=================================================================================
/// \brief Count the total length of all elements in the list.
///
/// \param pListToken  [IN]  Passed-in buffer holding the List token.
///
/// \exception throwing TCG_STATUS
///
/// \return tUINT32 the length (number of bytes) of the List data.
//=================================================================================
tUINT32 CTcgTokenProcessor::sizeofListTokenData( dta::tByte *pListToken )
{
   if( !isListToken(*pListToken) )
      return 0;

   tUINT8 *p = pListToken +1;
   int layerCnt = 0;
   while( !( isEndList(*p) && 0 == layerCnt ) )
   {
      if( isStartList(*p) )
         layerCnt++;

      if( isEndList(*p) )
         layerCnt--;

      p = skipSimpleToken(p);
   };

   return (tUINT32)(p - pListToken -1);

} // sizeofListTokenData

//=================================================================================
/// \brief Count the number of list-items at the present level in the list.
///
/// \param pListToken  [IN]  Passed-in buffer holding the List token.
///
/// \exception throwing TCG_STATUS
///
/// \return tUINT32 the number of current-level list items in the List.
//=================================================================================
tUINT32 CTcgTokenProcessor::numberOfListItems( dta::tByte *pListToken )
{
   if( !isListToken(*pListToken) )
      return 0;

   tUINT8 *p = pListToken +1;
   int itemCnt = 0;

   while( !( isEndList(*p) ) )
   {
      p = skipEmptyTokens( p, NULL );

      if( isAtom(*p) )
      {
         itemCnt++;
         p += sizeofAtom( p );
      }
      else if( isStartName(*p) )
      {
         itemCnt++;
         p += sizeofNamedValueToken( p );
      }
      else if( isStartList(*p) )
      {
         itemCnt++;
         p += sizeofListToken( p );
      }
      else
         throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Unrecognied token");      
   };

   return itemCnt;

} // numberOfListItems

//=================================================================================
/// \brief Retrieve List token elements, and save it to a caller supplied byte stream.
///
/// \param pListToken [IN]  Pointer to a buffer holding a List object.
/// \param data       [OUT] A caller passed-in buffer to keep the List token raw value.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getListTokenData( dta::tByte *pListToken, dta::tBytes &data )
{
   tUINT32 len = sizeofListTokenData( pListToken );
   data.resize( len );
   if( len > 0 )
      memcpy( &data[0], pListToken+1, len );

   return pListToken + len +2;

} // getListTokenData

//=================================================================================
/// \brief Build a NamedValue token from a raw byte stream of name & data, and save it to a given location.
///
/// \param pBuffer      [OUT] Destination buffer to keep the built NamedValue token.
/// \param pName        [IN]  Byte stream of Name for the NamedValue token.
/// \param nameLen      [IN]  Length of the Name.
/// \param pData        [IN]  Byte stream of NamedValue raw data.
/// \param dataLen      [IN]  Length of the NamedValue raw data.
/// \param tokenFormat  [IN]  If pData is already formatted in TCG token form, otherwise in raw byte stream.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildNamedValueToken( dta::tByte *pBuffer, dta::tByte *pName, tUINT32 nameLen, dta::tByte *pData, tUINT32 dataLen, bool tokenFormat )
{
   pBuffer = buildStartName( pBuffer );
   pBuffer = buildNamedValueTokenName( pBuffer, pName, nameLen );
   if( tokenFormat )
      pBuffer = buildNamedValueTokenDataObject( pBuffer, pData, dataLen );
   else
      pBuffer = buildNamedValueTokenDataRaw( pBuffer, pData, dataLen );

   return pBuffer;

} // buildNamedValueToken

//=================================================================================
/// \brief Build a NamedValue token from a signed integer, and save it to a given location.
///
/// \param pBuffer   [OUT] Destination buffer to keep the built NamedValue token.
/// \param pName     [IN]  Byte stream of Name for the NamedValue token.
/// \param nameLen   [IN]  Length of the Name.
/// \param data      [IN]  Signed interger upto 8-bytes in size.
/// \param size      [IN]  Preferred size of the data to be converted, -1 means size-fit(minimum length).
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildNamedValueToken( dta::tByte *pBuffer, dta::tByte *pName, tUINT32 nameLen, tINT64 data, int size )
{
   pBuffer = buildStartName( pBuffer );
   pBuffer = buildNamedValueTokenName( pBuffer, pName, nameLen );

   if( -1 == size )
      pBuffer = buildIntAtom( pBuffer, data );
   else
      pBuffer = buildAtom( pBuffer, data, size, false );

   pBuffer = buildEndName( pBuffer );

   return pBuffer;

} // buildNamedValueToken

//=================================================================================
/// \brief Build a NamedValue token from an unsigned integer, and save it to a given location.
///
/// \param pBuffer   [OUT] Destination buffer to keep the built NamedValue token.
/// \param pName     [IN]  Byte stream of Name for the NamedValue token.
/// \param nameLen   [IN]  Length of the Name.
/// \param data      [IN]  Unsigned interger upto 8-bytes in size.
/// \param size      [IN]  Preferred size of the data to be converted, -1 means size-fit(minimum length).
/// \param flagByte  [IN]  Bool value for the "B" (Byte) bit in the atom.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildNamedValueToken( dta::tByte *pBuffer, dta::tByte *pName, tUINT32 nameLen, tUINT64 data, int size, bool flagByte )
{
   pBuffer = buildStartName( pBuffer );
   pBuffer = buildNamedValueTokenName( pBuffer, pName, nameLen );

   if( -1 == size )
      pBuffer = buildIntAtom( pBuffer, data );
   else
      pBuffer = buildAtom( pBuffer, data, size, flagByte );

   pBuffer = buildEndName( pBuffer );

   return pBuffer;

} // buildNamedValueToken

//=================================================================================
/// \brief Build an integer NamedValue token from a raw byte stream of data, and save it to a given location.
///
/// \param pBuffer      [OUT] Destination buffer to keep the built NamedValue token.
/// \param name         [IN]  Integer value of the name.
/// \param pData        [IN]  Byte stream of NamedValue raw data.
/// \param dataLen      [IN]  Length of the NamedValue raw data.
/// \param tokenFormat  [IN]  If pData is already formatted in TCG token form, otherwise in raw byte stream.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildNamedValueToken( dta::tByte *pBuffer, tUINT64 name, dta::tByte *pData, tUINT32 dataLen, bool tokenFormat )
{
   pBuffer = buildStartName( pBuffer );
   pBuffer = buildNamedValueTokenName( pBuffer, name );
   if( tokenFormat )
      pBuffer = buildNamedValueTokenDataObject( pBuffer, pData, dataLen );
   else
      pBuffer = buildNamedValueTokenDataRaw( pBuffer, pData, dataLen );

   return pBuffer;

} // buildNamedValueToken

//=================================================================================
/// \brief Build an interger NamedValue token from a signed integer, and save it to a given location.
///
/// \param pBuffer   [OUT] Destination buffer to keep the built NamedValue token.
/// \param name      [IN]  Integer value of the Name.
/// \param data      [IN]  Signed interger upto 8-bytes in size.
/// \param size      [IN]  Preferred size of the data to be converted, -1 means size-fit(minimum length).
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildNamedValueToken( dta::tByte *pBuffer, tUINT64 name, tINT64 data, int size )
{
   pBuffer = buildStartName( pBuffer );

   pBuffer = buildNamedValueTokenName( pBuffer, name );
   if( -1 == size )
      pBuffer = buildIntAtom( pBuffer, data );
   else
      pBuffer = buildAtom( pBuffer, data, size, false );

   pBuffer = buildEndName( pBuffer );

   return pBuffer;

} // buildNamedValueToken

//=================================================================================
/// \brief Build an interger NamedValue token from an unsigned integer, and save it to a given location.
///
/// \param pBuffer   [OUT] Destination buffer to keep the built NamedValue token.
/// \param name      [IN]  Integer value of the Name.
/// \param data      [IN]  Unsigned interger upto 8-bytes in size.
/// \param size      [IN]  Preferred size of the data to be converted, -1 means size-fit(minimum length).
/// \param flagByte  [IN]  Bool value for the "B" (Byte) bit in the atom.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildNamedValueToken( dta::tByte *pBuffer, tUINT64 name, tUINT64 data, int size, bool flagByte )
{
   pBuffer = buildStartName( pBuffer );

   pBuffer = buildNamedValueTokenName( pBuffer, name );
   if( -1 == size )
      pBuffer = buildIntAtom( pBuffer, data );
   else
      pBuffer = buildAtom( pBuffer, data, size, flagByte );

   pBuffer = buildEndName( pBuffer );

   return pBuffer;

} // buildNamedValueToken

//=================================================================================
/// \brief Build an UID-Named Value token from a raw byte stream of data, and save it to a given location.
///
/// \param pBuffer      [OUT] Destination buffer to keep the built NamedValue token.
/// \param uid          [IN]  UID as the value of the name.
/// \param uidSize      [IN]  8 bytes for Full UID, or 4 bytes for Half UID.
/// \param pData        [IN]  Byte stream of NamedValue raw data.
/// \param dataLen      [IN]  Length of the NamedValue raw data.
/// \param tokenFormat  [IN]  If pData is already formatted in TCG token form, otherwise in raw byte stream.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildNamedValueToken( dta::tByte *pBuffer, tUINT64 uid, int uidSize, dta::tByte *pData, tUINT32 dataLen, bool tokenFormat )
{
   pBuffer = buildStartName( pBuffer );

   pBuffer = buildShortAtom( pBuffer, uid, uidSize, true );
   if( tokenFormat )
      pBuffer = buildNamedValueTokenDataObject( pBuffer, pData, dataLen );
   else
      pBuffer = buildNamedValueTokenDataRaw( pBuffer, pData, dataLen );

   return pBuffer;

} // buildNamedValueToken

//=================================================================================
/// \brief Build an UID-Named Value token from a signed integer, and save it to a given location.
///
/// \param pBuffer   [OUT] Destination buffer to keep the built NamedValue token.
/// \param uid       [IN]  UID as the value of the name.
/// \param uidSize   [IN]  8 bytes for Full UID, or 4 bytes for Half UID.
/// \param data      [IN]  Signed interger upto 8-bytes in size.
/// \param size      [IN]  Preferred size of the data to be converted, -1 means size-fit(minimum length).
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildNamedValueToken( dta::tByte *pBuffer, tUINT64 uid, int uidSize, tINT64 data, int size )
{
   pBuffer = buildStartName( pBuffer );

   pBuffer = buildShortAtom( pBuffer, uid, uidSize, true );
   if( -1 == size )
      pBuffer = buildIntAtom( pBuffer, data );
   else
      pBuffer = buildAtom( pBuffer, data, size, false );

   pBuffer = buildEndName( pBuffer );

   return pBuffer;

} // buildNamedValueToken

//=================================================================================
/// \brief Build an UID-Named Value token from an unsigned integer, and save it to a given location.
///
/// \param pBuffer   [OUT] Destination buffer to keep the built NamedValue token.
/// \param uid       [IN]  UID as the value of the name.
/// \param uidSize   [IN]  8 bytes for Full UID, or 4 bytes for Half UID.
/// \param data      [IN]  Unsigned interger up to 8-bytes in size.
/// \param size      [IN]  Preferred size of the data to be converted, -1 means size-fit(minimum length).
/// \param flagByte  [IN]  Bool value for the "B" (Byte) bit in the atom.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildNamedValueToken( dta::tByte *pBuffer, tUINT64 uid, int uidSize, tUINT64 data, int size, bool flagByte )
{
   pBuffer = buildStartName( pBuffer );

   pBuffer = buildShortAtom( pBuffer, uid, uidSize, true );
   if( -1 == size )
      pBuffer = buildIntAtom( pBuffer, data );
   else
      pBuffer = buildAtom( pBuffer, data, size, flagByte );

   pBuffer = buildEndName( pBuffer );

   return pBuffer;

} // buildNamedValueToken

//=================================================================================
/// \brief Build a NamedValue token from a byte stream of name & data, and save it to a given location.
///
/// \param pBuffer   [OUT] Destination buffer to keep the built NamedValue token.
/// \param pName     [IN]  Byte stream of Name for the NamedValue token.
/// \param length    [IN]  Length of the Name.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this part of the token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildNamedValueTokenName( dta::tByte *pBuffer, dta::tByte *pName, tUINT32 length )
{
   if( length <= TOKEN_MASK_SHORT_SIZE )
   {
      return buildShortAtom( pBuffer, pName, length, true, false );
   }
   else if( length <= TOKEN_MASK_MEDIUM_SIZE )
   {
      return buildMediumAtom( pBuffer, pName, length, true, false );
   }
   else if( length <= TOKEN_MASK_LONG_SIZE )
   {
      return buildLongAtom( pBuffer, pName, length, true, false );
   }
   else
   {
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Wrong data size");
   }
} // buildNamedValueTokenName

//=================================================================================
/// \brief Build a NamedValue token from an object byte-stream of name & data, and save it to a given location.
///
/// \param pBuffer   [OUT] Destination buffer to keep the built value part of the NamedValue token.
/// \param pData     [IN]  Byte stream of NamedValue object data (device format).
/// \param length    [IN]  Length of the NamedValue object data.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildNamedValueTokenDataObject( dta::tByte *pBuffer, dta::tByte *pData, tUINT32 length )
{
   if( NULL != pData && length > 0 )
   {
      memcpy( pBuffer, pData, length );
   }
   else
   {
      //length = 0;
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("NamedToken data can't be NULL");
   }

   *(pBuffer+length) = TOKEN_TYPE_END_NAME;
   return pBuffer + length+1;

} // buildNamedValueTokenDataObject

//=================================================================================
/// \brief Build a NamedValue token from a raw byte stream of name & data, and save it to a given location.
///
/// \param pBuffer   [OUT] Destination buffer to keep the built value part of the NamedValue token.
/// \param pData     [IN]  Byte stream of NamedValue raw data (host byte array format).
/// \param length    [IN]  Length of the NamedValue data.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildNamedValueTokenDataRaw( dta::tByte *pBuffer, dta::tByte *pData, tUINT32 length )
{
   if( NULL != pData )
   {
      pBuffer = buildAtom( pBuffer, pData, length, true, false );
   }
   else
   {
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("NamedToken data can't be NULL");
   }

   *pBuffer++ = TOKEN_TYPE_END_NAME;
   return pBuffer;

} // buildNamedValueTokenDataRaw

//=================================================================================
/// \brief Count the total length of the Name part(BYTE string or an integer) of a NamedValue token.
///
/// \param pNamedValueToken  [IN]  Passed-in buffer holding the NamedValue token.
///
/// \exception throwing TCG_STATUS
///
/// \return tUINT32 the length (number of bytes including header) of the Name part.
//=================================================================================
tUINT32 CTcgTokenProcessor::sizeofNamedValueTokenName( dta::tByte *pNamedValueToken )
{
   if( !isNamedValueToken(*pNamedValueToken) )
      return 0;

   return (tUINT32)(skipSimpleToken(pNamedValueToken+1) - pNamedValueToken -1); // including byte string header - short/medium/long

} // sizeofNamedValueTokenName

//=================================================================================
/// \brief Count the total length of the Value part of a NamedValue token.
///
/// \param pNamedValueToken  [IN]  Passed-in buffer holding the NamedValue token.
///
/// \exception throwing TCG_STATUS
///
/// \return tUINT32 the length (number of bytes including header) of the Value part.
//=================================================================================
tUINT32 CTcgTokenProcessor::sizeofNamedValueTokenValue( dta::tByte *pNamedValueToken )
{
   if( !isNamedValueToken(*pNamedValueToken) )
      return 0;

   tUINT8 *p1 = skipSimpleToken(pNamedValueToken+1); // pointing to the Value part
   tUINT8 *p2 = p1;
   int layerCnt = 0;
   while( !( isEndName( *p2 ) && 0 == layerCnt ) )
   {
       if( isStartName(*p2) )
          layerCnt++;

       if( isEndName(*p2) )
          layerCnt--;

       p2 = skipSimpleToken(p2);
   };

   return (tUINT32)(p2 - p1);

} // sizeofNamedValueTokenValue

//=================================================================================
/// \brief Retrieve the name of a NamedValue token, and save it to a caller supplied byte stream.
///
/// \param pNamedValueToken [IN]  Pointer to a buffer holding a NamedValue token object.
/// \param name             [OUT] A caller passed-in buffer to keep the name (device format) of NamedValue token.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following the Name part of this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getNamedValueTokenName( dta::tByte *pNamedValueToken, dta::tBytes &name )
{
   if( !isNamedValueToken(*pNamedValueToken) )
   {
      name.resize(0);
      return pNamedValueToken;
   }

   return getAtomData( pNamedValueToken+1, name );
} // getNamedValueTokenName

//=================================================================================
/// \brief Retrieve the value of the Name of a NamedValue token, and save it to a caller supplied variable.
///
/// \param pNamedValueToken [IN]  Pointer to a buffer holding an integer NamedValue token object.
/// \param name             [OUT] A caller passed-in buffer to keep the value of the name of NamedValue token.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following the Name part of this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getNamedValueTokenName( dta::tByte *pNamedValueToken, tUINT64 &name )
{
   if( !isNamedValueToken(*pNamedValueToken) )
      return pNamedValueToken;

   return getAtomData( pNamedValueToken+1, &name );

} // getNamedValueTokenName

//=================================================================================
/// \brief Retrieve the value of a NamedValue token, and save it to a caller supplied byte stream.
///
/// \param pNamedValueToken [IN]  Pointer to a buffer holding a NamedValue token object.
/// \param data             [OUT] A caller passed-in buffer to keep the raw value (token format) of NamedValue token.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getNamedValueTokenValue( dta::tByte *pNamedValueToken, dta::tBytes &data )
{
   if( !isNamedValueToken(*pNamedValueToken) )
   {
      data.resize(0);
      return pNamedValueToken;
   }

   dta::tByte *p = skipSimpleToken( pNamedValueToken+1 ); // skip the name part
   tUINT32 len = sizeofNamedValueTokenValue( pNamedValueToken );
   data.resize( len );
   if( len > 0 )
      memcpy( &data[0], p, len );

   return p + len +1; //including the End-of-Name (EN) byte

} // getNamedValueTokenValue

//=================================================================================
/// \brief Retrieve the value (integer) of a NamedValue token, and save it to a caller supplied variable.
///
/// \param pNamedValueToken [IN]  Pointer to a buffer holding a NamedValue token object.
/// \param data             [OUT] A caller passed-in buffer to keep the value (up to 64bits) of NamedValue token.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getNamedValueTokenValue( dta::tByte *pNamedValueToken, tUINT64 &data )
{
   if( !isNamedValueToken(*pNamedValueToken) )
      return pNamedValueToken;

   dta::tByte *p = skipSimpleToken( pNamedValueToken+1 ); // skip the name part
   return getAtomData( p, &data ) +1; //including the End-of-Name (EN) byte

} // getNamedValueTokenValue

//=================================================================================
/// \brief Build a Call token object, and save it to a given location.
///
/// \param pBuffer        [OUT] Destination buffer to keep the built Call token.
/// \param targetUID      [IN]  UID of the target of the call.
/// \param methodUID      [IN]  UID of the method of the call.
/// \param pParameters    [IN]  Pointer to a buffer containing the parameters in the form of a list elements.
/// \param paramLen       [IN]  Length of the parameters.
/// \param expectedStatus [IN]  Expected return status byte of the call.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildCallToken( dta::tByte *pBuffer, tUINT64 targetUID, tUINT64 methodUID, dta::tByte *pParameters, tUINT32 paramLen, tUINT8 expectedStatus )
{
   pBuffer = buildCallTokenHeader( pBuffer, targetUID, methodUID );

   if( NULL != pParameters && 0 != paramLen )
   {
      memcpy( pBuffer, &pParameters[0], paramLen );
      pBuffer += paramLen;
   }

   pBuffer = buildCallTokenFooter( pBuffer, expectedStatus );
   return pBuffer;

} // buildCallToken

//=================================================================================
/// \brief Build a Call token object, and save it to a given location.
///
/// \param pBuffer        [OUT] Destination buffer to keep the built Call token.
/// \param targetUID      [IN]  UID of the target of the call.
/// \param methodUID      [IN]  UID of the method of the call.
/// \param parameters     [IN]  Reference to a buffer containing the parameters in the form of a list elements.
/// \param expectedStatus [IN]  Expected return status byte of the call.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildCallToken( dta::tByte *pBuffer, tUINT64 targetUID, tUINT64 methodUID, dta::tBytes &parameters, tUINT8 expectedStatus )
{
   if( parameters.size() > 0 )
      return buildCallToken( pBuffer, targetUID, methodUID, &parameters[0], (tUINT32)parameters.size(), expectedStatus );
   else
      return buildCallToken( pBuffer, targetUID, methodUID, NULL, 0, expectedStatus );

} // buildCallToken

//=================================================================================
/// \brief Build the header part of a Call token object, and save it to a given location.
///
/// \param pBuffer        [OUT] Destination buffer to keep the built header part of the Call token.
/// \param targetUID      [IN]  UID of the target of the call.
/// \param methodUID      [IN]  UID of the method of the call.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following the header part of this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildCallTokenHeader( dta::tByte *pBuffer, tUINT64 targetUID, tUINT64 methodUID )
{
   *pBuffer++ = TOKEN_TYPE_CALL;
   pBuffer = buildUID( pBuffer, targetUID );
   pBuffer = buildUID( pBuffer, methodUID );
   pBuffer = buildStartList( pBuffer ); // start-list tag for parameters list
   return pBuffer;

} // buildCallTokenHeader

//=================================================================================
/// \brief Build the footer part of a Call token object, and save it to a given location.
///
/// \param pBuffer        [OUT] Destination buffer to keep the built footer part of the Call token.
/// \param expectedStatus [IN]  Expected return status byte of the call.
///
/// \pre Caller provides storage to save the result.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this Call token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildCallTokenFooter( dta::tByte *pBuffer, tUINT8 expectedStatus )
{
   // added end-list tag for the parameters list
   pBuffer = buildEndList( pBuffer );
   pBuffer = buildEOD( pBuffer );

   // build expected return status list
   pBuffer = buildStartList( pBuffer );
   *pBuffer++ = expectedStatus; // a TinyAtom actually
   *pBuffer++ = 0;
   *pBuffer++ = 0;
   pBuffer = buildEndList( pBuffer );

   return pBuffer;

} // buildCallTokenFooter

//=================================================================================
/// \brief Retrieve the data of the Results list returned from a call.
///
/// \param pReturnedData [IN]  Pointer to a buffer holding all the returned data from a call.
/// \param data          [OUT] A caller passed-in buffer to keep the raw data (list elements) of the returned data.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* Pointer to the buffer location following this Call token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::getCallReturnedListData( dta::tByte *pReturnedData, dta::tBytes &data )
{
   if( !isListToken( *pReturnedData ) )
   {
      data.resize(0);
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Unexpected token");
   }

   return getListTokenData( pReturnedData, data );

} // getCallReturnedListData

//=================================================================================
/// \brief Retrieve the Status byte returned from a call.
///
/// \param pReturnedData [IN]  Pointer to a buffer holding all the returned data from a call.
///
/// \exception throwing TCG_STATUS
///
/// \return tUINT8 the Status byte of the returned data.
//=================================================================================
tUINT8 CTcgTokenProcessor::getCallReturnedStatus( dta::tByte *pReturnedData )
{
   if( !isListToken( *pReturnedData ) ) // Expecting the Results list
   {
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Unexpected token");
   }

   pReturnedData += sizeofListToken( pReturnedData );

   if( !isEOD( *pReturnedData++ ) )     // Expecting an End-of-Data token
   {
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Unexpected token");
   }

   if( !isListToken( *pReturnedData ) ) // Expecting the Status list
   {
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Unexpected token");
   }

   return *++pReturnedData;

} // getCallReturnedStatus

//=================================================================================
/// \brief Build a specified number of Empty Atom tokens to a given location.
///
/// \param pBuffer  [OUT] Destination buffer to keep the built atom.
/// \param count    [IN]  Number of Empty tokens to build.
///
/// \pre Caller provides storage to save the result.
///
/// \return tByte* Pointer to the buffer location following this token.
//=================================================================================
dta::tByte* CTcgTokenProcessor::buildEmptyTokens( dta::tByte *pBuffer, int count )
{
   while( count-- )
      *pBuffer++ = TOKEN_TYPE_EMPTY;

   return pBuffer;

} // buildEmptyTokens

//=================================================================================
/// \brief Skip the current Empty tokens if applicable, and return a pointer to the next object.
///
/// \param pBuffer [IN]  Pointer to a buffer holding tokens, including Empty tokens.
/// \param pCount  [OUT] Pointer to an integer keeping the number of Empty tokens skipped.
///
/// \return tByte* the pointer to the next object in a buffer.
//=================================================================================
dta::tByte* CTcgTokenProcessor::skipEmptyTokens( dta::tByte *pBuffer, int *pCount )
{
   dta::tByte* p = pBuffer;
   if( NULL == p )
      return p;

   while( isEmptyToken( *p ) )
      p++;
   
   if( pCount != NULL )
      *pCount = (int)(p - pBuffer);

   return p;

} // skipEmptyTokens

//=================================================================================
/// \brief Skip the current simple token(entire atom token, or the tag byte of other tokens),
/// and return a pointer to the next object.
///
/// \param pSimpleToken [IN]  Pointer to a buffer holding a token.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* the pointer to the next object in a buffer.
//=================================================================================
dta::tByte* CTcgTokenProcessor::skipSimpleToken( dta::tByte *pSimpleToken )
{
   dta::tByte *p = pSimpleToken;

   // Count full Atom Tokens
   if( isTinyAtom(*p) )
      p++;
   else if( isShortAtom(*p) )
      p += sizeofShortAtom(p);
   else if( isMediumAtom(*p) )
      p += sizeofMediumAtom(p);
   else if( isLongAtom(*p) )
      p += sizeofLongAtom(p);
   else if( isEmptyToken(*p) )
      p++;

   // For Compound Tokens, count only the Tag byte
   else if( isStartList(*p) || isEndList(*p) || isStartName(*p) || isEndName(*p) )
      p++;

   // For Control Tokens, count only the Tag byte
   else if( isCallToken(*p) || isEOD(*p) || isStartTransactionToken(*p) || isEndTransactionToken(*p) )
      p++;

   else
      throw (TCG_STATUS)TS_INVALID_PARAMETER; //TXT("Unrecognied token");

   return p;

} // skipSimpleToken

//=================================================================================
/// \brief Retrieve NamedValue data-part location from a list (sinlge[...] or double[[...]] quoted).
///
/// \param list       [IN]  Holding a list ([...] or [[...]]) containing zero or more name-value pairs.
/// \param pName      [IN]  Name string.
/// \param nameLength [IN]  Length of the name string.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* the pointer to the data-part of the retrieved NamedValue. NULL if not found.
//=================================================================================
dta::tByte* CTcgTokenProcessor::retrieveNamedDataFromList( dta::tBytes & list, tUINT8 *pName, tUINT32 nameLength )
{
   if( list.size() < 6 ) // [, SN, nm, v, EN, ]
      return NULL;

   dta::tByte *p = &list[0];

   while( (p < &list[0] + list.size()) && isListToken( *p ) ) p++;
   if( isListToken( *p ) )
      return NULL;

   dta::tBytes name;

   while( p < &list[0] + list.size() )
   {
      if( !isNamedValueToken(*p) )
         return NULL;

      int sz = sizeofNamedValueTokenValue( p );
      p = getNamedValueTokenName( p, name );
      if( name.size() == nameLength && memcmp( &name[0], pName, nameLength ) == 0 )
         return p; // found, pointing to the value part of the named-token
      else
         p += sz +1;
   }

   return NULL;

} // retrieveNamedDataFromList

//=================================================================================
/// \brief Retrieve NamedValue data-part location from a list (sinlge[...] or double[[...]] quoted).
///
/// \param list   [IN]  Holding a list ([...] or [[...]]) containing zero or more name-value pairs.
/// \param name   [IN]  Integer name (eg. column number for a GET returned list of named-values).
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* the pointer to the data-part of the retrieved NamedValue. NULL if not found.
//=================================================================================
dta::tByte* CTcgTokenProcessor::retrieveNamedDataFromList( dta::tBytes & list, tUINT64 name )
{
   if( list.size() < 6 ) // [, SN, nm, v, EN, ]
      return NULL;

   dta::tByte *p = &list[0];

   if( !isListToken( *p ) )
      return NULL;

   while( (p < &list[0] + list.size()) && isListToken( *p ) ) p++;
   if( isListToken( *p ) )
      return NULL;

   dta::tBytes value;

   while( p < &list[0] + list.size() )
   {
      if( !isNamedValueToken(*p) )
         return NULL;

      int sz = sizeofNamedValueTokenValue( p );
      p = getNamedValueTokenName( p, value );
      if( value.size() > 0 && isAtom(value[0]) )
      {
         if( getAtomData( &value[0] ) == name )
            return p; // found, pointing to the value part of the named-token
      }
	  else
         return NULL; // error

      p += sz +1;
   }

   return NULL;

} // retrieveNamedDataFromList

//=================================================================================
/// \brief Retrieve NamedValue data-part location from a NamedValue token stream.
///
/// \param pNVStream    [IN]  Holding a token stream of NamedValue pairs.
/// \param streamLength [IN]  Length of the stream.
/// \param pName        [IN]  Name string.
/// \param nameLength   [IN]  Length of the name string.
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* the pointer to the data-part of the retrieved NamedValue. NULL if not found.
//=================================================================================
dta::tByte* CTcgTokenProcessor::retrieveNamedDataFromStream( dta::tByte* pNVStream, tUINT32 streamLength, tUINT8 *pName, tUINT32 nameLength )
{
   if( NULL == pNVStream || streamLength < 4 ) // (SN, nm, v, EN)
      return NULL;

   dta::tByte *p = pNVStream;
   dta::tBytes name;

   while( p < pNVStream + streamLength )
   {
      if( !isNamedValueToken(*p) )
         return NULL;

      int sz = sizeofNamedValueTokenValue( p );
      p = getNamedValueTokenName( p, name );
      if( name.size() == nameLength && memcmp( &name[0], pName, nameLength ) == 0 )
         return p; // found, pointing to the value part of the named-token
      else
         p += sz +1;
   }

   return NULL;

} // retrieveNamedDataFromStream

//=================================================================================
/// \brief Retrieve NamedValue data-part location from a NamedValue token stream.
///
/// \param pNVStream    [IN]  Holding a token stream of NamedValue pairs.
/// \param streamLength [IN]  Length of the stream.
/// \param name         [IN]  Integer name (eg. column number for a GET returned list of named-values).
///
/// \exception throwing TCG_STATUS
///
/// \return tByte* the pointer to the data-part of the retrieved NamedValue. NULL if not found.
//=================================================================================
dta::tByte* CTcgTokenProcessor::retrieveNamedDataFromStream( dta::tByte* pNVStream, tUINT32 streamLength, tUINT64 name )
{
   if( NULL == pNVStream || streamLength < 4 ) // (SN, nm, v, EN)
      return NULL;

   dta::tByte *p = pNVStream;
   tUINT64 value;

   while( p < pNVStream + streamLength )
   {
      if( !isNamedValueToken(*p) )
         return NULL;

      int sz = sizeofNamedValueTokenValue( p );
      dta::tByte *p1 = getNamedValueTokenName( p, value );
      if( p1 != p )
      {
         p = p1;
         if( value == name )
            return p; // found, pointing to the value part of the named-token
      }
	  else
         return NULL; // error

      p += sz +1;
   }

   return NULL;

} // retrieveNamedDataFromStream

