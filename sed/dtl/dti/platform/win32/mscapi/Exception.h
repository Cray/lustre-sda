/*! \file Exception.h
    \brief Seagate CExceptionChainObject declaration

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

#if !defined(_Exception_DOT_H)
#define      _Exception_DOT_H

//=========================================================
// Include files
//=========================================================
#include <tchar.h>

// IMPORTANT : PREREQUISITES FOR INCLUDING THIS FILE.
//
// 1) The enumeration eExceptionType must already exist
//    (it contains a list of valid exception types).
// 2) The enumeration eExceptionType must already contain
//    the enumeration value EXCEPTION_TYPE_UNHANDLED.
//
// This is important because the CExceptionChainObject classes and
// derivitaves will not compile without these definitions
// being in place.

//=========================================================
// Macros
//=========================================================

// M_ThrowTaggedEO() is an easy way to tag and throw an
// exception object with a single parameter: usually a 
// typedef derived from tException.  There's also an
// untagged macro version ( M_ThrowEO ) which assumes a
// default tag name.

#define M_ThrowTaggedEO( itemClass, itemValue, tag )       \
   ThrowEO<itemClass>( itemValue, (LPCTSTR)__FILE__, __LINE__, (LPCTSTR)tag );

#define M_ThrowEO( itemClass, itemValue )                  \
   M_ThrowTaggedEO( itemClass, itemValue, _ExceptionObjectTag )

// M_NamedTry() and M_EndNamedTry() are just macros to 
// define and undefine a default tag name for M_ThrowEO()
// above and M_CatchAndThrowExceptionObjects() below.

#define M_NamedTry( tagName ) \
   { const TCHAR *_ExceptionObjectTag = _T(tagName); try
#define M_Try() M_NamedTry( __FUNCTION__ )
#define M_EndTry() _ExceptionObjectTag; }

// M_CatchAndThrowExceptionObjects() is a handy macro to
// be used as a default catch() handler, which will add
// the default tag name to the chain, giving an easy way
// to build a call stack to callers.

#define M_CatchAndThrowExceptionObjects( value )           \
   catch( CExceptionStack& stack )                         \
   {                                                       \
      CExceptionNotHandled* pItem =                        \
         new CExceptionNotHandled(value,                   \
            (LPCSTR)__FILE__, __LINE__, _ExceptionObjectTag);\
      stack.Push( pItem );                                 \
      throw stack;                                         \
   }                                                       \
   M_EndTry()


//=========================================================
// Constant definitions
//=========================================================

//=========================================================
// enums (Typed constants)
//=========================================================

//=========================================================
// Structures
//=========================================================

//=========================================================
// Static and external variables
//=========================================================

//=========================================================
// Code : Class Definitions
//=========================================================

// All exception objects derive from CExceptionChainObject,
// and store some basic information in the base class
// for retrieval by the throw destination.
//
class CExceptionChainObject
{
public:
   CExceptionChainObject( eExceptionType ExceptionType, 
      const TCHAR* file, size_t line,
      const TCHAR* tag = NULL )
      : m_ExceptionType( ExceptionType ), m_pNext( 0 )
      , m_fileName(file), m_lineNumber( line ), m_tag( tag )
   {
   }

   virtual ~CExceptionChainObject();

   virtual int GetType() const;
   virtual int GetValue() const = 0;
   virtual size_t GetLine() const;
   virtual const TCHAR* GetFile() const;
   virtual const TCHAR* GetTag() const;

   virtual void SetLine( size_t lineNumber );
   virtual void SetFile( const TCHAR* fileName );
   virtual void SetTag( const TCHAR* tag );

protected:
   eExceptionType  m_ExceptionType;
   size_t          m_lineNumber;
   const TCHAR*         m_fileName;
   const TCHAR*         m_tag;

   // These members and functions are only for use by
   // the owning CExceptionStack object.
   friend class CExceptionStack;
   void SetNext( CExceptionChainObject* pNext );
   CExceptionChainObject* GetNext() const;
   CExceptionChainObject *m_pNext;
};

///////////////////////////////////////////////////////////
// A generic template class, that maps an enumeration onto
// the base CExceptionChainObject class.  Very useful, and
// should be the most common method of creating a derived
// error class for use.

template < class T, eExceptionType eoType > 
class tException : public CExceptionChainObject
{
public:
   tException( const T& value, 
      const TCHAR* file, size_t line, const TCHAR* tag )
      : m_value( value ), 
      CExceptionChainObject( eoType, file, line, tag ) 
   {}

   enum { ID = eoType };

   T GetTypedValue() const { return m_value; }
   virtual int GetValue() const { return m_value; }
protected:
   T m_value;
};

typedef tException< int, EXCEPTION_TYPE_UNHANDLED > CExceptionNotHandled;

///////////////////////////////////////////////////////////
// The CExceptionStack class is the actual exception object
// throw and caught ( by reference ) to the user.  It
// contains a list of 'CExceptionChainObject's denoting
// the call stack and exceptions of various types.
class CExceptionStack
{
public:
   CExceptionStack( CExceptionChainObject* first ) 
      : m_stack(0) { Push( first ); }
   CExceptionStack( CExceptionStack& two )
      : m_stack(0) { *this = two; }
   ~CExceptionStack()
   { while (Pop()); }

   void Push( CExceptionChainObject* top );
   bool Pop();
   bool Empty() const;
   CExceptionChainObject* Top();
   CExceptionChainObject* Find( eExceptionType type ) const;

   template < class T > bool Find( T*& objectType ) const
   {
      objectType = (T*)Find( eExceptionType(T::ID) );
      return (NULL != objectType);
   }

   CExceptionStack& operator=( CExceptionStack& two )
   {
      m_stack = two.m_stack;
      (const_cast<CExceptionStack&>(two)).m_stack = NULL;
      return *this;
   }
protected:
   CExceptionChainObject* m_stack;
};

//=========================================================
// Code : Inline Class and Template Functions
//=========================================================

// A template function that initializes a tExceptionObject
// (above) and then throws it appropriately.  See the
// macro M_ThrowEO() for a common use.
//
template < class itemClass, class itemValue >
void ThrowEO( const itemValue& value, const TCHAR* file, 
             size_t line, const TCHAR* tag=NULL )
{
   itemClass *item = new itemClass( value, file, line, tag );
   throw CExceptionStack(item);
}

///////////////////////////////////////////////////////////
// Inline function expansions of CExceptionChainObject.

inline CExceptionChainObject::~CExceptionChainObject(void)
{
}

inline int CExceptionChainObject::GetType() const
{
   return m_ExceptionType;
}

inline size_t CExceptionChainObject::GetLine() const
{
   return m_lineNumber;
}

inline const TCHAR* CExceptionChainObject::GetFile() const
{
   return m_fileName;
}

inline const TCHAR* CExceptionChainObject::GetTag() const
{
   return m_tag;
}

inline CExceptionChainObject* CExceptionChainObject::GetNext() const
{
   return m_pNext;
}

inline void CExceptionChainObject::SetLine( size_t lineNumber )
{
   m_lineNumber = lineNumber;
}

inline void CExceptionChainObject::SetFile( const TCHAR* fileName )
{
   m_fileName = fileName;
}

inline void CExceptionChainObject::SetTag( const TCHAR* tag )
{
   m_tag = tag;
}

inline void CExceptionChainObject::SetNext( CExceptionChainObject* pNext )
{
   m_pNext = pNext;
}

///////////////////////////////////////////////////////////
// Inline function expansions of CExceptionStack.

inline void CExceptionStack::Push( CExceptionChainObject* top )
{
   top->SetNext( m_stack );
   m_stack = top;
}

inline bool CExceptionStack::Pop()
{
   if ( m_stack )
   {
      CExceptionChainObject* temp = m_stack;
      m_stack = temp->GetNext();
      delete temp;
      return true;
   }
   return false;
}

inline CExceptionChainObject* CExceptionStack::Top() 
{ 
   return m_stack; 
}

inline bool CExceptionStack::Empty() const
{ 
   return NULL == m_stack; 
}

inline CExceptionChainObject* CExceptionStack::Find( eExceptionType type ) const
{
   CExceptionChainObject* current = m_stack;
   while ( current )
   {
      if ( current->GetType() == type )
      {
         return current;
      }
      current = current->GetNext();
   }
   return current;
}

#endif    // _Exception_DOT_H