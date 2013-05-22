#include <stdlib.h>
#include "tcg/Sample_HelperFunc_Wrappers/TCGDrive_Console.hpp"
#include "tcg/Sample_HelperFunc_Wrappers/TCGDaemon.hpp"
#include "../../dtl/dta/dtad/platform/linux32/syscore/scsiCore.cpp"

#if !defined(_WIN32)

#define _stricmp(s1, s2) strcasecmp(s1, s2)
#define _strnicmp(s1, s2, n) strncasecmp(s1, s2, (n))
#define sprintf_s( a, b, c, d ) sprintf(a, c, d)
#define _strtoui64 strtoul
#define _atoi64 atol
#define _MAX_PATH 255
#endif

#include <iostream>
#include "version.h"
#ifdef  VERSION_TOSTRING
#undef  VERSION_TOSTRING
#undef  VERSION_TOSTRING1
#undef  VERSION_TOSTRING2
#endif

#if (__linux__)
typedef tINT64 INT64;
typedef tUINT64 UINT64;
#endif

void SED_initiate (int Argc, char* Argv[]);

int main( int Argc, char* Argv[] )
{
	SED_initiate (Argc, &Argv[0]);

    	return 0;
}

void SED_initiate(int Argc, char* Argv[])
{
	int     sSuNum;
	int     no_dev      = 0;
	int     argc        = Argc;
	char    **argv      = new char*[argc];
	bool    bNoLog      = extractParameter((char*)"--NoLog", true, argc, argv)!= NULL;

	std::wstring wSerNum( 20, TXT(' ') );
        if (char *p = extractParameter( (char*)"=", false, argc, argv ))
        {
           if (strlen( p ) > 20)
              std::wcout << TXT("Specified Device Serial Number \"") << p
                         << TXT("\" exceeds 20 chars and will be ignored.\n\n");
           else
              for (unsigned int i = 0; i < strlen(p); i++)
                   wSerNum[i] = p[i];
        }

        for (int dev=0; dev<MAX_DEV; dev++)
        {
            std::string sSerNum( wSerNum.length(), ' ' );
	    std::copy(wSerNum.begin(), wSerNum.end(), sSerNum.begin());

            scan_sg(dev, sSerNum);
            /*we will get serial number of SED drives
              only and yet to cleanup this part.*/

	    if(!sSerNum.compare("                    "))
               continue;
            else
            {
               sSuNum = 0;
               no_dev++;

               CTcgDrive device(( bNoLog ? TXT("") : TXT("TCGProtocolLog.xml")),
               ( bNoLog ? TXT("") : TXT("DeviceEnumerationLog.txt")),
               sSerNum);

               SED_operation(sSerNum, no_dev, device, sSuNum);
            }
        }
}

void SED_operation( std::string sserNum, int no_dev, CTcgDrive &device,
                    int sSuNum )
{
        bool    breturn;
        bool    lock_decision;
        struct  str str_ret;
        int     next_state      = SED_INIT;
        int     current_state   = SED_INIT;

        while (current_state != SED_END)
        {
            switch (current_state)
            {
                case SED_INIT:
                {
                    if (!no_dev)
                    {
                       next_state = SED_END;
                    }
                    else
                    {
                       next_state = SED_GET_PASSWORD_FROM_AD;
                    }
                    break;
                }

                case SED_GET_PASSWORD_FROM_AD:
                {
                    str_ret = getParameter_fromAD(sserNum, sSuNum);

		    if (str_ret.entry_flag)
		    {
			    if (0 == str_ret.lock)
			    {
				    next_state = SED_UNLOCK;
			    }
			    else
			    {
				    next_state = SED_LOCK;
			    }
		    }
		    else
		    {
			    next_state = SED_BANDMASTER;
		    }
                    break;
                }

                case SED_UNLOCK:
                {
                    lock_decision = false;

                    breturn = SED_locking_operation(sserNum, sSuNum, device,
                                                    lock_decision);

                    if (breturn)
                    {
                       /*For now next_state is set to SED_END
                         because valid next_state is not decided.*/
                       next_state = SED_END;
		       //next_state = SED_ERASEMASTER;
                    }
                    else
                    {
                       next_state = SED_END;
                    }
                    break;
                }

                case SED_LOCK:
                {
                    lock_decision = true;

                    breturn = SED_locking_operation(sserNum, sSuNum, device,
                                                    lock_decision);

                    if (breturn)
                    {
                       /*For now next_state is set to SED_END
                         because valid next_state is not decided.*/
                       next_state = SED_END;
                    }
                    else
                    {
                       next_state = SED_END;
                    }
                    break;
                }

                case SED_ADD_DRIVE:
                {
                    break;
                }

                case SED_BANDMASTER:
                {
                     IOTableC_PIN pin(false);

                     if (NULL != str_ret.pin)
                     {
		        pin.PIN_length = (tINT8) strlen(str_ret.pin);
                        memcpy( pin.PIN, str_ret.pin, pin.PIN_length );
                        pin.PIN[pin.PIN_length] = 0;
                     }

		     AuthenticationParameter authent("BandMaster1", (tUINT8*)
		    			             "TFKJDS9X32JGGXEQTLCL0NHUTVSX015P");

                     breturn = device.setCredential("BandMaster1", pin, authent);

		     if (breturn)
		     {
		        std::wcout << TXT("Correct Password\n") << std::endl;
		     }
		     else
		     {
		        std::wcout << TXT("Wrong Password\n") << std::endl;
                     }


		     AuthenticationParameter authent1("EraseMaster1", (tUINT8*)
			                              "TFKJDS9X32JGGXEQTLCL0NHUTVSX015P");

                     breturn = device.setCredential("EraseMaster1", pin, authent1);

	             if (0 ==  str_ret.lock)
		     {
			next_state = SED_UNLOCK;
   		     }
	             else
	             {
	                next_state = SED_LOCK;
	             }

                     break;
                }

                case SED_ERASEMASTER:
                {
                     std::wcout << TXT("Performing EraseRange: ");

	             AuthenticationParameter authent("EraseMaster1", (tUINT8*)
		     			             str_ret.pin);

                     //for now this part is hard coded.
                     breturn = device.eraseBand(1, 1, authent, true);

                     next_state = SED_END;
                     break;
                }

                case SED_ADMIN:
                {
                     next_state = SED_END;
                     break;
                }

                case SED_END:
                     break;

                default:
                     break;
            }//switch end
            current_state = next_state;
        }//while end
}//function end

struct str getParameter_fromAD( std::string sserNum, int sSuNum )
{
        struct str s;
        string sNo = "6XM0VE6V0000B248FRFE";

        if (sNo == sserNum)
        {
           /*call rpc function to add entry in AD for e.g
	   it will pass (std::string sserNum, int sSuNum)
	   these values to rpc function.*/

           s.lock = 0;
	   s.pin = "TFKJDS9X32JGGXEQTLCL0NHUTVSX015P";
	   //s.pin = "TFKJDS9X32JGGXEQTLCL0NHUTVSX0153";
	   //s.entry_flag = false;
	   s.entry_flag = true;
        }
       else
       {
           /*call rpc function to add entry in AD for e.g
           it will pass (std::string sserNum, int sSuNum)
           these values to rpc function.*/

           s.lock = 0;
           s.pin = "AZCWPJ2HVEQNTYB70RUWH0ANTZMY2ZVF";
           s.entry_flag = true;
        }
        return(s);
}

bool SED_locking_operation( std::string sserNum, int sSuNum, CTcgDrive &device,
                            bool lock_decision )
{

        bool bresult = false;

        struct str str_ret;
        str_ret = getParameter_fromAD(sserNum, sSuNum);

	IOTableLocking row(false);

        row.ReadLocked = lock_decision;
        row.ReadLocked_isValid = true;

        row.WriteLocked = lock_decision;
        row.WriteLocked_isValid = true;


        row.ReadLockEnabled = true;
        row.ReadLockEnabled_isValid = true;

        row.WriteLockEnabled = true;
        row.WriteLockEnabled_isValid = true;

        AuthenticationParameter authent ("BandMaster1", (tUINT8*) str_ret.pin);
        bresult = device.setLockingRange(1, row, authent );

        return bresult;

}

char* extractParameter( char *tag, const bool getAll, int &argc, char* argv[] )
{
        size_t taglen  = strlen( tag );
        char *p     = NULL;

        for (int ii = 1; ii < argc; ii++)
        {
            if (_strnicmp( argv[ii], tag, taglen ) == 0)
            {

               if (strlen( argv[ii] ) == taglen)
               {
                  if (!getAll)
                  {
                     taglen = 0;
                     argc -= 1;
                     for (int jj = ii; jj < argc; jj++)
                         argv[jj] = argv[jj + 1];
                  }
               }

               p = argv[ii] + ( getAll ? 0 : taglen );
               argc -= 1;
               for (int jj = ii; jj < argc; jj++)
                   argv[jj] = argv[jj + 1];
               break;
            }
        }
        return p;
}






