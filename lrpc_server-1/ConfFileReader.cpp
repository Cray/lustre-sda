#include "ConfFileReader.h"
#include "lrpc_misc_server.h"
#include <cstdlib>

#define DBG_LEVEL 5

using namespace libconfig;

bool ConfFileReader::instanceFlag = false;
ConfFileReader* ConfFileReader::single = NULL;
ConfFileReader* ConfFileReader::getInstance()
{
    if(! instanceFlag)
    {
        single = new ConfFileReader();
        instanceFlag = true;
        return single;
    }
    else
    {
        return single;
    }
}
Setting& ConfFileReader::GetAttrValue(const char* attr) const 
{
    FILE *dbgstream = stderr;
    int  debug_level = DBG_LEVEL;

    try
    {
	return cfg.lookup(attr);
    }
    catch(...)
    {
        LRPC_LOG(LOG_INFO,"Attribute %s not defined in Config file", attr);
	exit(101);
    } 
}
bool ConfFileReader::IsAttr(const char* attr) const
{
  return cfg.exists(attr);
}

int ConfFileReader::ReadConfigFile()
{
  FILE *dbgstream = stderr;
  int  debug_level = DBG_LEVEL;

  try
  {
    /* Load the configuration.. */
    LRPC_LOG(LOG_INFO,"loading [lrpc.conf]..");
    cfg.readFile("/etc/lrpc.conf");
  }
  catch (ParseException &e)
  {
    LRPC_LOG(LOG_ERR,"Parse error at line %s : %s",e.getLine(),e.getError());
    exit(1);
  }
  catch (FileIOException &e) 
  {
    LRPC_LOG(LOG_ERR,"Configuration file not found.");
    exit(1);
  }
  return 0;
}

ConfFileReader::ConfFileReader ()
{
   ReadConfigFile();
}
   
ConfFileReader::ConfFileReader(const ConfFileReader&)
{
   // Prevent copy-construction
}

ConfFileReader& ConfFileReader::operator=(const ConfFileReader&)
{
   // Prevent assignment
}

Setting& get_attr_value(const char* attr)
{
    ConfFileReader* RdConf = ConfFileReader::getInstance();
    return RdConf->GetAttrValue(attr);
}

#if 0
int main()
{
	const char* ServerUrl=get_attr_value("SERVER_URL");
	std::cout << "ok (ServerUrl =" << ServerUrl << ")" << std::endl;
        return 0;
}
#endif
