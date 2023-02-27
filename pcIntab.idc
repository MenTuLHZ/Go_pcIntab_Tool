#include <idc.idc>

static main()
{
	 auto filePath = GetInputFilePath();
	 filePath = filePath + "_Log.txt";
	 Message("%s\r\n",filePath);
	 auto fileHandle = fopen(filePath,"r");
	 auto readLogStr;
	 while((readLogStr = readstr(fileHandle))!= -1)
	 {
		auto strIndex = strstr(readLogStr,":");
		auto funcName = "";
		auto addressStr = "";
		auto i = 0;
		for(;i < strIndex;i++)
		{
			funcName = funcName + readLogStr[i];
		}
		funcName  = funcName + "\x00";
		i = 1;
		for(;readLogStr[strIndex + i] != '\x00';i++ )
		{
			addressStr = addressStr + readLogStr[strIndex + i];
		}
		// È¥µô\r\n »»ÐÐ·û
		addressStr[strlen(addressStr) - 1] = '\x00';
		auto addressL = xtol(addressStr);
		//Message("%X %s\r\n",addressL,funcName);
		del_items(addressL,DELIT_SIMPLE,1);
		add_func(addressL,BADADDR);
		if(set_name(addressL,funcName,SN_FORCE|SN_PUBLIC) == 0)
		{
			Message("funName:%s error\r\n",funcName);
		}
	 }
	 Message("endRead\r\n");
}