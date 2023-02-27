// Go_pclntab.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <list>
#include "windows.h"
#include "Pe_Read.h"
using namespace std;
#define outBufLenght MAX_PATH * 5
#define HIDWORD(l)           ((l) >> 0x20)
struct pclntab_MagicNumBer
{
	DWORD magicNum;
	SHORT defaultNum;
};
struct ADDRESS_INFO_X86
{
	DWORD address;
	DWORD offset;
};
struct ADDRESS_INFO_X64
{
	ULONG64 address;
	DWORD offset;
};
enum pclntab_version
{
	pclntab_nothing = -1,
	pclntab_1,
	pclntab_2,
	pclntab_3,
	pclntab_max
};

typedef struct FuncInfor_X86
{
	DWORD codeAddress;
	DWORD FuncNameAddress;
}*PFuncInfor_X86;
typedef struct FuncInfor_X64
{
	ULONG64 codeAddress;
	DWORD FuncNameAddress;
}*PFuncInfor_X64;


BYTE* GetSection(Pe_Load _peLoad, char* _sectionName, DWORD& rdata_size, IMAGE_SECTION_HEADER*& section_p);
DWORD GetPeHead(Pe_Load _peLoad);
BOOL CheckCommand(int argc, char** argv, char* outPath);
void GetNewDir(char* _newDir, char* path);
int main(int argc, char** argv)
{
	list<char*> lFile;
	char path[outBufLenght] = { 0 };
	if (CheckCommand(argc, argv, path) == FALSE)
	{
		printf("command dir error \r\n");
		return -1;
	}
	char file_path[outBufLenght] = { 0 };
	strcat_s(file_path, outBufLenght, path);

	pclntab_MagicNumBer** MagicNum = (pclntab_MagicNumBer**)malloc(pclntab_max * sizeof(PVOID));
	if (MagicNum == NULL) { printf("malloc error\r\n"); return -1; }
	//https://github.com/golang/go/blob/master/src/debug/gosym/pclntab.go
	MagicNum[pclntab_1] = new pclntab_MagicNumBer{ 0xFFFFFFFA, 0x0000 };
	MagicNum[pclntab_2] = new pclntab_MagicNumBer{ 0xFFFFFFFB, 0x0000 };
	MagicNum[pclntab_3] = new pclntab_MagicNumBer{ 0xFFFFFFF0, 0x0000 };
	BYTE* _file_buffer = NULL;
	BYTE* rdata_p = NULL;
	DWORD rdata_size = 0;
	DWORD _file_size = 0;
	DWORD Out_value = 0;
	Pe_Load _peLoad;


	HANDLE file_h = CreateFileA(file_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
	if (file_h == INVALID_HANDLE_VALUE) { printf("file:%s CreateFile error num %d\r\n  \r\n ", file_path, GetLastError()); return -1; }
	DWORD outfilesize = 0;
	_file_size = GetFileSize(file_h, &outfilesize);
	//_file_buffer = (BYTE*)malloc(_file_size);
	_file_buffer = (BYTE*)VirtualAlloc(NULL, _file_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (_file_buffer == NULL) { printf("file:%s VirtualAlloc error num%d\r\n _file_size %d -  file_h %d - file_path %s \r\n", file_path,GetLastError(), _file_size, file_h, file_path); return -1; }
	if (!ReadFile(file_h, _file_buffer, _file_size, &Out_value, NULL)) { printf("file:%s ReadFile error\r\n", file_path); return -1; }
	CloseHandle(file_h);

	_peLoad.Init(_file_buffer, _file_size);
	IMAGE_SECTION_HEADER* rdata_section_p = NULL;
	rdata_p = GetSection(_peLoad, (char*)".rdata", rdata_size, rdata_section_p);
	if (rdata_p == NULL) { printf("file:%s GetSection .rdata error\r\n", file_path); return -1; }

	// find Magic Number
	BYTE* go_symtab = NULL;
	pclntab_version  pclntab_vFlag = pclntab_nothing;
	for (size_t i = 0; i < pclntab_max; i++)
	{
		for (size_t j = 0; j < (rdata_size - sizeof(pclntab_MagicNumBer)); j++)
		{
			pclntab_MagicNumBer* pe_Magic_Num = (pclntab_MagicNumBer*)&rdata_p[j];
			if (pe_Magic_Num->magicNum == MagicNum[i]->magicNum && pe_Magic_Num->defaultNum == MagicNum[i]->defaultNum)
			{
				go_symtab = &rdata_p[j];
				pclntab_vFlag = (pclntab_version)i;
				goto breakFindSymtab;
			}
		}
	}
	breakFindSymtab:
	char outLogFilePath[outBufLenght] = { 0 };
	// check pclntab_vFlag
	BYTE addressSize = 0;
	switch (pclntab_vFlag)
	{
	case pclntab_nothing:
		printf("file:%s find Magic Number error\r\n", file_path);
		return -1;
		break;
	case pclntab_1:
		addressSize = go_symtab[0x7];
		if (addressSize == 4)
		{
			DWORD funcTable_Num = *((DWORD*)&go_symtab[8]);

			DWORD functab_offset = *((DWORD*)((&go_symtab[8]) + (addressSize * 6)));
			DWORD funcTable = (DWORD)(&go_symtab[functab_offset]);

			DWORD nameTabl_offset = *((DWORD*)((&go_symtab[8]) + (addressSize * 2)));
			DWORD nameTable = (DWORD)(&go_symtab[nameTabl_offset]);
			ADDRESS_INFO_X86* foreach_table = (ADDRESS_INFO_X86*)funcTable;

			list<PFuncInfor_X86> lFuncInf;

			strcpy_s(outLogFilePath, outBufLenght, file_path);
			strcat_s(outLogFilePath, "_Log.txt");
			HANDLE new_fileH = CreateFileA(outLogFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL , NULL);
			DWORD numOfWrite = 0;
			if (new_fileH == NULL) { printf("file:%s Create File Error\r\n", file_path); return -1; }
			char outLogBuffer[outBufLenght] = { 0 };
			for (size_t i = 0; i < funcTable_Num; i++, foreach_table++)
			{
				ADDRESS_INFO_X86* sym_funInfo = (ADDRESS_INFO_X86*)((funcTable)+foreach_table->offset);
				PFuncInfor_X86 funcInfor = new FuncInfor_X86({ sym_funInfo->address ,(DWORD)(nameTable)+sym_funInfo->offset });
				printf("number:%x,Function Name:%s , Address:%X\r\n", i, funcInfor->FuncNameAddress, funcInfor->codeAddress);
				lFuncInf.push_back(funcInfor);
				sprintf_s(outLogBuffer, "%s:%X\r\n", funcInfor->FuncNameAddress, funcInfor->codeAddress);
				WriteFile(new_fileH, outLogBuffer, strlen(outLogBuffer), &numOfWrite, NULL);
				memset(outLogBuffer, 0, outBufLenght);
			}
			CloseHandle(new_fileH);
			//32bit 
		}
		else if (addressSize == 8)
		{
			ULONG64 funcTable_Num = *((ULONG64*)&go_symtab[8]);

			ULONG64 functab_offset = *((ULONG64*)((&go_symtab[8]) + (addressSize * 6)));
			ULONG64 funcTable = (ULONG64)(&go_symtab[functab_offset]);

			ULONG64 nameTabl_offset = *((ULONG64*)((&go_symtab[8]) + (addressSize * 2)));
			ULONG64 nameTable = (ULONG64)(&go_symtab[nameTabl_offset]);
			ADDRESS_INFO_X64* foreach_table = (ADDRESS_INFO_X64*)funcTable;

			list<PFuncInfor_X64> lFuncInf;

			strcpy_s(outLogFilePath, outBufLenght, file_path);
			strcat_s(outLogFilePath, "_Log.txt");
			HANDLE new_fileH = CreateFileA(outLogFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
			DWORD numOfWrite = 0;
			if (new_fileH == NULL) { printf("file:%s Create File Error\r\n", file_path); return -1; }
			char outLogBuffer[outBufLenght] = { 0 };
			for (size_t i = 0; i < funcTable_Num; i++, foreach_table++)
			{
				ADDRESS_INFO_X64* sym_funInfo = (ADDRESS_INFO_X64*)((funcTable)+foreach_table->offset);
				PFuncInfor_X64 funcInfor = new FuncInfor_X64({ sym_funInfo->address ,(DWORD)(nameTable)+sym_funInfo->offset }); 
				DWORD hiDword = HIDWORD(funcInfor->codeAddress);
				printf("number:%x,Function Name:%s , Address:%X%X\r\n", i, funcInfor->FuncNameAddress, hiDword, (DWORD)funcInfor->codeAddress);
				lFuncInf.push_back(funcInfor);
				sprintf_s(outLogBuffer, "%s:%X%X\r\n", funcInfor->FuncNameAddress, hiDword, (DWORD)funcInfor->codeAddress);
				WriteFile(new_fileH, outLogBuffer, strlen(outLogBuffer), &numOfWrite, NULL);
				memset(outLogBuffer, 0, outBufLenght);
			}
			CloseHandle(new_fileH);
		}
		else
		{
			printf("file:%s pclntab_1 go_symtab error", file_path);
			return -1;
		}
		return -1;
	case pclntab_2:
		addressSize = go_symtab[0x7];
		if (addressSize == 4)
		{
			DWORD funcTable_Num = go_symtab[8];
			ADDRESS_INFO_X86* funcTable_start = (ADDRESS_INFO_X86*)((&go_symtab[8]) + (addressSize * 1));
			list<PFuncInfor_X86> lFuncInf;

			strcpy_s(outLogFilePath, outBufLenght, file_path);
			strcat_s(outLogFilePath, "_Log.txt");
			HANDLE new_fileH = CreateFileA(outLogFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
			DWORD numOfWrite = 0;
			if (new_fileH == NULL) { printf("file:%s Create File Error\r\n", file_path); return -1; }
			char outLogBuffer[outBufLenght] = { 0 };
			for (size_t i = 0; i < funcTable_Num; i++, funcTable_start++)
			{
				ADDRESS_INFO_X86* sym_funInfo = (ADDRESS_INFO_X86*)((go_symtab)+funcTable_start->offset);
				PFuncInfor_X86 funcInfor = new FuncInfor_X86({ sym_funInfo->address ,(DWORD)((go_symtab)+sym_funInfo->offset) });
				printf("number:%x,Function Name:%s , Address:%X\r\n", i, funcInfor->FuncNameAddress, funcInfor->codeAddress);
				lFuncInf.push_back(funcInfor);
				sprintf_s(outLogBuffer, "%s:%X\r\n", funcInfor->FuncNameAddress, funcInfor->codeAddress);
				WriteFile(new_fileH, outLogBuffer, strlen(outLogBuffer), &numOfWrite, NULL);
				memset(outLogBuffer, 0, outBufLenght);
			}
			//32bit 
		}
		else if (addressSize == 8)
		{
			ULONG64 funcTable_Num = *((ULONG64*)&go_symtab[8]);
			ADDRESS_INFO_X64* funcTable_start = (ADDRESS_INFO_X64*)((&go_symtab[8]) + (addressSize * 1));
			list<PFuncInfor_X64> lFuncInf;

			strcpy_s(outLogFilePath, outBufLenght, file_path);
			strcat_s(outLogFilePath, "_Log.txt");
			HANDLE new_fileH = CreateFileA(outLogFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL , NULL);
			DWORD numOfWrite = 0;
			if (new_fileH == NULL) { printf("file:%s Create File Error\r\n", file_path); return -1; }
			char outLogBuffer[outBufLenght] = { 0 };
			for (size_t i = 0; i < funcTable_Num; i++, funcTable_start++)
			{
				ADDRESS_INFO_X64* sym_funInfo = (ADDRESS_INFO_X64*)((go_symtab)+funcTable_start->offset);
				PFuncInfor_X64 funcInfor = new FuncInfor_X64({ sym_funInfo->address ,(DWORD)((go_symtab)+sym_funInfo->offset) });
				DWORD hiDword = HIDWORD(funcInfor->codeAddress);
				printf("number:%x,Function Name:%s , Address:%X%X\r\n", i, funcInfor->FuncNameAddress, hiDword, (DWORD)funcInfor->codeAddress);
				lFuncInf.push_back(funcInfor);
				sprintf_s(outLogBuffer, "%s:%X%X\r\n", funcInfor->FuncNameAddress, hiDword, (DWORD)funcInfor->codeAddress);
				WriteFile(new_fileH, outLogBuffer, strlen(outLogBuffer), &numOfWrite, NULL);
				memset(outLogBuffer, 0, outBufLenght);
			}
			CloseHandle(new_fileH);
			//64 bit 
		}
		else
		{
			printf("file:%s pclntab_2 go_symtab error", file_path);
			return -1;
		}
	case pclntab_3:
		addressSize = go_symtab[0x7];
		if (addressSize == 4)
		{
			DWORD funcTable_Num = *((ULONG64*)&go_symtab[8]);

			DWORD functab_offset = *((DWORD*)((&go_symtab[8]) + (addressSize * 7)));
			DWORD funcTable = (DWORD)(&go_symtab[functab_offset]);

			DWORD nameTabl_offset = *((DWORD*)((&go_symtab[8]) + (addressSize * 3)));
			DWORD nameTable = (DWORD)(&go_symtab[nameTabl_offset]);
			ADDRESS_INFO_X86* foreach_table = (ADDRESS_INFO_X86*)funcTable;

			DWORD firstFunc = *((DWORD*)((&go_symtab[8]) + (addressSize * 2)));
			list<PFuncInfor_X86> lFuncInf;

			strcpy_s(outLogFilePath, outBufLenght, file_path);
			strcat_s(outLogFilePath, "_Log.txt");
			HANDLE new_fileH = CreateFileA(outLogFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
			DWORD numOfWrite = 0;
			if (new_fileH == NULL) { printf("file:%s Create File Error\r\n", file_path); return -1; }
			char outLogBuffer[outBufLenght] = { 0 };
			for (size_t i = 0; i < funcTable_Num; i++, foreach_table++)
			{
				ADDRESS_INFO_X86* sym_funInfo = (ADDRESS_INFO_X86*)((funcTable)+foreach_table->offset);
				PFuncInfor_X86 funcInfor = new FuncInfor_X86({ (firstFunc)+sym_funInfo->address , nameTable + sym_funInfo->offset });
				printf("number:%x,Function Name:%s , Address:%X\r\n", i, funcInfor->FuncNameAddress, funcInfor->codeAddress);
				lFuncInf.push_back(funcInfor);
				sprintf_s(outLogBuffer, "%s:%X\r\n", funcInfor->FuncNameAddress, funcInfor->codeAddress);
				WriteFile(new_fileH, outLogBuffer, strlen(outLogBuffer), &numOfWrite, NULL);
				memset(outLogBuffer, 0, outBufLenght);
			}
			CloseHandle(new_fileH);
			//32bit 
		}
		else if (addressSize == 8)
		{
			ULONG64 funcTable_Num = *((ULONG64*)&go_symtab[8]);

			ULONG64 functab_offset = *((ULONG64*)((&go_symtab[8]) + (addressSize * 7)));
			ULONG64 funcTable = (ULONG64)(&go_symtab[functab_offset]);

			ULONG64 nameTabl_offset = *((ULONG64*)((&go_symtab[8]) + (addressSize * 3)));
			DWORD nameTable = (DWORD)(&go_symtab[nameTabl_offset]);
			ADDRESS_INFO_X86* foreach_table = (ADDRESS_INFO_X86*)funcTable;

			ULONG64 firstFunc = *((ULONG64*)((&go_symtab[8]) + (addressSize * 2)));
			list<PFuncInfor_X64> lFuncInf;

			strcpy_s(outLogFilePath, outBufLenght, file_path);
			strcat_s(outLogFilePath, "_Log.txt");
			HANDLE new_fileH = CreateFileA(outLogFilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
			DWORD numOfWrite = 0;
			if (new_fileH == NULL) { printf("file:%s Create File Error\r\n", file_path); return -1; }
			char outLogBuffer[outBufLenght] = { 0 };
			for (size_t i = 0; i < funcTable_Num; i++, foreach_table++)
			{
				ADDRESS_INFO_X86* sym_funInfo = (ADDRESS_INFO_X86*)((funcTable)+foreach_table->offset);
				PFuncInfor_X64 funcInfor = new FuncInfor_X64({ (firstFunc)+sym_funInfo->address , nameTable + sym_funInfo->offset });
				DWORD hiDword = HIDWORD(funcInfor->codeAddress);
				printf("number:%x,Function Name:%s , Address:%X%X\r\n", i, funcInfor->FuncNameAddress, hiDword, (DWORD)funcInfor->codeAddress);
				lFuncInf.push_back(funcInfor);
				sprintf_s(outLogBuffer, "%s:%X%X\r\n", funcInfor->FuncNameAddress, hiDword, (DWORD)funcInfor->codeAddress);
				WriteFile(new_fileH, outLogBuffer, strlen(outLogBuffer), &numOfWrite, NULL);
				memset(outLogBuffer, 0, outBufLenght);
			}
			CloseHandle(new_fileH);
		}
		else
		{
			printf("file:%s pclntab_1 go_symtab error", file_path);
			return -1;
		}
	case pclntab_max:
		return -1;
	}

	if (_file_buffer != NULL)
	{
		VirtualFree(_file_buffer, 0, MEM_RESERVE);
		_file_buffer = NULL;
	}
	return 0;
}


BYTE* GetSection(Pe_Load _peLoad, char* _sectionName, DWORD& rdata_size, IMAGE_SECTION_HEADER*& out_section_p)
{
	IMAGE_SECTION_HEADER* section_p = NULL;
	section_p = Get_IMAGE_SECTION_HEADER_X64(_peLoad.file_buffer);
	if (section_p == NULL) { return NULL; }
	for (size_t i = 0; i < Get_NumberOfSections_X64(_peLoad.file_buffer); i++)
	{
		if (strcmp((char const*)section_p[i].Name, _sectionName) == 0)
		{
			out_section_p = &section_p[i];
			rdata_size = section_p[i].SizeOfRawData % Get_FileAlignment_X64(Get_IMAGE_OPTIONAL_HEADER_X64(_peLoad.file_buffer)) == 0 ? section_p[i].SizeOfRawData :
				Get_FileAlignment_X64(Get_IMAGE_OPTIONAL_HEADER_X64(_peLoad.file_buffer)) * (section_p[i].SizeOfRawData / Get_FileAlignment_X64(Get_IMAGE_OPTIONAL_HEADER_X64(_peLoad.file_buffer)) + 1);
			return (BYTE*)&_peLoad.file_buffer[section_p[i].PointerToRawData];
		}
	}
	//if ((section_p[0].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 && (section_p[2].Characteristics & IMAGE_SCN_MEM_READ) != 0)
	//{
	//	out_section_p = &section_p[2];
	//	rdata_size = section_p[2].SizeOfRawData % Get_FileAlignment_X64(Get_IMAGE_OPTIONAL_HEADER_X64(_peLoad.file_buffer)) == 0 ? section_p[2].SizeOfRawData :
	//		Get_FileAlignment_X64(Get_IMAGE_OPTIONAL_HEADER_X64(_peLoad.file_buffer)) * (section_p[2].SizeOfRawData / Get_FileAlignment_X64(Get_IMAGE_OPTIONAL_HEADER_X64(_peLoad.file_buffer)) + 1);
	//	return (BYTE*)&_peLoad.file_buffer[section_p[2].PointerToRawData];
	//}
	printf("find %s section error\r\n", _sectionName);
	printf("self select section? y/n\r\n");
	char in_char[outBufLenght];
	scanf_s("%s", &in_char);
	if (strcmp(in_char,"y") == 0)
	{
		printf("select section num!\r\n");
		for (size_t i = 0; i < Get_NumberOfSections_X64(_peLoad.file_buffer); i++)
		{
			printf("num %d: %s\r\n", i + 1, section_p[i].Name);
		}
		memset(in_char, 0, outBufLenght);
		scanf_s("%s", &in_char);
		int selectNum = atoi(in_char) - 1;
		out_section_p = &section_p[selectNum];
		rdata_size = section_p[selectNum].SizeOfRawData % Get_FileAlignment_X64(Get_IMAGE_OPTIONAL_HEADER_X64(_peLoad.file_buffer)) == 0 ? section_p[selectNum].SizeOfRawData :
			Get_FileAlignment_X64(Get_IMAGE_OPTIONAL_HEADER_X64(_peLoad.file_buffer)) * (section_p[selectNum].SizeOfRawData / Get_FileAlignment_X64(Get_IMAGE_OPTIONAL_HEADER_X64(_peLoad.file_buffer)) + 1);
		return (BYTE*)&_peLoad.file_buffer[section_p[selectNum].PointerToRawData];
	}
	return NULL;
}


DWORD GetPeHead(Pe_Load _peLoad)
{
	return ((Get_NumberOfSections_X64(_peLoad.file_buffer) * sizeof(IMAGE_SECTION_HEADER)) + Get_SizeOfOptionHeader(Get_IMAGE_FILE_HEADER_X64(_peLoad.file_buffer)) + ((DWORD)Get_IMAGE_OPTIONAL_HEADER_X64(_peLoad.file_buffer) - (DWORD)_peLoad.file_buffer));
}

BOOL CheckCommand(int argc, char** argv, char* outPath)
{
	if (argc < 1)
	{
		printf("Command error\r\n");
		return FALSE;
	}
	if (argv[1] == NULL)
	{
		printf("Command error\r\n");
		return FALSE;
	}
	strcpy_s(outPath, outBufLenght, argv[1]);
	return true;
}

void GetNewDir(char* _newDir, char* path)
{
	DWORD newDirStrSize = 0;
	for (size_t i = 0; i < strlen(path); i++)
	{
		if (path[i] == '\\')
		{
			newDirStrSize = i;
		}
	}
	memcpy(_newDir, path, newDirStrSize);
}