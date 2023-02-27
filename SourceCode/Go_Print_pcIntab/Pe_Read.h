//Pe_Read.h
#ifndef  PE_READ_H
#define PE_READ_H
#include <windows.h>
//声明
DWORD Get_e_lfanew_DWORD(BYTE* file_buffer);

// rva to roa arg1:file_buffer arg2:rva return foa
DWORD RVA_To_FOA(BYTE* file_buffer, DWORD RVA);
DWORD RVA_To_FOA_X64(BYTE* file_buffer, DWORD RVA);

// roa to foa arg1:file_buffer arg2:foa retrun:rva
DWORD FOA_TO_RVA(BYTE* file_buffer, DWORD FOA);

//------------------------------------------------------------------
//IMAGE_FILE_HEADER arg:pe_buffer peNT头
IMAGE_NT_HEADERS* Get_IMAGE_NT_HEADERS(PIMAGE_DOS_HEADER _pe_buffer);
IMAGE_NT_HEADERS64* Get_IMAGE_NT_HEADERS_X64(PIMAGE_DOS_HEADER dos_header_p);
DWORD Get_Signature(IMAGE_NT_HEADERS* _nt_headers);

//------------------------------------------------------------------
//IMAGE_FILE_HEADER arg:pe_buffer （pe文件头）
IMAGE_FILE_HEADER* Get_IMAGE_FILE_HEADER(BYTE* file_buffer);
IMAGE_FILE_HEADER* Get_IMAGE_FILE_HEADER_X64(BYTE* file_buffer);
WORD Get_Machine(IMAGE_FILE_HEADER* _file_header);
WORD Get_NumberOfSections(BYTE* _file_buffer);
WORD Get_NumberOfSections_X64(BYTE* _file_buffer);
DWORD Get_TimeDateStamp(IMAGE_FILE_HEADER* _file_header);
WORD Get_SizeOfOptionHeader(IMAGE_FILE_HEADER* _file_header);

//------------------------------------------------------------------
//IMAGE_OPTIONAL_HEADER arg:ne_header （可选pe头）
IMAGE_OPTIONAL_HEADER* Get_IMAGE_OPTIONAL_HEADER(BYTE* _pe_buffer);
IMAGE_OPTIONAL_HEADER64* Get_IMAGE_OPTIONAL_HEADER_X64(BYTE* _pe_buffer);
WORD Get_Magic(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_SizeOfCode(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_AddressOfEntryPoint(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_BaseOfCode(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_BaseOfData(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_ImageBase(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_ImageBase_X64(IMAGE_OPTIONAL_HEADER64* _OPTIONAL_HEADER);
DWORD Get_SectionAlignment(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_FileAlignment(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_FileAlignment_X64(IMAGE_OPTIONAL_HEADER64* _OPTIONAL_HEADER);
DWORD Get_SizeOfImage(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
DWORD Get_SizeOfHeaders(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
WORD Get_Subsystem(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);
IMAGE_DATA_DIRECTORY* Get_IMAGE_DATA_DIRECTORY(BYTE* _file_buffer);

//------------------------------------------------------------------
//IMAGE_SECTION_HEADER arg:pe_buffer （节表）返回值:IMAGE_SECTION_HEADER
IMAGE_SECTION_HEADER* Get_IMAGE_SECTION_HEADER(BYTE* _pe_buffer);
IMAGE_SECTION_HEADER* Get_IMAGE_SECTION_HEADER_X64(BYTE* _pe_buffer);

//------------------------------------------------------------------
//IMAGE_EXPORT_DIRECTORY arg:IMAGE_OPTIONAL_HEADER （导出表）返回值:IMAGE_EXPORT_DIRECTORY rva
DWORD Get_IMAGE_EXPORT_DIRECTORY(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);

//------------------------------------------------------------------
//IMAGE_IMPORT_DESCRIPTOR arg:IMAGE_OPTIONAL_HEADER （导入表）返回值:IMAGE_IMPORT_DESCRIPTOR rva
IMAGE_IMPORT_DESCRIPTOR* Get_IMAGE_IMPORT_DESCRIPTOR(BYTE* _file_buffer);

//------------------------------------------------------------------
//IMAGE_BASE_RELOCATION arg:IMAGE_OPTIONAL_HEADER （重定位表）返回值:IMAGE_BASE_RELOCATION rva
DWORD Get_IMAGE_BASE_RELOCATION(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);

//------------------------------------------------------------------
//IMAGE_BASE_RELOCATION arg:IMAGE_OPTIONAL_HEADER （资源表）返回值:IMAGE_RESOURCE_DIRECTORY rva
DWORD Get_IMAGE_RESOURCE_DIRECTORY(IMAGE_OPTIONAL_HEADER* _OPTIONAL_HEADER);

IMAGE_BOUND_IMPORT_DESCRIPTOR* Get_IMAGE_BOUND_IMPORT_DESCRIPTOR(BYTE* file_buffer);






//获取某些数量
DWORD Get_e_lfanew_DWORD(BYTE* file_buffer);
DWORD Get_VirtualSize(BYTE* file_buffer, WORD section_index);
DWORD Get_VirtualSize_X64(BYTE* file_buffer, WORD section_index);
DWORD Get_VirtualAddress(BYTE* file_buffer, WORD section_index);
DWORD Get_VirtualAddress_X64(BYTE* file_buffer, WORD section_index);
DWORD Get_SizeOfRawData(BYTE* file_buffer, WORD section_index);
DWORD Get_SizeOfRawData_X64(BYTE* file_buffer, WORD section_index);
DWORD Get_PointerToRawData(BYTE* file_buffer, WORD section_index);
DWORD Get_PointerToRawData_X64(BYTE* file_buffer, WORD section_index);
DWORD ImageAddressOffset_Add_ImageBase(BYTE* file_buffer, WORD section_index);
DWORD ImageAddressOffset_Add_ImageBase_X64(BYTE* file_buffer, WORD section_index);

//pe加载
typedef struct _Pe_Load
{
	//初始化大小 arg1:读取文件的指针 返回值:无
	void Init(BYTE* _pe_buffer, DWORD _file_buffer_size);

	//展开pe文件 arg1:读取文件的指针 返回值:无
	void Load_Pe(BYTE* _pe_buffer);

	DWORD file_buffer_size;
	BYTE* file_buffer;

	DWORD peLoad_buffer_size;
	BYTE* peLoad_buffer;
}Pe_Load;

#endif // ! 
