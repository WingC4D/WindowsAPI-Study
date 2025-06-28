#include <Windows.h>
#include <stdio.h>
#include <string.h>
#define _CRT_SECURE_NO_WARNINGS
static int ThrowMemoryError(int exit_code, char* type_of_memory) {
	printf("Failed to Allocate%sMemory!\nExiting Process With Exit Code : %d", type_of_memory, exit_code);
	return exit_code;
}

static void PrintFreed(char *buffer_name)
{
	printf("%s Freed Successfully!\n", buffer_name);
	return;
}

static void PrintContentAddressCall(char *buffer_name, char *function_call_1, void *buffer, char *function_call_2 ) 
{
	printf(
		"Content Of %s After Calling \"%s()\":\n%s\n%s's Address: %p\nCalling %s()...\n",
		buffer_name, 
		function_call_1,
		(char *)buffer,
		buffer_name,
		buffer,
		function_call_2
	);
	return;
}

int main()
{
	CHAR *string  = "[#] I Will Learn LowLevel Systems Architechture!\n\0";
	printf("Address of string: %p\n", string);
	CHAR *string1 = "[#] This Is The Example For malloc, VirtualAlloc, free & VirtualFree!\n\0";
	CHAR *string2 = "[#] malloc() Arguments:\n1.size_t: BufferSize\n\0";
	CHAR *string3 = "[#] VirtualAlloc() Arguments:\n1. LPVOID: NULL\n2. size_t: buffer_size\n3. DWORD: MEM_RESERVE | MEM_COMMIT\n4. DWORD: PAGE_READWRITE\n\0";
	CHAR *string4 = "[#] free() Arguments:\n1.void: (char *)pBuffer\n\0";
	CHAR *string5 = "[#] VirtualFree() Arguements:\n1. LPVOID: buffer\n2. SIZE_T: 0\n3. DWORD: MEM_FREE\n\0";
	const SIZE_T buffer_size = strlen(string) + strlen(string1) + strlen(string2) + strlen(string3) + strlen(string4) + strlen(string5) + 1;
	printf("Calling malloc()...\n");
	//malloc()
	CHAR *pBuffer = malloc(buffer_size);
	if (!pBuffer) {
		printf("Failed To Allocate Memory!\nExiting With Code: 1\n");
		return ThrowMemoryError(1, (char *)' '); //<- How is this an int?! GCC is a funny one, 
	}
	//Creating the Original Self Allocated memory Space
	strcpy_s(pBuffer, buffer_size, string);
	printf("Address Of Original Text: %p\n", pBuffer);
	strcat_s(pBuffer, buffer_size, string1);
	strcat_s(pBuffer, buffer_size, string2);
	strcat_s(pBuffer, buffer_size, string3);
	strcat_s(pBuffer, buffer_size, string4);
	strcat_s(pBuffer, buffer_size, string5);
	PrintContentAddressCall("pBuffer", "strcpy_s() & strat_s", pBuffer, "VirtualAlloc");
	printf("Calling VirtualAlloc");
	//VirtualAllocate()
	PVOID vpBuffer = VirtualAlloc(0, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!vpBuffer) {
		return ThrowMemoryError(2, " Virtual ");
	}
	printf("Calling memcpy()...\n");
	//malloc => VirtualAlloc()
	memcpy(vpBuffer, pBuffer, buffer_size);
	printf("Finished memcpy()!\nCalling SecureZeroMemory()...\n");
	//malloc SecureZeroMemory
	SecureZeroMemory(pBuffer, strlen(pBuffer));
	PrintContentAddressCall("pBuffer", "SecureZeroMemory", pBuffer, "free");
	//free()
	free(pBuffer);
	PrintFreed("\"pBuffer\" / Heap Memory");
	printf("Calling GetProcessHeap()...");
	//GetProccessHeap()
	HANDLE hHeap = GetProcessHeap();
	printf("Heap Handle: %p\n", hHeap);
	//HeapAlloc()
	PVOID hpBuffer = HeapAlloc(hHeap, 0, buffer_size);
	if (!hpBuffer) {
		return ThrowMemoryError(3, " Heap ");
	}
	
	PrintContentAddressCall("vpBuffer", "SecureZeroMemory", vpBuffer, "VirtualFree");
	//VirtualAlloc => HeapAlloc
	memcpy(hpBuffer, vpBuffer, buffer_size);
	//Virtual SecureZeroMemory()
	SecureZeroMemory(vpBuffer, buffer_size);
	PrintContentAddressCall("hpBuffer", "memcpy", hpBuffer, "SecureZeroMemory");
	
	//VirtualFree()
	VirtualFree(vpBuffer, 0, MEM_FREE);
	PrintFreed("\"vpBuffer\" / Virtual Memory");
	//LocalAlloc()
	printf("Calling LocalAlloc()...\n");
	PVOID pLocalBuffer = LocalAlloc(LMEM_FIXED, buffer_size);
	if (!pLocalBuffer) {
		ThrowMemoryError(4, "pLocalAlloc");
	}
	/*HeapAlloc => Temporary Virtual Buffer 
	As LocalAlloc alloctes memory to to the Heap and so does HeapAlloc.
	The MSDN Manual for the Local Alloc Clearly states not to use this function unless specifcally asked to do so.
	This is a study case  for how the Windows OS Allocates memory at the lowst level available to me (x64dbg).
	*/
	LPVOID pTemp = VirtualAlloc(0, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!pTemp) {
		ThrowMemoryError(5, "Temporary Virtual");
	}
	//copying out to Virtual Memory.
	memcpy(pTemp, hpBuffer, buffer_size);
	//copying back into the heap
	memcpy(pLocalBuffer, pTemp, buffer_size);
	
	PrintContentAddressCall("pTemp", "RtlFillMemory", pTemp, "RtlFillMemory");
	//Calling SecureZeroMemory(pTemp)
	SecureZeroMemory(pTemp, buffer_size);
	//freeing pTemp;
	VirtualFree(pTemp, buffer_size, MEM_FREE);
	PrintContentAddressCall("pTemp", "SecureZeroMemory(pTemp)", pLocalBuffer, "rtlFillMemoryBuffer");
	//using RtlFillMemory With 0 and the buffer's size as an alternative for SecureZeroMemory (Testing)
	RtlFillMemory(pLocalBuffer, buffer_size, 0);
	/*making Sure the Compiler doesn't optimize away the RtlFillMemory Call 
	by making sure to refrence the filled to memory*/
	printf("LocalBuffer's Contet After Calling RtlFillMemory: %d | %s |\nLocalBuffer's Address: %p\n", pLocalBuffer, pLocalBuffer, pLocalBuffer);
	//PrintContentAddressCall("pLocalBuffer", "VirtualFree", pLocalBuffer, "memcpy");
	
	//Heap SecureZeroMemory
	RtlFillMemory(hpBuffer, buffer_size, 0);
	HeapFree(hHeap, HEAP_ZERO_MEMORY, hpBuffer);
	//LocalFree()
	LocalFree(pLocalBuffer);
	//NOP (no operation x86 assembly) shell code trail and error.
	char nopsled[42];
	RtlFillMemory(nopsled, 42, 0x90);
	printf("NOP Sled?:\n");
	for (int i = 0; i < 42; ++i) {
		printf("%02X\n", nopsled[i]);
	}
	SecureZeroMemory(nopsled, 42);
	printf("%42X\n", nopsled);
	printf("Exiting Program With code 0\n");
	return 0;
  }