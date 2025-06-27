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
	char *string = "I Will Learn LowLevel Systems Architechture!\n\0";
	char *string1 = "This Is The Example For malloc, VirtualAlloc, free & VirtualFree!\n\0";
	char *string2 = "malloc() Arguments:\n1.size_t: BufferSize\n\0";
	char *string3 = "VirtualAlloc() Arguments:\n1. LPVOID: NULL\n2. size_t: buffer_size\n3. DWORD: MEM_RESERVE | MEM_COMMIT\n4. DWORD: PAGE_READWRITE\n\0";
	char* string4 = "free() Arguments:\n1.void: (char *)pBuffer\n\0";
	char* string5 = "VirtualFree() Arguements:\n1. LPVOID: buffer\n2. SIZE_T: 0\n3. DWORD: MEM_FREE\n\0";
	size_t buffer_size = strlen(string) + strlen(string1) + strlen(string2) + strlen(string3) + strlen(string4) + strlen(string5) + 1;
	printf("Calling malloc()...\n");
	char *pBuffer = malloc(buffer_size);
	if (!pBuffer) {
		printf("Failed To Allocate Memory!\nExiting With Code: 1\n");
		return ThrowMemoryError(1, ' ');
	}
	strcpy_s(pBuffer, buffer_size, string);
	strcat_s(pBuffer, buffer_size, string1);
	strcat_s(pBuffer, buffer_size, string2);
	strcat_s(pBuffer, buffer_size, string3);
	strcat_s(pBuffer, buffer_size, string4);
	strcat_s(pBuffer, buffer_size, string5);
	PrintContentAddressCall("pBuffer", "strcpy_s() & strat_s", pBuffer, "VirtualAlloc");
	printf("Calling VirtualAlloc");
	void* vpBuffer = VirtualAlloc(0, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!vpBuffer) {
		return ThrowMemoryError(3, " Virtual ");
	}
	printf("Calling memcpy()...\n");
	memcpy(vpBuffer, pBuffer, buffer_size);
	printf("Finished memcpy()!\nCalling SecureZeroMemory()...\n");
	SecureZeroMemory(pBuffer, strlen(pBuffer));
	PrintContentAddressCall("pBuffer", "SecureZeroMemory", pBuffer, "free");
	/*HeapAlloc()*/
	free(pBuffer);
	PrintFreed("\"pBuffer\" / Heap Memory");
	PrintContentAddressCall("vpBuffer", "memcpy", vpBuffer, "SecureZeroMemory");
	SecureZeroMemory(vpBuffer, buffer_size);
	PrintContentAddressCall("vpBuffer", "SecureZeroMemory", vpBuffer, "VirtualFree");
	VirtualFree(vpBuffer, 0, MEM_FREE);
	PrintFreed("\"vpBuffer\" / Virtual Memory");
	
	printf("Exiting Program With code 0\n");
	return 0;
  }




