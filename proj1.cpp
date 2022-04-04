#include "pin.H"
#include "uthash.h"
#include "stdio.h"
#include <vector>
#include <iostream>
#define MAIN "main"
#define FILENO "fileno"

// Taint the memory if the source of input is stdin
#define FGETS "fgets"
#define GETS "gets"

// Propagate if the src is tainted
#define STRCPY "strcpy@plt"
#define STRNCPY "strncpy@plt"
#define STRCAT "strcat@plt"
#define STRNCAT "strncat@plt"
#define MEMCPY "memcpy@plt"

// Reset tainted memory
#define BZERO "bzero@plt"
#define MEMSET "memset@plt"

using namespace std;

typedef int ( *FP_FILENO )(FILE*);
FP_FILENO org_fileno;
vector<string> __Trace;
string mainAdding;

// Creating has table and searching, adding and deleting methods for hash table
//Using uthash for data structure
struct taintedStruct {
	char* bytes;
	string stack_t;
	UT_hash_handle hh;
};

//Initializing the uthash structure 
struct taintedStruct* taintedHash = NULL;

//to check if byte exists in hash table and then returns true or false
bool findItem(char * bytes) {
	struct taintedStruct *item;
	HASH_FIND_INT(taintedHash, &bytes, item);
	if (item) {
		return true;
	}
	else {
		return false;
	}
}
//add tainted byte to hash table after checking if it already exists or not
void addItem(char* bytes) {
	struct taintedStruct *item;
	HASH_FIND_INT(taintedHash, &bytes,item);
	if (item == NULL) {
		item = (struct taintedStruct *) malloc(sizeof(taintedStruct));
		item->bytes=bytes;
		for (vector<string>::iterator i = __Trace.begin(); i != __Trace.end(); ++i)
			item->stack_t.append(*i);
		HASH_ADD_INT(taintedHash, bytes, item);
	}
}
// function to delete a byte from hash table if it exists there
void deleteItem(char* bytes) {
	struct taintedStruct *item;
	HASH_FIND_INT(taintedHash, &bytes, item);
	if (item) {
		HASH_DEL(taintedHash, item);
	}
}
// Hash table implementaion ends here
INT32 Usage()
{
		return -1;
}
bool isStdin(FILE *fd)
{
		int ret = org_fileno(fd);
		if(ret == 0) return true;
		return false;
}
bool fgets_stdin = false;
// to add bytes from fgets call to tainted hash table
VOID fgetsTail(char* ret)
{
		if(fgets_stdin) {
				printf("fgetsTail: ret %p\n", ret);
				for (size_t i=0; i < strlen(ret) ; i++) {
					addItem(ret+i);
				}
		}
		fgets_stdin = false;
}
// sets fgets_stdin to true if the fgets arg is from the stdin
VOID fgetsHead(char* dest, int size, FILE *stream)
{
		if(isStdin(stream)) {
				printf("fgetsHead: dest %p, size %d, stream: stdin)\n", dest, size);
				fgets_stdin = true;
		} 
}
// to add bytes from gets call to tainted hash table
VOID getsTail(char* dest)
{
		printf("getsTail: dest %p)\n", dest);
  		printf("size of dest: %u\n",(unsigned) strlen(dest));
		  for (size_t i=0; i < strlen(dest) ; i++) {
			  addItem(dest+i);
		  }
}
// to add bytes from the command line to tainted hash table
VOID mainHead(int argc, char** argv, ADDRINT inst_addr)
{
		printf("mainHead: argc: %d, argc: %p\n", argc, argv);
		for (int i = 1; i < argc ; i++) {
			for (size_t j = 0 ; j < strlen(argv[i]) ; j++) {
				addItem(&(argv[i][j]));
			}
		}

		char a[20];
		sprintf(a, "0x%x, ", inst_addr);
		mainAdding = a;
		__Trace.push_back(a);
}
// to add all destination bytes to hashtable if soruce bytes are tainted
VOID strcpyHead(char* dest, char* src)
{
		printf("strcpyHead: dest %p, src %p, size %d\n", dest, src, strlen(src));
		for (size_t i = 0 ; i < strlen(src) ; i++) {
			if (findItem(src+i)) {
					addItem(dest+i);
			}
		}
}
// to add all destination bytes to hashtable if soruce bytes are tainted
VOID strncpyHead(char* dest, char* src, size_t n)
{
		printf("strncpy: dest %p, src %p, size %d\n", dest, src, n);
		for (size_t i = 0 ; i < n ; i++) {
			if (findItem(src+i)) {
					addItem(dest+i);
			}
		}
}
// to add all destination bytes to hashtable if soruce bytes are tainted
VOID strcatHead(char* dest, char* src)
{
		printf("strcat: dest %p, size %d ,src %p, size %d\n", dest, strlen(dest), src, strlen(src));
		for (size_t i = 0 ; i < strlen(src) ; i++) {
			if (findItem(src + i)) {
				addItem(dest + strlen(dest) + i);
			}
		}

}
// to add all destination bytes to hashtable if soruce bytes upto n are tainted
VOID strncatHead(char* dest, char* src, size_t n)
{
		printf("strncat: dest %p, size %d ,src %p, size %d\n", dest, strlen(dest), src, strlen(src));
		for (size_t i = 0 ; i < n ; i++) {
			if (findItem(src + i)) {
				addItem(dest + strlen(dest) + i);
			}
		}

}
// to add all destination bytes to hashtable if soruce bytes upto n are tainted
VOID memcpyHead(char* dest, char* src, size_t n)
{
		printf("memcpyHead: dest %p, src %p, size %u\n",dest,src,n);
        for(size_t i = 0; i < n;i++){
            if(findItem(src+i)){
                	addItem(dest + i);
            }
        }
}
// delete specified bytes from ptr to n from hashtable 
VOID memsetHead(void* ptr, int x, size_t n)
{
		printf("memsetHead: pointer %p, value %d, size %u\n",ptr,x,n);
        for(size_t i = 0; i < n;i++){
            	deleteItem((char*)ptr + i);
        }
}
// delete specified bytes from ptr to n from hashtable
VOID bzeroHead(void* dest, int n)
{
		printf("bzeroHead: dest %p, size %d\n",dest, n);
		for ( int i = 0  ; i < n ; i++) {
			deleteItem((char*)dest +i);
		}
}
bool IsAddressInMainExecutable(ADDRINT addr)
{
	PIN_LockClient();
	RTN rtn = RTN_FindByAddress(addr);
	PIN_UnlockClient();
	if (rtn == RTN_Invalid())
		return false;

	SEC sec = RTN_Sec(rtn);
	if (sec == SEC_Invalid())
		return false;

	IMG img = SEC_Img(sec);
	if (img == IMG_Invalid())
		return false;
	if (IMG_IsMainExecutable(img))
		return true;

	return false;
}
// remove from vector the last element
VOID deleteTrace(ADDRINT instAddr, ADDRINT retAddr)
{
	if (IsAddressInMainExecutable(retAddr))
	{
		if (__Trace.size() > 0)
			__Trace.pop_back();
	}
}
//add to vector
VOID addTrace(ADDRINT inst_addr)
{
	if (IsAddressInMainExecutable(inst_addr))
	{
		char a[20];
		sprintf(a, "0x%x, ", inst_addr);
		__Trace.push_back(a);
	}
}
//additonal function that were missing were added
VOID Image(IMG img, VOID *v) {
		RTN rtn;
		rtn = RTN_FindByName(img, FGETS);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fgetsHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_END);

				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)fgetsTail, 
								IARG_FUNCRET_EXITPOINT_VALUE,
								IARG_END);
				RTN_Close(rtn);
		}
		rtn = RTN_FindByName(img, GETS);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getsTail, 
								//IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCRET_EXITPOINT_VALUE,
								IARG_END);
				RTN_Close(rtn);
		}
		rtn = RTN_FindByName(img, STRCPY);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcpyHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_END);
				RTN_Close(rtn);
		}
		rtn = RTN_FindByName(img, STRCAT);
                if(RTN_Valid(rtn)) {
                                RTN_Open(rtn);
                                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcatHead,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                                                IARG_END);
                                RTN_Close(rtn);
                }
	rtn = RTN_FindByName(img, STRNCAT);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncatHead,
	                            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);
				RTN_Close(rtn);
				}
	rtn = RTN_FindByName(img, STRNCPY);
       if(RTN_Valid(rtn)) {
                RTN_Open(rtn);
                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncpyHead,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);
                RTN_Close(rtn);
                }
	rtn = RTN_FindByName(img, BZERO);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)bzeroHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_END);
				RTN_Close(rtn);
		}
		rtn = RTN_FindByName(img, MEMSET);
		if(RTN_Valid(rtn)) {
                                RTN_Open(rtn);
                                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memsetHead,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                                                IARG_END);
                                RTN_Close(rtn);
                }
		rtn = RTN_FindByName(img, MEMCPY);
                if(RTN_Valid(rtn)) {
                                RTN_Open(rtn);
                                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memcpyHead,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                                                IARG_END);
                                RTN_Close(rtn);
                }
		rtn = RTN_FindByName(img, MAIN);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mainHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_END);
				RTN_Close(rtn);
		}
		rtn = RTN_FindByName(img, FILENO);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				AFUNPTR fptr = RTN_Funptr(rtn);
				org_fileno = (FP_FILENO)(fptr);
				RTN_Close(rtn);
		}
}
// main function to raise alarm when tainted data is used to alter normal program flow
VOID taintCheck(ADDRINT m, ADDRINT target,ADDRINT inst)
{
        char * tmp = (char*) m;
        if(findItem(tmp)) {
				taintedStruct *identified;
				HASH_FIND_INT(taintedHash, &tmp, identified);
                printf("********** Overflow Detected **********\n");
                printf("IndirectBranch(%p):jump to %p, stored in tainted byte (%p)\n",(void*)inst, (void*)target, tmp);
                cout << "Stack 0: History of Mem(" << static_cast<void *>(tmp) << "): ";
				cout << identified-> stack_t<< endl;
                printf("***************************************\n");
                PIN_ExitApplication(0);
        }
}
// for stack trace
VOID Instruction(INS ins, VOID *v) {
        if (INS_IsRet(ins))
		{
			if (INS_IsControlFlow(ins))
			{
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)deleteTrace,
							   IARG_INST_PTR,
							   IARG_BRANCH_TARGET_ADDR,
							   IARG_END);
			}
		}
		if (INS_IsCall(ins))
		{
			if (INS_IsControlFlow(ins))
			{
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)addTrace,
						   	IARG_INST_PTR,
						   	IARG_END);
			}
		}
		if(INS_IsIndirectControlFlow(ins)) {
                if(INS_IsMemoryRead(ins)) {
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)taintCheck,IARG_MEMORYREAD_EA,IARG_BRANCH_TARGET_ADDR, IARG_INST_PTR,IARG_END);
                }
        }
}
int main(int argc, char *argv[])
{
  PIN_InitSymbols();

		if(PIN_Init(argc, argv)){
				return Usage();
		}
		
  IMG_AddInstrumentFunction(Image, 0);
  INS_AddInstrumentFunction(Instruction,0);
		PIN_StartProgram();

		return 0;
}