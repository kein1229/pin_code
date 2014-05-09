#include "pin.H"
#include "pin_isa.H"
#include "calltrace.h"

//using namespace std;

char* exe;
UINT entry_addr;
UINT end_addr;
UINT main_tid;
bool trace_flag=false;
vector<CIns*> vecdata;

void set_tracing(bool flag) {
	trace_flag = flag;
}

bool check_img(const char* str) {

	if(!str)
		return false;

	if(strstr(str,exe))
		return true;

	return false;
}

map<int,FILE*> mapFD;
FILE* create_fd(int tid)
{
	char buf[256]={0,};

	map<int,FILE*>::iterator it = mapFD.find(tid);
	if(it != mapFD.end())
		return mapFD[tid];

	if(main_tid == (UINT)tid)
		sprintf(buf,"../%s/%s_main.out", RESULT, exe);
	else
		sprintf(buf,"../%s/%s_%d.out", RESULT, exe, tid);

	printf("File : %s\n",buf);
	FILE* pFd = fopen(buf,"w+");
	if(!pFd)
	{
		printf("File open failed %d\n",tid);
		return NULL;
	}
	mapFD[tid] =  pFd;

	return mapFD[tid];
}

VOID fini(INT32 code, VOID *v) {

	if(vecdata.empty()) {

		printf("vecdata empty!!\n");
		return;
	}

	vector<CIns*>::iterator it = vecdata.begin();

	while(it != vecdata.end()) {
		CIns* pdata = *it; if(pdata) {

			FILE* fd = create_fd(pdata->tid);
			if(!fd)
				return;

			pdata->print_data(fd);
			delete pdata;

		} else printf("pdata null\n");

		++it;
	}
}

#if SYSLOG
VOID ret_site(VOID* ip, ADDRINT* rsp, UINT32 framesize,
			  ADDRINT nextip, ADDRINT tid, bool is_sysret) { 
#else 
VOID ret_site(VOID* ip, ADDRINT* rsp, UINT32 framesize, 
			  ADDRINT nextip, ADDRINT tid) { 
#endif
	
	ADDRINT retval;
	ADDRINT rspval = *rsp;
	ADDRINT *psp = (ADDRINT *)rspval;
	retval = *psp;

	if(trace_flag) {

		PIN_LockClient();

		UINT cur_ins =(UINT)ip;
		RTN callee_rtn = RTN_FindByAddress(cur_ins);

		if(RTN_Valid(callee_rtn)) {

			RTN caller_rtn = RTN_FindByAddress(nextip);
			if(RTN_Valid(caller_rtn)) {

				CIns* pNew = new CRet( (UINT)retval,
									   RTN_FindNameByAddress(cur_ins),
									   RTN_FindNameByAddress(nextip),
									   framesize,
									   (UINT)nextip,
									   (UINT)ip,
#if SYSLOG
									   is_sysret,
#endif
									   (UINT)tid);
				
				vecdata.push_back(pNew);
			}
		}

		PIN_UnlockClient();
	}

	UINT tmp = (UINT)retval;
	if( end_addr == tmp && trace_flag)
		set_tracing(false);
}

VOID call_site(VOID* ip, INT32 taken, ADDRINT tgtip, ADDRINT nextip, THREADID tid) { 

	PIN_LockClient();
	
	if(tgtip == entry_addr && !trace_flag) {

		set_tracing(true);
		main_tid = tid;
		end_addr = nextip;
	}
	
	if(trace_flag) {

		RTN caller_rtn = RTN_FindByAddress((UINT)ip);
		if(RTN_Valid(caller_rtn)) {

			RTN callee_rtn = RTN_FindByAddress((UINT)tgtip);
			if(RTN_Valid(callee_rtn)) {

				const char* img_str = IMG_Name(SEC_Img(RTN_Sec(callee_rtn))).c_str();
				if(!check_img(img_str))
					return;

				CIns* pNew = new CCall( (UINT)tgtip,
										 RTN_FindNameByAddress((UINT)tgtip),
										 IMG_Name(SEC_Img(RTN_Sec(caller_rtn))),
										 (UINT)nextip,
										 (UINT)ip,
										 (UINT)tid);

				vecdata.push_back(pNew);
			}
		}
	}
}

VOID sub_add_site(VOID* ip, ADDRINT value, ADDRINT* rsp, ADDRINT* rbp, ADDRINT nextip, bool flag, ADDRINT tid) {

	if(trace_flag){

		eCNT etype = flag ? eCNT_SUB : eCNT_ADD;
		CIns* pNew = NULL;

		if(etype == eCNT_SUB){

			pNew = new CSub( (UINT)value,
							 (UINT)rsp, 
					 	     (UINT)nextip, 
						     (UINT)ip,
							 (UINT)tid);
		} else {
			
			pNew = new CAdd( (UINT)value, 
							 (UINT)rsp, 
					 	     (UINT)nextip, 
						     (UINT)ip,
							 (UINT)tid);
		}

		vecdata.push_back(pNew);
	}
}

VOID stk_site(VOID* ip, ADDRINT dest, ADDRINT source, THREADID tid) {

	if(trace_flag){
			
		PIN_LockClient();
		RTN rtn = RTN_FindByAddress((UINT)ip);
		PIN_UnlockClient();

		if(RTN_Valid(rtn)) {

			int size = source - dest;
			CIns* pNew = new CStk((UINT)size, 
						 		  (UINT)ip,
								  RTN_FindNameByAddress((UINT)ip),
								  (UINT)tid);

			vecdata.push_back(pNew);

		}
	}
}

VOID check_ins(INS ins) {

	OPCODE op = INS_Opcode(ins);

	if(INS_IsRet(ins) || INS_IsSysret(ins)) {

		UINT64 imm = 0;
		UINT op_cnt = INS_OperandCount(ins);
		if(op_cnt > 0 && INS_OperandIsImmediate(ins,0))
			imm = INS_OperandImmediate(ins,0);

		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) ret_site,
					   IARG_INST_PTR,
					   IARG_CALL_ORDER, CALL_ORDER_FIRST,
					   IARG_REG_REFERENCE, REG_STACK_PTR,
					   IARG_ADDRINT, (ADDRINT)imm,
					   IARG_ADDRINT, INS_NextAddress(ins),
					   IARG_THREAD_ID,
					   IARG_BOOL, INS_IsSysret(ins) ? true : false,
					   IARG_END);

	} else if(INS_IsCall(ins) && !INS_IsSyscall(ins)) {

			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) call_site,
						   IARG_INST_PTR,
						   IARG_BRANCH_TAKEN,
						   IARG_BRANCH_TARGET_ADDR,
						   IARG_ADDRINT, INS_NextAddress(ins),
						   IARG_THREAD_ID,
						   IARG_END);

	} else if(INS_IsLea(ins) && INS_OperandReg(ins,0) == 
			  REG_ESP && INS_RegRContain(ins, REG_EBP)) {

		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)stk_site,
					   IARG_INST_PTR,
					   IARG_REG_VALUE, REG_STACK_PTR,
					   IARG_REG_VALUE, REG_EBP,
					   IARG_ADDRINT, PIN_GetTid(),
					   IARG_END);

	} else if(op == XED_ICLASS_LEAVE) {

		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)stk_site,
					   IARG_INST_PTR,
					   IARG_REG_VALUE, REG_STACK_PTR,
					   IARG_REG_VALUE, REG_EBP,
					   IARG_ADDRINT, PIN_GetTid(),
					   IARG_END);

	} 
#if window
	else if(op == XED_ICLASS_MOV && INS_OperandIsReg(ins,0) && 
			  INS_OperandIsReg(ins,1) && REG_is_gr(INS_OperandReg(ins,0)) &&
			  REG_is_gr(INS_OperandReg(ins, 1))) {

		REG reg0 = INS_OperandReg(ins, 0);
		REG reg1 = INS_OperandReg(ins, 1);

		if(reg0 == REG_ESP && reg1 == REG_EBP) {

			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)stk_site,
						   IARG_INST_PTR,
					   	   IARG_REG_VALUE, REG_STACK_PTR,
					   	   IARG_REG_VALUE, REG_EBP,
					   	   IARG_ADDRINT, PIN_GetTid(),
					   	   IARG_END);
		}
	} 
#endif
	else if(op == XED_ICLASS_SUB) {
//	else if(op == XED_ICLASS_SUB || op == XED_ICLASS_ADD) {

		if( INS_OperandReg(ins,0) == REG_ESP && INS_OperandIsImmediate(ins,1) )	{

#if D_LOG
			printf("cur  ins : %s\n",INS_Disassemble(ins).c_str());
			printf("prev ins : %s\n\n",INS_Disassemble(INS_Prev(ins)).c_str());
#endif
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) sub_add_site,
						   IARG_INST_PTR,
						   IARG_ADDRINT, (ADDRINT)INS_OperandImmediate(ins,1),
						   IARG_REG_VALUE, REG_STACK_PTR,
	  					   IARG_REG_VALUE, REG_EBP,
						   IARG_ADDRINT, INS_NextAddress(ins),
						   IARG_BOOL, op == XED_ICLASS_SUB ? true : false,
						   IARG_THREAD_ID,
						   IARG_END);
		}
	} 
}

static VOID instruction(INS ins, void *a) {

	ADDRINT addr;

	if(!INS_Valid(ins))	{

		printf("Unvalid Ins\n");
		return;
	}

	addr = INS_Address(ins);
	RTN rtn = RTN_FindByAddress(addr);
	if(!RTN_Valid(rtn))
		return;

	const char* img_str = IMG_Name(SEC_Img(RTN_Sec(rtn))).c_str();
	if(!INS_IsCall(ins) && !check_img(img_str))
		return;

	check_ins(ins);
}

char* getexe(int cnt, char* file) {

	char* ptr = NULL;
	char* tmp = NULL;

	ptr = strtok(file,"/");
	while(ptr != NULL) {

		ptr = strtok(NULL,"/");
		if(ptr) tmp = ptr;
	}

	return tmp;
}

int main(int argc, char* argv[]) {

	char* ptr;

	if(argc <= 7) {

		printf("Usage : sudo ./pin -t \"dll or so\" \"main addr\" -- \"application\"\n");
		return 0;
	}

 	PIN_InitSymbols();
	PIN_Init(argc, argv);
	PIN_AddFiniFunction(fini, 0);
	PIN_SetSyntaxATT();
	
	if(!(exe = getexe(argc, argv[EXE_NAME])))
		return 0;

	entry_addr = (UINT)strtol(argv[MAIN_ADDR],&ptr,16);

	INS_AddInstrumentFunction(instruction, 0);
	PIN_StartProgram();

 	return 0;
}
