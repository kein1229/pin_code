#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <list>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define WINS		0
#define MAIN_ADDR 	5
#define EXE_NAME 	7
#define RESULT "test_result"
typedef unsigned int UINT;

using namespace std;

typedef enum {
	eCNT_PUSH=0,
	eCNT_RET,
	eCNT_CALL,
	eCNT_STK,
	eCNT_ADD,
	eCNT_SUB,
	eCNT_FRM,
	eCNT_MEM,
	eCNT_NONE = -1,
}eCNT;

typedef enum{
	eTYPE_CALL='C',
	eTYPE_STACK='S',
	eTYPE_PUSH='P',
	eTYPE_MEM='M',
	eTYPE_RET='R',
	eTYPE_FRAME='F',
	eTYPE_ADD='A',
	eTYPE_SUB='s'
}eTYPE;

typedef struct{
	UINT nLine;
	UINT call;
	UINT nextip;
	UINT ret;
}INFO;

/****************************************************************/

class CIns {

public:
	virtual void print_data(FILE*)=0;
	virtual ~CIns() {};

public:
	UINT ins_addr;
	UINT nextins_addr;
	UINT tid;
	eCNT etype;
};

class CCall: virtual public CIns {

public:
	CCall(UINT target, string str_func, string str_img, 
		  UINT next_ins, UINT ip, UINT tid);

	virtual ~CCall() {}
	void print_data(FILE* fd);

private:
	UINT 	target_addr;
	UINT 	ebp;
	UINT 	esp;
	UINT 	count;

	string 	func_name;
	string 	img_name;
};

class CRet : virtual public CIns {

public:
	CRet(UINT retval, string callee, string caller, 
		 UINT size, UINT next_ins, UINT ip, UINT tid);

	virtual ~CRet() {}
	void print_data(FILE* fd);

private:
	UINT 	ret_value;
	UINT 	framesize;
	UINT 	ebp;
	UINT 	esp;

	string 	callee;
	string 	caller;
};

class CSub : virtual public CIns {
	
public:
	CSub(UINT value, UINT ebp, UINT next_ins, UINT ip, UINT tid);
	virtual ~CSub() {}
	void print_data(FILE* fd);

private:
	UINT value;
	UINT esp;
};

class CAdd: virtual public CIns {

public:
	CAdd(UINT value, UINT ebp, UINT next_ins, UINT ip, UINT tid);
	virtual ~CAdd() {}
	void print_data(FILE* fd);

private:
	UINT value;
	UINT esp;
};

class CStk: virtual public CIns {

public:
	CStk(UINT size, UINT ip, string func, UINT tid);
	virtual ~CStk() {}
	void print_data(FILE* fd);

private:
	UINT 	framesize;
	string 	func_name; 
};

/****************************************************************/

CCall::CCall(UINT target, string str_func, string str_img, 
		  	 UINT next_ins, UINT ip, UINT tid) {

	this->target_addr   = target;
	this->func_name 	= str_func;
	this->img_name 		= str_img;
	this->count 		= 0;

	this->nextins_addr 	= next_ins;
	this->ins_addr 		= ip;
	this->etype 		= eCNT_CALL;
	this->tid 			= tid;
}

void CCall::print_data(FILE* fd) {

	fprintf(fd, "C %#x\t%#x\t%#x\t%s\n", this->ins_addr, 
										 this->target_addr, 
										 this->nextins_addr, 
										 this->func_name.c_str());
}

CRet::CRet(UINT retval, string callee, string caller, 
		   UINT size, UINT next_ins, UINT ip, UINT tid) {

	this->ret_value 	= retval;
	this->callee 		= callee;
	this->caller 		= caller;
	this->framesize		= size;

	this->nextins_addr 	= next_ins;
	this->ins_addr 		= ip;
	this->etype 		= eCNT_RET;
	this->tid 			= tid;
}

void CRet::print_data(FILE* fd) {

	fprintf(fd, "R %#x\t%#x\t%#x\t%d\n", this->ins_addr, 
							 	  this->ret_value,
								  this->nextins_addr,
							 	  this->framesize);
}

CSub::CSub(UINT value, UINT esp, UINT next_ins, UINT ip, UINT tid) {

	this->value 		= value;
	this->esp 			= esp;

	this->nextins_addr 	= next_ins;
	this->ins_addr 		= ip;
	this->etype 		= eCNT_SUB;
	this->tid 			= tid;
}

void CSub::print_data(FILE* fd) {

	fprintf(fd, "S %d\t%#x\n", this->value, this->esp);
}

CAdd::CAdd(UINT value, UINT esp, UINT next_ins, UINT ip, UINT tid) {

	this->value 		= value;
	this->esp 			= esp;

	this->nextins_addr 	= next_ins;
	this->ins_addr 		= ip;
	this->etype 		= eCNT_ADD;
	this->tid 			= tid;
}

void CAdd::print_data(FILE* fd) {

	fprintf(fd, "A %d\t%#x\n", this->value, this->esp);
}

CStk::CStk(UINT size, UINT ip, string func, UINT tid) {

	this->framesize = size;
	this->func_name = func;

	this->ins_addr 	= ip;
	this->etype 	= eCNT_FRM; 
	this->tid 		= tid;
}

void CStk::print_data(FILE* fd) {

	fprintf(fd, "F %d\n", this->framesize);
}
