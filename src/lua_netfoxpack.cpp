#include "lua_netfoxpack.hpp"
#include "../LuaFunction.hpp"
#include<stdlib.h>
#include<string.h>


#define Key_Value   "ABcde34gdbbddddd"
const unsigned int  g_dwDelta = 0xA55AA55A;
#define SOCKET_VER 0x66

//Decrypt
static void DecryptTEA(int *dwFirstChunk, int *dwSecondChunk)
{
	const unsigned int *dwXorKey = (unsigned int*)Key_Value;
	unsigned int sum = 0;
	unsigned int  y = *dwFirstChunk;
	unsigned int  z = *dwSecondChunk;
	unsigned int  dwDelta = g_dwDelta;
	short i;

	sum = dwDelta << 5;

	for (i = 0; i < 32; i++)
	{
		z -= (y << 4) + dwXorKey[2] ^ y + sum ^ (y >> 5) + dwXorKey[3];
		y -= (z << 4) + dwXorKey[0] ^ z + sum ^ (z >> 5) + dwXorKey[1];
		sum -= dwDelta;
	}

	*dwFirstChunk = y;
	*dwSecondChunk = z;
}

//Encrypt
static void EncryptTEA(unsigned int *dwFirstChunk, unsigned int *dwSecondChunk)
{
	unsigned int y = *dwFirstChunk;
	unsigned int z = *dwSecondChunk;
	unsigned int sum = 0;
	int i;

	unsigned int *key = (unsigned int *)"ABcde34gdbbddddd";

	unsigned int dwDelta = 0xA55AA55A;

	for (i = 0; i < 32; i++)
	{
		sum += dwDelta;
		y += ((z << 4) + key[0]) ^ (z + sum) ^ ((z >> 5) + key[1]);
		z += ((y << 4) + key[2]) ^ (y + sum) ^ ((y >> 5) + key[3]);
	}

	*dwFirstChunk = y;
	*dwSecondChunk = z;
}

//Decrypt
static void DecryptBuffer(unsigned char* pBuffer, unsigned short wDataSize)
{
	unsigned char *p = pBuffer;
	while (p < pBuffer + wDataSize)
	{
		DecryptTEA((int *)p, (int *)(p + sizeof(int)));
		p += sizeof(unsigned int) * 2;
	}
}

//Encrypt
static void EncryptBuffer(unsigned char* pBuffer, unsigned short wDataSize)
{
	unsigned char *p = pBuffer;

	while (p < pBuffer + wDataSize)
	{
		EncryptTEA((unsigned int *)p, (unsigned int *)(p + sizeof(unsigned int)));
		p += sizeof(unsigned int) * 2;
	}
}

#define CodecMETA  "netfoxCodec"

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct CMD_Info
{
	unsigned char cbVersion;
	unsigned char cbCheckCode;
	unsigned short wPacketSize;
}
#ifndef WIN32
__attribute__((packed, aligned(1))) CMD_Info;
#else
CMD_Info;
#pragma pack()
#endif

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct CMD_Command
{
	unsigned short							wMainCmdID;
	unsigned short							wSubCmdID;
}
#ifndef WIN32
__attribute__((packed, aligned(1))) CMD_Command;
#else
CMD_Command;
#pragma pack()
#endif

#ifdef WIN32
#pragma pack(1)
#endif
typedef struct  _CMD_Head{
	struct CMD_Info CmdInfo;
	struct CMD_Command CommandInfo;
}
#ifndef WIN32
__attribute__((packed, aligned(1))) CMD_Head;
#else
CMD_Head;
#pragma pack()
#endif

typedef struct _CodecData {
  int _readStep;
  int _currentReadSize;
  int mainID;
  int subID;
  int _needReadTotalSize;
  int _receiveSeqNum;
  char* _readBuffer;
}CodecData;

static inline CodecData** toCodecp(lua_State* L){
    return (CodecData**)luaL_checkudata(L, 1, CodecMETA);
}

CodecData* toCodec(lua_State* L) {
    auto w = toCodecp(L);
    if (*w == NULL)
        luaL_error(L, "Param already closed");
    return *w;
}

void CodecData_reset(CodecData* data) {
  data->_readStep = 0,
  data->_currentReadSize = 0,
  data->mainID = 0,
  data->subID = 0,
  data->_receiveSeqNum = 0;
  data->_needReadTotalSize = sizeof(CMD_Head);
}

void CodecData_init(CodecData* data) {
  CodecData_reset(data);
  data->_readBuffer = (char*)malloc(data->_needReadTotalSize);
}

void CodecData_destroy(CodecData* data) {
  if(data->_readBuffer)
    free(data->_readBuffer);
  data->_readBuffer = NULL;
}

static int _read_head_ok(CodecData* self){
	CMD_Head* header = (CMD_Head*)self->_readBuffer;
	DecryptBuffer((unsigned char*)header, sizeof(CMD_Head));
	//printf("receive main id is %d ,sub id is %d body size is %d,\r\n", header->CommandInfo.wMainCmdID, header->CommandInfo.wSubCmdID, header->CmdInfo.wPacketSize);
	if (header->CmdInfo.cbCheckCode != 0x02 || header->CmdInfo.cbVersion != SOCKET_VER){
		printf("header->CmdInfo.wPacketSize %d \r\n",header->CmdInfo.wPacketSize);
		printf("header->CmdInfo.cbCheckCode %d \r\n",header->CmdInfo.cbCheckCode);
		printf("header->CmdInfo.cbVersion %d \r\n",header->CmdInfo.cbVersion);
		printf("error on DecryptBuffer \r\n");
		return 0;
	}

	self->_needReadTotalSize = header->CmdInfo.wPacketSize - sizeof(CMD_Head);
	self->_receiveSeqNum ++;
	self->_readStep = 1;
	self->_currentReadSize = 0;
	self->mainID = header->CommandInfo.wMainCmdID;
	self->subID = header->CommandInfo.wSubCmdID;

	free(self->_readBuffer);
	self->_readBuffer = (char*)malloc(self->_needReadTotalSize);

	return 1;
}

static void _read_body_ok(CodecData* self,const LuaFunction& onMessage){
	int packageSize = 0;
	char* tmpBuffer = (char*)malloc(self->_needReadTotalSize + 100);
	memcpy(tmpBuffer, self->_readBuffer, self->_needReadTotalSize);
	packageSize = self->_needReadTotalSize;

  const char* package = (const char*)tmpBuffer;
  Data data;
  data.buf = package;
  data.len = packageSize;

	onMessage(data,packageSize,self->mainID,self->subID);
	free(tmpBuffer);

	// read head again
	free(self->_readBuffer);
	self->_readBuffer = (char*)malloc(sizeof(CMD_Head));
	self->_readStep = 0;
	self->_needReadTotalSize = sizeof(CMD_Head);
	self->_currentReadSize = 0;
}

static int netfox_process(lua_State* L){
  CodecData* self = toCodec(L);
  size_t nread;
  const char* buf = lua_tolstring(L,2,&nread);
  LuaFunction onMessage(L,3);
  LuaFunction onError(L,4);

	int end = 0;
	int big = 0;
	int readSize = 0;
	int ok = 0;
	int read_bytes = nread;
	int total_size = 0;
	int headIsOk = 0;
_retry:
	end = self->_currentReadSize + read_bytes;
	big = 0;
	ok = 0;
	if(end >= self->_needReadTotalSize){
		big = end - self->_needReadTotalSize;
		ok = 1;
	}
	readSize = read_bytes - big;
  //printf("total_size is %d\r\n",total_size);
  //printf("self->_currentReadSize is %d\r\n",self->_currentReadSize);
	memcpy(self->_readBuffer + self->_currentReadSize,buf + total_size,readSize);
	total_size += readSize;
	self->_currentReadSize += readSize;

	switch(self->_readStep){
	case 0:
		if(ok){
			headIsOk = _read_head_ok(self);
			if(headIsOk != 1){
				onError();
				return 0;
			}
		}
		break;

	case 1:
		if(ok){
			_read_body_ok(self,onMessage);
		}
		break;
	}

	if(big > 0){
		read_bytes = big;
		goto _retry;
	}

  return 0;
}

static int netfox_createPackage(lua_State* L) {
  size_t size;
  const char* data = lua_tolstring(L,1,&size);
	if(size > 65535)
		printf("the package is to big than unsigned short range");

  char* buffer = (char*)malloc(sizeof(CMD_Head) + size + 100);
  CMD_Head* pHeader = (CMD_Head*)buffer;

  char* write_data = (char*)buffer;
  pHeader->CommandInfo.wMainCmdID = 99;
  pHeader->CommandInfo.wSubCmdID = 99;
  pHeader->CmdInfo.cbVersion = SOCKET_VER;
  pHeader->CmdInfo.wPacketSize = sizeof(CMD_Head) + size;
  pHeader->CmdInfo.cbCheckCode = 0x02;
  EncryptBuffer((unsigned char*)pHeader, sizeof(CMD_Head));

  if (size > 0)
  {
  	memcpy(&write_data[sizeof(CMD_Head)], data, size);
  }

  int wSendSize = sizeof(CMD_Head) + size;
  lua_pushlstring(L,buffer,wSendSize);
  free(buffer);

  return 1;
}

static int Codec_create(lua_State* L)
{
    CodecData** w = (CodecData**)lua_newuserdata(L, sizeof(*w));
    *w = new CodecData();
    CodecData_init(*w);
    luaL_getmetatable(L, CodecMETA);
    lua_setmetatable(L, -2);

    return 1;
}

static int Codec_gc(lua_State* L)
{
    auto w = toCodecp(L);

    printf("finalizing LUA object (%s)\n", CodecMETA);

    if (!*w)
        return 0;

    CodecData_destroy(*w);
    delete *w;
    *w = nullptr; // mark as closed
    return 0;
}

static luaL_Reg methods[] = {
    { "__gc", Codec_gc },
    { NULL, NULL },
};

static luaL_Reg api[] = {
    { "CodecData", Codec_create },
    { "process", netfox_process},
    { "createPackage", netfox_createPackage},
    { NULL, NULL },
};

int luaopen_netfoxpack(lua_State* L)
{
  luaL_newmetatable(L, CodecMETA);
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index");
  luaL_register(L, NULL, methods);
  lua_pop(L, 1);

  // register the net api
  lua_newtable(L);
  luaL_register(L, NULL, api);

  return 1;
}
