#pragma once
#ifndef __LUA_NETFOXPACK_HPP__
#define __LUA_NETFOXPACK_HPP__

#if __cplusplus
extern "C" {
#endif

#include "lua.h"
#include "lauxlib.h"

int luaopen_netfoxpack(lua_State* L);

#if __cplusplus
}
#endif

#endif
