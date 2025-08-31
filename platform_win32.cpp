/*
 *  Copyright (C) 2025 UmeSoftware LLC
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <Windows.h>
#include <rpcdce.h>
#include "platform.h"

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

std::string CreateSessionId()
{
	UUID uuid;
	UuidCreateSequential(&uuid);

	RPC_CSTR strUuid;
	if (UuidToStringA(&uuid, &strUuid) != RPC_S_OK)
	{
		return "";
	}

	std::string session_id = reinterpret_cast<const char*>(strUuid);

	RpcStringFreeA(&strUuid);

	return session_id;
}