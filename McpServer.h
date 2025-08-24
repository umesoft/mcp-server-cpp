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

#pragma once

# include <functional>
#include <map>
#include <string>
#include <vector>

class McpServer 
{
public:
	McpServer(const char* server_name);

	enum PropertyType {
		PROPERTY_STRING = 1,
	};
	struct McpProperty {
		std::string property_name;
		PropertyType property_type;
		bool required;
	};
	struct McpContent {
		std::string type;
		std::string text;
	};

	void AddTool(
		const char* tool_name, 
		const char* tool_description, 
		const std::vector<McpProperty>& properties,
		std::function <std::vector<McpContent>(const std::map<std::string, std::string>& args)> callback
		);

	void Run(const char* url, uint64_t session_timeout);

private:
	std::string m_server_name;

	struct McpTool {
		std::string name;
		std::string description;
		std::vector<McpProperty> input_schema;
		std::function <std::vector<McpContent>(const std::map<std::string, std::string>& args)> callback;
	};
	std::map<std::string, McpTool> m_tools;

	static std::string GetPropertyType(PropertyType type);

	std::map<std::string, long> m_sessions;

	bool IsEnableSessionId(std::string session_id);
	void EraseSession(std::string session_id);
	void ClearSession();

	void* m_rpc_head;

	static void cbEvHander(void* connection, int event_code, void* event_data);
	static void cbTimerHandler(void* timer_data);
	static void cbInitialize(void* rpc_req);
	static void cbLoggingSetLevel(void* rpc_req);
	static void cbToolsList(void* rpc_req);
	static void cbToolsCall(void* rpc_req);
};
