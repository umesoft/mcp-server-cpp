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

#include <functional>
#include <map>
#include <string>
#include <vector>

class McpServer 
{
public:
	McpServer(const char* server_name);

	enum PropertyType {
		PROPERTY_NUMBER = 1,
		PROPERTY_STRING,
		PROPERTY_OBJECT
	};
	struct McpProperty {
		std::string property_name;
		PropertyType property_type;
		std::string description;
		bool required;
	};
	struct McpPropertyValue {
		std::string property_name;
		std::string value;
	};
	struct McpContent {
		PropertyType property_type;
		std::string value;
		std::vector<McpPropertyValue> properties;
	};

	void SetAuthorization(
		const char* authorization_servers,
		const char* scopes_supported
	);

	void AddTool(
		const char* tool_name, 
		const char* tool_description, 
		const std::vector<McpProperty>& input_schema,
		const std::vector<McpProperty>& output_schema,
		std::function <std::vector<McpContent>(const std::map<std::string, std::string>& args)> callback
		);

	bool Run(const char* url, uint64_t session_timeout);

private:
	std::string m_server_name;
	bool m_authorization;
	std::string m_authorization_servers;
	std::string m_scopes_supported;
	std::string m_url;
	std::string m_host;
	std::string m_entry_point;

	bool UpdateUrlPath(const char* url);

	struct McpTool {
		std::string name;
		std::string description;
		std::map<std::string, McpProperty> input_schema;
		std::map<std::string, McpProperty> output_schema;
		std::function <std::vector<McpContent>(const std::map<std::string, std::string>& args)> callback;
	};
	std::map<std::string, McpTool> m_tools;

	static std::string GetPropertyType(PropertyType type);
	static std::string GetPropertyValue(const McpTool& tool, McpPropertyValue type, bool escape);

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
