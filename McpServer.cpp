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

#define NOMINMAX

#include "McpServer.h"
#include "mongoose.h"
#include "platform.h"

#include "jwt-cpp/jwt.h"

typedef void (*mg_timer_handler_t)(void*);
typedef void (*mg_rpc_handler_t)(struct mg_rpc_req*);

static void mg_json_rpc2_vok(struct mg_rpc_req* r, const char* fmt, va_list* ap) {
	int len, off = mg_json_get(r->frame, "$.id", &len);
	if (off > 0) {
		mg_xprintf(r->pfn, r->pfn_data, "event: message\ndata: {\"jsonrpc\":\"2.0\",%m:%.*s,%m:", mg_print_esc, 0, "id", len,
			&r->frame.buf[off], mg_print_esc, 0, "result");
		mg_vxprintf(r->pfn, r->pfn_data, fmt == NULL ? "null" : fmt, ap);
		mg_xprintf(r->pfn, r->pfn_data, "}\n\n");
	}
}

static void mg_json_rpc2_ok(struct mg_rpc_req* r, const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	mg_json_rpc2_vok(r, fmt, &ap);
	va_end(ap);
}

void mg_json_rpc2_verr(struct mg_rpc_req* r, int code, const char* fmt, va_list* ap) {
	int len, off = mg_json_get(r->frame, "$.id", &len);
	mg_xprintf(r->pfn, r->pfn_data, "event: message\ndata: {\"jsonrpc\":\"2.0\",");
	if (off > 0) {
		mg_xprintf(r->pfn, r->pfn_data, "%m:%.*s,", mg_print_esc, 0, "id", len,
			&r->frame.buf[off]);
	}
	mg_xprintf(r->pfn, r->pfn_data, "%m:{%m:%d,%m:", mg_print_esc, 0, "error",
		mg_print_esc, 0, "code", code, mg_print_esc, 0, "message");
	mg_vxprintf(r->pfn, r->pfn_data, fmt == NULL ? "null" : fmt, ap);
	mg_xprintf(r->pfn, r->pfn_data, "}}\n\n");
}

static void mg_json_rpc2_err(struct mg_rpc_req* r, int code, const char* fmt, ...) {
		va_list ap;
	va_start(ap, fmt);
	mg_json_rpc2_verr(r, code, fmt, &ap);
	va_end(ap);
}

McpServer::McpServer(const char* server_name)
	: m_server_name(server_name)
	, m_authorization(false)
	, m_authorization_servers()
	, m_scopes_supported()
	, m_url()
	, m_host()
	, m_entry_point()
	, m_sessions()
	, m_rpc_head(nullptr)
{
}

void McpServer::cbEvHander(void* connection, int event_code, void* event_data)
{
	mg_connection* conn = (mg_connection*)connection;
	McpServer* self = (McpServer*)conn->fn_data;

	if (event_code == MG_EV_ACCEPT)
	{
		struct mg_tls_opts opts = 
		{ 
			.cert = mg_file_read(&mg_fs_posix, "cert.pem"),
			.key = mg_file_read(&mg_fs_posix, "key.pem")
		};
		mg_tls_init(conn, &opts);
	}
	else if (event_code == MG_EV_HTTP_MSG)
	{
		struct mg_http_message* hm = (struct mg_http_message*)event_data;
		if (mg_match(hm->uri, mg_str(self->m_entry_point.data()), NULL)) 
		{
			std::string auth_token = "";
			std::string session_id = "";

			mg_str authorization = mg_str_s("authorization");
			mg_str mcp_session_id = mg_str_s("mcp-session-id");
			for (int i = 0; i < MG_MAX_HTTP_HEADERS; i++)
			{
				if (hm->headers[i].name.buf == nullptr)
				{
					break;
				}
				if (mg_strcasecmp(hm->headers[i].name, authorization) == 0)
				{
					auth_token.assign(hm->headers[i].value.buf, hm->headers[i].value.len);
				}
				else if (mg_strcasecmp(hm->headers[i].name, mcp_session_id) == 0)
				{
					session_id.assign(hm->headers[i].value.buf, hm->headers[i].value.len);
				}
			}

			if (mg_strcasecmp(hm->method, mg_str("DELETE")) == 0)
			{
				mg_http_reply(conn, 200, "", "");
				self->EraseSession(session_id);
				return;
			}
			else if (mg_strcasecmp(hm->method, mg_str("GET")) == 0)
			{
				mg_http_reply(conn, 405, "", "");
				return;
			}
			else if (mg_strcasecmp(hm->method, mg_str("POST")) == 0)
			{
				if (self->m_authorization)
				{
					bool authorization_chk = false;

					if (!auth_token.empty())
					{
						std::string::size_type aPos = auth_token.find_first_of("Bearer ");
						if (aPos != std::string::npos)
						{
							std::string token = auth_token.substr(aPos + 7);
							auto decoded = jwt::decode(token);
							auto payload = decoded.get_payload_json();

							std::string aud_value = payload["aud"].get<std::string>();
							if (aud_value == self->m_url)
							{
								authorization_chk = true;
							}
						}
					}

					if (!authorization_chk)
					{
						std::string authenticate_header = "WWW-Authenticate: Bearer resource_metadata=\"";
						authenticate_header += self->m_host;
						authenticate_header += "/.well-known/oauth-protected-resource";
						authenticate_header += self->m_entry_point;
						authenticate_header += "\"\r\n";
						mg_http_reply(
							conn,
							401,
							authenticate_header.c_str(),
							""
						);
						return;
					}
				}

				char* method = mg_json_get_str(hm->body, "$.method");
				if (method != nullptr)
				{
					if (strcmp(method, "initialize") == 0)
					{
						session_id = CreateSessionId();
					}
					else
					{
						if (!self->IsEnableSessionId(session_id))
						{
							mg_http_reply(conn, 400, "", "");
							return;
						}
					}
					self->m_sessions[session_id] = 1;

					if (strcmp(method, "notifications/initialized") == 0)
					{
						std::string headers = "mcp-session-id: " + session_id + "\r\n";
						mg_http_reply(conn, 202, headers.c_str(), "");
						return;
					}
					else if (strcmp(method, "notifications/cancelled") == 0)
					{
						std::string headers = "mcp-session-id: " + session_id + "\r\n";
						mg_http_reply(conn, 202, headers.c_str(), "");
						return;
					}

					struct mg_rpc* s_rpc_head = (mg_rpc*)self->m_rpc_head;
					struct mg_iobuf io = { 0, 0, 0, 1024 };
					struct mg_rpc_req r = {
					  .head = &s_rpc_head,
					  .rpc = nullptr,
					  .pfn = mg_pfn_iobuf,
					  .pfn_data = &io,
					  .req_data = nullptr,
					  .frame = hm->body,
					};
					mg_rpc_process(&r);
					if (io.buf != NULL)
					{
						std::string headers = "Content-Type: text/event-stream\r\nmcp-session-id: " + session_id + "\r\n";
						mg_http_reply(conn, 200, headers.c_str(), (char*)io.buf);
					}
					else
					{
						mg_http_reply(conn, 500, "", "Internal Server Error");
					}
					mg_iobuf_free(&io);
				}
			}
		}
		else if (self->m_authorization && mg_strcmp(hm->uri, mg_str(("/.well-known/oauth-protected-resource" + self->m_entry_point).c_str())) == 0)
		{
			if (mg_strcasecmp(hm->method, mg_str("GET")) == 0)
			{
				mg_http_reply(
					conn,
					200,
					"Access-Control-Allow-Origin: *\r\nContent-Type: application/json\r\n",
					"{"
					"\"resource\": \"%s\","
					"\"authorization_servers\": [%s],"
					"\"scopes_supported\": [%s],"
					"\"bearer_methods_supported\": [\"header\"]"
					"}",
					self->m_url.c_str(),
					self->m_authorization_servers.c_str(),
					self->m_scopes_supported.c_str()
				);
			}
			else if (mg_strcasecmp(hm->method, mg_str("OPTIONS")) == 0)
			{
				mg_http_reply(
					conn,
					204,
					"Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET\r\nAccess-Control-Allow-Headers: mcp-protocol-version\r\n",
					""
				);
			}
			return;
		}
		else
		{
			mg_http_reply(conn, 405, "", "");
			return;
		}
	}
}

void McpServer::cbTimerHandler(void* timer_data)
{
	McpServer* self = (McpServer*)timer_data;
	self->ClearSession();
}

bool McpServer::IsEnableSessionId(std::string session_id)
{
	return m_sessions.find(session_id) != m_sessions.end();
}

void McpServer::EraseSession(std::string session_id)
{
	auto it = m_sessions.find(session_id);
	if (it != m_sessions.end())
	{
		m_sessions.erase(it);
	}
}

void McpServer::ClearSession()
{
	auto it = m_sessions.begin();
	while (it != m_sessions.end())
	{
		if (it->second > 0)
		{
			it->second--;
			it++;
		}
		else
		{
			it = m_sessions.erase(it);
		}
	}
}

void McpServer::cbInitialize(void* rpc_req)
{
	struct mg_rpc_req* r = (struct mg_rpc_req*)rpc_req;
	McpServer* self = (McpServer*)r->rpc->fn_data;
	mg_json_rpc2_ok(r,
		"{"
			"\"protocolVersion\": \"2025-03-26\","
			"\"capabilities\": {"
				"\"logging\": {},"
				"\"tools\": {}"
			"},"
			"\"serverInfo\": {"
				"\"name\": \"%s\","
				"\"version\" : \"1.0.0.0\""
			"}"
		"}",
		self->m_server_name.c_str()
	);
}

void McpServer::cbLoggingSetLevel(void* rpc_req)
{
	struct mg_rpc_req* r = (struct mg_rpc_req*)rpc_req;
	mg_json_rpc2_ok(r, "{}");
}

void McpServer::cbToolsList(void* rpc_req)
{
	struct mg_rpc_req* r = (struct mg_rpc_req*)rpc_req;
	McpServer* self = (McpServer*)r->rpc->fn_data;

	std::string tools_json = "";
	for (auto it = self->m_tools.begin(); it != self->m_tools.end(); it++)
	{
		McpTool& tool = it->second;

		if (!tools_json.empty()) {
			tools_json += ",";
		}
		tools_json += "{"
			"\"name\": \"" + tool.name + "\","
			"\"description\": \"" + tool.description + "\"";

		if (tool.input_schema.size() > 0)
		{
			tools_json += ",\"inputSchema\": {"
				"\"type\": \"object\","
				"\"properties\": {";

			std::string required_properties = "";

			int i = 0;
			for (auto it = tool.input_schema.begin(); it != tool.input_schema.end(); it++)
			{
				if (i > 0)
				{
					tools_json += ",";
				}
				const auto& prop = it->second;
				tools_json += "\"" + prop.property_name + "\": {"
					"\"type\": \"" + GetPropertyType(prop.property_type) + 
					"\",\"description\": \"" + prop.description + "\"}";

				if (prop.required) 
				{
					if (!required_properties.empty())
					{
						required_properties += ",";
					}
					required_properties += "\"" + prop.property_name + "\"";
				}
				i++;
			}

			tools_json += "}";

			if (!required_properties.empty()) {
				tools_json += ", \"required\": [" + required_properties + "]";
			}

			tools_json += "}";
		}

		if (tool.output_schema.size() > 0)
		{
			tools_json += ",\"outputSchema\": {"
				"\"type\": \"object\","
				"\"properties\": {"
					"\"content\": {"
						"\"type\": \"array\","
						"\"items\": {"
							"\"type\": \"object\","
							"\"properties\": {";

			std::string required_properties = "";

			int i = 0;
			for (auto it = tool.output_schema.begin(); it != tool.output_schema.end(); it++)
			{
				if (i > 0)
				{
					tools_json += ",";
				}
				const auto& prop = it->second;
				tools_json += "\"" + prop.property_name + "\": {"
					"\"type\": \"" + GetPropertyType(prop.property_type) +
					"\",\"description\": \"" + prop.description + "\"}";

				if (prop.required)
				{
					if (!required_properties.empty())
					{
						required_properties += ",";
					}
					required_properties += "\"" + prop.property_name + "\"";
				}
				i++;
			}

			tools_json += "}";

			if (!required_properties.empty())
			{
				tools_json += ", \"required\": [" + required_properties + "]";
			}

			tools_json += "}}},\"required\": [\"content\"]}";
		}

		tools_json += "}";
	}

	mg_json_rpc2_ok(
		r,
		"{\"tools\": [%s]}",
		tools_json.c_str()
	);
}

std::string McpServer::GetPropertyType(PropertyType type)
{
	switch (type) {
	case PROPERTY_NUMBER:
		return "number";
	case PROPERTY_STRING:
		return "string";
	default:
		return "unknown";
	}
}

std::string McpServer::GetPropertyValue(const McpTool& tool, McpPropertyValue value, bool escape)
{
	auto it = tool.output_schema.find(value.property_name);
	if (it == tool.output_schema.end())
	{
		return "";
	}

	switch (it->second.property_type) {
	case PROPERTY_NUMBER:
		return value.value;
	case PROPERTY_STRING:
		if (escape)
		{
			return "\\\"" + value.value + "\\\"";
		}
		else
		{
			return "\"" + value.value + "\"";
		}
	default:
		return "";
	}
}

void McpServer::cbToolsCall(void* rpc_req)
{
	struct mg_rpc_req* r = (struct mg_rpc_req*)rpc_req;
	McpServer* self = (McpServer*)r->rpc->fn_data;

	char* name = mg_json_get_str(
		r->frame, 
		"$.params.name"
	);

	auto it = self->m_tools.find(name);
	if (it == self->m_tools.end())
	{
		mg_json_rpc2_err(r, -32602, "Unknown tool: invalid_tool_name");
		return;
	}

	std::map<std::string, std::string> arguments;

	McpTool& tool = it->second;
	for (auto it2 = tool.input_schema.begin(); it2 != tool.input_schema.end(); it2++)
	{
		const auto& prop = it2->second;
		std::string property_name = "$.params.arguments." + prop.property_name;
		char* value = mg_json_get_str(
			r->frame,
			property_name.c_str()
		);
		arguments[prop.property_name] = value ? value : "";
	}

	std::vector<McpContent> contents = tool.callback(arguments);
	std::string content_json = "";
	std::string structured_content_json = "";

	if (tool.output_schema.size() == 0)
	{
		for (size_t i = 0; i < contents.size(); i++)
		{
			if (i > 0) {
				content_json += ",";
			}
			content_json += "{"
				"\"type\": \"" + GetPropertyType(contents[i].property_type) + "\","
				"\"text\": \"" + contents[i].value + "\""
				"}";
		}

		mg_json_rpc2_ok(
			r,
			"{\"content\": [%s]}",
			content_json.c_str()
		);
	}
	else
	{
		for (size_t i = 0; i < contents.size(); i++)
		{
			if (i > 0) 
			{
				content_json += ",";
				structured_content_json += ",";
			}
			content_json += "{\"type\": \"text\",\"text\": \"{";
			structured_content_json += "{";
			for (size_t j = 0; j < contents[i].properties.size(); j++)
			{
				if (j > 0) 
				{
					content_json += ",";
					structured_content_json += ",";
				}
				content_json += "\\\"" + contents[i].properties[j].property_name + "\\\": " + self->GetPropertyValue(tool, contents[i].properties[j], true);
				structured_content_json += "\"" + contents[i].properties[j].property_name + "\": " + self->GetPropertyValue(tool, contents[i].properties[j], false);
			}
			content_json += "}\"";
			content_json += "}";
			structured_content_json += "}";
		}

		mg_json_rpc2_ok(
			r,
			"{\"content\": [%s], \"structuredContent\": {\"content\": [%s]}}",
			content_json.c_str(),
			structured_content_json.c_str()
		);
	}
}

void McpServer::SetAuthorization(const char* authorization_servers, const char* scopes_supported)
{
	m_authorization_servers = authorization_servers;
	m_scopes_supported = scopes_supported;

	if (!m_authorization_servers.empty() && !m_scopes_supported.empty())
	{
		m_authorization = true;
	}
	else
	{
		m_authorization = false;
	}
}

void McpServer::AddTool(
	const char* tool_name, 
	const char* tool_description, 
	const std::vector<McpProperty>& input_schema,
	const std::vector<McpProperty>& output_schema,
	std::function <std::vector<McpContent>(const std::map<std::string, std::string>& args)> callback
)
{
	McpTool tool;
	tool.name = tool_name;
	tool.description = tool_description;
	for (auto it = input_schema.begin(); it != input_schema.end(); it++)
	{
		tool.input_schema[it->property_name] = *it;
	}
	for (auto it = output_schema.begin(); it != output_schema.end(); it++)
	{
		tool.output_schema[it->property_name] = *it;
	}
	tool.callback = callback;
	m_tools[tool_name] = tool;
}

bool McpServer::Run(const char* url, uint64_t session_timeout)
{
	if (!UpdateUrlPath(url))
	{
		return false;
	}

	struct mg_rpc* s_rpc_head = nullptr;

	struct mg_mgr mgr;
	mg_mgr_init(&mgr);

	struct mg_timer timer;
	mg_timer_init(&mgr.timers, &timer, session_timeout, MG_TIMER_REPEAT, (mg_timer_handler_t)McpServer::cbTimerHandler, this);

	mg_rpc_add(&s_rpc_head, mg_str("initialize"),		(mg_rpc_handler_t)McpServer::cbInitialize,		this);
	mg_rpc_add(&s_rpc_head, mg_str("logging/setLevel"), (mg_rpc_handler_t)McpServer::cbLoggingSetLevel, this);
	mg_rpc_add(&s_rpc_head, mg_str("tools/list"),		(mg_rpc_handler_t)McpServer::cbToolsList,		this);
	mg_rpc_add(&s_rpc_head, mg_str("tools/call"),		(mg_rpc_handler_t)McpServer::cbToolsCall,		this);

	m_rpc_head = s_rpc_head;

	mg_http_listen(
		&mgr, 
		m_host.c_str(),
		(mg_event_handler_t)cbEvHander,
		this
	);

	while (true)
	{
		mg_mgr_poll(&mgr, 1000);
	}

	mg_rpc_del(&s_rpc_head, NULL);
	m_rpc_head = nullptr;

	mg_mgr_free(&mgr);
}

bool McpServer::UpdateUrlPath(const char* url)
{
	m_url = url;

	std::string::size_type scheme_pos = m_url.find("://");
	if (scheme_pos == std::string::npos)
	{
		return false;
	}

	std::string withoutScheme = m_url.substr(scheme_pos + 3);

	std::string::size_type pos = withoutScheme.find('/');
	if (pos == std::string::npos) 
	{
		m_host = m_url;
		m_entry_point = "/";
	}
	else 
	{
		m_host = m_url.substr(0, scheme_pos + 3 + pos);
		m_entry_point = withoutScheme.substr(pos);
	}

	return true;
}
