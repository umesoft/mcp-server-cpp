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

#include "McpServer.h"

int main()
{
	McpServer server("MCP Test");

	server.SetAuthorization(
		"\"https://***tenant name***.us.auth0.com\"",
		"\"***api permission***\""
	);

	server.AddTool(
		"get_channels",
		"Returns a list of available TV channels.",
		std::vector<McpServer::McpProperty> {
			{ "location", McpServer::PROPERTY_STRING, "location of TV", true }
		},
		std::vector<McpServer::McpProperty> {
			{ "channel_no", McpServer::PROPERTY_STRING, "channel no", true },
			{ "service_name", McpServer::PROPERTY_STRING, "service name", true }
		},
		[](const std::map<std::string, std::string>& args) -> std::vector<McpServer::McpContent> {
			std::vector<McpServer::McpContent> contents;

			McpServer::McpContent content{
				.property_type = McpServer::PROPERTY_OBJECT,
				.value = ""
			};

			content.properties.push_back({
				.property_name = "channel_no",
				.value = "011"
				});
			content.properties.push_back({
				.property_name = "service_name",
				.value = "NHK G"
				});
			contents.push_back(content);

			content.properties.push_back({
				.property_name = "channel_no",
				.value = "021"
				});
			content.properties.push_back({
				.property_name = "service_name",
				.value = "ETV"
				});
			contents.push_back(content);

			return contents;
		}
	);

	server.Run(
		"https://localhost:8000/mcp",
		10 * 60 * 1000
	);

	return 0;
}
