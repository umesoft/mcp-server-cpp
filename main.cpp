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

	std::vector<McpServer::McpProperty> properties = {
		{"location", McpServer::PROPERTY_STRING, true}
	};
	server.AddTool(
		"get_channels",
		"Returns a list of available TV channels.",
		properties,
		[](const std::map<std::string, std::string>& args) -> std::vector<McpServer::McpContent>{
			std::vector<McpServer::McpContent> contents;
			contents.push_back({
				.type = "text",
				.text = "NHK G"
				});
			contents.push_back({
				.type = "text",
				.text = "ETV"
				});
			return contents;
		}
	);

	server.Run(
		"https://localhost:8000/mcp",
		10 * 60 * 1000
	);

	return 0;
}
