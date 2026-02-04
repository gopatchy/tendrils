package tendrils

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func (t *Tendrils) newMCPServer() *server.SSEServer {
	s := server.NewMCPServer("tendrils", "1.0.0",
		server.WithToolCapabilities(false))

	s.AddTool(
		mcp.NewTool("list_nodes",
			mcp.WithDescription("List all discovered network devices (nodes). Returns node names, types, interfaces, IPs, and MACs.")),
		t.mcpListNodes)

	s.AddTool(
		mcp.NewTool("get_node",
			mcp.WithDescription("Get detailed information about a specific node by name, IP address, or MAC address."),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("Node name, IP address, or MAC address to search for"))),
		t.mcpGetNode)

	s.AddTool(
		mcp.NewTool("list_links",
			mcp.WithDescription("List all discovered network links between devices. Shows which ports connect to which devices.")),
		t.mcpListLinks)

	s.AddTool(
		mcp.NewTool("list_errors",
			mcp.WithDescription("List current network errors including unreachable nodes, port errors, and high utilization warnings.")),
		t.mcpListErrors)

	s.AddTool(
		mcp.NewTool("search_nodes",
			mcp.WithDescription("Search for nodes by partial name, IP, or MAC address match."),
			mcp.WithString("query",
				mcp.Required(),
				mcp.Description("Search query (partial match on name, IP, or MAC)"))),
		t.mcpSearchNodes)

	s.AddTool(
		mcp.NewTool("get_topology",
			mcp.WithDescription("Get a summary of the network topology including node counts by type and connectivity overview.")),
		t.mcpGetTopology)

	return server.NewSSEServer(s,
		server.WithStaticBasePath("/tendrils/mcp"),
		server.WithKeepAlive(true))
}

func (t *Tendrils) mcpListNodes(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	t.nodes.mu.RLock()
	defer t.nodes.mu.RUnlock()

	nodes := t.getNodesLocked()
	if len(nodes) == 0 {
		return mcp.NewToolResultText("No nodes discovered yet."), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Discovered %d nodes:\n\n", len(nodes)))

	for _, node := range nodes {
		name := node.DisplayName()
		if name == "" {
			name = "(unnamed)"
		}
		nodeType := string(node.Type)
		if nodeType == "" {
			nodeType = "unknown"
		}

		if node.IsSelf {
			sb.WriteString(fmt.Sprintf("• %s [%s] ← THIS SERVER\n", name, nodeType))
		} else {
			sb.WriteString(fmt.Sprintf("• %s [%s]\n", name, nodeType))
		}

		for _, iface := range node.Interfaces {
			sb.WriteString(fmt.Sprintf("  - %s", iface.MAC))
			if len(iface.IPs) > 0 {
				sb.WriteString(fmt.Sprintf(" (%s)", strings.Join(iface.IPs.Slice(), ", ")))
			}
			if iface.Name != "" {
				sb.WriteString(fmt.Sprintf(" port:%s", iface.Name))
			}
			sb.WriteString("\n")
		}

		if node.Unreachable {
			sb.WriteString("  ⚠ UNREACHABLE\n")
		}
	}

	return mcp.NewToolResultText(sb.String()), nil
}

func (t *Tendrils) mcpGetNode(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, err := req.RequireString("query")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	t.nodes.mu.RLock()
	defer t.nodes.mu.RUnlock()

	queryLower := strings.ToLower(query)
	nodes := t.getNodesLocked()
	links := t.getLinksLocked()

	for _, node := range nodes {
		if matchesNode(node, queryLower) {
			return mcp.NewToolResultText(formatNodeDetails(node, links)), nil
		}
	}

	return mcp.NewToolResultText(fmt.Sprintf("no node found matching '%s'", query)), nil
}

func matchesNode(node *Node, query string) bool {
	for name := range node.Names {
		if strings.ToLower(name) == query {
			return true
		}
	}
	for _, iface := range node.Interfaces {
		if strings.ToLower(string(iface.MAC)) == query {
			return true
		}
		for ip := range iface.IPs {
			if strings.ToLower(ip) == query {
				return true
			}
		}
	}
	return false
}

func formatNodeDetails(node *Node, links []*Link) string {
	var sb strings.Builder

	name := node.DisplayName()
	if name == "" {
		name = "(unnamed)"
	}
	sb.WriteString(fmt.Sprintf("Node: %s\n", name))
	sb.WriteString(fmt.Sprintf("ID: %s\n", node.ID))
	if node.Type != "" {
		sb.WriteString(fmt.Sprintf("Type: %s\n", node.Type))
	}
	if node.IsSelf {
		sb.WriteString("This Server: YES (tendrils is running here)\n")
	}
	if node.Unreachable {
		sb.WriteString("Status: UNREACHABLE\n")
	}

	sb.WriteString("\nInterfaces:\n")
	for _, iface := range node.Interfaces {
		sb.WriteString(fmt.Sprintf("  • MAC: %s\n", iface.MAC))
		if iface.Name != "" {
			sb.WriteString(fmt.Sprintf("    Port: %s\n", iface.Name))
		}
		if len(iface.IPs) > 0 {
			sb.WriteString(fmt.Sprintf("    IPs: %s\n", strings.Join(iface.IPs.Slice(), ", ")))
		}
		if iface.Stats != nil {
			if iface.Stats.Speed > 0 {
				speed := iface.Stats.Speed
				if speed >= 1000000000 {
					sb.WriteString(fmt.Sprintf("    Speed: %dG\n", speed/1000000000))
				} else if speed >= 1000000 {
					sb.WriteString(fmt.Sprintf("    Speed: %dM\n", speed/1000000))
				}
			}
			if iface.Stats.InErrors > 0 || iface.Stats.OutErrors > 0 {
				sb.WriteString(fmt.Sprintf("    Errors: in=%d out=%d\n", iface.Stats.InErrors, iface.Stats.OutErrors))
			}
		}
	}

	if node.MulticastGroups != nil && len(node.MulticastGroups) > 0 {
		groups := node.MulticastGroups.Groups()
		var groupStrs []string
		for _, g := range groups {
			groupStrs = append(groupStrs, g.String())
		}
		sb.WriteString(fmt.Sprintf("\nMulticast Groups: %s\n", strings.Join(groupStrs, ", ")))
	}
	if node.ArtNetInputs != nil && len(node.ArtNetInputs) > 0 {
		universes := node.ArtNetInputs.Universes()
		var univStrs []string
		for _, u := range universes {
			univStrs = append(univStrs, u.String())
		}
		sb.WriteString(fmt.Sprintf("Art-Net Inputs: %s\n", strings.Join(univStrs, ", ")))
	}
	if node.ArtNetOutputs != nil && len(node.ArtNetOutputs) > 0 {
		universes := node.ArtNetOutputs.Universes()
		var univStrs []string
		for _, u := range universes {
			univStrs = append(univStrs, u.String())
		}
		sb.WriteString(fmt.Sprintf("Art-Net Outputs: %s\n", strings.Join(univStrs, ", ")))
	}

	var connectionCount int
	for _, link := range links {
		if link.NodeA.ID == node.ID || link.NodeB.ID == node.ID {
			connectionCount++
		}
	}
	if connectionCount > 0 {
		sb.WriteString(fmt.Sprintf("\nConnections: %d links\n", connectionCount))
	}

	return sb.String()
}

func (t *Tendrils) mcpListLinks(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	t.nodes.mu.RLock()
	defer t.nodes.mu.RUnlock()

	links := t.getLinksLocked()
	if len(links) == 0 {
		return mcp.NewToolResultText("No links discovered yet."), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Discovered %d links:\n\n", len(links)))

	for _, link := range links {
		sb.WriteString(fmt.Sprintf("• %s\n", link.String()))
	}

	return mcp.NewToolResultText(sb.String()), nil
}

func (t *Tendrils) mcpListErrors(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	errors := t.errors.GetErrors()
	if len(errors) == 0 {
		return mcp.NewToolResultText("No errors currently reported."), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Current errors (%d):\n\n", len(errors)))

	for _, e := range errors {
		sb.WriteString(fmt.Sprintf("• [%s] %s", e.Type, e.NodeName))
		if e.Port != "" {
			sb.WriteString(fmt.Sprintf(" port %s", e.Port))
		}
		if e.InErrors > 0 || e.OutErrors > 0 {
			sb.WriteString(fmt.Sprintf(" (in=%d out=%d)", e.InErrors, e.OutErrors))
		}
		if e.Utilization > 0 {
			sb.WriteString(fmt.Sprintf(" (%.0f%% utilization)", e.Utilization))
		}
		sb.WriteString("\n")
	}

	return mcp.NewToolResultText(sb.String()), nil
}

func (t *Tendrils) mcpSearchNodes(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, err := req.RequireString("query")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	t.nodes.mu.RLock()
	defer t.nodes.mu.RUnlock()

	queryLower := strings.ToLower(query)
	nodes := t.getNodesLocked()
	var matches []*Node

	for _, node := range nodes {
		if nodeContains(node, queryLower) {
			matches = append(matches, node)
		}
	}

	if len(matches) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("no nodes found matching '%s'", query)), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d nodes matching '%s':\n\n", len(matches), query))

	for _, node := range matches {
		name := node.DisplayName()
		if name == "" {
			name = "(unnamed)"
		}
		nodeType := string(node.Type)
		if nodeType == "" {
			nodeType = "unknown"
		}

		if node.IsSelf {
			sb.WriteString(fmt.Sprintf("• %s [%s] ← THIS SERVER\n", name, nodeType))
		} else {
			sb.WriteString(fmt.Sprintf("• %s [%s]\n", name, nodeType))
		}
		for _, iface := range node.Interfaces {
			sb.WriteString(fmt.Sprintf("  - %s", iface.MAC))
			if len(iface.IPs) > 0 {
				sb.WriteString(fmt.Sprintf(" (%s)", strings.Join(iface.IPs.Slice(), ", ")))
			}
			sb.WriteString("\n")
		}
	}

	return mcp.NewToolResultText(sb.String()), nil
}

func nodeContains(node *Node, query string) bool {
	for name := range node.Names {
		if strings.Contains(strings.ToLower(name), query) {
			return true
		}
	}
	for _, iface := range node.Interfaces {
		if strings.Contains(strings.ToLower(string(iface.MAC)), query) {
			return true
		}
		for ip := range iface.IPs {
			if strings.Contains(ip, query) {
				return true
			}
		}
	}
	return false
}

func (t *Tendrils) mcpGetTopology(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	t.nodes.mu.RLock()
	defer t.nodes.mu.RUnlock()

	nodes := t.getNodesLocked()
	links := t.getLinksLocked()
	errors := t.errors.GetErrors()

	typeCounts := map[string]int{}
	var unreachable int
	var selfNode *Node
	for _, node := range nodes {
		nodeType := string(node.Type)
		if nodeType == "" {
			nodeType = "unknown"
		}
		typeCounts[nodeType]++
		if node.Unreachable {
			unreachable++
		}
		if node.IsSelf {
			selfNode = node
		}
	}

	var sb strings.Builder
	sb.WriteString("Network Topology Summary\n")
	sb.WriteString("========================\n\n")
	if selfNode != nil {
		sb.WriteString(fmt.Sprintf("This server: %s\n", selfNode.DisplayName()))
	}
	sb.WriteString(fmt.Sprintf("Total nodes: %d\n", len(nodes)))
	sb.WriteString(fmt.Sprintf("Total links: %d\n", len(links)))
	sb.WriteString(fmt.Sprintf("Active errors: %d\n", len(errors)))
	if unreachable > 0 {
		sb.WriteString(fmt.Sprintf("Unreachable nodes: %d\n", unreachable))
	}

	sb.WriteString("\nNodes by type:\n")
	for nodeType, count := range typeCounts {
		sb.WriteString(fmt.Sprintf("  • %s: %d\n", nodeType, count))
	}

	return mcp.NewToolResultText(sb.String()), nil
}
