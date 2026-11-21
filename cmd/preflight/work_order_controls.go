package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// validateWorkOrderProfile checks a work order's build profile against the
// lane conventions in lane_profiles.go.
func validateWorkOrderProfile(platform, lane, name string) error {
	if _, err := resolveLaneProfile(name, platform, lane); err != nil {
		return err
	}
	return nil
}

// Cancel the workflow first: the legacy work-order endpoint changes only the
// order and resource leases. Returning success before the workflow is durably
// cancelled would leave its jobs running behind a cancelled queue row.
func runCancelWorkOrder(args []string, stdout, stderr io.Writer, client *http.Client) int {
	id := ""
	jsonOut := false
	for _, arg := range args {
		switch arg {
		case "--help", "-h":
			printCancelWorkOrderHelp(stdout)
			return 0
		case "--json":
			jsonOut = true
		default:
			if id != "" || !strings.HasPrefix(arg, "pfwo_") || strings.ContainsAny(arg, "/?# \\%") {
				fmt.Fprintln(stderr, "cancel requires one work-order id (pfwo_...)")
				return 2
			}
			id = arg
		}
	}
	if id == "" {
		printCancelWorkOrderHelp(stderr)
		return 2
	}
	ctx := newBuildOpsContext()
	if !ctx.requireWorkspace(stderr) {
		return 2
	}
	endpoint := ctx.endpoint("/work-orders/"+url.PathEscape(id), nil)
	raw, err := getPreflightWorkspaceJSON(client, endpoint, ctx.token, ctx.workspaceID)
	if err != nil {
		fmt.Fprintf(stderr, "read work order: %v\n", err)
		return 1
	}
	var response struct {
		WorkOrder *workOrder `json:"workOrder"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		fmt.Fprintf(stderr, "decode work order: %v\n", err)
		return 1
	}
	order := response.WorkOrder
	if order == nil || order.ID != id || order.WorkspaceID != ctx.workspaceID {
		fmt.Fprintln(stderr, "work order not found in the configured workspace")
		return 1
	}
	if order.Status == "succeeded" || order.Status == "failed" {
		fmt.Fprintf(stderr, "work order %s is already %s; cancellation would overwrite its outcome\n", id, order.Status)
		return 1
	}
	if order.ActiveWorkflowID != "" {
		workflowEndpoint := ctx.endpoint("/workflows/"+url.PathEscape(order.ActiveWorkflowID)+"/cancel", nil)
		raw, err = postPreflightWorkspaceJSON(client, workflowEndpoint, ctx.token, ctx.workspaceID, map[string]string{
			"workspaceId": ctx.workspaceID,
			"reason":      "work order cancelled via CLI",
		})
		if err != nil {
			fmt.Fprintf(stderr, "cancel active workflow: %v; work-order status was not changed\n", err)
			return 1
		}
		var workflow struct {
			Projection *proveAppWorkflowProjection `json:"workflowProjection"`
		}
		if err := json.Unmarshal(raw, &workflow); err != nil || workflow.Projection == nil || workflow.Projection.WorkflowID != order.ActiveWorkflowID || workflow.Projection.Status != "cancelled" {
			fmt.Fprintln(stderr, "active workflow did not confirm cancellation; work-order status was not changed")
			return 1
		}
	}
	raw, err = postPreflightWorkspaceJSON(client, endpoint+"/cancel", ctx.token, ctx.workspaceID, map[string]string{"workspaceId": ctx.workspaceID})
	if err != nil {
		fmt.Fprintf(stderr, "cancel work order: %v; retry this command to finish recording cancellation\n", err)
		return 1
	}
	response.WorkOrder = nil
	if err := json.Unmarshal(raw, &response); err != nil || response.WorkOrder == nil || response.WorkOrder.ID != id || response.WorkOrder.WorkspaceID != ctx.workspaceID || response.WorkOrder.Status != "cancelled" {
		fmt.Fprintln(stderr, "work-order cancellation was not confirmed; inspect the queue before retrying")
		return 1
	}
	if jsonOut {
		return writeJSON(stdout, response)
	}
	fmt.Fprintf(stdout, "Cancelled work order %s\n", id)
	return 0
}

func printCancelWorkOrderHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: preflight cancel <work-order-id> [--json]")
	fmt.Fprintln(w, "Cancel the selected order's active workflow, then record work-order cancellation.")
	fmt.Fprintln(w, "Use the configured workspace; completed successful/failed orders are preserved.")
}
