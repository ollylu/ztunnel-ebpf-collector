package discovery

import (
	"context"
	"errors"
)

// ResolveCapture verifies the observing process and the server Pod generation.
// daprd is an explicit opt-in for the local, plaintext daprd-to-app connection.
func ResolveCapture(ctx context.Context, root string, pods []Pod, node, namespace, name, source string) (Process, Process, error) {
	var selected []Pod
	for _, p := range pods {
		if p.Namespace == namespace && p.Name == name && p.Node == node {
			selected = append(selected, p)
		}
	}
	if source == "daprd" {
		ps, e := find(ctx, root, selected, node, "daprd")
		if e != nil || len(ps) != 1 {
			return Process{}, Process{}, errors.New("no unique verified daprd in server Pod")
		}
		return ps[0], ps[0], nil
	}
	if source != "ztunnel" {
		return Process{}, Process{}, errors.New("unsupported capture source")
	}
	targets, e := Find(ctx, root, pods, node)
	if e != nil || len(targets) != 1 {
		return Process{}, Process{}, errors.New("no unique verified ztunnel")
	}
	workers, e := FindWorkload(ctx, root, selected, node)
	if e != nil || len(workers) == 0 {
		return Process{}, Process{}, errors.New("no verified local server process")
	}
	// The observer is ztunnel; a workload process only anchors the target
	// Pod's network namespace. Multiple containers/processes are valid when
	// they agree on the Pod generation, address and namespace. Never widen
	// the socket filter to accommodate conflicting identities.
	anchor := workers[0]
	for _, worker := range workers[1:] {
		if worker.Pod.UID != anchor.Pod.UID || worker.Pod.IP != anchor.Pod.IP || worker.NetNS != anchor.NetNS {
			return Process{}, Process{}, errors.New("ambiguous server Pod identity or network namespace")
		}
	}
	return targets[0], anchor, nil
}
