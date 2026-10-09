// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The anchor handle, and why its absence was invisible for weeks.
//
// A cluster WITH upstream children is never an edge endpoint:
// _layout.ts draws one edge per upstream, each landing on the child's
// own handle. With zero children — a redirect destination, or a route
// whose pool is empty — the edge lands on the parent. Svelte Flow
// anchors an edge on a handle; with none it draws NOTHING, and logs
// nothing either.
//
// So every redirect destination since v2.61 sat on the canvas with no
// visible connection to the host pointing at it. The operator reported
// it three times, once as "rien vers les noeuds a droite" while the
// Caddy hub was still in place — which should have told me the EDGE
// was the problem and not the hub. Two releases went into the hub and
// the edge's opacity before I looked at the handle.

import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/svelte";
import type { BackendClusterNodeData } from "../../_types";

vi.mock("@xyflow/svelte", async () => {
  const actual =
    await vi.importActual<typeof import("@xyflow/svelte")>("@xyflow/svelte");
  const HandleProbe = (await import("./HandleProbe.test.svelte")).default;
  return { ...actual, Handle: HandleProbe };
});

const BackendClusterNode = (await import("./BackendClusterNode.svelte"))
  .default;

function data(
  over: Partial<BackendClusterNodeData> = {},
): BackendClusterNodeData {
  return {
    kind: "backend-cluster",
    clusterLabel: "dest",
    lbPolicy: "round_robin",
    healthyCount: 0,
    unhealthyCount: 0,
    totalCount: 0,
    hasHealthCheck: false,
    ...over,
  } as BackendClusterNodeData;
}

/** The full NodeProps surface SvelteFlow hands a custom node. Same
 *  shape as FQDNNode.test.ts's helper — the component reads only
 *  `data`, and the rest exists so the call typechecks. */
function nodeProps(d: BackendClusterNodeData): any {
  return {
    id: "redirect-to-x",
    type: "backend-cluster",
    data: d,
    dragging: false,
    selected: false,
    isConnectable: false,
    positionAbsoluteX: 0,
    positionAbsoluteY: 0,
    width: 260,
    height: 68,
    zIndex: 0,
  };
}

describe("BackendClusterNode — the edge anchor", () => {
  it("renders a target handle when it has no upstream children", () => {
    // THE fix. Without this the redirect edge has nowhere to land
    // and Svelte Flow draws no line, which is what the operator saw.
    render(BackendClusterNode, {
      props: nodeProps(
        data({
          redirectTarget: "https://example.com",
          redirectSourceHosts: ["a.test"],
        }),
      ),
    });
    const handle = screen.getByTestId("flow-handle");
    expect(handle.getAttribute("data-handle-type")).toBe("target");
  });

  it("renders it on the left, where the edge arrives from", () => {
    render(BackendClusterNode, {
      props: nodeProps(data({ redirectTarget: "https://example.com" })),
    });
    expect(
      screen.getByTestId("flow-handle").getAttribute("data-handle-position"),
    ).toBe("left");
  });

  it("also anchors a proxy route whose pool is empty", () => {
    // Same geometry, different cause: _layout.ts emits the single
    // fallback edge to the parent so the operator can see the route
    // exists at all, with its empty-pool warning.
    render(BackendClusterNode, {
      props: nodeProps(data({ warning: "No upstream configured" })),
    });
    expect(screen.getByTestId("flow-handle")).toBeInTheDocument();
  });

  it("renders NO handle when the cluster has children", () => {
    // The control, and the reason Critique 6 removed the handle in
    // the first place: an always-present one implies "connect here"
    // on every cluster while the edges land on the children.
    render(BackendClusterNode, {
      props: nodeProps(data({ totalCount: 3, healthyCount: 3 })),
    });
    expect(screen.queryByTestId("flow-handle")).not.toBeInTheDocument();
  });

  it("keeps the destination legible beside the anchor", () => {
    // The anchor is geometry, not content: adding it must not
    // disturb what the node says.
    render(BackendClusterNode, {
      props: nodeProps(
        data({
          redirectTarget: "https://discord.gg/abc",
          redirectSourceHosts: ["join.test", "chat.test"],
        }),
      ),
    });
    expect(screen.getByTestId("cluster-redirect-target").textContent).toContain(
      "https://discord.gg/abc",
    );
    expect(
      screen.getByTestId("cluster-redirect-sources").textContent,
    ).toContain("join.test");
  });
});
