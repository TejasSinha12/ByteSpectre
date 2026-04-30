import { Share2 } from 'lucide-react';
import type { ClassRelationship, MethodCallEdge } from '../lib/types';

interface RelationshipGraphProps {
  relationships: ClassRelationship[];
  methodCallEdges: MethodCallEdge[];
}

interface GraphNode {
  id: string;
  label: string;
  x: number;
  y: number;
  kind: 'class' | 'target';
}

export function RelationshipGraph({ relationships, methodCallEdges }: RelationshipGraphProps) {
  const graph = buildGraph(relationships, methodCallEdges);

  return (
    <section className="panel relationship-graph">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Interactive graph surface</p>
          <h3>Bytecode Relationship Map</h3>
        </div>
        <Share2 size={20} />
      </div>
      {graph.nodes.length === 0 ? (
        <div className="empty-state">No relationship edges available yet. Analyze a JAR with classes to populate the graph.</div>
      ) : (
        <svg viewBox="0 0 900 420" role="img" aria-label="Bytecode relationship map">
          {graph.edges.map((edge) => (
            <line key={`${edge.source}-${edge.target}-${edge.index}`} x1={edge.source.x} y1={edge.source.y} x2={edge.target.x} y2={edge.target.y} />
          ))}
          {graph.nodes.map((node) => (
            <g key={node.id} transform={`translate(${node.x} ${node.y})`}>
              <circle r={node.kind === 'target' ? 18 : 22} />
              <text y={42}>{node.label}</text>
            </g>
          ))}
        </svg>
      )}
    </section>
  );
}

function buildGraph(relationships: ClassRelationship[], calls: MethodCallEdge[]) {
  const edgePairs = [
    ...relationships.slice(0, 10).map((edge) => [edge.source, edge.target] as const),
    ...calls.slice(0, 12).map((edge) => [edge.sourceClass, edge.targetOwner] as const)
  ];
  const ids = Array.from(new Set(edgePairs.flat())).slice(0, 18);
  const centerX = 450;
  const centerY = 205;
  const radiusX = 330;
  const radiusY = 142;
  const nodes: GraphNode[] = ids.map((id, index) => {
    const angle = (Math.PI * 2 * index) / Math.max(1, ids.length);
    return {
      id,
      label: simpleName(id),
      x: centerX + Math.cos(angle) * radiusX,
      y: centerY + Math.sin(angle) * radiusY,
      kind: calls.some((edge) => edge.targetOwner === id) ? 'target' : 'class'
    };
  });
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const edges = edgePairs
    .map(([source, target], index) => {
      const sourceNode = nodeMap.get(source);
      const targetNode = nodeMap.get(target);
      return sourceNode && targetNode ? { source: sourceNode, target: targetNode, index } : null;
    })
    .filter((edge): edge is { source: GraphNode; target: GraphNode; index: number } => edge !== null)
    .slice(0, 22);
  return { nodes, edges };
}

function simpleName(value: string) {
  const parts = value.split('.');
  return parts[parts.length - 1] || value;
}

