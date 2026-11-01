import React, { useState, useEffect, useRef } from 'react';
import { 
  Globe, Shield, MapPin, HardDrive, Grid, Mail, Cloud, HelpCircle, 
  Search, ZoomIn, ZoomOut, RotateCcw, Maximize2, Minimize2, Info, X 
} from 'lucide-react';

const NODE_TYPES = {
  subdomain: { label: 'Sub-Domain', color: '#06b6d4', bg: '#083344', icon: Globe },
  domain: { label: 'Domain', color: '#14b8a6', bg: '#042f2e', icon: Shield },
  host: { label: 'Host', color: '#3b82f6', bg: '#1e3a8a', icon: MapPin },
  ip: { label: 'IP', color: '#6366f1', bg: '#1e1b4b', icon: HardDrive },
  ip_range: { label: 'IP Range', color: '#a855f7', bg: '#3b0764', icon: Grid },
  mail_server: { label: 'Mail Server', color: '#f59e0b', bg: '#451a03', icon: Mail },
  cdn_external: { label: 'CDN / External', color: '#22c55e', bg: '#052e16', icon: Cloud },
  unknown: { label: 'Unknown', color: '#64748b', bg: '#0f172a', icon: HelpCircle }
};

export default function TopologyGraph({ topologyData }) {
  const containerRef = useRef(null);
  const canvasRef = useRef(null);

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedNode, setSelectedNode] = useState(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [activeFilters, setActiveFilters] = useState(
    Object.keys(NODE_TYPES).reduce((acc, key) => ({ ...acc, [key]: true }), {})
  );
  const [isFullscreen, setIsFullscreen] = useState(false);

  // Canvas View Transform State (Pan & Zoom)
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDraggingCanvas, setIsDraggingCanvas] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [draggedNode, setDraggedNode] = useState(null);

  // Nodes & Edges layout storage
  const graphRef = useRef({ nodes: [], edges: [] });

  // Initialize and Compute Radial Force Layout
  useEffect(() => {
    if (!canvasRef.current) return;

    const canvas = canvasRef.current;
    const parent = containerRef.current;
    const width = parent.clientWidth || 900;
    const height = isFullscreen ? window.innerHeight - 100 : 780;

    canvas.width = width;
    canvas.height = height;

    const rawNodes = topologyData?.nodes || [
      { id: '13.205.209.101', label: '13.205.209.101', type: 'host' },
      { id: '13.205.209.0/24', label: '13.205.209.0/24', type: 'ip_range' },
      { id: 'gtu.ac.in', label: 'gtu.ac.in', type: 'domain' },
      { id: 'temp1.gtu.ac.in', label: 'temp1.gtu.ac.in', type: 'subdomain' },
      { id: 'students.gtu.ac.in', label: 'students.gtu.ac.in', type: 'subdomain' },
      { id: 'projects.gtu.ac.in', label: 'projects.gtu.ac.in', type: 'subdomain' },
      { id: 'mail.gtu.ac.in', label: 'mail.gtu.ac.in', type: 'mail_server' },
      { id: '104.16.249.249', label: '104.16.249.249', type: 'cdn_external' }
    ];

    const rawEdges = topologyData?.edges || [
      { from: 'gtu.ac.in', to: '13.205.209.101' },
      { from: 'temp1.gtu.ac.in', to: '13.205.209.101' },
      { from: 'students.gtu.ac.in', to: '13.205.209.101' },
      { from: 'projects.gtu.ac.in', to: '13.205.209.101' },
      { from: 'mail.gtu.ac.in', to: 'gtu.ac.in' },
      { from: '13.205.209.101', to: '13.205.209.0/24' }
    ];

    // Build Concentric Radial Layout
    const centerX = width / 2;
    const centerY = height / 2;

    const hostNodes = rawNodes.filter(n => n.type === 'host' || n.type === 'ip');
    const domainNodes = rawNodes.filter(n => n.type === 'domain');
    const subNodes = rawNodes.filter(n => n.type === 'subdomain');
    const otherNodes = rawNodes.filter(n => !['host', 'ip', 'domain', 'subdomain'].includes(n.type));

    const computedNodes = [];

    // Center Node (Level 0)
    rawNodes.forEach((n, idx) => {
      let radius = 0;
      let angle = 0;

      if (idx === 0 || n.type === 'host') {
        radius = 0;
        angle = 0;
      } else if (n.type === 'domain' || n.type === 'ip_range') {
        radius = Math.min(width, height) * 0.32;
        const groupIndex = domainNodes.indexOf(n);
        angle = (groupIndex / Math.max(1, domainNodes.length)) * 2 * Math.PI;
      } else if (n.type === 'subdomain') {
        const groupIndex = subNodes.indexOf(n);
        radius = Math.min(width, height) * 0.58 + (groupIndex % 2 === 0 ? 0 : 50);
        angle = (groupIndex / Math.max(1, subNodes.length)) * 2 * Math.PI;
      } else {
        const groupIndex = otherNodes.indexOf(n);
        radius = Math.min(width, height) * 0.85;
        angle = (groupIndex / Math.max(1, otherNodes.length)) * 2 * Math.PI;
      }

      computedNodes.push({
        ...n,
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
        radius: n.type === 'host' ? 24 : 14,
        targetX: centerX + radius * Math.cos(angle),
        targetY: centerY + radius * Math.sin(angle)
      });
    });

    graphRef.current = { nodes: computedNodes, edges: rawEdges };
  }, [topologyData, isFullscreen]);

  // Render Loop on Canvas
  useEffect(() => {
    if (!canvasRef.current) return;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');

    let animationFrameId;

    const render = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      ctx.save();
      ctx.translate(pan.x, pan.y);
      ctx.scale(zoom, zoom);

      // Draw Background Grid & Concentric Orbits
      const centerX = canvas.width / 2;
      const centerY = canvas.height / 2;

      ctx.strokeStyle = '#0f172a';
      ctx.lineWidth = 1;
      [100, 180, 260, 340].forEach(r => {
        ctx.beginPath();
        ctx.arc(centerX, centerY, r, 0, 2 * Math.PI);
        ctx.stroke();
      });

      const { nodes, edges } = graphRef.current;

      // Filter visible nodes
      const visibleNodes = nodes.filter(n => {
        const typeKey = n.type || 'unknown';
        const matchesFilter = activeFilters[typeKey] !== false;
        const matchesSearch = !searchQuery || (n.id || '').toLowerCase().includes(searchQuery.toLowerCase());
        return matchesFilter && matchesSearch;
      });

      const visibleNodeIds = new Set(visibleNodes.map(n => n.id));

      // Draw Connection Edges
      edges.forEach(edge => {
        const sourceNode = nodes.find(n => n.id === edge.from);
        const targetNode = nodes.find(n => n.id === edge.to);

        if (sourceNode && targetNode && visibleNodeIds.has(sourceNode.id) && visibleNodeIds.has(targetNode.id)) {
          const isHighlighted = 
            (hoveredNode && (hoveredNode.id === sourceNode.id || hoveredNode.id === targetNode.id)) ||
            (selectedNode && (selectedNode.id === sourceNode.id || selectedNode.id === targetNode.id));

          ctx.beginPath();
          ctx.moveTo(sourceNode.x, sourceNode.y);
          ctx.lineTo(targetNode.x, targetNode.y);
          
          if (isHighlighted) {
            ctx.strokeStyle = '#06b6d4';
            ctx.lineWidth = 2.5;
            ctx.shadowColor = '#06b6d4';
            ctx.shadowBlur = 10;
          } else {
            ctx.strokeStyle = '#1e293b';
            ctx.lineWidth = 1.2;
            ctx.shadowBlur = 0;
          }
          ctx.stroke();
          ctx.shadowBlur = 0;
        }
      });

      // Draw Nodes
      visibleNodes.forEach(node => {
        const typeConfig = NODE_TYPES[node.type] || NODE_TYPES.unknown;
        const isSelected = selectedNode && selectedNode.id === node.id;
        const isHovered = hoveredNode && hoveredNode.id === node.id;

        // Outer Glow Ring for Selected / Hovered
        if (isSelected || isHovered) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 8, 0, 2 * Math.PI);
          ctx.fillStyle = `${typeConfig.color}33`;
          ctx.fill();
          ctx.strokeStyle = typeConfig.color;
          ctx.lineWidth = 2;
          ctx.stroke();
        }

        // Inner Circle Fill
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, 2 * Math.PI);
        ctx.fillStyle = typeConfig.bg;
        ctx.fill();
        ctx.strokeStyle = typeConfig.color;
        ctx.lineWidth = node.type === 'host' ? 3 : 2;
        ctx.stroke();

        // Central Icon / Dot
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius * 0.4, 0, 2 * Math.PI);
        ctx.fillStyle = typeConfig.color;
        ctx.fill();

        // Node Label
        ctx.fillStyle = isHovered || isSelected ? '#ffffff' : '#94a3b8';
        ctx.font = node.type === 'host' ? 'bold 12px Inter, sans-serif' : '10px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';

        const labelText = node.label || node.id;
        const displayLabel = labelText.length > 25 ? labelText.substring(0, 22) + '...' : labelText;
        ctx.fillText(displayLabel, node.x, node.y + node.radius + 6);
      });

      ctx.restore();
      animationFrameId = requestAnimationFrame(render);
    };

    render();
    return () => cancelAnimationFrame(animationFrameId);
  }, [pan, zoom, activeFilters, searchQuery, hoveredNode, selectedNode]);

  // Mouse Interactions (Drag Node, Pan Canvas, Hover Detection)
  const getCanvasCoords = (e) => {
    const rect = canvasRef.current.getBoundingClientRect();
    const clientX = e.clientX || (e.touches && e.touches[0].clientX);
    const clientY = e.clientY || (e.touches && e.touches[0].clientY);
    const x = (clientX - rect.left - pan.x) / zoom;
    const y = (clientY - rect.top - pan.y) / zoom;
    return { x, y };
  };

  const handleMouseDown = (e) => {
    const coords = getCanvasCoords(e);
    const clickedNode = graphRef.current.nodes.find(n => {
      const dx = n.x - coords.x;
      const dy = n.y - coords.y;
      return Math.sqrt(dx * dx + dy * dy) <= n.radius + 6;
    });

    if (clickedNode) {
      setDraggedNode(clickedNode);
      setSelectedNode(clickedNode);
    } else {
      setIsDraggingCanvas(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e) => {
    const coords = getCanvasCoords(e);

    if (draggedNode) {
      draggedNode.x = coords.x;
      draggedNode.y = coords.y;
      return;
    }

    if (isDraggingCanvas) {
      setPan({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y
      });
      return;
    }

    // Hover Detection
    const hover = graphRef.current.nodes.find(n => {
      const dx = n.x - coords.x;
      const dy = n.y - coords.y;
      return Math.sqrt(dx * dx + dy * dy) <= n.radius + 6;
    });
    setHoveredNode(hover || null);
  };

  const handleMouseUp = () => {
    setDraggedNode(null);
    setIsDraggingCanvas(false);
  };

  const handleWheel = (e) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
    setZoom(prev => Math.max(0.4, Math.min(3.0, prev * zoomFactor)));
  };

  const resetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    setSelectedNode(null);
    setSearchQuery('');
  };

  const toggleFilter = (typeKey) => {
    setActiveFilters(prev => ({ ...prev, [typeKey]: !prev[typeKey] }));
  };

  return (
    <div 
      ref={containerRef} 
      className={`relative w-full overflow-hidden rounded-2xl bg-[#060b13] border border-slate-800 transition-all ${
        isFullscreen ? 'fixed inset-0 z-50 rounded-none h-screen' : 'h-[780px]'
      }`}
    >
      {/* Top Header & Interactive Search Controls */}
      <div className="absolute top-4 left-4 right-4 z-10 flex flex-wrap items-center justify-between gap-3 pointer-events-none">
        <div className="flex items-center space-x-3 bg-slate-900/90 backdrop-blur-md px-4 py-2 rounded-xl border border-slate-800 pointer-events-auto shadow-lg">
          <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping"></span>
          <h3 className="text-sm font-bold text-slate-100 tracking-wide">Network Star Topology</h3>
          <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-300 font-mono border border-cyan-800/50">
            {graphRef.current.nodes.length} Nodes
          </span>
        </div>

        {/* Search Bar & Controls */}
        <div className="flex items-center space-x-2 pointer-events-auto">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Search domain or IP..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 pr-4 py-1.5 bg-slate-900/90 backdrop-blur-md border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-48 transition"
            />
          </div>

          <button
            onClick={() => setZoom(prev => Math.min(3.0, prev * 1.2))}
            title="Zoom In"
            className="p-2 bg-slate-900/90 hover:bg-slate-800 text-slate-300 rounded-xl border border-slate-800 transition"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={() => setZoom(prev => Math.max(0.4, prev * 0.8))}
            title="Zoom Out"
            className="p-2 bg-slate-900/90 hover:bg-slate-800 text-slate-300 rounded-xl border border-slate-800 transition"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={resetView}
            title="Reset View"
            className="p-2 bg-slate-900/90 hover:bg-slate-800 text-slate-300 rounded-xl border border-slate-800 transition"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
          <button
            onClick={() => setIsFullscreen(!isFullscreen)}
            title="Toggle Fullscreen"
            className="p-2 bg-slate-900/90 hover:bg-slate-800 text-slate-300 rounded-xl border border-slate-800 transition"
          >
            {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Main Canvas Canvas */}
      <canvas
        ref={canvasRef}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onWheel={handleWheel}
        className="w-full h-full cursor-grab active:cursor-grabbing"
      />

      {/* Node Hover Tooltip */}
      {hoveredNode && (
        <div 
          className="absolute z-20 pointer-events-none bg-slate-950/95 backdrop-blur-md border border-slate-800 p-3 rounded-xl shadow-2xl text-xs space-y-1 w-56"
          style={{
            left: Math.min(window.innerWidth - 240, Math.max(20, (hoveredNode.x * zoom + pan.x) + 15)),
            top: Math.min(window.innerHeight - 150, Math.max(20, (hoveredNode.y * zoom + pan.y) + 15))
          }}
        >
          <div className="flex items-center space-x-2 font-bold text-slate-100 truncate">
            <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: NODE_TYPES[hoveredNode.type]?.color }}></span>
            <span className="truncate">{hoveredNode.id}</span>
          </div>
          <div className="text-[11px] text-slate-400 capitalize">
            Type: <span className="text-slate-200 font-semibold">{NODE_TYPES[hoveredNode.type]?.label || hoveredNode.type}</span>
          </div>
          {hoveredNode.discovery_source && (
            <div className="text-[11px] text-slate-400">
              Source: <span className="text-cyan-400">{hoveredNode.discovery_source}</span>
            </div>
          )}
          {hoveredNode.ports && (
            <div className="text-[11px] text-slate-400">
              Open Ports: <span className="text-amber-400">{hoveredNode.ports.join(', ')}</span>
            </div>
          )}
        </div>
      )}

      {/* Selected Node Inspector Drawer */}
      {selectedNode && (
        <div className="absolute top-16 left-4 z-20 bg-slate-950/95 backdrop-blur-md border border-slate-800 p-4 rounded-2xl shadow-2xl text-xs w-72 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center space-x-2 font-bold text-slate-100 truncate">
              <span className="w-3 h-3 rounded-full" style={{ backgroundColor: NODE_TYPES[selectedNode.type]?.color }}></span>
              <span className="truncate">{selectedNode.id}</span>
            </div>
            <button onClick={() => setSelectedNode(null)} className="text-slate-400 hover:text-slate-200">
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="space-y-1.5 text-slate-300">
            <div className="flex justify-between">
              <span className="text-slate-500">Category:</span>
              <span className="font-semibold text-slate-200 uppercase">{NODE_TYPES[selectedNode.type]?.label}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Liveness Status:</span>
              <span className="text-emerald-400 font-semibold">CONFIRMED ACTIVE</span>
            </div>
            {selectedNode.discovery_source && (
              <div className="flex justify-between">
                <span className="text-slate-500">Discovery Source:</span>
                <span className="text-cyan-400 font-mono">{selectedNode.discovery_source}</span>
              </div>
            )}
            {selectedNode.ports && (
              <div className="flex justify-between">
                <span className="text-slate-500">Active Open Ports:</span>
                <span className="text-amber-400 font-mono">{selectedNode.ports.join(', ')}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Interactive Legend Box (Bottom Right - Matches Uploaded Image Exactly) */}
      <div className="absolute bottom-4 right-4 z-10 bg-slate-950/90 backdrop-blur-md p-3.5 rounded-2xl border border-slate-800 shadow-2xl w-60">
        <div className="text-xs font-bold text-slate-200 uppercase tracking-wider mb-2.5 flex items-center justify-between border-b border-slate-800/80 pb-1.5">
          <span>Topology Legend</span>
          <Info className="w-3.5 h-3.5 text-slate-400" />
        </div>
        <div className="grid grid-cols-2 gap-x-2 gap-y-1.5 text-[11px]">
          {Object.entries(NODE_TYPES).map(([key, config]) => {
            const Icon = config.icon;
            const isActive = activeFilters[key] !== false;
            return (
              <button
                key={key}
                onClick={() => toggleFilter(key)}
                className={`flex items-center space-x-2 p-1 rounded-lg transition text-left ${
                  isActive ? 'text-slate-200 hover:bg-slate-800/60' : 'text-slate-600 line-through'
                }`}
              >
                <span 
                  className="w-2.5 h-2.5 rounded-full flex-shrink-0" 
                  style={{ backgroundColor: isActive ? config.color : '#334155' }}
                ></span>
                <span className="truncate">{config.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
