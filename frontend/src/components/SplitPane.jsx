import React, { useState, useRef, useEffect } from 'react';

export default function SplitPane({ left, right, defaultLeftWidth = 33 }) {
  const [leftWidth, setLeftWidth] = useState(defaultLeftWidth);
  const [isDragging, setIsDragging] = useState(false);
  const containerRef = useRef(null);

  useEffect(() => {
    const handleMouseMove = (e) => {
      if (!isDragging || !containerRef.current) return;
      const containerRect = containerRef.current.getBoundingClientRect();
      const newLeftWidth = ((e.clientX - containerRect.left) / containerRect.width) * 100;
      
      // Constrain between 20% and 80% to prevent boxes from getting too small
      if (newLeftWidth > 20 && newLeftWidth < 80) {
        setLeftWidth(newLeftWidth);
      }
    };

    const handleMouseUp = () => {
      setIsDragging(false);
    };

    if (isDragging) {
      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
    } else {
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    }

    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, [isDragging]);

  return (
    <div ref={containerRef} className="flex flex-col lg:flex-row w-full gap-0 h-full relative" style={{ minHeight: '500px' }}>
      <div 
        className="flex-shrink-0 mb-6 lg:mb-0"
        style={{ width: window.innerWidth >= 1024 ? `calc(${leftWidth}% - 12px)` : '100%' }}
      >
        {left}
      </div>
      
      {/* Resizer Handle - only visible on lg screens */}
      <div 
        className="hidden lg:flex flex-shrink-0 w-6 items-center justify-center cursor-col-resize z-10"
        onMouseDown={() => setIsDragging(true)}
      >
        {/* User requested empty blank space for handle */}
      </div>

      <div className="flex-1 min-w-0 h-full">
        {right}
      </div>
    </div>
  );
}
