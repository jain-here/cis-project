'use client';

import { riskLevelColor } from '@/lib/scoring';
import type { RiskLevel } from '@/types';

interface RiskGaugeProps {
  score: number;
  riskLevel: RiskLevel | null;
  size?: number;
}

export function RiskGauge({ score, riskLevel, size = 200 }: RiskGaugeProps) {
  const radius = size * 0.38;
  const cx = size / 2;
  const cy = size / 2;
  const strokeWidth = size * 0.08;

  // Arc goes from 225deg to -45deg (270deg sweep)
  const startAngle = 225;
  const endAngle = -45;
  const sweepDeg = 270;

  const color = riskLevelColor(riskLevel);

  function polarToXY(angleDeg: number, r: number) {
    const rad = ((angleDeg - 90) * Math.PI) / 180;
    return {
      x: cx + r * Math.cos(rad),
      y: cy + r * Math.sin(rad),
    };
  }

  function arcPath(fromDeg: number, toDeg: number, r: number) {
    const start = polarToXY(fromDeg, r);
    const end = polarToXY(toDeg, r);
    const largeArc = Math.abs(toDeg - fromDeg) > 180 ? 1 : 0;
    // Use counter-clockwise sweep for our angle convention so the 270deg arc renders fully.
    return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 0 ${end.x} ${end.y}`;
  }

  const scoreAngle = startAngle - (score / 100) * sweepDeg;
  const bgPath = arcPath(startAngle, endAngle, radius);
  const fgPath = score > 0 ? arcPath(startAngle, scoreAngle, radius) : '';

  // Needle
  const needleAngle = startAngle - (score / 100) * sweepDeg;
  const needleTip = polarToXY(needleAngle, radius * 0.72);
  const needleBase1 = polarToXY(needleAngle + 90, strokeWidth * 0.3);
  const needleBase2 = polarToXY(needleAngle - 90, strokeWidth * 0.3);

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        {/* Track */}
        <path
          d={bgPath}
          fill="none"
          stroke="#1e293b"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />
        {/* Score arc */}
        {fgPath && (
          <path
            d={fgPath}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            style={{
              filter: `drop-shadow(0 0 ${strokeWidth * 0.4}px ${color}80)`,
            }}
          />
        )}
        {/* Needle */}
        <polygon
          points={`${needleTip.x},${needleTip.y} ${needleBase1.x},${needleBase1.y} ${needleBase2.x},${needleBase2.y}`}
          fill={color}
          opacity={0.9}
        />
        {/* Center dot */}
        <circle cx={cx} cy={cy} r={strokeWidth * 0.45} fill={color} />
        <circle cx={cx} cy={cy} r={strokeWidth * 0.25} fill="#0f172a" />

        {/* Score text */}
        <text
          x={cx}
          y={cy + size * 0.2}
          textAnchor="middle"
          fill={color}
          fontSize={size * 0.22}
          fontWeight="bold"
          fontFamily="monospace"
        >
          {score}
        </text>
        <text
          x={cx}
          y={cy + size * 0.33}
          textAnchor="middle"
          fill="#64748b"
          fontSize={size * 0.08}
          fontFamily="sans-serif"
        >
          / 100
        </text>
      </svg>
    </div>
  );
}
