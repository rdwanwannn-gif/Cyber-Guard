import React, { useEffect, useRef, useState } from 'react';
import { Pause, Play, RotateCcw, Globe as GlobeIcon } from 'lucide-react';
import type { Translations } from '../i18n/translations';
import {
  interpolateGreatCircleArc,
  projectSpherePoint,
  resolveGeoCoordinates,
  SOC_HOME_HUB,
  WORLD_CONTINENTS,
} from '../lib/globeProjection';
import type { ThreatAlert } from '../lib/types';

interface LiveThreatGlobeProps {
  t: Translations;
  alerts: ThreatAlert[];
  isDark: boolean;
}

export function LiveThreatGlobe({ t, alerts, isDark }: LiveThreatGlobeProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  const [autoRotate, setAutoRotate] = useState(true);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);

  // Refs so animation loop never triggers React re-renders
  const rotationRef = useRef(-1.55); // Start centered near Asia-Pacific / Europe
  const tiltRef = useRef(0.28);
  const autoRotateRef = useRef(true);
  const isDarkRef = useRef(isDark);
  const alertsRef = useRef<ThreatAlert[]>(alerts);
  const prevTopAlertIdRef = useRef<string | null>(alerts[0]?.id ?? null);
  const draggingRef = useRef<{ active: boolean; lastX: number; lastY: number }>({
    active: false,
    lastX: 0,
    lastY: 0,
  });

  useEffect(() => {
    autoRotateRef.current = autoRotate;
  }, [autoRotate]);

  useEffect(() => {
    isDarkRef.current = isDark;
  }, [isDark]);

  useEffect(() => {
    alertsRef.current = alerts;
    const topAlert = alerts[0];
    if (topAlert && topAlert.id !== prevTopAlertIdRef.current) {
      prevTopAlertIdRef.current = topAlert.id;
      setSelectedAlertId(topAlert.id);
      const coord = resolveGeoCoordinates(topAlert.sourceGeo);
      rotationRef.current = (-coord.lon * Math.PI) / 180;
      tiltRef.current = Math.max(-0.4, Math.min(0.6, (coord.lat * Math.PI) / 180 * 0.5));
    }
  }, [alerts]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const prefersReducedMotion =
      typeof window !== 'undefined' &&
      window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

    let animId = 0;
    let lastTime = performance.now();

    const syncCanvasSize = () => {
      const rect = container.getBoundingClientRect();
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      const w = Math.max(240, Math.floor(rect.width));
      const h = Math.max(220, Math.floor(rect.height));
      if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
        canvas.width = w * dpr;
        canvas.height = h * dpr;
      }
    };

    syncCanvasSize();
    const resizeObserver = new ResizeObserver(syncCanvasSize);
    resizeObserver.observe(container);

    const drawFrame = (now: number) => {
      const dt = Math.min(0.05, (now - lastTime) / 1000);
      lastTime = now;

      if (autoRotateRef.current && !draggingRef.current.active && !prefersReducedMotion) {
        rotationRef.current += dt * 0.22;
      }

      const dpr = Math.min(2, window.devicePixelRatio || 1);
      const width = canvas.width / dpr;
      const height = canvas.height / dpr;
      const cx = width / 2;
      const cy = height / 2;
      const radius = Math.min(width, height) * 0.42;

      const dark = isDarkRef.current;
      const rot = rotationRef.current;
      const tilt = tiltRef.current;

      ctx.save();
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, width, height);

      // Subtle atmospheric halo
      const halo = ctx.createRadialGradient(cx, cy, radius * 0.85, cx, cy, radius * 1.15);
      halo.addColorStop(0, dark ? 'rgba(14, 165, 233, 0.14)' : 'rgba(2, 132, 199, 0.10)');
      halo.addColorStop(1, 'rgba(14, 165, 233, 0)');
      ctx.fillStyle = halo;
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.15, 0, Math.PI * 2);
      ctx.fill();

      // Ocean sphere fill
      const oceanGrad = ctx.createRadialGradient(
        cx - radius * 0.3,
        cy - radius * 0.3,
        radius * 0.1,
        cx,
        cy,
        radius,
      );
      if (dark) {
        oceanGrad.addColorStop(0, '#0f2544');
        oceanGrad.addColorStop(0.7, '#09172e');
        oceanGrad.addColorStop(1, '#040b18');
      } else {
        oceanGrad.addColorStop(0, '#f0f9ff');
        oceanGrad.addColorStop(0.75, '#dbeafe');
        oceanGrad.addColorStop(1, '#bfdbfe');
      }

      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.fillStyle = oceanGrad;
      ctx.fill();

      // Clip interior of Earth sphere for graticules & landmasses
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.clip();

      // Latitude & Longitude graticules
      ctx.strokeStyle = dark ? 'rgba(148, 163, 184, 0.12)' : 'rgba(51, 65, 85, 0.13)';
      ctx.lineWidth = 0.75;

      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath();
        let started = false;
        for (let lon = -180; lon <= 180; lon += 6) {
          const p = projectSpherePoint(lat, lon, rot, tilt, radius, cx, cy);
          if (p.visible) {
            if (!started) {
              ctx.moveTo(p.x, p.y);
              started = true;
            } else {
              ctx.lineTo(p.x, p.y);
            }
          } else {
            started = false;
          }
        }
        ctx.stroke();
      }

      for (let lon = -180; lon < 180; lon += 30) {
        ctx.beginPath();
        let started = false;
        for (let lat = -84; lat <= 84; lat += 6) {
          const p = projectSpherePoint(lat, lon, rot, tilt, radius, cx, cy);
          if (p.visible) {
            if (!started) {
              ctx.moveTo(p.x, p.y);
              started = true;
            } else {
              ctx.lineTo(p.x, p.y);
            }
          } else {
            started = false;
          }
        }
        ctx.stroke();
      }

      // Draw world continents
      ctx.fillStyle = dark ? 'rgba(30, 58, 95, 0.85)' : 'rgba(148, 163, 184, 0.52)';
      ctx.strokeStyle = dark ? 'rgba(56, 189, 248, 0.48)' : 'rgba(2, 132, 199, 0.55)';
      ctx.lineWidth = 1;

      for (const poly of WORLD_CONTINENTS) {
        const projected = poly.map(([lon, lat]) =>
          projectSpherePoint(lat, lon, rot, tilt, radius, cx, cy),
        );
        const visibleCount = projected.filter((p) => p.z > -0.15).length;
        if (visibleCount < 2) continue;

        ctx.beginPath();
        let drawing = false;
        for (let i = 0; i < projected.length; i += 1) {
          const pt = projected[i];
          if (pt.z > -0.18) {
            if (!drawing) {
              ctx.moveTo(pt.x, pt.y);
              drawing = true;
            } else {
              ctx.lineTo(pt.x, pt.y);
            }
          } else {
            drawing = false;
          }
        }
        ctx.fill();
        ctx.stroke();
      }

      ctx.restore();

      // Sphere outer border rim
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.strokeStyle = dark ? 'rgba(56, 189, 248, 0.35)' : 'rgba(2, 132, 199, 0.45)';
      ctx.lineWidth = 1.25;
      ctx.stroke();

      // Draw SOC Home Hub marker (Jakarta)
      const hubPt = projectSpherePoint(
        SOC_HOME_HUB.lat,
        SOC_HOME_HUB.lon,
        rot,
        tilt,
        radius,
        cx,
        cy,
      );

      if (hubPt.visible) {
        ctx.beginPath();
        ctx.arc(hubPt.x, hubPt.y, 6.5, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(16, 185, 129, 0.25)';
        ctx.fill();

        ctx.beginPath();
        ctx.arc(hubPt.x, hubPt.y, 3.2, 0, Math.PI * 2);
        ctx.fillStyle = '#10b981';
        ctx.fill();
      }

      // Draw Live Threat Great-Circle Arcs & Origin Pins
      const activeAlerts = alertsRef.current.slice(0, 8);
      const pulsePhase = (now / 1000) % 1;

      activeAlerts.forEach((alert, idx) => {
        const origin = resolveGeoCoordinates(alert.sourceGeo);
        const arc = interpolateGreatCircleArc(origin, SOC_HOME_HUB, 24);
        const color =
          alert.severity === 'critical'
            ? '#ef4444'
            : alert.severity === 'high'
              ? '#f59e0b'
              : '#0ea5e9';

        // Arc path
        ctx.beginPath();
        let hasSegment = false;
        const arcScreenPts: Array<{ x: number; y: number; visible: boolean }> = [];
        for (const step of arc) {
          const sp = projectSpherePoint(
            step.lat,
            step.lon,
            rot,
            tilt,
            radius * step.altitude,
            cx,
            cy,
          );
          arcScreenPts.push(sp);
          if (sp.visible) {
            if (!hasSegment) {
              ctx.moveTo(sp.x, sp.y);
              hasSegment = true;
            } else {
              ctx.lineTo(sp.x, sp.y);
            }
          } else {
            hasSegment = false;
          }
        }
        ctx.strokeStyle =
          alert.status === 'blocked' || alert.status === 'mitigated'
            ? dark
              ? 'rgba(148, 163, 184, 0.35)'
              : 'rgba(100, 116, 139, 0.35)'
            : color;
        ctx.lineWidth = alert.severity === 'critical' ? 1.8 : 1.3;
        ctx.stroke();

        // Traveling telemetry pulse along arc
        if (!prefersReducedMotion) {
          const travelIdx = Math.floor(((pulsePhase + idx * 0.19) % 1) * (arcScreenPts.length - 1));
          const packetPt = arcScreenPts[travelIdx];
          if (packetPt && packetPt.visible) {
            ctx.beginPath();
            ctx.arc(packetPt.x, packetPt.y, 2.5, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.fill();
          }
        }

        // Origin marker
        const originPt = projectSpherePoint(origin.lat, origin.lon, rot, tilt, radius, cx, cy);
        if (originPt.visible) {
          if (alert.status === 'active' || alert.status === 'investigating') {
            const ringRadius = 4 + pulsePhase * 7;
            ctx.beginPath();
            ctx.arc(originPt.x, originPt.y, ringRadius, 0, Math.PI * 2);
            ctx.strokeStyle = `${color}88`;
            ctx.lineWidth = 1.2;
            ctx.stroke();
          }
          ctx.beginPath();
          ctx.arc(originPt.x, originPt.y, 3.2, 0, Math.PI * 2);
          ctx.fillStyle = color;
          ctx.fill();
        }
      });

      ctx.restore();
      animId = window.requestAnimationFrame(drawFrame);
    };

    animId = window.requestAnimationFrame(drawFrame);
    return () => {
      window.cancelAnimationFrame(animId);
      resizeObserver.disconnect();
    };
  }, []);

  function handlePointerDown(e: React.PointerEvent<HTMLCanvasElement>) {
    draggingRef.current = { active: true, lastX: e.clientX, lastY: e.clientY };
    e.currentTarget.setPointerCapture(e.pointerId);
  }

  function handlePointerMove(e: React.PointerEvent<HTMLCanvasElement>) {
    if (!draggingRef.current.active) return;
    const dx = e.clientX - draggingRef.current.lastX;
    const dy = e.clientY - draggingRef.current.lastY;
    draggingRef.current.lastX = e.clientX;
    draggingRef.current.lastY = e.clientY;
    rotationRef.current += dx * 0.008;
    tiltRef.current = Math.max(-0.65, Math.min(0.85, tiltRef.current + dy * 0.006));
  }

  function handlePointerUp(e: React.PointerEvent<HTMLCanvasElement>) {
    draggingRef.current.active = false;
    if (e.currentTarget.hasPointerCapture(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId);
    }
  }

  function handleFocusAlert(alert: ThreatAlert) {
    setSelectedAlertId(alert.id);
    const coord = resolveGeoCoordinates(alert.sourceGeo);
    rotationRef.current = (-coord.lon * Math.PI) / 180;
    tiltRef.current = Math.max(-0.4, Math.min(0.6, (coord.lat * Math.PI) / 180 * 0.5));
  }

  const activeThreatPreview =
    alerts.find((a) => a.id === selectedAlertId) ?? alerts[0] ?? null;

  return (
    <div
      data-testid="live-threat-globe"
      data-rotating={autoRotate ? 'true' : 'false'}
      className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 flex flex-col justify-between"
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50 flex items-center gap-2">
            <GlobeIcon className="w-4 h-4 text-sky-600 dark:text-sky-400 shrink-0" aria-hidden="true" />
            <span>{t.overview.globeTitle}</span>
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            {t.overview.globeSubtitle}
          </p>
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          <button
            type="button"
            onClick={() => setAutoRotate((v) => !v)}
            aria-label={autoRotate ? t.overview.pauseRotation : t.overview.resumeRotation}
            title={autoRotate ? t.overview.pauseRotation : t.overview.resumeRotation}
            className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            {autoRotate ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
          </button>
          <button
            type="button"
            onClick={() => {
              rotationRef.current = -1.55;
              tiltRef.current = 0.28;
              setAutoRotate(true);
              setSelectedAlertId(null);
            }}
            aria-label={t.overview.resetView}
            title={t.overview.resetView}
            className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div
        ref={containerRef}
        className="relative w-full h-56 my-2 cursor-grab active:cursor-grabbing select-none"
      >
        <canvas
          ref={canvasRef}
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerUp}
          onPointerCancel={handlePointerUp}
          aria-label={t.overview.globeTitle}
          className="w-full h-full block touch-none"
        />
      </div>

      <div className="pt-3 border-t border-slate-200 dark:border-slate-800 space-y-2">
        <div className="flex flex-wrap items-center gap-1.5">
          {alerts.slice(0, 4).map((a) => (
            <button
              key={a.id}
              type="button"
              onClick={() => handleFocusAlert(a)}
              className={`px-2 py-1 rounded text-[11px] font-mono transition-colors whitespace-nowrap ${
                activeThreatPreview?.id === a.id
                  ? 'bg-sky-50 dark:bg-sky-950/60 text-sky-700 dark:text-sky-300'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}
            >
              {a.sourceGeo.split(',')[0]}
            </button>
          ))}
        </div>
        {activeThreatPreview && (
          <div className="flex items-center justify-between gap-2 text-xs font-mono text-slate-600 dark:text-slate-400 truncate">
            <span className="truncate">
              {activeThreatPreview.sourceIp} ({activeThreatPreview.sourceGeo}) -&gt; Jakarta SOC
            </span>
            <span
              className={`uppercase font-semibold shrink-0 ${
                activeThreatPreview.severity === 'critical'
                  ? 'text-red-600 dark:text-red-400'
                  : activeThreatPreview.severity === 'high'
                    ? 'text-amber-600 dark:text-amber-400'
                    : 'text-sky-600 dark:text-sky-400'
              }`}
            >
              {activeThreatPreview.severity}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
