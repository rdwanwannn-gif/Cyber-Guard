import test from 'node:test';
import assert from 'node:assert/strict';
import {
  interpolateGreatCircleArc,
  projectSpherePoint,
  resolveGeoCoordinates,
  SOC_HOME_HUB,
} from './globeProjection';

test('resolveGeoCoordinates maps known threat origins and falls back deterministically', () => {
  const de = resolveGeoCoordinates('Frankfurt, DE');
  assert.equal(Math.round(de.lat), 50);
  assert.equal(Math.round(de.lon), 9);

  const sg = resolveGeoCoordinates('Singapore, SG');
  assert.equal(Math.round(sg.lon), 104);

  const custom1 = resolveGeoCoordinates('Reykjavik, IS');
  const custom2 = resolveGeoCoordinates('Reykjavik, IS');
  assert.deepEqual(custom1, custom2);
});

test('projectSpherePoint projects front-facing vs back-facing points accurately', () => {
  const front = projectSpherePoint(0, 0, 0, 0, 100, 150, 150);
  assert.equal(front.visible, true);
  assert.equal(Math.round(front.x), 150);
  assert.equal(Math.round(front.y), 150);

  const back = projectSpherePoint(0, 180, 0, 0, 100, 150, 150);
  assert.equal(back.visible, false);
});

test('interpolateGreatCircleArc elevates midpoints cleanly along spherical path', () => {
  const from = resolveGeoCoordinates('Frankfurt, DE');
  const arc = interpolateGreatCircleArc(from, SOC_HOME_HUB, 16);
  assert.equal(arc.length, 17);
  assert.equal(arc[0].altitude, 1);
  assert.ok(arc[8].altitude > 1.05);
  assert.ok(Math.abs(arc[16].altitude - 1) < 1e-6);
});
