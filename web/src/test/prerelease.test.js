import { describe, expect, it } from 'vitest';
import { hostTarget, openJob, ver } from '../selectors.js';
import { statusFixture } from './fixtures.js';

describe('출시 전 목표와 버전 표시', () => {
  it('공식 버전 번호와 구분해 표시한다', () => {
    expect(ver(-2)).toBe('출시 전 pre2');
    expect(ver(2)).toBe('v2');
  });
  it('출시 전 링 목표는 정식 목표와 오래된 즉시 업데이트보다 우선한다', () => {
    const status = statusFixture();
    status.tracks[0].prerelease_ring_versions = { 1: -3 };
    status.hosts[0].update_now_kernel = status.hosts[0].status.kernel;
    status.hosts[0].update_now_version = 9;
    expect(hostTarget(status, status.hosts[0])).toBe(-3);
  });
  it('출시 전 빌드는 정식 즉시 업데이트의 후보로 선택하지 않는다', () => {
    const status = statusFixture();
    status.jobs = [{ ...status.jobs[0], prerelease: true, version: -1, status: 'built' }];
    expect(openJob(status, status.hosts[0].status.kernel)).toBeUndefined();
  });
});
