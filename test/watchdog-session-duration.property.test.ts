// Feature: org-security-controls, Property 6: Session Duration Constraint
import * as fc from 'fast-check';
import { validateSessionDuration } from '../lambda/watchdog/handler';

/**
 * Validates: Requirements 15.2
 */
describe('Property 6: Session Duration Constraint', () => {
  it('accepts durations <= 3600 without throwing', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 3600 }),
        (duration) => {
          expect(() => validateSessionDuration(duration)).not.toThrow();
        },
      ),
      { numRuns: 100 },
    );
  });

  it('rejects durations > 3600 by throwing an error', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 3601, max: 7200 }),
        (duration) => {
          expect(() => validateSessionDuration(duration)).toThrow(
            /exceeds maximum allowed value of 3600 seconds/,
          );
        },
      ),
      { numRuns: 100 },
    );
  });

  it('accepts exactly 3600', () => {
    expect(() => validateSessionDuration(3600)).not.toThrow();
  });
});
