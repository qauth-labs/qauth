import { createMemoryRoundLimits } from './memory-round-limits';
import { describeRoundLimitStore } from './round-limit-store-contract';

describeRoundLimitStore('the memory store', async () => {
  let clock = Date.UTC(2026, 10, 5);
  return {
    store: createMemoryRoundLimits(() => clock),
    advance: (ms: number) => {
      clock += ms;
    },
  };
});
