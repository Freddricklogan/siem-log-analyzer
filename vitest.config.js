import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.js'],
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      // Pure logic only. The DOM layer (ui/charts/main/exec-shell) is exercised
      // by the Playwright smoke test, not by unit tests.
      include: ['src/rules.js', 'src/generate.js', 'src/detect.js', 'src/correlate.js', 'src/report.js']
    }
  }
});
