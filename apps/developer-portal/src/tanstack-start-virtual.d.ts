// Start's resolved server entry: its default handler, or src/server.ts if one
// is ever added. Aliased by the Start Vite plugin; imported by src/node-entry.ts.
declare module 'virtual:tanstack-start-server-entry' {
  import type { ServerEntry } from '@tanstack/react-start/server-entry';

  const entry: ServerEntry;
  export default entry;
}
