import dotenv from 'dotenv';
import { createSocApp } from './app';
import { SecurityWorkspaceStore } from './state';

dotenv.config();

declare global {
  // eslint-disable-next-line no-var
  var __sentinelGridStore: SecurityWorkspaceStore | undefined;
}

function getStore(): SecurityWorkspaceStore {
  if (!globalThis.__sentinelGridStore) {
    globalThis.__sentinelGridStore = new SecurityWorkspaceStore();
  }
  return globalThis.__sentinelGridStore;
}

const socApp = createSocApp(getStore(), {
  wsSupported: false,
});

export default socApp;
