import { createServerFn } from '@tanstack/react-start';

import { logoutHandler } from './logout.server';

export const logoutFn = createServerFn({ method: 'POST' }).handler(logoutHandler);
