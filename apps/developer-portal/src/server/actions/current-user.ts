import { createServerFn } from '@tanstack/react-start';

import { currentUserHandler, type CurrentUserResult } from './current-user.server';

export type { CurrentUserResult };

export const currentUserFn = createServerFn({ method: 'GET' }).handler(currentUserHandler);
