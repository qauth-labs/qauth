import { Button } from '@qauth-labs/ui';
import { createFileRoute, Link, Outlet, redirect, useRouter } from '@tanstack/react-router';

import { currentUserFn } from '../server/actions/current-user';
import { logoutFn } from '../server/actions/logout';
import type { UserInfoData } from '../server/auth-server-client';

export const Route = createFileRoute('/_authed')({
  beforeLoad: async () => {
    const result = await currentUserFn();
    if (result === null) {
      throw redirect({ to: '/login' });
    }
    return { user: result.user };
  },
  component: AuthedLayout,
});

function AuthedLayout() {
  const { user } = Route.useRouteContext() as { user: UserInfoData };
  const router = useRouter();

  async function handleLogout() {
    await logoutFn();
    await router.navigate({ to: '/login' });
  }

  return (
    <div className="bg-background min-h-screen">
      <header className="border-border bg-card border-b px-6 py-3">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-x-6 gap-y-2">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-1">
            <span className="font-display text-foreground text-xl whitespace-nowrap">
              QAuth Developer Portal
            </span>
            <nav className="flex items-center gap-4">
              <Link to="/clients" className="text-body hover:text-foreground text-sm">
                Clients
              </Link>
              {/*
                #366: the consent screen had no link anywhere in the portal, so
                a developer could only reach it by typing the URL. Between that
                and having no test, nothing exercised the page and its 401 went
                unnoticed.
              */}
              <Link to="/consents" className="text-body hover:text-foreground text-sm">
                Authorized apps
              </Link>
            </nav>
          </div>
          <div className="flex min-w-0 items-center gap-4">
            <span className="text-muted-foreground min-w-0 truncate text-sm">
              {user.email ?? user.sub}
            </span>
            <Button variant="ghost" size="sm" type="button" onClick={() => void handleLogout()}>
              Log out
            </Button>
          </div>
        </div>
      </header>

      <Outlet />
    </div>
  );
}
