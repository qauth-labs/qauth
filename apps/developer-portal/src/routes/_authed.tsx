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
    <div className="min-h-screen bg-gray-50">
      <header className="border-b border-gray-200 bg-white px-6 py-3">
        <div className="mx-auto flex max-w-5xl items-center justify-between">
          <div className="flex items-center gap-6">
            <span className="text-sm font-medium text-gray-700">QAuth Developer Portal</span>
            <nav className="flex items-center gap-4">
              <Link to="/clients" className="text-sm text-gray-600 hover:text-gray-900">
                Clients
              </Link>
              {/*
                #366: the consent screen had no link anywhere in the portal, so
                a developer could only reach it by typing the URL. Between that
                and having no test, nothing exercised the page and its 401 went
                unnoticed.
              */}
              <Link to="/consents" className="text-sm text-gray-600 hover:text-gray-900">
                Authorized apps
              </Link>
            </nav>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-500">{user.email ?? user.sub}</span>
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
