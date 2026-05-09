import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@qauth-labs/ui';
import { createFileRoute } from '@tanstack/react-router';

import type { UserInfoData } from '../../server/auth-server-client';

export const Route = createFileRoute('/_authed/dashboard')({
  component: DashboardPage,
});

function DashboardPage() {
  const { user } = Route.useRouteContext() as { user: UserInfoData };

  return (
    <main className="mx-auto max-w-5xl px-6 py-10">
      <h1 className="mb-8 text-2xl font-semibold text-gray-900">
        Welcome, {user.email ?? user.sub}
      </h1>

      <div className="grid gap-6 sm:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>OAuth Clients</CardTitle>
            <CardDescription>
              Manage applications that use QAuth for authentication.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-gray-400">Coming soon in Phase 2.2.</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>API Keys</CardTitle>
            <CardDescription>Generate and revoke keys for direct API access.</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-gray-400">Coming soon in Phase 2.3.</p>
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
