import { Button } from '@qauth/ui';
import { createFileRoute } from '@tanstack/react-router';

export const Route = createFileRoute('/')({
  component: Home,
});

function Home() {
  return <Button variant="link">Click me</Button>;
}
