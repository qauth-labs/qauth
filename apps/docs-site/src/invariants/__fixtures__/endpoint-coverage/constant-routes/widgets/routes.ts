// Mirrors apps/auth-server/src/app/admin/clients/routes.ts: routes written as
// the module's own path constants and templates built on them, beside calls
// that share a method name and are not routes.
declare const UNKNOWN_BASE: string;

const WIDGETS_PATH = '/admin/v1-rc.0/realms/:realmId/widgets';
const WIDGET_PATH = `${WIDGETS_PATH}/:widgetId`;
const NOT_A_PATH = `${UNKNOWN_BASE}/nowhere`;
const WIDGET_OPERATION_IDS = { create: 'widgets.create' };

interface Typed {
  get(path: string, options: object, handler: () => unknown): void;
  post(path: string, options: object, handler: () => unknown): void;
  patch(path: string, options: object, handler: () => unknown): void;
}

export function widgetRoutes(
  typed: Typed,
  registry: Map<string, string>,
  repository: { delete(id: string, realm: string): void }
) {
  registry.get(WIDGET_OPERATION_IDS.create);
  repository.delete('a', 'b');
  typed.get(WIDGETS_PATH, {}, () => null);
  typed.post(WIDGETS_PATH, {}, () => null);
  typed.patch(WIDGET_PATH, {}, () => null);
  typed.post(`${WIDGET_PATH}/enable`, {}, () => null);
  typed.get('/admin/v1-rc.0/realms/:realmId/gadgets', {}, () => null);
  typed.get(NOT_A_PATH, {}, () => null);
  typed.get(`${UNKNOWN_BASE}/elsewhere`, {}, () => null);
  typed.get('/health', {}, () => null);
}
