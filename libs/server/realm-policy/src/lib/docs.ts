/** The docs page generated from the schema, as docs.qauth.dev serves it. */
export const REALM_POLICIES_PAGE_URL = 'https://docs.qauth.dev/reference/realm-policies/';

/** The page's section for a group, the docs link of a field that has no page of its own. */
export function groupDocsLink(group: string): string {
  return `${REALM_POLICIES_PAGE_URL}#${group.toLowerCase()}`;
}
