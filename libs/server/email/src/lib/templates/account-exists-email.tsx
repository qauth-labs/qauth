import * as React from 'react';

import { Body, Container, Head, Html, Preview, Section, Text } from './components';

/**
 * React Email template sent when someone registers an address that already
 * has an account.
 *
 * Registration answers every address the same way, so the person who already
 * owns the address learns about the attempt here, and only here. The mail
 * carries no link and no token: nothing in it can sign anyone in or change the
 * account, so it is safe to send whoever made the attempt.
 *
 * @returns React component
 */
export function AccountExistsEmail() {
  return (
    <Html>
      <Head />
      <Preview>Someone tried to create an account with your email address</Preview>
      <Body style={main}>
        <Container style={container}>
          <Section style={section}>
            <Text style={title}>You already have an account</Text>
            <Text style={text}>
              Someone just tried to create a QAuth account with this email address. You already have
              an account with it, so no new account was created and your existing account was not
              changed.
            </Text>
            <Text style={text}>
              If this was you, sign in with your existing password instead of registering again. If
              you no longer know your password, contact the administrator of this service.
            </Text>
            <Text style={footer}>
              If this was not you, you can safely ignore this email. Nobody can sign in to your
              account without your password.
            </Text>
          </Section>
        </Container>
      </Body>
    </Html>
  );
}

// Styles, matching the verification email.
const main = {
  backgroundColor: '#f6f9fc',
  fontFamily:
    '-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Ubuntu,sans-serif',
};

const container = {
  backgroundColor: '#ffffff',
  margin: '0 auto',
  padding: '20px 0 48px',
  marginBottom: '64px',
};

const section = {
  padding: '0 48px',
};

const title = {
  fontSize: '24px',
  lineHeight: '1.3',
  fontWeight: '700',
  color: '#1a1a1a',
  margin: '0 0 20px',
};

const text = {
  fontSize: '16px',
  lineHeight: '1.5',
  color: '#4a5568',
  margin: '0 0 16px',
};

const footer = {
  fontSize: '14px',
  lineHeight: '1.5',
  color: '#718096',
  margin: '32px 0 0',
  paddingTop: '16px',
  borderTop: '1px solid #e2e8f0',
};
