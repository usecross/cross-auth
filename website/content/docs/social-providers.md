---
title: Social Providers
description: Add social login with GitHub, Google, and other OAuth providers.
order: 4
section: Guides
---

## Overview

Cross-Auth supports social login through OAuth 2.0 providers. Users can sign in with their existing accounts from services like GitHub and Google, and Cross-Auth will create or link accounts in your storage.

## How It Works

1. The user clicks "Sign in with GitHub" (or another provider).
2. Your app redirects to the provider's authorization URL.
3. The user authorizes your app.
4. The provider redirects back to your app with an authorization code.
5. Cross-Auth exchanges the code for user info and creates/links the account.

## Account Linking

Cross-Auth supports linking multiple social accounts to a single user. If a user signs in with GitHub and later connects their Google account, both providers are linked to the same user record via the `SocialAccount` model.

The `POST /{provider}/link` endpoint handles account linking for authenticated users.

## Configuration

Each provider requires:

- **Client ID** -- From the provider's developer console.
- **Client Secret** -- From the provider's developer console.
- **Redirect URI** -- The callback URL in your app.
