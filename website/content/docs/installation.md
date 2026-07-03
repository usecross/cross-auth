---
title: Installation
description: Install Cross-Auth in your Python project.
order: 2
section: Getting Started
---

## Install with uv

```bash
uv add cross-auth
```

## Install with pip

```bash
pip install cross-auth
```

## Storage adapters

Cross-Auth ships optional storage adapters behind extras. Install the ones you
need:

```bash
uv add 'cross-auth[redis]'      # RedisStorage for secondary storage
uv add 'cross-auth[sqlmodel]'   # SQLModel accounts and session adapters
uv add 'cross-auth[redis,sqlmodel]'
```

Without the extras, the core library does not depend on Redis or SQLModel. The
Redis adapter needs a Redis server 6.2 or newer. See the
[Storage](/docs/storage) guide for usage.

## Requirements

- Python 3.11 or higher
- A web framework (FastAPI, Django, Flask, etc.)
- A database for user storage (a built-in adapter, or any ORM or driver that
  implements the storage protocols)
