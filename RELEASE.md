---
release type: minor
---

Add support for Django 6.0 and 6.1 alongside Django 5.2 LTS. Python 3.15 is
supported with Django 6.1.3 or later; Python 3.11 continues to use Django 5.2.
The Django test matrix covers each supported series with SQLite and PostgreSQL,
using both Django's default user model and a custom UUID user model, including
Cross Auth's optional session engine.
