# Repository guidance

## Attribute access and typing

- Prefer direct attribute access when the attribute name is known. Do not use
  `getattr` or `setattr` with a literal name to bypass missing type information.
- Express required attributes with concrete types or small protocols. For ORM
  adapters, use the shared SQLModel bases and `col(model.field)` for query
  expressions while preserving callers' concrete model types. Prefer explicit
  typed mappings when selecting among a fixed set of fields. Avoid column
  protocol casts, casts to `Any`, or lookup wrappers that hide missing types.
- Keep reflection for genuinely dynamic field names and runtime capability or
  configuration checks, where an attribute may legitimately be absent.
- Run the relevant tests and `ty check . --exclude website` after typing
  changes.
