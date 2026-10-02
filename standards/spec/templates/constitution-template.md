# <project> constitution

Durable principles that govern this corpus. **Tier 2**: subordinate to the
bootstrap spec (`specs/000-*/spec.md`) and governing all ordinary specs.

**Normative hierarchy (highest wins):**

1. `specs/000-*/spec.md`: the bootstrap spec. Non-overridable.
2. `standards/spec/constitution.md`: this document.
3. `standards/spec/contract.md`: normative summary of the bootstrap spec.
4. Ordinary specs (`001`+).

---

## I. <Principle name>

<One paragraph. State the principle as a durable rule, and cite the bootstrap
anchor it rests on, if any.>

## II. <Principle name>

<...>

## III. <Principle name>

<...>

---

## Amendment

This constitution may be changed by an approved ordinary spec that claims
the affected text as a section authority unit with `establishes`, `refines`
(with a named `aspect`), or `co_authority`, provided the change contradicts no
bootstrap `unamendable` anchor. `amends` targets spec ids and does not amend
this constitution file.
